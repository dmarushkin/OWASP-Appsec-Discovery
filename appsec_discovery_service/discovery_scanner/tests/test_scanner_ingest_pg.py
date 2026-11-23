"""External parsers (POST /ingest): the scanner side against a real Postgres."""

import json
from types import SimpleNamespace

from sqlalchemy import text


def q(sql, **params):
    from discovery_common import db
    with db.get_engine().connect() as conn:
        return conn.execute(text(sql), params).all()


def x(sql, **params):
    from discovery_common import db
    with db.unit_of_work() as s:
        return s.execute(text(sql), params)


def table(name, *columns):
    return {"name": name, "type": "table", "file": "db01/billing", "props": {"schema": "dbo"},
            "fields": [{"name": c, "type": "nvarchar", "line": i + 1} for i, c in enumerate(columns)]}


def external_project(path="external/payments/db01"):
    # the built-in keyword scoring is opt-in (kw-fields / kw-props disabled on a new install): on for these tests
    x("UPDATE rules SET enabled = true WHERE scope ->> 'source' = 'core'")
    pid = x("INSERT INTO gitlab_projects (project_name, full_path, visibility, source, created_at, updated_at) "
            "VALUES ('db01', :p, 'private', 'external', now(), now()) RETURNING id", p=path).scalar()
    bid = x("INSERT INTO gitlab_branches (branch_name, is_main, commit, project_id, project_path, created_at, updated_at) "
            "VALUES ('snapshot', true, 'ingest-none', :p, :path, now(), now()) RETURNING id", p=pid, path=path).scalar()
    return pid, bid


def push(pid, parser, *objects, llm=False, status="committed"):
    batch = x("INSERT INTO ingest_batches (project_id, parser, snapshot, status, llm) VALUES (:p, :parser, 's1', :st, :llm) "
              "RETURNING id", p=pid, parser=parser, st=status, llm=llm).scalar()
    x("INSERT INTO ingest_chunks (batch_id, seq, payload, objects, fields, content_hash) "
      "VALUES (:b, 0, CAST(:pl AS jsonb), :n, 0, 'h')", b=batch, pl=json.dumps({"objects": list(objects)}), n=len(objects))
    return batch


def snapshot(bid):
    return sorted(q("SELECT o.parser, o.name, (SELECT count(*) FROM object_fields f WHERE f.content_hash = o.content_hash) "
                    "FROM branch_objects b JOIN objects o USING (content_hash) WHERE b.branch_id = :b", b=bid))


def test_ingest_applies_rules_replaces_the_parser_state_and_skips_unchanged(pg_scanner):
    dbs = pg_scanner.db
    scan_service = pg_scanner.load("services.scan_service")
    pid, bid = external_project()
    b1 = push(pid, "mssql", table("dbo.Clients", "Id", "PassportNumber", "Phone"), table("dbo.Orders", "Id", "Amount"))
    push(pid, "cmdb", {"name": "billing-api", "type": "service", "fields": [{"name": "owner"}]})

    stats = scan_service.ingest_branch(dbs.get_branch_by_id(bid), "mssql")
    assert stats["objects"] == 2 and stats["batch_id"] == b1
    assert scan_service.ingest_branch(dbs.get_branch_by_id(bid), "cmdb")["objects"] == 1
    assert snapshot(bid) == [("cmdb", "billing-api", 1), ("mssql", "dbo.Clients", 3), ("mssql", "dbo.Orders", 2)]
    # core keyword scoring (score_tags) hits the passport column like code
    assert ("PassportNumber", "match") in q("SELECT field_name, status FROM rule_hits")
    branch = dbs.get_branch_by_id(bid)
    assert branch.scanned_commit == branch.commit and branch.commit.startswith("ingest-")
    assert q("SELECT status FROM ingest_batches WHERE id = :b", b=b1) == [("processed",)]

    # the same state with the same rules: skipped; force: processed again
    assert scan_service.ingest_branch(dbs.get_branch_by_id(bid), "mssql")["skipped"] is True
    assert scan_service.ingest_branch(dbs.get_branch_by_id(bid), "mssql", force=True)["objects"] == 2

    # a new state without Orders: removed from the snapshot, cmdb untouched, the old state dropped
    label = dbs.get_branch_by_id(bid).commit
    b2 = push(pid, "mssql", table("dbo.Clients", "Id", "PassportNumber", "Phone"))
    assert scan_service.ingest_branch(dbs.get_branch_by_id(bid), "mssql")["objects"] == 1
    assert snapshot(bid) == [("cmdb", "billing-api", 1), ("mssql", "dbo.Clients", 3)]
    # the old state is superseded: its chunks are gone, its row (Idempotency-Key) is kept so a
    # late retry of that request is replayed instead of rolling the snapshot back
    assert q("SELECT id, status FROM ingest_batches WHERE parser = 'mssql' ORDER BY id") == [
        (b1, "superseded"), (b2, "processed")]
    assert q("SELECT count(*) FROM ingest_chunks WHERE batch_id = :b", b=b1) == [(0,)]
    assert dbs.latest_ingest_batch(pid, "mssql")["id"] == b2
    x("UPDATE ingest_batches SET created_at = now() - interval '8 days' WHERE id = :b", b=b1)
    cleanup = pg_scanner.load("services.cleanup_service")
    assert cleanup.cleanup()["superseded_ingest_states"] == 1
    assert q("SELECT id FROM ingest_batches WHERE parser = 'mssql'") == [(b2,)]
    assert dbs.get_branch_by_id(bid).commit != label                     # new snapshot label

    # an open upload session is never processed nor dropped
    push(pid, "mssql", table("dbo.Tmp", "x"), status="open")
    assert scan_service.ingest_branch(dbs.get_branch_by_id(bid), "mssql")["skipped"] is True
    assert q("SELECT count(*) FROM ingest_batches WHERE status = 'open'")[0][0] == 1


def test_ingest_inventory_project_and_duplicates(pg_scanner):
    dbs = pg_scanner.db
    scan_service = pg_scanner.load("services.scan_service")
    pid, bid = external_project()
    x("UPDATE gitlab_projects SET scan_mode = 'inventory' WHERE id = :p", p=pid)
    push(pid, "mssql", table("dbo.Clients", "PassportNumber"), table("dbo.Clients", "PassportNumber"))
    assert scan_service.ingest_branch(dbs.get_branch_by_id(bid), "mssql")["objects"] == 1    # duplicate dropped
    assert q("SELECT count(*) FROM rule_hits")[0][0] == 0
    assert scan_service.ingest_branch(dbs.get_branch_by_id(bid), "nothing") is None


def test_ingest_job_queues_llm_and_marks_failures(pg_scanner, monkeypatch):
    from discovery_common import jobs
    dbs = pg_scanner.db
    pid, bid = external_project()
    batch = push(pid, "mssql", table("dbo.Clients", "Phone"), llm=True)
    handlers = pg_scanner.load("services.job_handlers")
    monkeypatch.setattr(handlers, "llm_configured", lambda settings=None: True)
    job = SimpleNamespace(id=1, kind="ingest", payload={"branch_id": bid, "parser": "mssql", "batch_id": batch},
                          attempts=1, max_attempts=5, last_attempt=False)
    handlers.ingest_job(job)
    commit = dbs.get_branch_by_id(bid).scanned_commit
    assert q("SELECT kind, dedup_key FROM jobs") == [("llm_score", f"llm_score:{bid}:{commit}")]

    b2 = push(pid, "mssql", table("dbo.Other", "x"))
    monkeypatch.setattr(handlers, "ingest_branch", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    job.payload["batch_id"], job.last_attempt = b2, True
    try:
        handlers.ingest_job(job)
    except RuntimeError:
        pass
    assert q("SELECT status, error FROM ingest_batches WHERE id = :b", b=b2) == [("failed", "boom")]
    assert jobs  # imported for the kinds check
