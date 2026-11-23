"""Scanner DB layer against a real Postgres (TEST_DATABASE_URL; skipped without it):
inventory upserts, transactional main/MR saves, hit semantics, carry-over, LLM
candidates, retention / GC."""

import json

import pytest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sqlalchemy import text

from appsec_discovery.models import CodeObject, CodeObjectField, CodeObjectProp, RuleHit


def project_gl(id=101, path="grp/proj", name="proj", activity="2026-11-01T10:00:00.000Z"):
    return SimpleNamespace(id=id, name=name, path_with_namespace=path, description=None, visibility="private",
                           default_branch="main", created_at="2026-01-01T10:00:00.000Z", last_activity_at=activity)


def branch_gl(name, commit="c1", date="2026-11-01T10:00:00.000+03:00"):
    return SimpleNamespace(name=name, commit={"id": commit, "committed_date": date})


def mr_gl(iid, source, target, state="opened", updated=None):
    updated = updated or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return SimpleNamespace(iid=iid, source_branch=source, target_branch=target, state=state, title="t",
                           description=None, created_at=updated, updated_at=updated)


def obj(name, fields, hash_=None, line=1, file="/m.go", props=None):
    """A parsed object; card / email fields are scored by a core ``score_tags`` keyword (high, pii)."""
    scored = [f for f in fields if "card" in f or "email" in f]
    return CodeObject(
        hash=hash_ or f"id-{name}", object_name=name, object_type="dto", parser="go", file=file, line=line,
        properties={k: CodeObjectProp(prop_name=k, prop_value=v, file=file, line=line) for k, v in (props or {}).items()},
        fields={f: CodeObjectField(field_name=f, field_type=t, file=file, line=line + i + 1,
                                   severity=("high" if f in scored else None), tags=(["pii"] if f in scored else None))
                for i, (f, t) in enumerate(fields.items())},
        hits=[RuleHit(rule="score_tags", rule_type="keyword", subject="field", field_name=f, severity="high",
                      tags=["pii"], status="match") for f in scored] or None,
    )


def records(project_id, *objects):
    from discovery_common.mapping import from_code_object
    return [from_code_object(o, project_id) for o in objects]


def q(sql, **params):
    from discovery_common import db
    with db.get_engine().connect() as conn:
        return conn.execute(text(sql), params).all()


def setup_project(dbs):
    # the built-in keyword scoring (kw-fields / kw-props) is opt-in on a new install: on for these tests
    _exec("UPDATE rules SET enabled = true WHERE scope ->> 'source' = 'core'")
    project, result = dbs.upsert_project(project_gl())
    assert result == "inserted" and project.gitlab_id == 101
    main, _ = dbs.upsert_branch(branch_gl("main"), project.id, project.full_path, True)
    feature, _ = dbs.upsert_branch(branch_gl("feature", "f1"), project.id, project.full_path, False)
    mr, _ = dbs.upsert_mr(mr_gl(1, "feature", "main"), project.id, project.full_path, feature, main)
    return project, main, feature, mr


def classifier(dbs, prompt):
    """An LLM field rule without category (the built-in classifier), made by a user."""
    _exec("INSERT INTO rules (kind, name, target, mode, scope, prompt, version, enabled) "
          "VALUES ('llm', 'classifier', 'field', 'review', '{}', :p, 1, true)", p=prompt)
    return next(r for r in dbs.get_rules("llm") if r.name == "classifier")


def save_main(scanner, branch, commit, recs):
    scan_service = scanner.load("services.scan_service")
    rules = scanner.db.get_rules("keyword")
    hits = scan_service.keyword_hits(recs, rules, "grp/proj")
    return scanner.db.save_main_scan(branch, commit, recs, hits, None)


def save_mr(scanner, source, target, commit, recs):
    from discovery_common.mapping import compute_delta
    scan_service = scanner.load("services.scan_service")
    delta = compute_delta(recs, scanner.db.load_branch_snapshot(target.id))
    changed = [r for _, _, r in delta if r is not None]
    hits = scan_service.keyword_hits(changed, scanner.db.get_rules("keyword"), "grp/proj")
    scanner.db.save_mr_delta(source, commit, delta, hits, None)
    return delta


def test_inventory_upserts(pg_scanner):
    dbs = pg_scanner.db
    # a row created before migration 0002 (no gitlab_id) is adopted by full_path
    q_exec = lambda sql: _exec(sql)  # noqa: E731
    q_exec("INSERT INTO gitlab_projects (project_name, full_path, visibility, created_at, updated_at) "
           "VALUES ('proj', 'grp/proj', 'private', now(), now())")
    project, result = dbs.upsert_project(project_gl())
    assert result == "updated" and project.gitlab_id == 101
    assert dbs.upsert_project(project_gl())[1] == "checked"
    # same name, other project: no longer mixed up (P0-3)
    other, result = dbs.upsert_project(project_gl(id=102, path="other/proj"))
    assert result == "inserted" and other.id != project.id

    main, _ = dbs.upsert_branch(branch_gl("main"), project.id, project.full_path, True)
    assert dbs.upsert_branch(branch_gl("main"), project.id, project.full_path, True)[1] == "checked"
    assert dbs.upsert_branch(branch_gl("main", "c2"), project.id, project.full_path, True)[1] == "updated"
    # default branch changed: the old main is demoted, its snapshot dropped
    _exec(f"UPDATE gitlab_branches SET scanned_commit = 'c2' WHERE id = {main.id}")
    master, _ = dbs.upsert_branch(branch_gl("master"), project.id, project.full_path, True)
    assert q("SELECT branch_name, is_main, scanned_commit FROM gitlab_branches ORDER BY id") == [
        ("main", False, None), ("master", True, None)]

    mr, result = dbs.upsert_mr(mr_gl(5, "main", "master"), project.id, project.full_path, dbs.get_branch(project.id, "main"), master)
    assert result == "inserted"
    assert dbs.upsert_mr(mr_gl(5, "main", "master"), project.id, project.full_path, dbs.get_branch(project.id, "main"), master)[1] == "checked"
    dbs.set_mr_processed(mr.id)
    assert dbs.get_mr(mr.id).processed_at is not None

    # processed_at never moves back: an older job finishing after a newer one (P2-4)
    from datetime import datetime
    dbs.set_branch_processed(master.id, datetime(2026, 1, 2))
    dbs.set_branch_processed(master.id, datetime(2026, 1, 1))
    assert dbs.get_branch_by_id(master.id).processed_at == datetime(2026, 1, 2)
    dbs.set_branch_processed(master.id, datetime(2026, 1, 3))
    assert dbs.get_branch_by_id(master.id).processed_at == datetime(2026, 1, 3)


def _exec(sql, **params):
    from discovery_common import db
    with db.unit_of_work() as s:
        return s.execute(text(sql), params)


def test_main_scan_is_transactional_diff_apply(pg_scanner):
    project, main, feature, mr = setup_project(pg_scanner.db)

    v1 = records(project.id, obj("User", {"email": "string", "id": "int"}), obj("Ping", {"id": "int"}))
    stats = save_main(pg_scanner, main, "c1", v1)
    assert stats["written"] == 2 and stats["deleted"] == 0 and stats["hits"] == 1
    assert pg_scanner.db.get_branch_by_id(main.id).scanned_commit == "c1"
    assert q("SELECT count(*) FROM objects")[0][0] == 2 and q("SELECT count(*) FROM object_fields")[0][0] == 3

    # unchanged rescan writes nothing; moved lines only touch branch_objects (no new object version)
    assert save_main(pg_scanner, main, "c2", v1)["written"] == 0
    moved = records(project.id, obj("User", {"email": "string", "id": "int"}, line=10), obj("Ping", {"id": "int"}))
    assert save_main(pg_scanner, main, "c3", moved)["written"] == 1
    assert q("SELECT count(*) FROM objects")[0][0] == 2

    # shape change -> new version; removed object -> row deleted; old version is an orphan for GC
    v2 = records(project.id, obj("User", {"email": "string", "id": "int", "card": "string"}))
    stats = save_main(pg_scanner, main, "c4", v2)
    assert (stats["deleted"], stats["written"]) == (1, 1)
    assert q("SELECT count(*) FROM objects")[0][0] == 3
    assert q("SELECT count(*) FROM branch_objects")[0][0] == 1

    # a failing save leaves nothing behind (single transaction)
    bad = records(project.id, obj("Broken", {"x": "int"}))
    try:
        pg_scanner.db.save_main_scan(SimpleNamespace(id=main.id), "c5", bad, [{"rule_id": 999999}], None)
    except Exception:
        pass
    assert q("SELECT count(*) FROM objects WHERE name = 'Broken'")[0][0] == 0
    assert pg_scanner.db.get_branch_by_id(main.id).scanned_commit == "c4"


def test_hits_never_overwrite_human_decisions(pg_scanner):
    project, main, feature, mr = setup_project(pg_scanner.db)
    recs = records(project.id, obj("User", {"email": "string"}))
    save_main(pg_scanner, main, "c1", recs)
    (status, seen), = q("SELECT status, last_seen_at FROM rule_hits")
    assert status == "match"

    _exec("UPDATE rule_hits SET status = 'no_match', reviewer = 'alice', last_seen_at = now() - interval '3 days'")
    save_main(pg_scanner, main, "c2", recs)
    (status, reviewer, seen2), = q("SELECT status, reviewer, last_seen_at FROM rule_hits")
    assert (status, reviewer) == ("no_match", "alice")
    assert seen2 > datetime.now(timezone.utc) - timedelta(hours=1)        # main scans refresh last_seen_at

    # ... at most once a day, and MR scans never do
    _exec("UPDATE rule_hits SET last_seen_at = now() - interval '2 hours'")
    save_main(pg_scanner, main, "c3", recs)
    assert q("SELECT last_seen_at < now() - interval '1 hour' FROM rule_hits")[0][0] is True


def test_mr_delta_and_prune(pg_scanner):
    dbs = pg_scanner.db
    project, main, feature, mr = setup_project(dbs)
    save_main(pg_scanner, main, "c1", records(project.id,
              obj("User", {"email": "string", "id": "int"}), obj("Ping", {"id": "int"}), obj("Gone", {"x": "int"})))

    source = records(project.id,
                     obj("User", {"email": "string", "id": "int", "card_number": "string"}),   # modified: new field
                     obj("Ping", {"id": "int"}),                                                # unchanged
                     obj("Card", {"card_pan": "string"}))                                       # added
    delta = save_mr(pg_scanner, feature, main, "f1", source)
    assert sorted(c for c, _, _ in delta) == ["added", "modified", "removed"]
    assert q("SELECT change, content_hash IS NULL FROM branch_objects WHERE branch_id = :b ORDER BY change",
             b=feature.id) == [("added", False), ("modified", False), ("removed", True)]

    # MR merged into main: MR rows equal to main are pruned
    save_main(pg_scanner, main, "c2", source)
    assert q("SELECT count(*) FROM branch_objects WHERE branch_id = :b", b=feature.id)[0][0] == 0

    # only the main / only open MR read queries
    from discovery_common import db, testing
    with db.get_engine().connect() as conn:
        assert {r["field_name"] for r in testing.main_fields(conn, project.id, "card")} == {"card_number", "card_pan"}
        assert testing.open_mr_fields(conn, project.id) == []
        save_mr(pg_scanner, feature, main, "f2", source + records(project.id, obj("New", {"passport": "string"})))
        assert [(r["mr_id"], r["field_name"], r["change"]) for r in testing.open_mr_fields(conn, project.id, "pass")] == [
            (1, "passport", "added")]
        assert [r["change"] for r in testing.open_mr_delta(conn, project.id)] == ["added"]


def test_identity_change_carries_decisions_over(pg_scanner):
    project, main, feature, mr = setup_project(pg_scanner.db)
    save_main(pg_scanner, main, "c1", records(project.id, obj("User", {"email": "string"}, hash_="old-hash")))
    _exec("UPDATE rule_hits SET status = 'no_match', reviewer = 'bob'")

    # same parser/type/name/file, new core identity hash (P1-8 style change)
    stats = save_main(pg_scanner, main, "c2", records(project.id, obj("User", {"email": "string"}, hash_="new-hash")))
    assert stats["carried"] == 1
    rows = q("SELECT object_key, status, reviewer FROM rule_hits ORDER BY first_seen_at")
    new_key = records(project.id, obj("User", {"email": "string"}, hash_="new-hash"))[0].object_key
    assert [(r.status, r.reviewer) for r in rows if r.object_key == new_key] == [("no_match", "bob")]


def test_llm_candidates_and_verdict_upserts(pg_scanner):
    dbs = pg_scanner.db
    project, main, feature, mr = setup_project(dbs)
    save_main(pg_scanner, main, "c1", records(project.id, obj("Profile", {"nick": "string", "bio": "string"})))

    rule = classifier(dbs, "prompt")
    assert {c["field_name"] for c in dbs.get_llm_candidates(main.id, rule)} == {"nick", "bio"}

    from discovery_common.mapping import hit_row
    key = records(project.id, obj("Profile", {"nick": "string", "bio": "string"}))[0].object_key
    dbs.upsert_llm_hits([hit_row(rule, project.id, key, "nick", "pending_review", model="m"),
                         hit_row(rule, project.id, key, "bio", "no_match", model="m")], is_main=True)
    assert dbs.get_llm_candidates(main.id, rule) == []                       # verdicts stored, nothing to ask

    _exec("UPDATE rule_hits SET reviewer = 'carol', status = 'match' WHERE field_name = 'nick'")
    _exec("UPDATE rules SET prompt = 'new prompt', version = version + 1 WHERE id = :r", r=rule.id)   # an edit
    rule2 = next(r for r in dbs.get_rules("llm") if r.id == rule.id)
    assert rule2.version == rule.version + 1
    # human decision is final; the machine 'no_match' verdict is stale under the new version: kept, asked again by a
    # rollout slice (migration), not by a normal run
    assert dbs.get_llm_candidates(main.id, rule2) == []
    assert {c["field_name"] for c in dbs.get_llm_candidates(main.id, rule2, migration=True)} == {"bio"}
    dbs.upsert_llm_hits([hit_row(rule2, project.id, key, "nick", "no_match", model="m2"),
                         hit_row(rule2, project.id, key, "bio", "pending_review", model="m2")], is_main=True)
    assert sorted(q("SELECT field_name, status, reviewer, rule_version FROM rule_hits WHERE rule_id = :r", r=rule.id)) == [
        ("bio", "pending_review", None, rule2.version), ("nick", "match", "carol", rule.version)]



def test_new_core_prompts_reask_every_machine_verdict_but_not_human_decisions(pg_scanner):
    dbs = pg_scanner.db
    project, main, feature, mr = setup_project(dbs)
    fields = {"nick": "string", "bio": "string", "mail": "string", "note": "string"}
    save_main(pg_scanner, main, "c1", records(project.id, obj("Profile", fields)))
    rule = classifier(dbs, "prompt")
    from discovery_common.mapping import hit_row
    LLM_PROMPTS_VERSION = "classifier3"          # the classifier family (migration 0024)
    key = records(project.id, obj("Profile", fields))[0].object_key
    dbs.upsert_llm_hits([hit_row(rule, project.id, key, name, status, model="m") for name, status in
                         (("nick", "match"), ("bio", "no_match"), ("mail", "pending_review"), ("note", "no_match"))],
                        is_main=True)
    assert {r.prompt_version for r in q("SELECT prompt_version FROM rule_hits")} == {LLM_PROMPTS_VERSION}
    assert dbs.get_llm_candidates(main.id, rule) == []                     # same prompts: nothing to ask
    _exec("UPDATE rule_hits SET reviewer = 'carol' WHERE field_name = 'note'")   # a human rejected 'note'

    _exec("UPDATE rule_hits SET prompt_version = 'core2.2'")              # verdicts made by older prompts
    # every machine verdict is stale (asked again by a rollout slice), incl. the machine-confirmed one (mode
    # auto); not 'note'
    assert dbs.get_llm_candidates(main.id, rule) == []
    assert {c["field_name"] for c in dbs.get_llm_candidates(main.id, rule, migration=True)} == {"nick", "bio", "mail"}
    dbs.upsert_llm_hits([hit_row(rule, project.id, key, name, status, model="m2") for name, status in
                         (("nick", "no_match"), ("bio", "pending_review"), ("mail", "no_match"), ("note", "match"))],
                        is_main=True)
    rows = {r.field_name: (r.status, r.reviewer, r.model, r.prompt_version)
            for r in q("SELECT field_name, status, reviewer, model, prompt_version FROM rule_hits")}
    assert rows == {"nick": ("no_match", None, "m2", LLM_PROMPTS_VERSION),
                    "bio": ("pending_review", None, "m2", LLM_PROMPTS_VERSION),
                    "mail": ("no_match", None, "m2", LLM_PROMPTS_VERSION),
                    "note": ("no_match", "carol", "m", "core2.2")}       # the human decision is untouched
    assert dbs.get_llm_candidates(main.id, rule, migration=True) == []

def test_mr_closing_and_cleanup(pg_scanner, monkeypatch):
    dbs = pg_scanner.db
    cleanup = pg_scanner.use_real("services.cleanup_service")
    project, main, feature, mr = setup_project(dbs)
    save_main(pg_scanner, main, "c1", records(project.id, obj("User", {"email": "string"})))
    save_mr(pg_scanner, feature, main, "f1", records(project.id, obj("User", {"email": "string", "card": "string"})))

    # GitLab no longer lists MR 1 as opened: it is merged, its source branch (and delta) goes away
    assert cleanup.close_missing_mrs(project.id, [], lambda iid: "merged") == 1
    assert q("SELECT state, closed_at IS NOT NULL, source_branch_id FROM gitlab_mrs") == [("merged", True, None)]
    assert q("SELECT branch_name FROM gitlab_branches") == [("main",)]
    assert q("SELECT count(*) FROM branch_objects WHERE NOT is_main")[0][0] == 0

    # stale open MR: source branch released
    stale, _ = dbs.upsert_branch(branch_gl("stale"), project.id, project.full_path, False)
    dbs.upsert_mr(mr_gl(2, "stale", "main", updated="2020-01-01T00:00:00.000Z"), project.id, project.full_path, stale, main)
    assert cleanup.release_stale_mr_branches(project.id) == 1

    # GC: orphan object versions, closed MR rows, old scans, hit retention
    _exec("UPDATE gitlab_mrs SET closed_at = now() - interval '8 days' WHERE state = 'merged'")
    _exec("INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version, status, last_seen_at) "
          "SELECT id, gen_random_uuid(), :p, gen_random_uuid(), 'gone', 1, 'pending_review', now() - interval '20 days' "
          "FROM rules WHERE name = 'llm'", p=project.id)
    _exec("INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version, status, last_seen_at) "
          "SELECT id, gen_random_uuid(), :p, gen_random_uuid(), 'gone2', 1, 'match', now() - interval '20 days' "
          "FROM rules WHERE name = 'llm'", p=project.id)
    for i in range(25):
        _exec("INSERT INTO discovery_scans (project_id, branch_id, project_path, branch_name, branch_commit, scanner, "
              "rules_version, parsers, scanned_at) VALUES (:p, :b, 'grp/proj', 'main', :c, 'discovery', '2', '{all}', now())",
              p=project.id, b=main.id, c=f"c{i}")
    orphans_before = q("SELECT count(*) FROM objects o WHERE NOT EXISTS "
                       "(SELECT 1 FROM branch_objects b WHERE b.content_hash = o.content_hash)")[0][0]
    assert orphans_before == 1

    stats = cleanup.cleanup()
    assert stats["orphan_objects"] == 1 and stats["old_closed_mrs"] == 1 and stats["old_scans"] == 5
    assert stats["hits_pending_orphan"] == 1 and stats["hits_decided_unseen"] == 0
    assert stats["old_jobs"] == 0
    assert q("SELECT count(*) FROM rule_hits WHERE field_name = 'email'")[0][0] == 1    # live subject kept

    # lock held by someone else -> skipped
    from discovery_common import db
    with db.get_engine().connect() as other:
        other.execute(text("SELECT pg_advisory_lock(:k)"), {"k": cleanup.GC_LOCK_KEY})
        assert cleanup.cleanup() is None
        other.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": cleanup.GC_LOCK_KEY})
        other.commit()


PROTO_V1 = """syntax = "proto3";
package demo.v1;
service Users {
  rpc Get (GetUserRequest) returns (User);
}
message GetUserRequest {
  int64 id = 5;
}
message User {
  int64 id = 1;
  string email = 2;
}
"""

# MR: a new field with a sensitive name (core keyword scoring -> confirmed hit) and moved lines
PROTO_V2 = PROTO_V1.replace("syntax", "// header\n\nsyntax").replace("string email = 2;", "string email = 2;\n  string card_number = 3;")


def test_end_to_end_main_then_mr_with_core_scan(pg_scanner, monkeypatch, tmp_path):
    """Real core scan (protobuf parser, no semgrep) -> main snapshot -> MR delta -> rescan
    -> merge -> MR rows pruned."""
    dbs = pg_scanner.db
    pg_scanner.setenv(PARSERS="protobuf")
    monkeypatch.chdir(tmp_path)
    pg_scanner.gl_service.clone_gitlab_project_code = lambda *a, **kw: True
    pg_scanner.gl_service.get_mr_changed_files = lambda *a: {"users.proto"}

    project, main, feature, mr = setup_project(dbs)

    def checkout(branch_id, commit, source):
        folder = tmp_path / "code" / str(project.id) / str(branch_id) / commit
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "users.proto").write_text(source)

    checkout(main.id, "c1", PROTO_V1)
    checkout(feature.id, "f1", PROTO_V2)

    scan_service = pg_scanner.load("services.scan_service")

    main = dbs.get_branch_by_id(main.id)
    assert scan_service.scan_branch(main) is True
    assert q("SELECT count(*) FROM branch_objects WHERE branch_id = :b", b=main.id)[0][0] == 1
    (field_name, status), = q("SELECT field_name, status FROM rule_hits")   # field naming is the parser's
    assert field_name.endswith("email") and status == "match"

    mr = dbs.get_mr(mr.id)
    mr.target_branch_commit = "c1"
    mr.source_branch_commit = "f1"
    assert scan_service.scan_mr(mr) is True
    assert q("SELECT change FROM branch_objects WHERE branch_id = :b", b=feature.id) == [("modified",)]
    card_hits = "SELECT count(*) FROM rule_hits WHERE field_name LIKE '%card_number'"
    assert q(card_hits) == [(1,)]                                         # the MR's new field is scored

    assert scan_service.scan_mr(mr) is True                               # rescan: same delta, same hit
    assert q(card_hits) == [(1,)]

    # merged: main at the MR's code; the MR delta row now equals main and is pruned
    checkout(main.id, "c2", PROTO_V2)
    main.commit = "c2"
    assert scan_service.scan_branch(main) is True
    assert q("SELECT count(*) FROM branch_objects WHERE branch_id = :b", b=feature.id)[0][0] == 0
    assert q("SELECT count(*) FROM branch_objects b JOIN object_fields f USING (content_hash) "
             "WHERE b.branch_id = :b AND f.field_name LIKE '%card_number'", b=main.id) == [(1,)]


ORDERS_V1 = """syntax = "proto3";
package demo.v1;
service Orders {
  rpc GetOrder (Order) returns (Order);
}
message Order {
  int64 id = 1;
}
"""
ORDERS_V2 = ORDERS_V1.replace("int64 id = 1;", "int64 id = 1;\n  string status = 2;")
PAY = """syntax = "proto3";
package demo.v1;
service Payments {
  rpc Pay (Payment) returns (Payment);
}
message Payment {
  int64 amount = 1;
}
"""


def _behind_target_setup(pg_scanner, monkeypatch, tmp_path):
    """main c1 -> c2 (orders changed, pay added after the fork); feature f1 forked at c1 and
    only changes users.proto. Both main snapshots are scanned by scan_branch."""
    dbs = pg_scanner.db
    pg_scanner.setenv(PARSERS="protobuf")
    monkeypatch.chdir(tmp_path)
    pg_scanner.gl_service.clone_gitlab_project_code = lambda *a, **kw: True
    project, main, feature, mr = setup_project(dbs)

    def checkout(branch_id, commit, files):
        folder = tmp_path / "code" / str(project.id) / str(branch_id) / commit
        folder.mkdir(parents=True, exist_ok=True)
        for name, source in files.items():
            (folder / name).write_text(source)

    checkout(main.id, "c1", {"users.proto": PROTO_V1, "orders.proto": ORDERS_V1})
    checkout(main.id, "c2", {"users.proto": PROTO_V1, "orders.proto": ORDERS_V2, "pay.proto": PAY})
    checkout(feature.id, "f1", {"users.proto": PROTO_V2, "orders.proto": ORDERS_V1})

    scan_service = pg_scanner.load("services.scan_service")

    assert scan_service.scan_branch(dbs.get_branch_by_id(main.id)) is True               # c1
    main, _ = dbs.upsert_branch(branch_gl("main", "c2"), project.id, project.full_path, True)
    assert scan_service.scan_branch(dbs.get_branch_by_id(main.id)) is True               # c2
    assert dbs.get_branch_by_id(main.id).scanned_commit == "c2"

    main_scans = []
    real_scan_main = scan_service.scan_main
    monkeypatch.setattr(scan_service, "scan_main", lambda *a, **kw: main_scans.append(a[1]) or real_scan_main(*a, **kw))

    mr = dbs.get_mr(mr.id)
    mr.source_branch_commit = "f1"
    return scan_service, feature, mr, main_scans


def _mr_rows(branch_id):
    return sorted(q("SELECT bo.change, o.file FROM branch_objects bo LEFT JOIN objects o USING (content_hash) "
                    "WHERE bo.branch_id = :b", b=branch_id), key=lambda r: (r[0], r[1] or ""))


def test_mr_behind_target_delta_has_only_files_changed_since_merge_base(pg_scanner, monkeypatch, tmp_path):
    scan_service, feature, mr, main_scans = _behind_target_setup(pg_scanner, monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(scan_service, "get_mr_changed_files", lambda *a: calls.append(a) or {"users.proto"})

    mr.target_branch_commit = "c2"
    assert scan_service.scan_mr(mr) is True
    # without the merge-base filter: orders 'modified' (the older version) and pay 'removed'
    assert {change for change, _ in _mr_rows(feature.id)} == {"modified"}
    assert {file for _, file in _mr_rows(feature.id)} == {"/users.proto"}
    assert main_scans == []                                   # the c2 snapshot is reused, no second scan
    assert calls == [(mr.project_id, feature.id, "f1", "main", "c2")]


def test_mr_delta_falls_back_to_target_head_when_changes_are_unknown(pg_scanner, monkeypatch, tmp_path):
    scan_service, feature, mr, _ = _behind_target_setup(pg_scanner, monkeypatch, tmp_path)
    monkeypatch.setattr(scan_service, "get_mr_changed_files", lambda *a: None)

    mr.target_branch_commit = "c2"
    assert scan_service.scan_mr(mr) is True
    rows = _mr_rows(feature.id)
    assert ("removed", None) in rows                          # pay.proto objects (old behaviour)
    assert ("modified", "/orders.proto") in rows


def test_mr_with_stale_target_commit_does_not_rescan_newer_main_snapshot(pg_scanner, monkeypatch, tmp_path):
    """The main snapshot is at the branch head (c2); an MR still pointing at c1 uses it
    instead of scanning main back to c1 (which would replace the newer snapshot)."""
    scan_service, feature, mr, main_scans = _behind_target_setup(pg_scanner, monkeypatch, tmp_path)
    monkeypatch.setattr(scan_service, "get_mr_changed_files", lambda *a: {"users.proto"})

    mr.target_branch_commit = "c1"
    assert scan_service.scan_mr(mr) is True
    assert main_scans == []
    assert pg_scanner.db.get_branch_by_id(mr.target_branch_id).scanned_commit == "c2"


def test_scan_branch_skips_clone_when_already_scanned(pg_scanner, monkeypatch, tmp_path):
    """A main already scanned at its commit (e.g. as an MR target) is not cloned again."""
    scan_service, feature, mr, main_scans = _behind_target_setup(pg_scanner, monkeypatch, tmp_path)
    clones = []
    pg_scanner.gl_service.clone_gitlab_project_code = lambda *a, **kw: clones.append(a) or True
    scan_service = pg_scanner.load("services.scan_service")

    assert scan_service.scan_branch(pg_scanner.db.get_branch_by_id(mr.target_branch_id)) is True
    assert clones == []


def test_scan_branch_force_scans_again(pg_scanner, monkeypatch, tmp_path):
    scan_service, feature, mr, main_scans = _behind_target_setup(pg_scanner, monkeypatch, tmp_path)
    main = pg_scanner.db.get_branch_by_id(mr.target_branch_id)
    assert scan_service.scan_branch(main) is True and main_scans == []          # same rules: skipped
    assert scan_service.scan_branch(main, force=True) is True and main_scans == ["c2"]


def test_inventory_project_is_scanned_without_categorisation(pg_scanner, monkeypatch, tmp_path):
    """scan_mode=inventory: objects / fields stored, no keyword hits, no LLM; switching back
    to rules rescans (the scan marker includes the mode) and categorises."""
    dbs = pg_scanner.db
    pg_scanner.setenv(PARSERS="protobuf")
    monkeypatch.chdir(tmp_path)
    pg_scanner.gl_service.clone_gitlab_project_code = lambda *a, **kw: True
    project, main, feature, mr = setup_project(dbs)
    folder = tmp_path / "code" / str(project.id) / str(main.id) / "c1"
    folder.mkdir(parents=True)
    (folder / "users.proto").write_text(PROTO_V2)
    _exec(f"UPDATE gitlab_projects SET scan_mode = 'inventory' WHERE id = {project.id}")

    scan_service = pg_scanner.load("services.scan_service")
    llm_calls = []
    monkeypatch.setattr(scan_service, "llm_configured", lambda settings=None: True)
    monkeypatch.setattr(scan_service, "run_llm_rules", lambda *a, **kw: llm_calls.append(a) or 0)

    assert scan_service.scan_branch(dbs.get_branch_by_id(main.id)) is True
    assert q("SELECT count(*) FROM branch_objects WHERE branch_id = :b", b=main.id)[0][0] == 1
    assert q("SELECT count(*) FROM object_fields")[0][0] > 0
    assert q("SELECT count(*) FROM rule_hits")[0][0] == 0
    assert scan_service.llm_score_branch(dbs.get_branch_by_id(main.id)) is True and llm_calls == []

    _exec(f"UPDATE gitlab_projects SET scan_mode = 'rules' WHERE id = {project.id}")
    assert scan_service.scan_branch(dbs.get_branch_by_id(main.id)) is True
    assert q("SELECT count(*) FROM rule_hits WHERE status = 'match'")[0][0] > 0


def _graphql_sample():
    from pathlib import Path
    return (Path(__file__).resolve().parents[3] / "tests" / "graphql_samples" / "query.graphql").read_text()


def test_parse_with_parser_subset_keeps_the_other_parsers_objects(pg_scanner, monkeypatch, tmp_path):
    dbs = pg_scanner.db
    pg_scanner.setenv(PARSERS="protobuf,graphql")
    monkeypatch.chdir(tmp_path)
    pg_scanner.gl_service.clone_gitlab_project_code = lambda *a, **kw: True
    project, main, feature, mr = setup_project(dbs)
    folder = tmp_path / "code" / str(project.id) / str(main.id) / "c1"
    folder.mkdir(parents=True)
    (folder / "users.proto").write_text(PROTO_V1)
    (folder / "schema.graphql").write_text(_graphql_sample())

    scan_service = pg_scanner.load("services.scan_service")
    by_parser = lambda: dict(q("SELECT o.parser, count(*) FROM branch_objects b JOIN objects o USING (content_hash) "  # noqa: E731
                               "WHERE b.branch_id = :b GROUP BY 1", b=main.id))
    assert scan_service.scan_branch(dbs.get_branch_by_id(main.id)) is True
    before = by_parser()
    assert before.get("protobuf") and before.get("graphql")

    # the code changes: the proto gets a new service, the graphql schema is gone from disk
    (folder / "users.proto").write_text(PROTO_V1 + ORDERS_V1.replace('syntax = "proto3";\npackage demo.v1;\n', ""))
    (folder / "schema.graphql").unlink()
    assert scan_service.scan_branch(dbs.get_branch_by_id(main.id), parsers=["protobuf"]) is True
    after = by_parser()
    assert after["graphql"] == before["graphql"]                  # not parsed: kept
    assert after["protobuf"] == before["protobuf"] + 1            # replaced by the new parse
    assert dbs.get_branch_by_id(main.id).scanned_commit == "c1"

    # same commit: the same subset and the full parse are both skipped (markers); the test
    # changed the files without a new commit, so a forced full parse drops what is gone
    calls = []
    real_scan_main = scan_service.scan_main
    monkeypatch.setattr(scan_service, "scan_main", lambda *a, **kw: calls.append(kw.get("parsers")) or real_scan_main(*a, **kw))
    assert scan_service.scan_branch(dbs.get_branch_by_id(main.id), parsers=["protobuf"]) is True and calls == []
    assert scan_service.scan_branch(dbs.get_branch_by_id(main.id)) is True and calls == []
    assert scan_service.scan_branch(dbs.get_branch_by_id(main.id), force=True) is True and calls == [None]
    assert "graphql" not in by_parser()


def test_partial_main_scan_fails_the_job_keeps_objects_and_is_not_rescanned_per_mr(pg_scanner, monkeypatch, tmp_path):
    """A parser fails on main: the scan is partial (job retried, nothing of the failed parser
    deleted, no scanned_commit); MR scans of that target reuse the partial snapshot instead
    of cloning and scanning the same main commit again."""
    dbs = pg_scanner.db
    pg_scanner.setenv(PARSERS="protobuf,graphql")
    monkeypatch.chdir(tmp_path)
    clones = []
    pg_scanner.gl_service.clone_gitlab_project_code = lambda *a, **kw: clones.append(a[1]) or True
    pg_scanner.gl_service.get_mr_changed_files = lambda *a: None
    project, main, feature, mr = setup_project(dbs)
    for branch_id, commit in ((main.id, "c1"), (main.id, "c2"), (feature.id, "f1")):
        folder = tmp_path / "code" / str(project.id) / str(branch_id) / commit
        folder.mkdir(parents=True)
        (folder / "users.proto").write_text(PROTO_V1)
        (folder / "schema.graphql").write_text(_graphql_sample())

    scan_service = pg_scanner.load("services.scan_service")
    by_parser = lambda: dict(q("SELECT o.parser, count(*) FROM branch_objects b JOIN objects o USING (content_hash) "  # noqa: E731
                               "WHERE b.branch_id = :b GROUP BY 1", b=main.id))
    assert scan_service.scan_branch(dbs.get_branch_by_id(main.id)) is True
    before = by_parser()

    # c2: the graphql parser fails (only the protobuf objects come back)
    real = scan_service.run_discovery_scan
    scans = []

    def graphql_fails(path, pid, branch_id, name, commit, rules, parsers=None):
        scans.append((branch_id, commit))
        records, _ = real(path, pid, branch_id, name, commit, rules, parsers=["protobuf"])
        return records, "partial"

    monkeypatch.setattr(scan_service, "run_discovery_scan", graphql_fails)
    main, _ = dbs.upsert_branch(branch_gl("main", "c2"), project.id, project.full_path, True)
    with pytest.raises(scan_service.ScanError, match="^partial scan at c2: a parser failed$"):     # the job is retried
        scan_service.scan_branch(dbs.get_branch_by_id(main.id))
    assert by_parser() == before                                                     # graphql objects kept
    assert dbs.get_branch_by_id(main.id).scanned_commit == "c1"
    assert q("SELECT rules_version LIKE '%+partial' FROM discovery_scans WHERE branch_commit = 'c2'") == [(True,)]

    # MR into that main: the partial c2 snapshot is used, main is not cloned / scanned again
    scans.clear(), clones.clear()
    monkeypatch.setattr(scan_service, "run_discovery_scan", real)
    mr = dbs.get_mr(mr.id)
    mr.source_branch_commit, mr.target_branch_commit = "f1", "c2"
    assert scan_service.scan_mr(mr) is True
    assert clones == ["feature"]
    assert q("SELECT count(*) FROM branch_objects WHERE branch_id = :b", b=feature.id) == [(0,)]   # same code

    # the retried job scans the main again
    monkeypatch.setattr(scan_service, "run_discovery_scan", graphql_fails)
    with pytest.raises(scan_service.ScanError):
        scan_service.scan_branch(dbs.get_branch_by_id(main.id))
    assert scans == [(main.id, "c2")]
    monkeypatch.setattr(scan_service, "run_discovery_scan", real)
    assert scan_service.scan_branch(dbs.get_branch_by_id(main.id)) is True
    assert dbs.get_branch_by_id(main.id).scanned_commit == "c2"


# ---- stage 5b: rules from the DB, review decisions, rule versions -----------------------------

def save_scored(scanner, branch, commit, rules, *objects):
    """Main scan of ``objects`` scored by the core with the DB keyword rules (P1-6 mapping)."""
    from appsec_discovery.scoring import RuleScorer

    scan_service = scanner.load("services.scan_service")
    config = scan_service.build_score_config(scanner.settings(), rules, "grp/proj")
    scorer = RuleScorer.from_config(config)
    recs = records(branch.project_id, *[scorer.score(o.copy(deep=True)) for o in objects])
    hits = scan_service.keyword_hits(recs, rules, "grp/proj")
    return scanner.db.save_main_scan(branch, commit, recs, hits, None)


def test_rule_edit_reevaluates_pending_hits_and_keeps_decisions(pg_scanner):
    dbs = pg_scanner.db
    project, main, feature, mr = setup_project(dbs)
    _exec("""INSERT INTO rules (kind, name, category, severity, target, mode, scope, version, enabled)
             VALUES ('keyword', 'contacts', 'contact', 'low', 'field', 'review',
                     '{"field_re": "^(phone|nick|fax)$", "action": "score"}', 1, true)""")
    profile = obj("Profile", {"phone": "string", "nick": "string", "fax": "string", "bio": "string"})

    def contacts():
        return {r.field_name: (r.status, r.category, r.reviewer, r.rule_version) for r in q(
            "SELECT h.* FROM rule_hits h JOIN rules r ON r.id = h.rule_id WHERE r.name = 'contacts'")}

    save_scored(pg_scanner, main, "c1", dbs.get_rules("keyword"), profile)
    assert contacts() == {f: ("pending_review", "contact", None, 1) for f in ("phone", "nick", "fax")}

    # humans: nick confirmed; phone re-categorised but still pending (both recorded with a reviewer)
    _exec("UPDATE rule_hits SET status = 'match', reviewer = 'bob' WHERE field_name = 'nick'")
    _exec("UPDATE rule_hits SET category = 'pii', reviewer = 'bob' WHERE field_name = 'phone'")
    save_scored(pg_scanner, main, "c2", dbs.get_rules("keyword"), profile)       # same rule version
    assert contacts()["phone"] == ("pending_review", "pii", "bob", 1)
    assert contacts()["nick"] == ("match", "contact", "bob", 1)

    # nick reopened, then the rule is edited (version 2): bio and nick match, phone and fax no more
    _exec("UPDATE rule_hits SET status = 'pending_review' WHERE field_name = 'nick'")
    _exec("""UPDATE rules SET scope = '{"field_re": "^(bio|nick)$", "action": "score"}', version = 2
             WHERE name = 'contacts'""")
    stats = save_scored(pg_scanner, main, "c3", dbs.get_rules("keyword"), profile)
    assert contacts() == {
        "bio": ("pending_review", "contact", None, 2),       # new proposal
        "nick": ("pending_review", "contact", "bob", 2),     # reopened: re-proposed by the new version
        "phone": ("pending_review", "pii", "bob", 1),        # a human touched it: kept
    }                                                        # fax: unreviewed, no longer matching: dropped
    assert stats["stale_pending"] == 1


def test_no_env_managed_llm_rule(pg_scanner):
    """Migration 0028 removed the rule synced from LLM_PROMPT: only the default rules of migration 0013 are left."""
    dbs = pg_scanner.db
    assert sorted(r.name for r in dbs.get_rules("llm", include_disabled=True)) == [
        "api-with-auth", "db-tables-with-client-data"]
    assert [r.name for r in dbs.get_rules("llm")] == ["db-tables-with-client-data"]    # api-with-auth is off


def test_llm_object_rule_candidates_and_machine_verdicts(pg_scanner):
    from discovery_common.mapping import hit_row

    dbs = pg_scanner.db
    project, main, feature, mr = setup_project(dbs)
    save_main(pg_scanner, main, "c1", records(project.id, obj("Token", {"value": "string"})))
    _exec("""INSERT INTO rules (kind, name, category, severity, target, mode, scope, prompt, version, enabled)
             VALUES ('llm', 'secrets', 'secret', 'high', 'object', 'review', '{}', 'Holds secrets?', 1, true)""")
    rule = next(r for r in dbs.get_rules("llm") if r.name == "secrets")
    key = records(project.id, obj("Token", {"value": "string"}))[0].object_key

    (cand,) = dbs.get_llm_candidates(main.id, rule)
    assert (cand["object_key"], cand["field_name"], cand["field_key"], cand["name"]) == (key, None, key, "Token")

    dbs.upsert_llm_hits([hit_row(rule, project.id, key, None, "need_more_info", model="m", reason="unclear")],
                        is_main=True)
    assert dbs.get_llm_candidates(main.id, rule) == []
    assert q("SELECT status, reason, reviewer FROM rule_hits WHERE rule_id = :r", r=rule.id) == [
        ("need_more_info", "unclear", None)]

    _exec("UPDATE rules SET version = 2 WHERE name = 'secrets'")             # prompt edited
    rule = next(r for r in dbs.get_rules("llm") if r.name == "secrets")
    assert dbs.get_llm_candidates(main.id, rule) == []                         # stale: kept until a rollout
    assert len(dbs.get_llm_candidates(main.id, rule, migration=True)) == 1     # machine verdict: asked again
    dbs.upsert_llm_hits([hit_row(rule, project.id, key, None, "pending_review", model="m2", reason="a token")],
                        is_main=True)
    assert q("SELECT status, rule_version, reason FROM rule_hits WHERE rule_id = :r", r=rule.id) == [
        ("pending_review", 2, "a token")]

    _exec("UPDATE rule_hits SET status = 'no_match', reviewer = 'eve'")       # human decision
    _exec("UPDATE rules SET version = 3 WHERE name = 'secrets'")
    rule = next(r for r in dbs.get_rules("llm") if r.name == "secrets")
    assert dbs.get_llm_candidates(main.id, rule, migration=True) == []         # never re-asked
    dbs.upsert_llm_hits([hit_row(rule, project.id, key, None, "match", model="m3")], is_main=True)
    assert q("SELECT status, reviewer FROM rule_hits WHERE rule_id = :r", r=rule.id) == [("no_match", "eve")]


def test_run_selected_llm_rules_only_runs_those_rules_once(pg_scanner, monkeypatch):
    from appsec_discovery.ai import FakeLlmBackend

    dbs = pg_scanner.db
    project, main, feature, mr = setup_project(dbs)
    save_main(pg_scanner, main, "c1", records(project.id, obj("Token", {"value": "string"})))
    for name in ("secrets", "other"):
        _exec(f"""INSERT INTO rules (kind, name, category, severity, target, mode, scope, prompt, version, enabled)
                  VALUES ('llm', '{name}', '{name}', 'high', 'object', 'review', '{{}}', 'Match?', 1, true)""")
    secrets = q("SELECT id FROM rules WHERE name = 'secrets'")[0][0]

    pg_scanner.use_real("services.score_service")
    scan_service = pg_scanner.load("services.scan_service")
    backend = FakeLlmBackend('{"verdict": "match", "reason": "holds a token"}')
    monkeypatch.setattr(scan_service, "llm_configured", lambda settings=None: True)
    monkeypatch.setattr(scan_service, "get_llm_backend", lambda *a, **kw: backend)

    branch = dbs.get_branch_by_id(main.id)
    assert scan_service.run_selected_llm_rules(branch, [secrets]) is True
    assert q("SELECT r.name, h.status FROM rule_hits h JOIN rules r ON r.id = h.rule_id WHERE r.kind = 'llm'") == [
        ("secrets", "pending_review")]
    calls = len(backend.calls)
    assert calls == 1
    assert scan_service.run_selected_llm_rules(branch, [secrets]) is True and len(backend.calls) == calls  # cached

    _exec(f"UPDATE gitlab_projects SET scan_mode = 'inventory' WHERE id = {project.id}")
    other = q("SELECT id FROM rules WHERE name = 'other'")[0][0]
    assert scan_service.run_selected_llm_rules(branch, [other]) is True and len(backend.calls) == calls


def test_combination_and_llm_object_rules_store_the_matched_fields(pg_scanner, monkeypatch):
    from appsec_discovery.ai import FakeLlmBackend

    dbs = pg_scanner.db
    project, main, feature, mr = setup_project(dbs)
    _exec("""INSERT INTO rules (kind, name, category, severity, target, mode, scope, version, enabled) VALUES
             ('keyword', 'person-contact', 'pii', 'high', 'object', 'auto',
              '{"fields_all": ["last_?name|fio", "phone"], "action": "score"}', 1, true)""")
    _exec("UPDATE rules SET enabled = false WHERE scope ->> 'source' = 'core'")
    rules = dbs.get_rules("keyword")
    save_scored(pg_scanner, main, "c1", rules, obj("Client", {"LastName": "string", "Phone": "string", "id": "int"}),
                obj("Lead", {"FirstName": "string", "Phone": "string"}))
    assert q("SELECT o.name, h.status, h.fields FROM rule_hits h JOIN objects o ON o.object_key = h.object_key") == [
        ("Client", "match", ["LastName", "Phone"])]                    # Lead: a first name only

    _exec("""INSERT INTO rules (kind, name, category, severity, target, mode, scope, prompt, version, enabled)
             VALUES ('llm', 'person-llm', 'pii', 'high', 'object', 'review', '{}', 'last name + phone', 1, true)""")
    pg_scanner.use_real("services.score_service")
    scan_service = pg_scanner.load("services.scan_service")
    backend = FakeLlmBackend(lambda system, user, schema: json.dumps(
        {"verdict": "match", "reason": "a person", "fields": ["LastName", "Phone"]} if "LastName" in user
        else {"verdict": "no_match", "fields": []}))
    monkeypatch.setattr(scan_service, "llm_configured", lambda settings=None: True)
    monkeypatch.setattr(scan_service, "get_llm_backend", lambda *a, **kw: backend)
    llm = q("SELECT id FROM rules WHERE name = 'person-llm'")[0][0]
    assert scan_service.run_selected_llm_rules(dbs.get_branch_by_id(main.id), [llm]) is True
    assert q("SELECT o.name, h.status, h.fields, h.reason FROM rule_hits h JOIN objects o ON o.object_key = h.object_key "
             "WHERE h.rule_id = :r ORDER BY 1", r=llm) == [
        ("Client", "pending_review", ["LastName", "Phone"], "a person"), ("Lead", "no_match", None, None)]


def test_rule_edit_updates_and_drops_machine_confirmed_hits_of_auto_rules(pg_scanner):
    dbs = pg_scanner.db
    project, main, feature, mr = setup_project(dbs)
    _exec("""INSERT INTO rules (kind, name, category, severity, target, mode, scope, version, enabled)
             VALUES ('keyword', 'contacts', 'contact', 'high', 'field', 'auto',
                     '{"field_re": "^(phone|fax|nick)$", "action": "score"}', 1, true)""")
    _exec("UPDATE rules SET enabled = false WHERE scope ->> 'source' = 'core'")
    profile = obj("Profile", {"phone": "string", "fax": "string", "nick": "string"})

    def contacts():
        return {r.field_name: (r.status, r.severity, r.reviewer, r.rule_version) for r in q(
            "SELECT h.* FROM rule_hits h JOIN rules r ON r.id = h.rule_id WHERE r.name = 'contacts'")}

    save_scored(pg_scanner, main, "c1", dbs.get_rules("keyword"), profile)
    assert contacts() == {f: ("match", "high", None, 1) for f in ("phone", "fax", "nick")}
    _exec("UPDATE rule_hits SET reviewer = 'bob' WHERE field_name = 'nick'")        # a human kept it

    # severity low, fax and nick no longer match (version 2)
    _exec("""UPDATE rules SET severity = 'low', scope = '{"field_re": "^phone$", "action": "score"}', version = 2
             WHERE name = 'contacts'""")
    stats = save_scored(pg_scanner, main, "c2", dbs.get_rules("keyword"), profile)
    assert contacts() == {
        "phone": ("match", "low", None, 2),          # machine verdict: follows the rule
        "nick": ("match", "high", "bob", 1),         # human decision: kept
    }                                                    # fax: machine verdict, no longer matching: dropped
    assert stats["stale_pending"] == 1

    # auto -> review (the API keeps the version for mode / severity edits): the machine-confirmed
    # hit becomes a proposal again; the human decision stays
    _exec("UPDATE rules SET mode = 'review', severity = 'medium' WHERE name = 'contacts'")
    save_scored(pg_scanner, main, "c3", dbs.get_rules("keyword"), profile)
    assert contacts() == {"phone": ("pending_review", "medium", None, 2), "nick": ("match", "high", "bob", 1)}


def test_force_push_to_an_older_commit_is_queued_for_a_scan(pg_scanner):
    dbs = pg_scanner.db
    project, _ = dbs.upsert_project(project_gl())
    main, _ = dbs.upsert_branch(branch_gl("main", "h2", "2026-11-02T10:00:00.000Z"), project.id, project.full_path, True)
    dbs.set_branch_processed(main.id, main.updated_at)                 # h2 scanned
    # git reset --hard h1 && git push -f: the head's commit date is older
    main, result = dbs.upsert_branch(branch_gl("main", "h1", "2026-11-01T10:00:00.000Z"), project.id,
                                     project.full_path, True)
    assert result == "updated" and main.commit == "h1"
    assert main.processed_at < main.updated_at                         # _needs_processing: queued
    # the same head again: unchanged
    assert dbs.upsert_branch(branch_gl("main", "h1", "2026-11-01T10:00:00.000Z"), project.id,
                             project.full_path, True)[1] == "checked"


def test_main_scan_finishing_after_a_default_branch_change_is_not_saved(pg_scanner):
    dbs = pg_scanner.db
    project, main, feature, mr = setup_project(dbs)
    scanning = dbs.get_branch_by_id(main.id)                    # a scan of main starts ...
    master, _ = dbs.upsert_branch(branch_gl("master"), project.id, project.full_path, True)   # ... main demoted
    stats = save_main(pg_scanner, scanning, "c1", records(project.id, obj("User", {"email": "string"})))
    assert stats == {"skipped": "not main"}
    assert q("SELECT count(*) FROM branch_objects WHERE branch_id = :b", b=main.id) == [(0,)]
    assert dbs.get_branch_by_id(main.id).scanned_commit is None


def test_source_branch_of_two_mrs_holds_the_delta_of_the_oldest_one(pg_scanner, monkeypatch):
    """feature -> main (MR 1) and feature -> release (MR 2, a backport): the delta on feature
    belongs to MR 1; readers show it under MR 1 only, a main scan prunes it only for MR 1, and
    when MR 1 closes the delta is dropped and MR 2 is queued for a scan."""
    from discovery_common import db, testing

    dbs = pg_scanner.db
    project, main, feature, mr1 = setup_project(dbs)
    release, _ = dbs.upsert_branch(branch_gl("release"), project.id, project.full_path, False)
    mr2, _ = dbs.upsert_mr(mr_gl(2, "feature", "release"), project.id, project.full_path, feature, release)
    assert dbs.get_delta_owner(feature.id) == mr1.id

    save_main(pg_scanner, main, "c1", records(project.id, obj("User", {"id": "int"})))
    save_mr(pg_scanner, feature, main, "f1", records(project.id, obj("User", {"id": "int"}),
                                                     obj("Card", {"card_pan": "string"})))
    with db.get_engine().connect() as conn:
        assert {r["mr_id"] for r in testing.open_mr_delta(conn, project.id)} == {1}
        assert {r["mr_id"] for r in testing.open_mr_fields(conn, project.id)} == {1}
        assert {r["mr_id"] for r in testing.open_mr_fields(conn, None, "card")} == {1}

    # MR 1 closed: the delta (vs main) is dropped, MR 2 owns the branch now and is re-scanned
    dbs.set_mr_processed(mr2.id)
    cleanup = pg_scanner.load("services.cleanup_service")
    assert cleanup.close_missing_mrs(project.id, [2], lambda iid: "closed") == 1
    assert dbs.get_delta_owner(feature.id) == mr2.id
    assert q("SELECT count(*) FROM branch_objects WHERE branch_id = :b", b=feature.id) == [(0,)]
    assert dbs.get_mr(mr2.id).processed_at is None
    assert dbs.get_branch_by_id(feature.id) is not None                # still the source of MR 2


def test_llm_object_rule_mark_fields_lifecycle(pg_scanner, monkeypatch):
    """mark_fields: one call per object marks the object and the named fields; a re-ask replaces
    the machine field marks (a field no longer named is dropped), human decisions on field hits
    survive re-asks and identity changes (carry-over); field hits never make extra calls."""
    from appsec_discovery.ai import FakeLlmBackend

    dbs = pg_scanner.db
    project, main, feature, mr = setup_project(dbs)
    _exec("UPDATE rules SET enabled = false WHERE scope ->> 'source' = 'core'")
    client = {"LastName": "string", "Phone": "string", "Email": "string", "id": "int"}
    save_main(pg_scanner, main, "c1", records(project.id, obj("Client", client)))
    _exec("""INSERT INTO rules (kind, name, category, severity, target, mode, scope, prompt, version, enabled)
             VALUES ('llm', 'person-mark', 'pii', 'high', 'object', 'review', '{"mark_fields": true}',
                     'last name + phone', 1, true)""")
    rule_id = q("SELECT id FROM rules WHERE name = 'person-mark'")[0][0]

    pg_scanner.use_real("services.score_service")
    scan_service = pg_scanner.load("services.scan_service")
    answer = {"verdict": "match", "reason": "a person", "fields": ["LastName", "Phone"]}
    backend = FakeLlmBackend(lambda system, user, schema: json.dumps(answer), model="m1")
    monkeypatch.setattr(scan_service, "llm_configured", lambda settings=None: True)
    monkeypatch.setattr(scan_service, "get_llm_backend", lambda *a, **kw: backend)

    def run():           # as a rollout slice (stale verdicts of older versions too)
        assert scan_service.run_selected_llm_rules(dbs.get_branch_by_id(main.id), [rule_id], migration=True) is True

    def hits():
        return q("SELECT h.field_name, h.status, h.severity, h.category, h.reason, h.rule_version, h.reviewer, "
                 "h.fields, h.subject_key = h.object_key FROM rule_hits h WHERE h.rule_id = :r "
                 "ORDER BY h.field_name NULLS FIRST", r=rule_id)

    run()
    assert len(backend.calls) == 1
    assert hits() == [
        (None, "pending_review", "high", "pii", "a person", 1, None, ["LastName", "Phone"], True),
        ("LastName", "pending_review", "high", "pii", "a person", 1, None, None, False),
        ("Phone", "pending_review", "high", "pii", "a person", 1, None, None, False),
    ]
    key = records(project.id, obj("Client", client))[0].object_key
    from discovery_common import keys
    assert {r[0] for r in q("SELECT subject_key FROM rule_hits WHERE rule_id = :r AND field_name IS NOT NULL",
                            r=rule_id)} == {keys.field_key(key, "LastName"), keys.field_key(key, "Phone")}
    run()
    assert len(backend.calls) == 1                     # field hits are no candidates: nothing asked again

    # a human decides the Phone field hit; deciding the object hit does not decide the fields
    _exec("UPDATE rule_hits SET status = 'no_match', reviewer = 'eve' WHERE rule_id = :r AND field_name = 'Phone'",
          r=rule_id)

    # a new rule version: the object is asked again (one call), the model drops LastName, adds Email
    _exec("UPDATE rules SET version = 2 WHERE id = :r", r=rule_id)
    answer.update(fields=["Phone", "Email"], reason="contacts")
    run()
    assert len(backend.calls) == 2
    assert hits() == [
        (None, "pending_review", "high", "pii", "contacts", 2, None, ["Email", "Phone"], True),
        ("Email", "pending_review", "high", "pii", "contacts", 2, None, None, False),
        ("Phone", "no_match", "high", "pii", "a person", 1, "eve", None, False),   # human: untouched
    ]

    # no_match on the next version: the machine field marks go, the human decision stays
    _exec("UPDATE rules SET version = 3 WHERE id = :r", r=rule_id)
    answer.update(verdict="no_match", fields=[], reason=None)
    run()
    assert len(backend.calls) == 3
    assert [(r[0], r[1], r[6]) for r in hits()] == [(None, "no_match", None), ("Phone", "no_match", "eve")]

    # identity change (same parser / type / name / file, new hash): the field decision is carried over
    save_main(pg_scanner, main, "c2", records(project.id, obj("Client", client, hash_="id2-Client")))
    new_key = records(project.id, obj("Client", client, hash_="id2-Client"))[0].object_key
    assert q("SELECT field_name, status, reviewer FROM rule_hits WHERE rule_id = :r AND object_key = :k "
             "ORDER BY field_name NULLS FIRST", r=rule_id, k=new_key) == [
        (None, "no_match", None), ("Phone", "no_match", "eve")]


def test_llm_object_rule_mark_fields_off_drops_machine_marks_on_reask(pg_scanner):
    """Switching mark_fields off (a new version): re-asked objects lose their machine field marks."""
    from discovery_common.mapping import hit_row

    dbs = pg_scanner.db
    project, main, feature, mr = setup_project(dbs)
    save_main(pg_scanner, main, "c1", records(project.id, obj("Client", {"LastName": "string", "Phone": "string"})))
    _exec("""INSERT INTO rules (kind, name, category, severity, target, mode, scope, version, enabled)
             VALUES ('llm', 'p', 'pii', 'high', 'object', 'review', '{"mark_fields": true}', 1, true)""")
    rule = next(r for r in dbs.get_rules("llm") if r.name == "p")
    key = records(project.id, obj("Client", {"LastName": "string", "Phone": "string"}))[0].object_key
    dbs.upsert_llm_hits([hit_row(rule, project.id, key, None, "pending_review", fields=["LastName", "Phone"]),
                         hit_row(rule, project.id, key, "LastName", "pending_review"),
                         hit_row(rule, project.id, key, "Phone", "pending_review")],
                        is_main=True, rule_id=rule.id, asked_objects=[key])
    assert len(q("SELECT 1 FROM rule_hits WHERE rule_id = :r", r=rule.id)) == 3
    _exec("UPDATE rules SET version = 2, scope = '{}' WHERE id = :r", r=rule.id)
    rule = next(r for r in dbs.get_rules("llm") if r.name == "p")
    dbs.upsert_llm_hits([hit_row(rule, project.id, key, None, "pending_review", fields=["Phone"])],
                        is_main=True, rule_id=rule.id, asked_objects=[key])
    assert q("SELECT field_name, rule_version FROM rule_hits WHERE rule_id = :r", r=rule.id) == [(None, 2)]


# ---- storage at scale (migration 0030): presence flags, stored hashes, retention -------------------------------

def _presence_consistent():
    """Every hit's stored in_main / in_open_mr equals the EXISTS form the API used before 0030."""
    from discovery_common import presence
    wrong = q(f"SELECT h.rule_id, h.field_name, h.in_main, h.in_open_mr, ({presence.IN_MAIN}) AS im, "
              f"({presence.IN_OPEN_MR}) AS imr FROM rule_hits h "
              f"WHERE h.in_main <> ({presence.IN_MAIN}) OR h.in_open_mr <> ({presence.IN_OPEN_MR})")
    assert wrong == [], wrong


def _flags(field_name):
    return q("SELECT in_main, in_open_mr FROM rule_hits WHERE field_name = :f ORDER BY rule_id", f=field_name)


def test_presence_flags_follow_snapshots_mrs_and_branches(pg_scanner):
    dbs = pg_scanner.db
    cleanup = pg_scanner.use_real("services.cleanup_service")
    project, main, feature, mr = setup_project(dbs)

    # main scan: its keyword hits are in_main
    save_main(pg_scanner, main, "c1", records(project.id, obj("User", {"email": "string", "id": "int"})))
    assert _flags("email") == [(True, False)]
    _presence_consistent()

    # MR adds a field: its hit is only in the open MR; the email hit is in both
    save_mr(pg_scanner, feature, main, "f1", records(project.id, obj("User", {"email": "string", "id": "int", "card": "string"})))
    assert _flags("card") == [(False, True)] and _flags("email") == [(True, True)]
    _presence_consistent()

    # the MR is closed (GitLab state), then reopened: in_open_mr follows the MR row
    dbs.upsert_mr(mr_gl(1, "feature", "main", state="closed"), project.id, project.full_path, feature, main)
    assert _flags("card") == [(False, False)]
    _presence_consistent()
    dbs.upsert_mr(mr_gl(1, "feature", "main"), project.id, project.full_path, feature, main)
    assert _flags("card") == [(False, True)]
    _presence_consistent()

    # merged into main: the MR delta is pruned by the main scan, the card hit is in_main now
    stats = save_main(pg_scanner, main, "c2", records(project.id, obj("User", {"email": "string", "id": "int", "card": "string"})))
    assert stats["pruned_mr_rows"] == 1 and stats["presence"] >= 1
    assert _flags("card") == [(True, False)] and _flags("email") == [(True, False)]
    _presence_consistent()

    # the MR vanishes from GitLab: its source branch is released, nothing else changes
    assert cleanup.close_missing_mrs(project.id, [], lambda iid: "merged") == 1
    _presence_consistent()

    # the object leaves main: its hits are in no branch (retention candidates), kept with their decisions
    save_main(pg_scanner, main, "c3", records(project.id, obj("Other", {"x": "int"})))
    assert _flags("card") == [(False, False)] and _flags("email") == [(False, False)]
    assert q("SELECT count(*) FROM rule_hits WHERE field_name IN ('email', 'card')")[0][0] == 2
    _presence_consistent()

    # ... and comes back
    save_main(pg_scanner, main, "c4", records(project.id, obj("User", {"email": "string", "id": "int", "card": "string"})))
    assert _flags("email") == [(True, False)]
    _presence_consistent()

    # a stale open MR released by the sync, an untracked branch dropped by the GC: both refresh the flags
    stale, _ = dbs.upsert_branch(branch_gl("stale", "s1"), project.id, project.full_path, False)
    dbs.upsert_mr(mr_gl(2, "stale", "main"), project.id, project.full_path, stale, main)
    save_mr(pg_scanner, stale, main, "s1", records(project.id, obj("User", {"email": "string", "id": "int", "card": "string", "card_iban": "string"})))
    assert _flags("card_iban") == [(False, True)]
    _exec("UPDATE gitlab_mrs SET updated_at = '2020-01-01' WHERE mr_id = 2")
    assert cleanup.release_stale_mr_branches(project.id) == 1
    assert _flags("card_iban") == [(False, False)]
    _presence_consistent()

    other, _ = dbs.upsert_branch(branch_gl("other", "o1"), project.id, project.full_path, False)
    dbs.upsert_mr(mr_gl(3, "other", "main"), project.id, project.full_path, other, main)
    save_mr(pg_scanner, other, main, "o1", records(project.id, obj("User", {"email": "string", "id": "int", "card": "string", "card_ssn": "string"})))
    assert _flags("card_ssn") == [(False, True)]
    _exec("UPDATE gitlab_mrs SET state = 'closed' WHERE mr_id = 3")        # as if closed behind the sync's back
    stats = cleanup.cleanup()
    assert stats["untracked_branches"] == 1
    assert _flags("card_ssn") == [(False, False)]
    _presence_consistent()

    # the default branch changes: the demoted main's hits are not in main any more
    dbs.upsert_branch(branch_gl("master", "m1"), project.id, project.full_path, True)
    assert _flags("email") == [(False, False)]
    _presence_consistent()

    # LLM verdicts: upsert_llm_hits sets the exact presence of the verdicts' objects
    master = dbs.get_branch(project.id, "master")
    save_main(pg_scanner, master, "m1", records(project.id, obj("User", {"email": "string", "id": "int"})))
    rule = classifier(dbs, "Is it personal data?")
    (user_key,) = [r[0] for r in q("SELECT DISTINCT object_key FROM objects WHERE name = 'User'")]
    from discovery_common import keys
    dbs.upsert_llm_hits([{"rule_id": rule.id, "subject_key": keys.field_key(user_key, "id"), "project_id": project.id,
                          "object_key": user_key, "field_name": "id", "rule_version": 1, "status": "no_match",
                          "decided_tier": "service", "prompt_version": "classifier3", "model": "m"}], is_main=True)
    assert q("SELECT in_main, in_open_mr FROM rule_hits WHERE rule_id = :r", r=rule.id) == [(True, False)]
    _presence_consistent()


def test_stored_llm_hashes_are_the_python_ones_and_follow_renames(pg_scanner):
    dbs = pg_scanner.db
    project, main, feature, mr = setup_project(dbs)
    save_main(pg_scanner, main, "c1", records(project.id, obj("User", {"email": "string", "id": "int"})))
    assert q("SELECT count(*) FROM object_fields WHERE llm_hash IS DISTINCT FROM "
             "llm_field_hash(field_name, field_type, comment, samples)")[0][0] == 0
    assert q("SELECT count(*) FROM objects o WHERE names_hash IS DISTINCT FROM llm_names_hash(o.name, "
             "ARRAY(SELECT f.field_name FROM object_fields f WHERE f.content_hash = o.content_hash))")[0][0] == 0
    from discovery_common import keys
    assert q("SELECT names_hash FROM objects") == [(keys.names_hash("User", ["email", "id"]),)]
    # the same version under another name (the name is not in the content hash): name and names_hash follow
    save_main(pg_scanner, main, "c2", records(project.id, obj("Person", {"email": "string", "id": "int"}, hash_="id-User")))
    assert q("SELECT name, names_hash FROM objects") == [("Person", keys.names_hash("Person", ["email", "id"]))]
    # the candidate queries compare the stored hashes: an unchanged snapshot has no candidate after a run
    rule = classifier(dbs, "Is it personal data?")
    assert {c["field_name"] for c in dbs.get_llm_candidates(main.id, rule)} == {"email", "id"}
    (user_key,) = [r[0] for r in q("SELECT DISTINCT object_key FROM objects")]
    dbs.upsert_llm_hits([{"rule_id": rule.id, "subject_key": keys.field_key(user_key, "email"), "project_id": project.id,
                          "object_key": user_key, "field_name": "email", "rule_version": 1, "status": "match",
                          "decided_tier": "service", "prompt_version": "classifier3", "model": "m",
                          "names_hash": keys.names_hash("Person", ["email"]),
                          "subject_hash": keys.field_subject_hash("email", "string", None, None)}], is_main=True)
    assert {c["field_name"] for c in dbs.get_llm_candidates(main.id, rule)} == {"id"}      # email: answered


def test_cleanup_retention_of_verifications_trials_and_hits_by_presence(pg_scanner):
    dbs = pg_scanner.db
    cleanup = pg_scanner.use_real("services.cleanup_service")
    project, main, feature, mr = setup_project(dbs)
    save_main(pg_scanner, main, "c1", records(project.id, obj("User", {"email": "string"})))
    rule_id = q("SELECT id FROM rules WHERE kind = 'llm' ORDER BY id LIMIT 1")[0][0]

    # a live hit (in_main) long unseen stays; a hit in no branch of the same age goes
    _exec("UPDATE rule_hits SET last_seen_at = now() - interval '400 days'")
    _exec("INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version, status, last_seen_at) "
          "VALUES (:r, gen_random_uuid(), :p, gen_random_uuid(), 'gone', 1, 'no_match', now() - interval '400 days')",
          r=rule_id, p=project.id)
    # harness verifications and prompt trials past their retention; a trial a proposal refers to is kept
    verification = ("INSERT INTO llm_verifications (rule_id, rule_version, subject_key, object_key, project_id, sample, "
                    "service_status, service_verdict, outcome, created_at) VALUES (:r, 1, gen_random_uuid(), "
                    "gen_random_uuid(), :p, 'qa', 'match', 'match', 'final', now() - :age)")
    _exec(verification, r=rule_id, p=project.id, age=timedelta(days=400))
    _exec(verification, r=rule_id, p=project.id, age=timedelta(days=10))
    trial = ("INSERT INTO prompt_trials (rule_id, rule_version, prompt_version, candidate_prompt, prompt_hash, status, "
             "created_at) VALUES (:r, 1, 'classifier3', 'p', :h, :s, now() - interval '100 days') RETURNING id")
    old_done = _exec(trial, r=rule_id, h="h1", s="done").scalar()
    _exec("INSERT INTO prompt_trial_items (trial_id, subject_key, object_key, content_hash, project_id, role, expected) "
          "VALUES (:t, gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), :p, 'target', 'match')", t=old_done, p=project.id)
    _exec(trial, r=rule_id, h="h2", s="queued")                                             # not finished: kept
    kept = _exec(trial, r=rule_id, h="h3", s="done").scalar()
    _exec("INSERT INTO prompt_proposals (rule_id, base_version, prompt, prompt_hash, trial_id, rationale) "
          "VALUES (:r, 1, 'p', 'h3', :t, 'why')", r=rule_id, t=kept)

    stats = cleanup.cleanup()
    assert (stats["hits_rejected_unseen"], stats["hits_decided_unseen"]) == (1, 0)
    assert q("SELECT field_name FROM rule_hits") == [("email",)]
    assert stats["llm_verifications"] == 1 and q("SELECT count(*) FROM llm_verifications")[0][0] == 1
    assert stats["prompt_trials"] == 1
    assert sorted(r[0] for r in q("SELECT prompt_hash FROM prompt_trials")) == ["h2", "h3"]
    assert q("SELECT count(*) FROM prompt_trial_items")[0][0] == 0
    assert q("SELECT to_regclass('_gc_orphans')") == [(None,)]                              # temp table dropped

    # retention off (0 days) skips the steps
    pg_scanner.setenv(LLM_VERIFICATIONS_RETENTION_DAYS="0", PROMPT_TRIALS_RETENTION_DAYS="0")
    stats = cleanup.cleanup()
    assert (stats["llm_verifications"], stats["prompt_trials"]) == (0, 0)
