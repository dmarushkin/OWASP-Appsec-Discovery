"""Progress of LLM rule runs and the external executor (llm_work_items) against a real Postgres
(TEST_DATABASE_URL; skipped without it): an external run records exactly the calls a service
run sends, and its replayed answers store exactly the hits a service run stores."""

import json
from types import SimpleNamespace

from sqlalchemy import text

from appsec_discovery.models import CodeObject, CodeObjectField


def obj(name, fields, file="/m.go"):
    return CodeObject(
        hash=f"id-{name}", object_name=name, object_type="dto", parser="go", file=file, line=1, properties={},
        fields={f: CodeObjectField(field_name=f, field_type=t, file=file, line=i + 2) for i, (f, t) in enumerate(fields.items())},
    )


def q(sql, **params):
    from discovery_common import db
    with db.get_engine().connect() as conn:
        return conn.execute(text(sql), params).all()


def _exec(sql, **params):
    from discovery_common import db
    with db.unit_of_work() as s:
        return s.execute(text(sql), params)


OBJECTS = {
    "Client": {"LastName": "string", "Phone": "string", "Email": "string", "id": "int"},
    "Order": {"amount": "int", "comment": "string"},
    "Token": {"value": "string"},
}


def answer(system, user, schema):
    """A deterministic model: the classifier, field and object rule answers."""
    props = schema["properties"]
    if "verdict" in props:                                      # object rule
        if "LastName" in user:
            return json.dumps({"verdict": "match", "reason": "a person", "fields": ["LastName", "Phone"]})
        if "Token" in user:
            return json.dumps({"verdict": "need_more_info", "reason": "maybe a secret", "fields": ["value"]})
        return json.dumps({"verdict": "no_match"})
    item = props["fields"]["items"]["properties"]
    names = item["name"]["enum"]
    if "category" in item:                                      # classifier
        return json.dumps({"fields": [{"name": n, "category": "pii"} for n in names if n in ("Email", "Phone")]})
    return json.dumps({"fields": [{"name": n, "verdict": "match", "reason": "contact"} for n in names
                                  if n in ("Email", "Phone")]})


def setup(pg_scanner, monkeypatch):
    from discovery_common.mapping import from_code_object

    dbs = pg_scanner.db
    project, _ = dbs.upsert_project(SimpleNamespace(
        id=101, name="proj", path_with_namespace="grp/proj", description=None, visibility="private",
        default_branch="main", created_at="2026-01-01T10:00:00.000Z", last_activity_at="2026-11-01T10:00:00.000Z"))
    main, _ = dbs.upsert_branch(SimpleNamespace(name="main", commit={"id": "c1", "committed_date": "2026-11-01T10:00:00.000+03:00"}),
                                project.id, project.full_path, True)
    # only the rules of these tests: no core keyword rules, no default LLM rule (migration 0013)
    _exec("UPDATE rules SET enabled = false WHERE scope ->> 'source' = 'core' OR updated_by = 'migration:0013_example_rules'")
    recs = [from_code_object(obj(name, fields), project.id) for name, fields in OBJECTS.items()]
    dbs.save_main_scan(main, "c1", recs, [], None)
    # person / contacts and a classifier (an LLM field rule without category, named llm here)
    _exec("""INSERT INTO rules (kind, name, category, severity, target, mode, scope, prompt, version, enabled) VALUES
             ('llm', 'person', 'pii', 'high', 'object', 'review', '{"mark_fields": true}', 'last name + phone', 1, true),
             ('llm', 'contacts', 'contact', 'low', 'field', 'auto', '{}', 'contact data', 1, true),
             ('llm', 'llm', NULL, 'medium', 'field', 'review', '{}', NULL, 1, true)""")
    pg_scanner.use_real("services.score_service")
    scan_service = pg_scanner.load("services.scan_service")
    rules = dict(q("SELECT name, id FROM rules WHERE kind = 'llm' AND name IN ('llm', 'person', 'contacts') "
                   "AND deleted_at IS NULL"))
    work = pg_scanner.load("services.llm_work_service")
    return SimpleNamespace(dbs=dbs, project=project, branch=dbs.get_branch_by_id(main.id), rules=rules,
                           scan=scan_service, work=work)


def use_backend(monkeypatch, env, backend):
    """The service's LLM: scan_service (rules with a category) and score_service (the classifier)."""
    import sys
    for module in (env.scan, sys.modules["services.score_service"]):
        monkeypatch.setattr(module, "llm_configured", lambda settings=None: True)
        monkeypatch.setattr(module, "get_llm_backend", lambda *a, **kw: backend)


def new_job(rule_ids, executor="external", branch_id=1, tag="", kind=None):
    from discovery_common import jobs
    kind = kind or ("llm_prepare" if executor == "external" else "llm_score")
    return jobs.enqueue(kind, {"branch_id": branch_id, "rule_ids": rule_ids, "executor": executor},
                        f"llm_rule:{executor}:{rule_ids}:{branch_id}{tag}")


def items(job_id):
    return q("SELECT id, rule_id, object_key, call_index, system_prompt, user_prompt, json_schema, status, error "
             "FROM llm_work_items WHERE job_id = :j ORDER BY id", j=job_id)


def progress(job_id):
    return q("SELECT progress FROM jobs WHERE id = :j", j=job_id)[0][0]


def claim_and_submit(job_id, respond=answer, model="claude-test"):
    from discovery_common import db, llm_work
    claimed = {"items": []}
    while True:                                                 # small chunks (CLAIM_MAX), as a harness does
        with db.unit_of_work() as s:
            chunk = llm_work.claim(s, "agent@example.com", job_id=job_id, limit=llm_work.CLAIM_MAX)
        if not chunk["items"]:
            break
        claimed = {**chunk, "items": claimed["items"] + chunk["items"]}
    submitted = [{"id": i["id"], "lease": i["lease"], "model": model,
                  "answer": respond(i["system_prompt"], i["user_prompt"], i["json_schema"])} for i in claimed["items"]]
    with db.unit_of_work() as s:
        result = llm_work.submit(s, "agent@example.com", submitted)
    return claimed, result


HITS_SQL = ("SELECT rule_id, subject_key, project_id, object_key, field_name, rule_version, model, category, severity, "
            "status, reviewer, reason, fields FROM rule_hits WHERE rule_id = ANY(:r) ORDER BY rule_id, subject_key")


def test_external_run_records_the_service_prompts_and_stores_the_same_hits(pg_scanner, monkeypatch):
    from appsec_discovery.ai import FakeLlmBackend

    env = setup(pg_scanner, monkeypatch)
    rule_ids = sorted(env.rules.values())
    job_id = new_job(rule_ids)

    stats = env.work.prepare_external_run(job_id, env.branch, rule_ids)
    recorded = items(job_id)
    # one call per object: person (3 objects), contacts (Client, Order, Token), classifier (Client, Order, Token)
    assert stats["items"] == len(recorded) == 9 and {r.call_index for r in recorded} == {0}
    assert progress(job_id) | {"started_at": None} == progress(job_id) | {
        "executor": "external", "phase": "awaiting_answers", "total_objects": 9, "done_objects": 0, "failed_objects": 0,
        "pending_objects": 9, "rule_ids": rule_ids, "started_at": None}
    # a second external run does not ask the same objects again
    second = new_job(rule_ids, tag=":2")
    assert env.work.prepare_external_run(second, env.branch, rule_ids)["skipped_open_objects"] == 9
    assert items(second) == [] and progress(second)["phase"] == "done"

    claimed, result = claim_and_submit(job_id)
    assert result["rejected"] == [] and len(result["accepted"]) == 9 and result["apply_jobs"]
    assert "untrusted data" in claimed["instruction"]
    assert env.work.apply_answers(job_id) == {"applied": 9, "failed": 0, "expired": 0, "more": False}
    external_hits = q(HITS_SQL, r=rule_ids)
    assert {h.model for h in external_hits} == {"claude-test via mcp"}
    p = progress(job_id)
    assert (p["phase"], p["done_objects"], p["total_objects"], p["pending_objects"], p["answered_objects"]) == (
        "done", 9, 9, 0, 0) and p["finished_at"]
    assert {r.status for r in items(job_id)} == {"applied"}

    # the same rules run by the service with the same answers: the same calls, the same hits
    _exec("DELETE FROM rule_hits WHERE rule_id = ANY(:r)", r=rule_ids)
    backend = FakeLlmBackend(answer, model="claude-test via mcp")
    use_backend(monkeypatch, env, backend)
    service_job = new_job(rule_ids, executor="service")
    tracker = __import__("discovery_common.llm_work", fromlist=["JobProgress"]).JobProgress(
        service_job, rule_ids=rule_ids, every_n=1000, every_s=1000)
    assert env.scan.run_selected_llm_rules(env.branch, rule_ids, progress=tracker) is True
    tracker.finish()
    assert sorted((c[0], c[1], json.dumps(c[2], sort_keys=True)) for c in backend.calls) == sorted(
        (r.system_prompt, r.user_prompt, json.dumps(r.json_schema, sort_keys=True)) for r in recorded)
    assert q(HITS_SQL, r=rule_ids) == external_hits
    assert any(h.field_name == "LastName" and h.rule_id == env.rules["person"] for h in external_hits)   # mark_fields
    sp = progress(service_job)
    assert (sp["executor"], sp["phase"], sp["total_objects"], sp["done_objects"], sp["failed_objects"]) == (
        "service", "done", 9, 9, 0)


def test_external_apply_expires_changed_prompts_and_fails_bad_answers(pg_scanner, monkeypatch):
    env = setup(pg_scanner, monkeypatch)
    person, contacts, llm = env.rules["person"], env.rules["contacts"], env.rules["llm"]
    job_id = new_job([person, contacts, llm])
    env.work.prepare_external_run(job_id, env.branch, [person, contacts, llm])

    def respond(system, user, schema):
        if "verdict" in schema["properties"]:
            return "{}"                                          # valid JSON, but no verdict: the core parser refuses it
        return answer(system, user, schema)

    claim_and_submit(job_id, respond)
    # the contacts prompt was edited without a version bump: the rebuilt prompt differs
    _exec("UPDATE rules SET prompt = 'other contact data' WHERE id = :r", r=contacts)
    # the classifier got a new version meanwhile
    _exec("UPDATE rules SET version = version + 1 WHERE id = :r", r=llm)
    assert env.work.apply_answers(job_id) == {"applied": 0, "failed": 3, "expired": 6, "more": False}

    rows = {(r.rule_id, r.status, r.error.split(":")[0]) for r in items(job_id)}
    assert (person, "failed", "LlmError") in rows
    assert any(r[0] == contacts and r[1] == "expired" and "prompt changed" in r[2] for r in rows)
    assert any(r[0] == llm and r[1] == "expired" and "rule changed" in r[2] for r in rows)
    assert q("SELECT count(*) FROM rule_hits WHERE rule_id = ANY(:r)", r=[person, contacts, llm])[0][0] == 0
    p = progress(job_id)
    assert (p["phase"], p["done_objects"], p["failed_objects"], p["expired_objects"]) == ("done", 0, 3, 6)

    # the failed objects are still candidates: a new external run asks them again
    again = new_job([person], tag=":again")
    assert env.work.prepare_external_run(again, env.branch, [person])["items"] == 3


def test_service_llm_score_job_writes_progress(pg_scanner, monkeypatch):
    from appsec_discovery.ai import FakeLlmBackend
    from discovery_common.jobs import Job

    env = setup(pg_scanner, monkeypatch)
    backend = FakeLlmBackend(answer)
    use_backend(monkeypatch, env, backend)
    handlers = pg_scanner.load("services.job_handlers")
    job_id = new_job([env.rules["person"]], executor="service")
    handlers.llm_score_job(Job(id=job_id, kind="llm_score", payload={"branch_id": env.branch.id,
                                                                     "rule_ids": [env.rules["person"]]}))
    p = progress(job_id)
    assert (p["executor"], p["phase"], p["total_objects"], p["done_objects"], p["rule_ids"]) == (
        "service", "done", 3, 3, [env.rules["person"]]) and p["started_at"] and p["finished_at"]

    # external through the handler (an llm_score job queued before migration 0016): items, nothing asked
    ext = new_job([env.rules["contacts"]], kind="llm_score")
    handlers.llm_score_job(Job(id=ext, kind="llm_score", payload={"branch_id": env.branch.id, "executor": "external",
                                                                  "rule_ids": [env.rules["contacts"]]}))
    assert len(items(ext)) == 3 and len(backend.calls) == 3
    claim_and_submit(ext)
    handlers.llm_apply_job(Job(id=0, kind="llm_apply", payload={"job_id": ext}))
    assert {r.status for r in items(ext)} == {"applied"}


def test_cleanup_expires_unanswered_and_deletes_finished_items(pg_scanner, monkeypatch):
    env = setup(pg_scanner, monkeypatch)
    job_id = new_job([env.rules["person"]])
    env.work.prepare_external_run(job_id, env.branch, [env.rules["person"]])
    _exec("UPDATE llm_work_items SET created_at = now() - interval '8 days' WHERE job_id = :j", j=job_id)
    cleanup = pg_scanner.load("services.cleanup_service")
    stats = cleanup.cleanup()
    assert stats["llm_work_expired_runs"] == 1
    assert {r.status for r in items(job_id)} == {"expired"} and progress(job_id)["phase"] == "done"
    _exec("UPDATE llm_work_items SET updated_at = now() - interval '8 days' WHERE job_id = :j", j=job_id)
    assert cleanup.cleanup()["llm_work_finished"] == 3 and items(job_id) == []


def test_service_run_leaves_objects_reserved_by_the_external_executor(pg_scanner, monkeypatch):
    from appsec_discovery.ai import FakeLlmBackend

    env = setup(pg_scanner, monkeypatch)
    rule_ids = sorted(env.rules.values())
    job_id = new_job(rule_ids)
    assert env.work.prepare_external_run(job_id, env.branch, rule_ids)["items"] == 9   # every object reserved

    backend = FakeLlmBackend(answer, model="service-model")
    use_backend(monkeypatch, env, backend)
    assert env.scan.run_selected_llm_rules(env.branch, rule_ids) is True
    assert backend.calls == [] and q(HITS_SQL, r=rule_ids) == []         # no model call, nothing stored twice

    # the external answers are applied as usual; then nothing is left for the service
    claim_and_submit(job_id)
    assert env.work.apply_answers(job_id)["applied"] == 9
    assert env.scan.run_selected_llm_rules(env.branch, rule_ids) is True and backend.calls == []

    # an unanswered reservation released by the harness goes back to the service
    _exec("DELETE FROM rule_hits WHERE rule_id = :r", r=env.rules["person"])
    second = new_job([env.rules["person"]], tag=":again")
    assert env.work.prepare_external_run(second, env.branch, [env.rules["person"]])["items"] == 3
    _exec("UPDATE llm_work_items SET status = 'expired' WHERE job_id = :j", j=second)
    assert env.scan.run_selected_llm_rules(env.branch, [env.rules["person"]]) is True
    assert len(backend.calls) == 3


def test_lapsed_reservations_of_a_crashed_harness_are_taken_over_by_the_service(pg_scanner, monkeypatch):
    from appsec_discovery.ai import FakeLlmBackend

    env = setup(pg_scanner, monkeypatch)
    person = [env.rules["person"]]
    job_id = new_job(person)
    assert env.work.prepare_external_run(job_id, env.branch, person)["items"] == 3
    from discovery_common import db, llm_work
    with db.unit_of_work() as s:                        # the harness claims one item and crashes
        (claimed,) = llm_work.claim(s, "agent@example.com", job_id=job_id, limit=1)["items"]

    backend = FakeLlmBackend(answer, model="service-model")
    use_backend(monkeypatch, env, backend)
    assert env.scan.run_selected_llm_rules(env.branch, person) is True
    assert backend.calls == []                          # lease running, the rest freshly reserved

    _exec("UPDATE llm_work_items SET lease_until = now() - interval '1 minute' WHERE id = :i", i=claimed["id"])
    _exec("UPDATE llm_work_items SET created_at = now() - interval '25 hours' WHERE job_id = :j AND status = 'pending'",
          j=job_id)
    assert env.scan.run_selected_llm_rules(env.branch, person) is True
    assert len(backend.calls) == 3                      # every lapsed reservation asked by the service
    assert {(r.status, r.error) for r in items(job_id)} == {
        ("expired", "taken over by a service run (the reservation lapsed)")}
    assert progress(job_id)["phase"] == "done"
    with db.unit_of_work() as s:                        # the crashed harness comes back late
        late = llm_work.submit(s, "agent@example.com", [{"id": claimed["id"], "lease": claimed["lease"],
                                                         "model": "late", "answer": "{}"}])
    assert late["accepted"] == [] and len(late["rejected"]) == 1


def test_service_run_skips_objects_reserved_by_an_external_run_mid_run(pg_scanner, monkeypatch):
    """The service selects the candidates of every rule up front; an external run prepared
    while it is running reserves the objects not asked yet: the service re-checks the
    reservations before each chunk and leaves them to the external run (counted as done,
    skipped_objects). The object asked in the same chunk is expired by the apply."""
    from appsec_discovery.ai import FakeLlmBackend
    from discovery_common.llm_work import JobProgress

    env = setup(pg_scanner, monkeypatch)
    person = [env.rules["person"]]
    monkeypatch.setattr(env.scan, "RESERVED_RECHECK_EVERY", 1)
    external = []

    def respond(system, user, schema):
        if not external:                                # the first model call: an external run is prepared
            external.append(new_job(person, tag=":mid-run"))
            assert env.work.prepare_external_run(external[0], env.branch, person)["items"] == 3
        return answer(system, user, schema)

    backend = FakeLlmBackend(respond, model="service-model")
    use_backend(monkeypatch, env, backend)
    service_job = new_job(person, executor="service")
    tracker = JobProgress(service_job, rule_ids=person, every_n=1000, every_s=1000)
    assert env.scan.run_selected_llm_rules(env.branch, person, progress=tracker) is True
    tracker.finish()
    assert len(backend.calls) == 1                      # the other two objects left to the external run
    sp = progress(service_job)
    assert (sp["phase"], sp["total_objects"], sp["done_objects"], sp["failed_objects"], sp["skipped_objects"]) == (
        "done", 3, 3, 0, 2)
    assert q("SELECT count(*) FROM rule_hits WHERE rule_id = :r AND field_name IS NULL", r=person[0])[0][0] == 1

    # the external answers: the object the service answered meanwhile is no candidate any more
    claim_and_submit(external[0])
    assert env.work.apply_answers(external[0]) == {"applied": 2, "failed": 0, "expired": 1, "more": False}
    assert q("SELECT count(*) FROM rule_hits WHERE rule_id = :r AND field_name IS NULL", r=person[0])[0][0] == 3
    assert {r.error for r in items(external[0]) if r.status == "expired"} == {
        "no longer a candidate (decided, answered by another run, or removed)"}


def test_external_prepare_and_apply_run_in_slices_on_the_control_worker(pg_scanner, monkeypatch):
    """A large external run is recorded / applied in bounded slices: the job is requeued
    between them (no attempt used), progress says preparing until the last slice."""
    from discovery_common import jobs

    env = setup(pg_scanner, monkeypatch)
    rule_ids = sorted(env.rules.values())
    handlers = pg_scanner.load("services.job_handlers")
    supervisor = pg_scanner.load("supervisor")
    assert {"llm_prepare", "llm_apply"} <= set(supervisor.CONTROL_KINDS) and supervisor.LLM_KINDS == ["llm_score", "llm_trial"]
    monkeypatch.setattr(env.work, "PREPARE_SLICE_OBJECTS", 4)
    monkeypatch.setattr(env.work, "APPLY_CHUNK", 4)
    monkeypatch.setattr(env.work, "APPLY_SLICE_CHUNKS", 1)
    worker = jobs.Worker("control-test", handlers.HANDLERS, jobs.WorkerConfig(kinds=supervisor.CONTROL_KINDS))

    job_id = new_job(rule_ids)
    phases = []
    for _ in range(10):
        status = worker.run_once()
        (job_status, attempts), = q("SELECT status, attempts FROM jobs WHERE id = :j", j=job_id)
        phases.append((status, progress(job_id)["phase"], len(items(job_id))))
        if job_status == "done":
            break
        assert (job_status, attempts) == ("pending", 0)     # requeued, the slice used no attempt
    # 9 objects, 4 per slice
    assert phases == [("pending", "preparing", 4), ("pending", "preparing", 8), ("done", "awaiting_answers", 9)]
    p = progress(job_id)
    assert (p["total_objects"], p["pending_objects"], p["skipped_open_objects"], p["failed_prompts"]) == (9, 9, 0, 0)
    assert p["started_at"] and not p.get("finished_at")

    claimed, result = claim_and_submit(job_id)
    (apply_job,) = result["apply_jobs"]
    _exec("UPDATE jobs SET run_after = now() WHERE id = :j", j=apply_job)
    statuses = []
    while True:
        status = worker.run_once()
        if status is None:
            break
        statuses.append(status)
    assert statuses == ["pending", "pending", "done"]       # 4 + 4 + 1 answers
    assert {r.status for r in items(job_id)} == {"applied"} and progress(job_id)["phase"] == "done"
    assert q("SELECT status, attempts FROM jobs WHERE id = :j", j=apply_job) == [("done", 1)]


def test_take_over_a_pending_service_run_and_give_the_rest_back(pg_scanner, monkeypatch):
    """A pending service llm_score job becomes an external run with the same id (prepared by the control
    worker, answered by the harness, closed by the apply); a running one is never taken; giving the
    unanswered rest back queues a service run that asks only what is left."""
    from appsec_discovery.ai import FakeLlmBackend
    from discovery_common import db, jobs, llm_work

    env = setup(pg_scanner, monkeypatch)
    handlers = pg_scanner.load("services.job_handlers")
    person = env.rules["person"]
    # the LLM run after a main scan (no rule_ids: every enabled rule) and a selected-rules run
    after_scan = jobs.enqueue("llm_score", {"branch_id": env.branch.id, "commit": "c1"}, "llm_score:1:c1")
    selected = jobs.enqueue("llm_score", {"branch_id": env.branch.id, "commit": "c1", "rule_ids": [person]},
                            f"llm_rule:{person}:v1:{env.branch.id}:c1")
    running = jobs.enqueue("llm_score", {"branch_id": env.branch.id, "rule_ids": [person]}, "llm_rule:running")
    _exec("UPDATE jobs SET status = 'running', locked_by = 'w', locked_at = now() WHERE id = :j", j=running)
    with db.unit_of_work() as s:
        assert llm_work.take_over(s, "agent@example.com", job_id=running) == []           # running: never
        assert llm_work.take_over(s, "agent@example.com", job_id=selected) == [selected]
        assert llm_work.take_over(s, "agent@example.com", job_id=selected) == []          # taken already
    (kind, payload, prog, status, attempts), = q("SELECT kind, payload, progress, status, attempts FROM jobs "
                                                  "WHERE id = :j", j=selected)
    assert (kind, status, attempts) == ("llm_prepare", "pending", 0)
    assert payload == {"branch_id": env.branch.id, "commit": "c1", "rule_ids": [person], "executor": "external",
                       "taken_over_by": "agent@example.com"}
    assert (prog["executor"], prog["phase"], prog["taken_over_by"], prog["rule_ids"]) == (
        "external", "preparing", "agent@example.com", [person])

    # the LLM workers do not see it any more; the control worker prepares it
    assert jobs.claim("llm-w", ["llm_score"], lease_seconds=None).id == after_scan
    _exec("UPDATE jobs SET status = 'pending', locked_by = NULL, attempts = 0 WHERE id = :j", j=after_scan)
    control = jobs.Worker("control-w", {"llm_prepare": handlers.llm_prepare_job, "llm_apply": handlers.llm_apply_job},
                          jobs.WorkerConfig(kinds=["llm_prepare", "llm_apply"]))
    assert control.run_once() == "done"
    assert len(items(selected)) == 3 and progress(selected)["phase"] == "awaiting_answers"
    assert progress(selected)["taken_over_by"] == "agent@example.com"

    # the harness answers one object, then gives the rest back to the service
    with db.unit_of_work() as s:
        one = llm_work.claim(s, "agent@example.com", job_id=selected, limit=1)
        llm_work.submit(s, "agent@example.com", [{"id": one["items"][0]["id"], "lease": one["lease"], "model": "c",
                                                  "answer": answer(one["items"][0]["system_prompt"],
                                                                   one["items"][0]["user_prompt"],
                                                                   one["items"][0]["json_schema"])}])
        llm_work.claim(s, "other@example.com", job_id=selected, limit=1)                # someone else's lease
        released = llm_work.release_run(s, "agent@example.com", selected)
    assert len(released["released"]) == 2 and released["service_job"]
    assert {r.status for r in items(selected)} == {"answered", "expired"}
    (kind, payload), = q("SELECT kind, payload FROM jobs WHERE id = :j", j=released["service_job"])
    assert kind == "llm_score" and payload == {"branch_id": env.branch.id, "commit": "c1", "rule_ids": [person],
                                               "requested_by": "agent@example.com", "released_from": selected}
    _exec("UPDATE jobs SET run_after = now() WHERE kind = 'llm_apply'")               # queued with a delay
    assert control.run_once() == "done"                                                # the apply of the answer
    assert {r.status for r in items(selected)} == {"applied", "expired"}

    backend = FakeLlmBackend(answer, model="m")
    use_backend(monkeypatch, env, backend)
    _exec("DELETE FROM jobs WHERE id = :j", j=after_scan)
    llm = jobs.Worker("llm-w", {"llm_score": handlers.llm_score_job}, jobs.WorkerConfig(kinds=["llm_score"]))
    assert llm.run_once() == "done"
    assert len(backend.calls) == 2                       # only the objects without a verdict
    assert len(q("SELECT 1 FROM rule_hits WHERE rule_id = :r AND field_name IS NULL", r=person)) == 3
    with db.unit_of_work() as s:                         # nothing unanswered any more: nothing to queue
        assert llm_work.release_run(s, "agent@example.com", selected)["service_job"] is None


def test_take_over_gives_rules_to_a_run_without_rule_ids_and_refuses_a_preparing_release(pg_scanner, monkeypatch):
    from discovery_common import db, jobs, llm_work

    env = setup(pg_scanner, monkeypatch)
    after_scan = jobs.enqueue("llm_score", {"branch_id": env.branch.id, "commit": "c1"}, "llm_score:1:c1")
    with db.unit_of_work() as s:
        assert llm_work.take_over(s, "agent@example.com") == [after_scan]                 # the oldest one
    (payload,), = q("SELECT payload FROM jobs WHERE id = :j", j=after_scan)
    enabled = [r[0] for r in q("SELECT id FROM rules WHERE kind = 'llm' AND deleted_at IS NULL "
                               "AND enabled IS NOT FALSE ORDER BY id")]
    assert payload["rule_ids"] == enabled and set(env.rules.values()) <= set(enabled)
    import pytest
    with db.unit_of_work() as s:
        with pytest.raises(llm_work.WorkError, match="still being prepared"):
            llm_work.release_run(s, "agent@example.com", after_scan)
        with pytest.raises(llm_work.WorkError, match="limit must be 1..5"):
            llm_work.take_over(s, "agent@example.com", limit=6)
