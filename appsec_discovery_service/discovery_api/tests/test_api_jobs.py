"""Read endpoints added in stage 6 (P3-2 / P2-4): scanner job queue, project by id,
and the API docs behind nginx (root_path /api)."""

import json

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("mcp")
pydantic = pytest.importorskip("pydantic")
if not pydantic.VERSION.startswith("2"):
    pytest.skip("the API runs on pydantic v2", allow_module_level=True)

from test_api_rest import lst  # noqa: E402

JOBS_SQL = """
INSERT INTO jobs (kind, payload, dedup_key, status, attempts, last_error, finished_at) VALUES
  ('sync_projects', '{"full": true}', 'sync_projects', 'done', 1, NULL, now()),
  ('scan_branch', '{"branch_id": 1}', 'scan_branch:1:c1', 'failed', 5, 'RuntimeError: clone failed', now()),
  ('scan_mr', '{"mr_id": 7}', 'scan_mr:7:f1:c1', 'pending', 1, 'RuntimeError: gitlab 502', NULL),
  ('scan_mr', '{"mr_id": 8}', 'scan_mr:8:f2:c1', 'running', 1, NULL, NULL)
"""


def test_jobs_are_listed_filtered_and_sorted(api, sql):
    sql(JOBS_SQL)

    items, crange = lst(api, "/jobs", range=[0, 1])
    assert crange == "jobs 0-1/4"
    assert [i["dedup_key"] for i in items] == ["scan_mr:8:f2:c1", "scan_mr:7:f1:c1"]      # newest first
    assert items[1]["payload"] == {"mr_id": 7} and items[1]["attempts"] == 1

    mrs, crange = lst(api, "/jobs", filter={"kind": "scan_mr", "status": ["pending", "running"]})
    assert len(mrs) == 2 and crange == "jobs 0-1/2"
    assert [i["kind"] for i in lst(api, "/jobs", filter={"q": "clone"})[0]] == ["scan_branch"]
    assert [i["status"] for i in lst(api, "/jobs", sort=["attempts", "DESC"])[0]][0] == "failed"

    job = items[0]
    assert api.get(f"/jobs/{job['id']}").json()["dedup_key"] == "scan_mr:8:f2:c1"
    assert api.get("/jobs/999999").status_code == 404
    assert api.get("/jobs/stats").json() == {
        "sync_projects": {"done": 1}, "scan_branch": {"failed": 1}, "scan_mr": {"pending": 1, "running": 1}}

    # whitelists: unknown sort fields / filters / values are refused, not passed to SQL
    for params in ({"sort": json.dumps(["payload", "ASC"])}, {"filter": json.dumps({"locked_by": "x"})},
                   {"filter": json.dumps({"kind": "drop table"})}, {"filter": json.dumps({"status": "zombie"})},
                   {"range": json.dumps([5, 1])}):
        assert api.get("/jobs", params=params).status_code == 422, params

    assert api.get("/jobs", headers={"Authorization": ""}).status_code == 401


def test_project_by_id(api, seed):
    row = api.get("/projects/1", params={"detail": "false"}).json()
    assert {k: row[k] for k in ("id", "full_path", "project_name", "scan_mode", "pending_hits", "group_path")} == {
        "id": 1, "full_path": "grp/proj", "project_name": "proj", "scan_mode": "rules", "pending_hits": 3,
        "group_path": "grp/proj"}
    assert "hits_by_rule" not in row
    assert api.get("/projects/42").status_code == 404


def test_docs_behind_nginx_use_the_api_prefix(api_settings):
    """uvicorn runs with --root-path /api (Dockerfile): the docs page loads /api/openapi.json."""
    from fastapi.testclient import TestClient

    import main

    with TestClient(main.create_app(), root_path="/api") as client:
        docs = client.get("/docs")
        assert docs.status_code == 200 and "/api/openapi.json" in docs.text
        assert client.get("/openapi.json").status_code == 200


def test_job_health_aggregates_the_queue(api, sql):
    """GET /jobs/health (UI "Pipeline health", MCP job_health): per kind counts, oldest pending / longest running
    age, typical run / wait time, ETA, busy workers, service LLM throughput and ETA from jobs.progress."""
    sql(JOBS_SQL)
    # a pending job waits from GREATEST(created_at, run_after): the seeds set run_after = created_at (the column
    # defaults to the insert time)
    sql("""INSERT INTO jobs (kind, payload, dedup_key, status, attempts, created_at, run_after, locked_by, locked_at,
                             finished_at, progress)
           VALUES
           ('llm_score', '{"branch_id": 1}', 'llm_rule:1', 'pending', 0, now() - interval '2 hours',
            now() - interval '2 hours', NULL, NULL, NULL, NULL),
           ('llm_score', '{"branch_id": 2}', 'llm_rule:2', 'pending', 0, now() - interval '10 minutes',
            now() - interval '10 minutes', NULL, NULL, NULL, NULL),
           ('llm_score', '{"branch_id": 3}', 'llm_rule:3', 'running', 1, now() - interval '30 minutes',
            now() - interval '30 minutes', 'host:llm-0:1', now() - interval '20 minutes', NULL,
            jsonb_build_object('phase', 'running', 'done_objects', 40, 'total_objects', 100,
                               'started_at', to_char(now() - interval '20 minutes', 'YYYY-MM-DD"T"HH24:MI:SSOF'))),
           ('llm_score', '{"branch_id": 4}', 'llm_rule:4', 'done', 1, now() - interval '55 minutes',
            now() - interval '55 minutes', NULL, now() - interval '45 minutes',
            now() - interval '30 minutes', '{"phase": "done", "done_objects": 200, "total_objects": 200}'),
           ('llm_score', '{"branch_id": 5}', 'llm_rule:5', 'done', 1, now() - interval '4 hours' - interval '15 minutes',
            now() - interval '4 hours' - interval '15 minutes', NULL, now() - interval '4 hours' - interval '5 minutes',
            now() - interval '4 hours', '{"phase": "done", "done_objects": 100, "total_objects": 100}'),
           ('llm_prepare', '{"branch_id": 6, "executor": "external"}', 'llm_rule:external:6', 'done', 1,
            now() - interval '1 hour', now() - interval '1 hour', NULL, NULL, now() - interval '50 minutes',
            '{"phase": "awaiting_answers"}')""")
    health = api.get("/jobs/health").json()
    llm = health["kinds"]["llm_score"]
    assert (llm["pending"], llm["running"], llm["done_1h"], llm["done_24h"], llm["retrying"]) == (2, 1, 1, 2, 0)
    assert 7000 < llm["oldest_pending_s"] < 7400 and 1150 < llm["longest_running_s"] < 1300
    # 2 pending at 1 done per hour; runs of 15 and 5 minutes (p50 10 min); every job of 24 h waited 10 minutes
    assert (llm["eta_s"], llm["typical_run_s"], llm["typical_wait_s"]) == (7200, 600, 600)
    assert llm["scheduled"] == {"count": 0, "next_run_in_s": None} and llm["last_done_at"] is not None
    assert health["kinds"]["scan_mr"]["retrying"] == 1 and health["kinds"]["scan_branch"]["failed_24h"] == 1
    assert health["kinds"]["scan_branch"]["eta_s"] is None                       # nothing pending
    assert health["totals"]["oldest_pending_kind"] == "llm_score" and health["totals"]["pending"] == 3
    # running jobs, the longest running first (a job without locked_at - seeded directly - comes last)
    assert [(w["kind"], w["locked_by"]) for w in health["workers"]] == [("llm_score", "host:llm-0:1"), ("scan_mr", None)]
    assert health["workers"][0]["progress"] == {"phase": "running", "done_objects": 40, "total_objects": 100}
    rate = health["llm"]
    # 200 objects finished in the last hour + 40 of the run started 20 minutes ago; runs of 24 h average 150 objects
    assert (rate["objects_done_1h"], rate["objects_per_hour"], rate["objects_done_24h"]) == (200, 240, 300)
    assert rate["avg_objects_per_run_24h"] == 150.0 and rate["pending_runs"] == 2 and rate["estimated_pending_objects"] == 300
    assert rate["eta_s"] == int(300 / 240 * 3600)
    assert api.get("/jobs/health", headers={"Authorization": ""}).status_code == 401


def test_job_health_on_an_empty_queue(api):
    health = api.get("/jobs/health").json()
    assert health["kinds"] == {} and health["workers"] == [] and health["totals"]["oldest_pending_s"] is None
    assert health["llm"]["eta_s"] is None and health["llm"]["estimated_pending_objects"] is None
    assert health["scans"]["scan_branch"] == {"full": 0, "skipped": 0} and health["scans"]["scan_mr"] == {"full": 0, "skipped": 0}


def test_job_health_counts_diff_skipped_scans(api, sql):
    """Scans the scanner ended without a clone (progress.skipped: no parser file changed) vs full ones, 24 hours."""
    sql("""INSERT INTO jobs (kind, payload, dedup_key, status, attempts, created_at, run_after, finished_at, progress)
           VALUES
           ('scan_branch', '{"branch_id": 1}', 'sb:1', 'done', 1, now() - interval '2 hours', now() - interval '2 hours',
            now() - interval '1 hour', '{"phase": "skipped", "skipped": "no parser files changed", "changed_files": 3}'),
           ('scan_branch', '{"branch_id": 2}', 'sb:2', 'done', 1, now() - interval '2 hours', now() - interval '2 hours',
            now() - interval '1 hour', '{"phase": "skipped", "reason": "language not in SCAN_LANGS"}'),
           ('scan_branch', '{"branch_id": 3}', 'sb:3', 'done', 1, now() - interval '2 hours', now() - interval '2 hours',
            now() - interval '1 hour', '{"phase": "done", "objects": 12}'),
           ('scan_branch', '{"branch_id": 4}', 'sb:4', 'done', 1, now() - interval '3 days', now() - interval '3 days',
            now() - interval '2 days', '{"phase": "skipped", "skipped": "no parser files changed", "changed_files": 1}'),
           ('scan_mr', '{"mr_id": 5}', 'sm:5', 'done', 1, now() - interval '2 hours', now() - interval '2 hours',
            now() - interval '1 hour', '{"phase": "skipped", "skipped": "no parser files changed", "changed_files": 0}'),
           ('scan_mr', '{"mr_id": 6}', 'sm:6', 'failed', 3, now() - interval '2 hours', now() - interval '2 hours',
            now() - interval '1 hour', '{"phase": "failed"}')""")
    health = api.get("/jobs/health").json()
    assert health["kinds"]["scan_branch"]["skipped_24h"] == 1 and health["kinds"]["scan_branch"]["done_24h"] == 3
    assert health["scans"]["scan_branch"] == {"full": 2, "skipped": 1}        # the SCAN_LANGS skip counts as a job, not a diff skip
    assert health["scans"]["scan_mr"] == {"full": 0, "skipped": 1}
    assert health["kinds"]["llm_score"]["skipped_24h"] == 0 if "llm_score" in health["kinds"] else True


SCHEDULED_SQL = """
INSERT INTO jobs (kind, payload, dedup_key, status, created_at, run_after) VALUES
  ('cleanup', '{}', 'cleanup', 'pending', now() - interval '11 hours', now() + interval '13 hours')
"""


def test_job_health_scheduled_jobs_do_not_age_and_eta(api, sql):
    """A job due in the future (the periodic cleanup, run_after ahead) is scheduled, not an old pending job: the
    totals' oldest pending job is the oldest DUE one of the other kinds; eta_s = pending / done_1h hours."""
    sql(SCHEDULED_SQL)
    only = api.get("/jobs/health").json()                        # the only pending job is the future cleanup
    assert only["kinds"]["cleanup"]["pending"] == 1 and only["kinds"]["cleanup"]["oldest_pending_s"] is None
    assert only["totals"]["oldest_pending_s"] is None and only["totals"]["oldest_pending_kind"] is None

    sql("""INSERT INTO jobs (kind, payload, dedup_key, status, created_at, run_after) VALUES
           ('scan_branch', '{"branch_id": 1}', 'scan_branch:1:c9', 'pending', now() - interval '10 minutes',
            now() - interval '10 minutes')""")
    sql("""INSERT INTO jobs (kind, payload, dedup_key, status)
           SELECT 'llm_score', '{}', 'llm_rule:p:' || g, 'pending' FROM generate_series(1, 21) g""")
    sql("""INSERT INTO jobs (kind, payload, dedup_key, status, finished_at)
           SELECT 'llm_score', '{}', 'llm_rule:d:' || g, 'done', now() - interval '5 minutes' FROM generate_series(1, 9) g""")
    health = api.get("/jobs/health").json()
    cleanup = health["kinds"]["cleanup"]
    assert cleanup["oldest_pending_s"] is None and cleanup["scheduled"]["count"] == 1
    assert 46000 < cleanup["scheduled"]["next_run_in_s"] < 47000
    assert health["totals"]["oldest_pending_kind"] == "scan_branch" and 590 < health["totals"]["oldest_pending_s"] < 660
    assert health["totals"]["pending"] == 23
    assert health["kinds"]["llm_score"]["eta_s"] == 8400                       # 21 pending at 9 per hour
    assert health["kinds"]["scan_branch"]["eta_s"] is None                     # nothing done in the last hour


def test_jobs_carry_their_subject_retry_cancel_and_error_groups(api, seed, sql):
    """Every job names what it works on (subject from its payload); operators retry failed jobs and cancel pending
    ones; GET /jobs/errors groups failures by kind and normalised error text."""
    from conftest import ADMIN
    llm = seed["rules"]["llm"]
    (mr_id,), = sql("SELECT id FROM gitlab_mrs WHERE mr_id = 7")
    sql("""INSERT INTO jobs (kind, payload, dedup_key, status, attempts, last_error, finished_at) VALUES
           ('scan_branch', '{"branch_id": 1, "commit": "c1"}', 'scan_branch:1:c1', 'failed', 5,
            'RuntimeError: clone failed for commit abc1234def0 (attempt 5)', now() - interval '2 hours'),
           ('scan_branch', '{"branch_id": 1, "commit": "c0"}', 'scan_branch:1:c0', 'failed', 5,
            'RuntimeError: clone failed for commit 9f8e7d6c5b4 (attempt 3)', now() - interval '1 hour'),
           ('scan_mr', :mr_payload, 'scan_mr:x:f1:c1', 'pending', 0, NULL, NULL),
           ('scan_mr', '{"mr_id": 999999}', 'scan_mr:999999:f1:c1', 'failed', 5, 'gitlab 502 on 10.0.0.1', now()),
           ('llm_score', :llm_payload, 'llm_rule:x', 'done', 1, NULL, now()),
           ('sync_projects', '{"full": true}', 'sync_projects', 'done', 1, NULL, now())""",
        mr_payload=json.dumps({"mr_id": mr_id, "source_commit": "f1"}),
        llm_payload=json.dumps({"branch_id": 1, "commit": "c1", "rule_ids": [llm]}))
    jobs = {j["dedup_key"]: j for j in lst(api, "/jobs", range=[0, 49])[0]}
    assert jobs["scan_branch:1:c1"]["subject"] == {"project_id": 1, "project_path": "grp/proj", "branch_name": "main",
                                                   "mr_iid": None, "rule_names": None}
    assert jobs["scan_mr:x:f1:c1"]["subject"] == {"project_id": 1, "project_path": "grp/proj", "branch_name": "feature",
                                                  "mr_iid": 7, "rule_names": None}
    assert jobs["llm_rule:x"]["subject"]["rule_names"] == ["llm"] and jobs["llm_rule:x"]["subject"]["branch_name"] == "main"
    assert jobs["sync_projects"]["subject"] is None and jobs["scan_mr:999999:f1:c1"]["subject"] is None
    assert api.get(f"/jobs/{jobs['scan_mr:x:f1:c1']['id']}").json()["subject"]["mr_iid"] == 7

    # failures of the last 24 hours, grouped: two clone failures differing in commit / attempt are one cause
    errors = api.get("/jobs/errors", params={"hours": 24}).json()
    assert errors["hours"] == 24
    clone = next(e for e in errors["items"] if e["kind"] == "scan_branch")
    assert (clone["error_prefix"], clone["count"]) == ("RuntimeError: clone failed for commit # (attempt #)", 2)
    assert clone["sample_job_id"] == jobs["scan_branch:1:c0"]["id"] and len(clone["job_ids"]) == 2
    assert clone["first_seen_at"] < clone["last_seen_at"]
    gitlab = next(e for e in errors["items"] if e["kind"] == "scan_mr")
    assert (gitlab["error_prefix"], gitlab["count"]) == ("gitlab # on #.#.#.#", 1)
    assert api.get("/jobs/errors", params={"hours": 0}).status_code == 422
    assert [e["count"] for e in api.get("/jobs/errors", params={"hours": 1}).json()["items"]] == [1]  # only the 502

    # retry: failed -> pending again, the error kept in the payload
    failed = jobs["scan_branch:1:c1"]
    r = api.post(f"/jobs/{failed['id']}/retry")
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["status"], body["attempts"], body["finished_at"], body["last_error"]) == ("pending", 0, None, None)
    assert body["payload"]["previous_error"].startswith("RuntimeError: clone failed") and body["payload"]["commit"] == "c1"
    assert api.post(f"/jobs/{failed['id']}/retry").status_code == 409              # pending now
    assert api.post(f"/jobs/{jobs['sync_projects']['id']}/retry").status_code == 409   # done
    assert api.post("/jobs/999999/retry").status_code == 404

    # cancel: pending -> failed by the user
    pending = jobs["scan_mr:x:f1:c1"]
    r = api.post(f"/jobs/{pending['id']}/cancel")
    assert r.status_code == 200, r.text
    assert (r.json()["status"], r.json()["last_error"]) == ("failed", f"cancelled by {ADMIN}")
    assert r.json()["finished_at"] is not None
    assert api.post(f"/jobs/{pending['id']}/cancel").status_code == 409
    assert api.post(f"/jobs/{jobs['sync_projects']['id']}/cancel").status_code == 409
    assert api.post("/jobs/999999/cancel").status_code == 404
    assert api.post(f"/jobs/{pending['id']}/retry", headers={"Authorization": ""}).status_code == 401


def test_mcp_job_health_retry_and_cancel(live_api, sql):
    """MCP job_health is the same function as GET /jobs/health; job_retry / job_cancel for agents keeping the
    pipeline going."""
    from test_api_mcp import payload, run

    sql(SCHEDULED_SQL)
    sql("""INSERT INTO jobs (kind, payload, dedup_key, status, attempts, last_error, finished_at) VALUES
           ('scan_branch', '{"branch_id": 1}', 'scan_branch:1:c1', 'failed', 5, 'boom', now())""")
    (failed_id,), = sql("SELECT id FROM jobs WHERE kind = 'scan_branch'")
    (cleanup_id,), = sql("SELECT id FROM jobs WHERE kind = 'cleanup'")

    async def flow(client):
        names = {t.name for t in (await client.list_tools()).tools}
        health = payload(await client.call_tool("job_health", {}))
        retried = payload(await client.call_tool("job_retry", {"job_id": failed_id}))
        again = await client.call_tool("job_retry", {"job_id": failed_id})
        cancelled = payload(await client.call_tool("job_cancel", {"job_id": cleanup_id}))
        return names, health, retried, again, cancelled

    names, health, retried, again, cancelled = run(live_api, flow)
    assert {"job_health", "job_retry", "job_cancel"} <= names
    assert health["totals"]["oldest_pending_s"] is None and health["kinds"]["cleanup"]["scheduled"]["count"] == 1
    assert retried["status"] == "pending" and retried["payload"]["previous_error"] == "boom"
    assert again.is_error
    assert cancelled["status"] == "failed" and cancelled["last_error"].startswith("cancelled by ")


def test_job_errors_group_one_cause_across_subjects_and_keep_the_cause(api, sql):
    """The scanner quotes the subject of a failure (project, branch, MR); the grouping replaces quoted parts and
    numbers, so the deleted-branch cause on three MRs of two projects is one row that still names the cause."""
    sql("""INSERT INTO jobs (kind, payload, dedup_key, status, attempts, last_error, finished_at) VALUES
           ('scan_mr', '{"mr_id": 1}', 'a', 'failed', 1, :e1, now()), ('scan_mr', '{"mr_id": 2}', 'b', 'failed', 1, :e2, now()),
           ('scan_mr', '{"mr_id": 3}', 'c', 'failed', 1, :e3, now()), ('scan_mr', '{"mr_id": 4}', 'd', 'failed', 5, :e4, now())""",
        e1="scan of 'grp/proj', MR !25: cannot clone source branch 'release/2024-11': remote branch not found in upstream origin (deleted?)",
        e2="scan of 'grp/proj', MR !31: cannot clone source branch 'feature-x': remote branch not found in upstream origin (deleted?)",
        e3="scan of 'grp/other-proj', MR !2: cannot clone source branch 'fix/typo': remote branch not found in upstream origin (deleted?)",
        e4="scan of 'grp/proj', MR !40: cannot clone source branch 'feature-y': git clone failed: fatal: unable to access '<repo>': Could not resolve host: gitlab.example")
    items = api.get("/jobs/errors", params={"hours": 24}).json()["items"]
    assert [(i["error_prefix"], i["count"]) for i in items] == [
        ("scan of '#', MR !#: cannot clone source branch '#': remote branch not found in upstream origin (deleted?)", 3),
        ("scan of '#', MR !#: cannot clone source branch '#': git clone failed: fatal: unable to access '#': Could not resolve host: gitlab.example", 1),
    ]


def test_llm_rule_errors_list_failed_objects_runs_and_refused_harness_answers(api, seed, sql):
    """GET /llm_rules/{id}/errors: the failed objects with their reason (from jobs.progress.errors), counts per error
    class, the runs that ended failed / incomplete and failed harness work items; only this rule's."""
    llm, other = seed["rules"]["llm"], seed["rules"]["user-objects"]
    progress = {
        "executor": "service", "rule_ids": [llm], "phase": "incomplete", "total_objects": 4, "done_objects": 1,
        "failed_objects": 3, "finished_at": "2026-11-20T10:00:00+00:00",
        "error": "LLM rule 'llm': 3 of 4 objects failed: LlmError: LLM answer truncated at max_tokens=8192 (2), "
                 "APITimeoutError: Request timed out (1) (1 verdicts stored)",
        "errors": {"total": 3, "items": [
            {"rule_id": llm, "rule": "llm", "object": "User", "object_key": seed["user_key"], "field": "email",
             "error": "LlmError: LLM answer truncated at max_tokens=8192 (raise LLM_MAX_TOKENS)"},
            {"rule_id": llm, "rule": "llm", "object": "Card", "object_key": seed["card_key"],
             "error": "LlmError: LLM answer truncated at max_tokens=8192 (raise LLM_MAX_TOKENS)"},
            {"rule_id": llm, "rule": "llm", "object": "Gone", "object_key": seed["gone_key"],
             "error": "APITimeoutError: Request timed out."},
            {"rule_id": 999999, "rule": "another", "object": "X", "object_key": "k", "error": "ValueError: not ours"}],
            "by_class": [
                {"rule_id": llm, "rule": "llm", "error_class": "LlmError: LLM answer truncated at max_tokens=8192", "count": 2},
                {"rule_id": llm, "rule": "llm", "error_class": "APITimeoutError: Request timed out", "count": 1},
                {"rule_id": 999999, "rule": "another", "error_class": "ValueError: not ours", "count": 1}]}}
    sql("""INSERT INTO jobs (kind, payload, dedup_key, status, attempts, last_error, finished_at, progress) VALUES
           ('llm_score', :p1, 'run1', 'failed', 1, :e1, now() - interval '1 hour', CAST(:pr AS jsonb)),
           ('llm_score', '{"branch_id": 1, "commit": "c1"}', 'run2', 'failed', 5, :e2, now() - interval '2 hours', NULL),
           ('llm_score', :p3, 'run3', 'failed', 1, 'LLM rule ''user-objects'' failed: x', now(), NULL),
           ('llm_score', :p1, 'run4', 'done', 1, NULL, now() - interval '20 days', CAST(:pr AS jsonb)),
           ('llm_prepare', :p1, 'ext', 'done', 1, NULL, now(), '{"executor": "external", "phase": "awaiting_answers"}')""",
        p1=json.dumps({"branch_id": 1, "commit": "c1", "rule_ids": [llm]}),
        p3=json.dumps({"branch_id": 1, "commit": "c1", "rule_ids": [other]}),
        pr=json.dumps(progress, default=str),
        e1="LLM rules [%d] on 'grp/proj', branch 'main': %s" % (llm, progress["error"]),
        e2="LLM scoring of 'grp/proj', branch 'main': LLM rule 'llm': candidates not selected: OperationalError: connection lost")
    (ext_job,), = sql("SELECT id FROM jobs WHERE dedup_key = 'ext'")
    (run1,), = sql("SELECT id FROM jobs WHERE dedup_key = 'run1'")
    (run2,), = sql("SELECT id FROM jobs WHERE dedup_key = 'run2'")
    sql("""INSERT INTO llm_work_items (job_id, rule_id, rule_version, project_id, branch_id, object_key, content_hash,
                                       prompt_hash, user_prompt, status, error, answered_by, answer_model)
           VALUES (:j, :r, 1, 1, 1, :k, :h, 'hash', 'q', 'failed', 'LlmError: LLM answer has no ''verdict'': ''maybe''',
                   'harness-1', 'local-model'),
                  (:j, :r, 1, 1, 1, :k2, :h2, 'hash', 'q', 'applied', NULL, 'harness-1', 'local-model')""",
        j=ext_job, r=llm, k=seed["user_key"], h=seed["user_hash"], k2=seed["card_key"], h2=seed["card_hash"])

    r = api.get(f"/llm_rules/{llm}/errors")
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["rule_id"], body["rule_name"], body["hours"], body["total"]) == (llm, "llm", 24 * 7, 3)
    assert [(c["error_class"], c["count"], c["jobs"], c["last_job_id"]) for c in body["by_class"]] == [
        ("LlmError: LLM answer truncated at max_tokens=8192", 2, 1, run1), ("APITimeoutError: Request timed out", 1, 1, run1)]
    assert [(i["job_id"], i["object"], i["field"], i["error"][:41]) for i in body["items"]] == [
        (run1, "Card", None, "LlmError: LLM answer truncated at max_tok"),
        (run1, "Gone", None, "APITimeoutError: Request timed out."[:41]),
        (run1, "User", "email", "LlmError: LLM answer truncated at max_tok")]
    assert [(x["id"], x["status"], x["phase"]) for x in body["runs"]] == [(run2, "failed", None), (run1, "failed", "incomplete")]
    assert body["runs"][1]["error"] == progress["error"] and body["runs"][1]["project_path"] == "grp/proj"
    assert body["runs"][0]["last_error"].startswith("LLM scoring of 'grp/proj', branch 'main': LLM rule 'llm': candidates")
    assert [(w["job_id"], w["object"], w["error"], w["answered_by"]) for w in body["work_items"]] == [
        (ext_job, "User", "LlmError: LLM answer has no 'verdict': 'maybe'", "harness-1")]
    # window and unknown rules
    assert api.get(f"/llm_rules/{llm}/errors", params={"hours": 24 * 25}).json()["total"] == 6
    assert api.get(f"/llm_rules/{llm}/errors", params={"hours": 0}).status_code == 422
    r = api.get(f"/llm_rules/{other}/errors")            # another rule: only its own failures (404 if it is a keyword rule)
    (kind,), = sql("SELECT kind FROM rules WHERE id = :id", id=other)
    assert r.status_code == (200 if kind == "llm" else 404)
    if kind == "llm":
        assert [x["last_error"] for x in r.json()["runs"]] == ["LLM rule 'user-objects' failed: x"] and r.json()["total"] == 0
    assert api.get("/llm_rules/999999/errors").status_code == 404
    assert api.get(f"/llm_rules/{seed['rules'][__import__('discovery_common.models', fromlist=['CORE_FIELD_RULE']).CORE_FIELD_RULE]}/errors").status_code == 404

    # the runs lists (dashboard, Harness page) expose the per-object errors of a run
    runs = api.get("/llm_runs", params={"limit": 20}).json()
    run = next(x for x in runs["recent"] if x["id"] == run1)
    assert run["error"] == progress["error"] and run["errors"]["total"] == 3 and len(run["errors"]["items"]) == 4
