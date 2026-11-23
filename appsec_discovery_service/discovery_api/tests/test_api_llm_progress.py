"""Coverage of the LLM rules (GET /llm_progress, MCP llm_progress, the Projects list's ``llm``
field) against a real Postgres, with synthetic llm_coverage rows (written by the scanner in
production) and one project per state."""

import pytest

pytest.importorskip("fastapi")
pydantic = pytest.importorskip("pydantic")
if not pydantic.VERSION.startswith("2"):
    pytest.skip("the API runs on pydantic v2", allow_module_level=True)

STATES_SQL = """
UPDATE rules SET enabled = false WHERE kind = 'llm';
INSERT INTO rules (id, kind, name, category, severity, target, mode, scope, prompt, version, enabled) VALUES
  (100, 'llm', 'pii', 'pii', 'high', 'field', 'review', '{}', 'personal data', 2, true),
  (101, 'llm', 'person', 'pii', 'high', 'object', 'review', '{}', 'a person', 1, true),
  (102, 'llm', 'off', 'x', 'low', 'field', 'review', '{}', 'disabled', 1, false);
INSERT INTO gitlab_projects (id, gitlab_id, project_name, full_path, visibility, created_at, updated_at, scan_mode,
                             source) VALUES
  (1, 101, 'current', 'a/current', 'private', now(), now(), 'rules', 'gitlab'),
  (2, 102, 'outdated', 'a/outdated', 'private', now(), now(), 'rules', 'gitlab'),
  (3, 103, 'stale', 'a/stale', 'private', now(), now(), 'rules', 'gitlab'),
  (4, 104, 'never', 'a/never', 'private', now(), now(), 'rules', 'gitlab'),
  (5, 105, 'failed', 'a/failed', 'private', now(), now(), 'rules', 'gitlab'),
  (6, 106, 'noscan', 'a/noscan', 'private', now(), now(), 'rules', 'gitlab'),
  (7, 107, 'nomain', 'a/nomain', 'private', now(), now(), 'rules', 'gitlab'),
  (8, 108, 'inv', 'inv/x', 'private', now(), now(), 'inventory', 'gitlab'),
  (9, NULL, 'db01', 'a/external', 'private', now(), now(), 'rules', 'external');
INSERT INTO gitlab_branches (id, branch_name, is_main, commit, scanned_commit, project_id, project_path, created_at,
                             updated_at) VALUES
  (1, 'main', true, 'c1', 'c1', 1, 'a/current', now(), now()),
  (2, 'main', true, 'c2', 'c2', 2, 'a/outdated', now(), now()),
  (3, 'main', true, 'c3-new', 'c3-new', 3, 'a/stale', now(), now()),
  (4, 'main', true, 'c4', 'c4', 4, 'a/never', now(), now()),
  (5, 'main', true, 'c5', 'c5', 5, 'a/failed', now(), now()),
  (6, 'main', true, 'c6', NULL, 6, 'a/noscan', now(), now()),
  (8, 'main', true, 'c8', 'c8', 8, 'inv/x', now(), now()),
  (9, 'main', true, 'ingest:1', 'ingest:1', 9, 'a/external', now(), now()),
  (11, 'feature', false, 'f1', 'f1', 1, 'a/current', now(), now()),
  (12, 'other', false, 'g1', NULL, 1, 'a/current', now(), now());
INSERT INTO gitlab_mrs (id, project_id, project_path, source_branch_id, source_branch, source_branch_commit,
                        target_branch_id, target_branch, target_branch_commit, mr_id, title, state, created_at,
                        updated_at) VALUES
  (1, 1, 'a/current', 11, 'feature', 'f1', 1, 'main', 'c1', 1, 'covered', 'opened', now(), now()),
  (2, 1, 'a/current', 12, 'other', 'g1', 1, 'main', 'c1', 2, 'not scanned', 'opened', now(), now());
INSERT INTO llm_coverage (branch_id, rule_id, rule_version, prompt_version, commit, candidates_total, answered,
                          pending_external, failed) VALUES
  (1, 100, 2, :pv, 'c1', 10, 10, 0, 0), (1, 101, 1, :pv, 'c1', 5, 5, 0, 0), (1, 102, 1, :pv, 'c1', 9, 0, 0, 0),
  (2, 100, 2, :pv, 'c2', 8, 5, 2, 1), (2, 101, 1, :pv, 'c2', 2, 2, 0, 0),
  (3, 100, 2, :pv, 'c3-old', 4, 4, 0, 0), (3, 101, 1, :pv, 'c3-old', 1, 1, 0, 0),
  (4, 100, 2, :pv, 'c4', 2, 2, 0, 0),
  (5, 100, 2, :pv, 'c5', 6, 1, 0, 5), (5, 101, 1, :pv, 'c5', 4, 0, 0, 4),
  (8, 100, 2, :pv, 'c8', 3, 0, 0, 0),
  (9, 100, 2, 'core-old', 'ingest:1', 3, 3, 0, 0), (9, 101, 1, :pv, 'ingest:1', 1, 1, 0, 0),
  (11, 100, 2, :pv, 'f1', 2, 2, 0, 0), (11, 101, 1, :pv, 'f1', 1, 1, 0, 0);
INSERT INTO jobs (kind, payload, dedup_key, status, attempts, last_error, finished_at, progress) VALUES
  ('llm_score', '{"branch_id": 1, "commit": "c1"}', 'llm_score:1:c1', 'done', 1, NULL, now(), '{"phase": "done"}'),
  ('llm_score', '{"branch_id": 2, "rule_ids": [100]}', 'llm_rule:2', 'running', 1, NULL, NULL, '{"phase": "running"}'),
  ('llm_prepare', '{"branch_id": 3, "rule_ids": [100], "executor": "external"}', 'llm_rule:ext:3', 'pending', 0, NULL,
   NULL, NULL),
  ('llm_score', '{"branch_id": 5, "commit": "c5"}', 'llm_score:5:c5', 'failed', 5, 'LLM unavailable', now(),
   '{"phase": "incomplete"}'),
  ('llm_prepare', '{"branch_id": 9, "rule_ids": [101], "executor": "external"}', 'llm_rule:ext:9', 'done', 1, NULL,
   now(), '{"phase": "awaiting_answers"}'),
  ('llm_coverage', '{}', 'llm_coverage', 'pending', 0, NULL, NULL, NULL);
"""


@pytest.fixture
def states(sql):
    from discovery_common.models import CORE_PROMPT_FAMILIES
    sql(STATES_SQL, pv=CORE_PROMPT_FAMILIES["rule"])        # the rules' pinned core prompts family (rule prompts)


def by_path(body):
    return {item["project_path"]: item for item in body["projects"]["items"]}


def test_llm_progress_totals_rules_and_states(api, states):
    r = api.get("/llm_progress")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["main"] == {
        "projects": 8, "current": 1, "outdated": 3, "never": 1, "not_scanned": 2, "failed": 1, "queued": 1,
        "running": 1, "awaiting_answers": 1, "answered": 34, "total": 46, "pending_external": 2, "failed_subjects": 10,
        "answered_stale": 0}
    assert body["mrs"] == {"open": 2, "current": 1, "outdated": 0, "never": 0, "not_scanned": 1, "failed": 0,
                           "queued": 0, "running": 0, "awaiting_answers": 0}
    rules = {r["name"]: r for r in body["rules"]}
    assert set(rules) == {"pii", "person"}                       # enabled LLM rules only
    pii = rules["pii"]
    assert (pii["answered"], pii["total"], pii["remaining"], pii["pending_external"], pii["failed"]) == (25, 33, 8, 2, 6)
    assert (pii["projects"], pii["projects_counted"], pii["projects_fresh"], pii["projects_current"]) == (6, 6, 4, 2)
    person = rules["person"]
    assert (person["answered"], person["total"], person["projects_counted"], person["projects_current"]) == (9, 13, 5, 3)
    assert body["queue"]["llm_coverage"] == {"pending": 1, "running": 0}
    assert body["last_computed_at"]

    items = by_path(body)
    assert "inv/x" not in items and body["projects"]["total"] == 8
    assert {p: (i["state"], i["job"]) for p, i in items.items()} == {
        "a/current": ("current", None), "a/outdated": ("outdated", "running"), "a/stale": ("outdated", "queued"),
        "a/never": ("never", None), "a/failed": ("failed", None), "a/noscan": ("not_scanned", None),
        "a/nomain": ("not_scanned", None), "a/external": ("outdated", "awaiting_answers")}
    assert [i["project_path"] for i in body["projects"]["items"]] == [
        "a/failed", "a/never", "a/external", "a/outdated", "a/stale", "a/nomain", "a/noscan", "a/current"]
    failed = items["a/failed"]
    assert (failed["last_job_status"], failed["last_error"], failed["answered"], failed["total"],
            failed["remaining"], failed["failed_subjects"]) == ("failed", "LLM unavailable", 1, 10, 9, 9)
    never = {r["name"]: r for r in items["a/never"]["rules"]}
    assert never["pii"] == {**never["pii"], "answered": 2, "total": 2, "fresh": True}
    assert never["person"]["answered"] is None and never["person"]["fresh"] is False
    stale = {r["name"]: r["fresh"] for r in items["a/stale"]["rules"]}
    assert stale == {"pii": False, "person": False}
    current = items["a/current"]
    assert current["mrs"] == {"open": 2, "current": 1, "queued": 0, "running": 0, "failed": 0}
    assert current["last_job_status"] == "done" and current["remaining"] == 0


def test_llm_progress_filters_and_paging(api, states):
    def paths(**params):
        body = api.get("/llm_progress", params=params).json()["projects"]
        return body["total"], [i["project_path"] for i in body["items"]]

    assert paths(status="active") == (3, ["a/external", "a/outdated", "a/stale"])
    assert paths(status="awaiting_answers") == (1, ["a/external"])
    assert paths(status="incomplete") == (5, ["a/failed", "a/never", "a/external", "a/outdated", "a/stale"])
    assert paths(status="current,not_scanned") == (3, ["a/nomain", "a/noscan", "a/current"])
    assert paths(q="fail") == (1, ["a/failed"])
    assert paths(project_id="1,8") == (1, ["a/current"])
    assert paths(limit=2, offset=1) == (8, ["a/never", "a/external"])
    assert paths(limit=2, offset=50) == (8, [])
    body = api.get("/llm_progress", params={"projects": "false"}).json()
    assert "projects" not in body and body["main"]["projects"] == 8
    assert api.get("/llm_progress", params={"status": "bogus"}).status_code == 422
    assert api.get("/llm_progress", headers={"Authorization": ""}).status_code == 401


def test_llm_progress_without_rules_or_data(api, sql):
    sql("UPDATE rules SET enabled = false WHERE kind = 'llm'")
    body = api.get("/llm_progress").json()
    assert body["rules"] == [] and body["main"]["projects"] == 0 and body["mrs"]["open"] == 0
    assert body["projects"] == {"total": 0, "items": []} and body["last_computed_at"] is None


def test_projects_list_carries_llm_state(api, states):
    r = api.get("/projects", params={"sort": '["full_path", "ASC"]', "range": "[0, 9]"})
    assert r.status_code == 200, r.text
    rows = {p["full_path"]: p for p in r.json()}
    assert rows["a/current"]["llm"]["state"] == "current"
    assert rows["a/outdated"]["llm"]["job"] == "running"
    assert rows["a/failed"]["llm"]["remaining"] == 9
    assert rows["inv/x"]["llm"] is None


def test_mcp_llm_progress(live_api, states):
    from test_api_mcp import payload, run

    async def flow(client):
        names = {t.name for t in (await client.list_tools()).tools}
        full = payload(await client.call_tool("llm_progress", {"status": ["failed"], "limit": 5}))
        bad = await client.call_tool("llm_progress", {"status": ["nope"]})
        return names, full, bad

    names, full, bad = run(live_api, flow)
    assert "llm_progress" in names
    assert full["main"]["current"] == 1 and full["mrs"]["current"] == 1
    assert [i["project_path"] for i in full["projects"]["items"]] == ["a/failed"]
    assert bad.is_error
