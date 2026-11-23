"""Progress of the parse scans (GET /scan_progress, MCP scan_progress, the Projects list's
``scan`` field) against a real Postgres, with one synthetic project per state."""

import pytest

pytest.importorskip("fastapi")
pydantic = pytest.importorskip("pydantic")
if not pydantic.VERSION.startswith("2"):
    pytest.skip("the API runs on pydantic v2", allow_module_level=True)

STATES_SQL = """
INSERT INTO gitlab_projects (id, gitlab_id, project_name, full_path, visibility, created_at, updated_at, processed_at,
                             scan_mode, source) VALUES
  (1, 101, 'current', 'a/current', 'private', now(), now() - interval '1 hour', now(), 'rules', 'gitlab'),
  (2, 102, 'outdated', 'a/outdated', 'private', now(), now(), NULL, 'rules', 'gitlab'),
  (3, 103, 'never', 'a/never', 'private', now(), now(), now() - interval '1 day', 'rules', 'gitlab'),
  (4, 104, 'partial', 'a/partial', 'private', now(), now(), now(), 'rules', 'gitlab'),
  (5, 105, 'failed', 'a/failed', 'private', now(), now(), now(), 'rules', 'gitlab'),
  (6, 106, 'skipped', 'a/skipped', 'private', now(), now(), now(), 'rules', 'gitlab'),
  (7, 107, 'nomain', 'a/nomain', 'private', now(), now(), NULL, 'rules', 'gitlab'),
  (8, 108, 'inv', 'inv/current', 'private', now(), now(), now(), 'inventory', 'gitlab'),
  (9, NULL, 'db01', 'external/x/db01', 'private', now(), now(), NULL, 'rules', 'external');
INSERT INTO gitlab_branches (id, branch_name, is_main, commit, scanned_commit, project_id, project_path, created_at,
                             updated_at) VALUES
  (1, 'main', true, 'c1', 'c1', 1, 'a/current', now(), now()),
  (2, 'main', true, 'c2', 'c2-old', 2, 'a/outdated', now(), now()),
  (3, 'main', true, 'c3', NULL, 3, 'a/never', now(), now()),
  (4, 'main', true, 'c4', NULL, 4, 'a/partial', now(), now()),
  (5, 'main', true, 'c5', 'c5-old', 5, 'a/failed', now(), now()),
  (6, 'main', true, 'c6', NULL, 6, 'a/skipped', now(), now()),
  (8, 'main', true, 'c8', 'c8', 8, 'inv/current', now(), now()),
  (9, 'main', true, 'ingest:1', 'ingest:1', 9, 'external/x/db01', now(), now()),
  (11, 'feature', false, 'f1', 'f1', 1, 'a/current', now(), now()),
  (12, 'other', false, 'g2', NULL, 1, 'a/current', now(), now()),
  (14, 'fix', false, 'h1', 'h0', 5, 'a/failed', now(), now());
INSERT INTO discovery_scans (project_id, branch_id, project_path, branch_name, branch_commit, scanner, rules_version,
                             parsers, scanned_at) VALUES
  (1, 1, 'a/current', 'main', 'c1', 'discovery', '2.0.0+kw.abc', '{all}', now() - interval '1 hour'),
  (4, 4, 'a/partial', 'main', 'c4', 'discovery', '2.0.0+kw.abc+partial', '{all}', now());
INSERT INTO gitlab_mrs (id, project_id, project_path, source_branch_id, source_branch, source_branch_commit,
                        target_branch_id, target_branch, target_branch_commit, mr_id, title, state, created_at,
                        updated_at) VALUES
  (1, 1, 'a/current', 11, 'feature', 'f1', 1, 'main', 'c1', 1, 'current', 'opened', now(), now()),
  (2, 1, 'a/current', 12, 'other', 'g2', 1, 'main', 'c1', 2, 'never', 'opened', now(), now()),
  (3, 2, 'a/outdated', NULL, 'gone', 'x1', 2, 'main', 'c2', 3, 'untracked', 'opened', now(), now()),
  (4, 5, 'a/failed', 14, 'fix', 'h1', 5, 'main', 'c5', 4, 'failed', 'opened', now(), now()),
  (5, 1, 'a/current', 11, 'feature', 'f1', 1, 'main', 'c1', 5, 'backport', 'opened', now(), now()),
  (6, 1, 'a/current', 11, 'feature', 'f0', 1, 'main', 'c1', 6, 'closed', 'closed', now(), now());
INSERT INTO jobs (kind, payload, dedup_key, status, attempts, last_error, finished_at) VALUES
  ('scan_branch', '{"branch_id": 1, "commit": "c1"}', 'scan_branch:1:c1', 'done', 1, NULL, now()),
  ('scan_branch', '{"branch_id": 2, "commit": "c2"}', 'scan_branch:2:c2', 'running', 1, NULL, NULL),
  ('scan_branch', '{"branch_id": 3, "commit": "c3"}', 'scan_branch:3:c3', 'pending', 1, 'clone failed', NULL),
  ('scan_branch', '{"branch_id": 5, "commit": "c5"}', 'scan_branch:5:c5', 'failed', 5, 'parser go failed', now()),
  ('scan_branch', '{"branch_id": 6, "commit": "c6"}', 'scan_branch:6:c6', 'done', 1, NULL, now()),
  ('scan_branch', '{"branch_id": 2, "commit": "c2", "parsers": ["go"]}', 'scan_branch:2:c2:p=go', 'done', 1, NULL,
   now()),
  ('sync_branches_mrs', '{"project_id": 2}', 'sync_branches_mrs:2', 'pending', 0, NULL, NULL),
  ('scan_mr', '{"mr_id": 2, "source_commit": "g2"}', 'scan_mr:2:g2:c1', 'pending', 0, NULL, NULL),
  ('scan_mr', '{"mr_id": 4, "source_commit": "h1"}', 'scan_mr:4:h1:c5', 'failed', 5, 'boom', now()),
  ('ingest', '{"branch_id": 9, "parser": "pg"}', 'ingest:9:pg:1', 'pending', 0, NULL, NULL),
  ('sync_projects', '{}', 'sync_projects', 'done', 1, NULL, now());
"""


@pytest.fixture
def states(sql):
    sql(STATES_SQL)


def by_path(body):
    return {item["project_path"]: item for item in body["projects"]["items"]}


def test_scan_progress_totals_and_states(api, states):
    r = api.get("/scan_progress")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["main"] == {
        "projects": 8, "synced": 5, "sync_queued": 1, "sync_running": 0, "scanned_current": 2, "outdated": 1,
        "never_scanned": 1, "partial": 1, "failed": 1, "skipped": 1, "no_main": 1, "queued": 1, "running": 1,
        "retrying": 1}
    assert body["by_scan_mode"]["inventory"]["projects"] == 1
    assert body["by_scan_mode"]["inventory"]["scanned_current"] == 1
    assert body["by_scan_mode"]["rules"]["projects"] == 7
    # every MR was updated now: the three tracked ones are active (the scanner's "activity in the last day")
    assert body["mrs"].pop("oldest_waiting_s") >= 0
    assert body["mrs"] == {"open": 5, "scanned_current": 1, "outdated": 0, "never_scanned": 1, "partial": 0,
                           "failed": 1, "not_tracked": 2, "queued": 1, "running": 0,
                           "active_24h": 3, "active_scanned": 1, "active_waiting": 1}
    assert body["external"] == {"projects": 1, "with_state": 1, "pending": 1, "running": 0}
    assert body["queue"]["scan_branch"] == {"pending": 1, "running": 1}
    assert body["queue"]["sync_branches_mrs"] == {"pending": 1, "running": 0}
    assert body["last_projects_sync"]["status"] == "done"

    items = by_path(body)
    assert "external/x/db01" not in items and body["projects"]["total"] == 8
    assert {p: i["state"] for p, i in items.items()} == {
        "a/current": "current", "a/outdated": "outdated", "a/never": "never_scanned", "a/partial": "partial",
        "a/failed": "failed", "a/skipped": "skipped", "a/nomain": "no_main", "inv/current": "current"}
    # problems first
    assert [i["project_path"] for i in body["projects"]["items"]][:3] == ["a/failed", "a/partial", "a/skipped"]
    assert (items["a/outdated"]["job"], items["a/outdated"]["synced"], items["a/outdated"]["sync_job"]) == (
        "running", False, "queued")
    never = items["a/never"]
    assert (never["job"], never["retrying"], never["last_error"], never["synced"]) == (
        "queued", True, "clone failed", False)
    failed = items["a/failed"]
    assert (failed["last_job_status"], failed["last_error"], failed["commit"], failed["scanned_commit"]) == (
        "failed", "parser go failed", "c5", "c5-old")
    assert failed["mrs"] == {"open": 1, "scanned_current": 0, "queued": 0, "running": 0, "failed": 1}
    assert items["a/partial"]["last_scan_partial"] is True and items["a/partial"]["last_scan_commit"] == "c4"
    current = items["a/current"]
    assert (current["synced"], current["job"], current["last_scan_commit"], current["last_scan_partial"]) == (
        True, None, "c1", False)
    assert current["mrs"] == {"open": 3, "scanned_current": 1, "queued": 1, "running": 0, "failed": 0}


def test_scan_progress_counts_the_active_mrs_the_scanner_scans(api, states, sql):
    """The scanner queues MR scans only for MRs with activity in the last day: the MR figures of the pipeline health
    count those apart (how many are scanned, how many wait, for how long)."""
    sql("UPDATE gitlab_mrs SET updated_at = now() - interval '3 days'")
    sql("UPDATE gitlab_mrs SET updated_at = now() - interval '2 hours' WHERE id IN (1, 2, 3)")     # 3: not tracked
    sql("""UPDATE jobs SET created_at = now() - interval '30 minutes', run_after = now() - interval '30 minutes'
           WHERE dedup_key = 'scan_mr:2:g2:c1'""")
    mrs = api.get("/scan_progress", params={"projects": "false"}).json()["mrs"]
    assert (mrs["open"], mrs["active_24h"], mrs["active_scanned"], mrs["active_waiting"]) == (5, 2, 1, 1)
    assert 1750 < mrs["oldest_waiting_s"] < 1900
    sql("UPDATE gitlab_mrs SET updated_at = now() - interval '3 days' WHERE id = 2")
    mrs = api.get("/scan_progress", params={"projects": "false"}).json()["mrs"]
    assert (mrs["active_24h"], mrs["active_waiting"], mrs["oldest_waiting_s"], mrs["queued"]) == (1, 0, None, 1)


def test_scan_progress_filters_and_paging(api, states):
    def paths(**params):
        body = api.get("/scan_progress", params=params).json()["projects"]
        return body["total"], [i["project_path"] for i in body["items"]]

    assert paths(status="active") == (2, ["a/never", "a/outdated"])
    assert paths(status="attention") == (2, ["a/failed", "a/partial"])
    assert paths(status="current,no_main") == (3, ["a/nomain", "a/current", "inv/current"])
    assert paths(status="not_synced") == (3, ["a/never", "a/outdated", "a/nomain"])
    assert paths(scan_mode="inventory") == (1, ["inv/current"])
    assert paths(q="fail") == (1, ["a/failed"])
    assert paths(project_id="1,8") == (2, ["a/current", "inv/current"])
    assert paths(limit=2, offset=1) == (8, ["a/partial", "a/skipped"])
    assert paths(limit=2, offset=50) == (8, [])
    body = api.get("/scan_progress", params={"projects": "false"}).json()
    assert "projects" not in body and body["main"]["projects"] == 8
    assert api.get("/scan_progress", params={"status": "bogus"}).status_code == 422
    assert api.get("/scan_progress", params={"scan_mode": "x"}).status_code == 422
    assert api.get("/scan_progress", headers={"Authorization": ""}).status_code == 401


def test_projects_list_carries_scan_state(api, states):
    r = api.get("/projects", params={"sort": '["full_path", "ASC"]', "range": "[0, 9]"})
    assert r.status_code == 200, r.text
    rows = {p["full_path"]: p for p in r.json()}
    assert rows["a/failed"]["scan"]["state"] == "failed"
    assert rows["a/outdated"]["scan"]["job"] == "running"
    assert rows["a/current"]["scan"]["mrs"]["open"] == 3
    assert rows["external/x/db01"]["scan"] is None


def test_scan_progress_empty_database(api):
    body = api.get("/scan_progress").json()
    assert body["main"]["projects"] == 0 and body["mrs"]["open"] == 0
    assert body["projects"] == {"total": 0, "items": []} and body["last_projects_sync"] is None


def test_mcp_scan_progress(live_api, states):
    from test_api_mcp import payload, run

    async def flow(client):
        names = {t.name for t in (await client.list_tools()).tools}
        # the project list is opt-in over MCP (thousands of projects): include_projects=true
        full = payload(await client.call_tool("scan_progress", {"status": ["failed"], "limit": 5, "include_projects": True}))
        bad = await client.call_tool("scan_progress", {"status": ["nope"]})
        return names, full, bad

    names, full, bad = run(live_api, flow)
    assert "scan_progress" in names
    assert full["main"]["scanned_current"] == 2 and full["mrs"]["failed"] == 1
    assert [i["project_path"] for i in full["projects"]["items"]] == ["a/failed"]
    assert bad.is_error
