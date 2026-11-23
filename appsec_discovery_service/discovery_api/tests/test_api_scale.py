"""API at scale (contracts 1, 4-8): presence from the stored flags, estimated totals and keyset paging, the objects
list without DISTINCT ON, snapshots with ETag / 304, hits aggregate / clusters / decide + undo, autocompletes and
groups, the project page, MCP tokens, the MCP byte cap and cursor paging."""

import json

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("mcp")
pydantic = pytest.importorskip("pydantic")
if not pydantic.VERSION.startswith("2"):
    pytest.skip("the API runs on pydantic v2", allow_module_level=True)

from conftest import ADMIN  # noqa: E402


def lst(client, path, **params):
    query = {k: (json.dumps(v) if k in ("range", "sort", "filter") else v) for k, v in params.items()}
    response = client.get(path, params=query)
    assert response.status_code == 200, response.text
    return response.json(), response.headers


def ids(items):
    return {i["id"] for i in items}


# ---- presence and paging (contracts 1, 5) ----------------------------------------------------------------------

def test_presence_comes_from_the_stored_flags(api, seed, sql):
    live, headers = lst(api, "/hits")
    assert ids(live) == {seed["email_llm"], seed["card_llm"], seed["email_core"], seed["user_obj"]}
    assert headers["Content-Range"] == "hits 0-3/4" and headers["X-Total-Estimate"] == "false"
    # the flags, not a per-row EXISTS: flipping a flag changes the list at once
    sql("UPDATE rule_hits SET in_main = false WHERE subject_key = :k", k=seed["user_email"])
    assert seed["email_llm"] not in ids(lst(api, "/hits", filter={"presence": "main"})[0])
    assert seed["email_llm"] in ids(lst(api, "/hits", filter={"presence": "all"})[0])
    row = next(i for i in lst(api, "/hits", filter={"presence": "all"})[0] if i["id"] == seed["email_llm"])
    assert (row["in_main"], row["in_open_mr"]) == (False, False)


def test_keyset_paging_and_estimates(api, seed, sql):
    first, headers = lst(api, "/hits", range=[0, 1], sort=["first_seen_at", "ASC"])
    assert len(first) == 2 and headers["Content-Range"] == "hits 0-1/4"
    cursor = headers["X-Next-Cursor"]
    second, headers2 = lst(api, "/hits", range=[0, 1], sort=["first_seen_at", "ASC"], after=cursor)
    assert [i["id"] for i in second] == [i["id"] for i in lst(api, "/hits", range=[2, 3], sort=["first_seen_at", "ASC"])[0]]
    assert "X-Next-Cursor" not in headers2                        # the last page
    assert ids(first) | ids(second) == ids(lst(api, "/hits")[0])
    # a cursor is bound to its sort order
    assert api.get("/hits", params={"after": cursor, "sort": json.dumps(["severity", "DESC"])}).status_code == 422
    assert api.get("/hits", params={"after": "nope"}).status_code == 422
    # the cursor may travel inside the react-admin filter
    via_filter, _ = lst(api, "/hits", range=[0, 1], sort=["first_seen_at", "ASC"], filter={"after": cursor})
    assert [i["id"] for i in via_filter] == [i["id"] for i in second]
    # mixed sort directions and a nullable sort key: every row exactly once across the pages
    sql("UPDATE rule_hits SET reviewed_at = now() WHERE subject_key = :k", k=seed["card_number"])
    seen, after, pages = [], None, 0
    while True:
        page, h = lst(api, "/hits", range=[0, 0], sort=["reviewed_at", "DESC"], filter={"presence": "all"},
                      **({"after": after} if after else {}))
        seen += [i["id"] for i in page]
        pages += 1
        after = h.get("X-Next-Cursor")
        if not after or pages > 10:
            break
    assert sorted(seen) == sorted(ids(lst(api, "/hits", filter={"presence": "all"})[0])) and pages == 5

    # the total is exact under the cap; above it an estimate (the cap is lowered for the test)
    from services import paging
    original = paging.COUNT_CAP
    paging.COUNT_CAP = 2
    try:
        _, h = lst(api, "/hits", range=[0, 0])
        assert h["X-Total-Estimate"] == "true" and int(h["Content-Range"].split("/")[1]) >= 2
        _, h = lst(api, "/hits", range=[0, 0], exact="true")
        assert h["X-Total-Estimate"] == "false" and h["Content-Range"] == "hits 0-0/4"
        _, h = lst(api, "/hits", range=[0, 0], filter={"exact": True})
        assert h["Content-Range"] == "hits 0-0/4"
    finally:
        paging.COUNT_CAP = original


def test_keyset_condition_orders_nulls_last():
    from services.paging import keyset_condition
    binds = {}
    sql = keyset_condition([("h.reviewed_at", True), ("h.rule_id", False)], [("2026-01-01T00:00:00", "ts"), (3, "int")], binds)
    assert "h.reviewed_at < CAST(:ks0 AS timestamptz) OR h.reviewed_at IS NULL" in sql
    assert "h.reviewed_at = CAST(:ks0 AS timestamptz) AND (h.rule_id > CAST(:ks1 AS bigint)" in sql
    binds = {}
    sql = keyset_condition([("h.reviewed_at", True), ("h.rule_id", False)], [(None, "null"), (3, "int")], binds)
    assert sql.startswith("((h.reviewed_at IS NULL AND (") and "h.rule_id > CAST(:kst1_0 AS bigint)" in sql


# ---- objects (P0-5) and groups (contract 7) -------------------------------------------------------------------

def test_objects_list_per_presence_and_group(api, seed, sql):
    main, h = lst(api, "/objects")
    assert [o["name"] for o in main] == ["User"] and h["Content-Range"] == "objects 0-0/1"
    mr, _ = lst(api, "/objects", filter={"presence": "mr"})
    assert [(o["name"], o["source"]) for o in mr] == [("Card", "mr")]
    live, _ = lst(api, "/objects", filter={"presence": "live"}, sort=["name", "ASC"])
    assert [(o["name"], o["source"]) for o in live] == [("Card", "mr"), ("User", "main")]
    # per-row figures of the page only; labels / fields / tags still there
    user = main[0]
    assert (user["fields"], user["labels"], user["tags"]) == (2, 0, None)
    # keyset over the live list
    page1, h1 = lst(api, "/objects", range=[0, 0], filter={"presence": "live"})
    page2, h2 = lst(api, "/objects", range=[0, 0], filter={"presence": "live"}, after=h1["X-Next-Cursor"])
    assert [o["name"] for o in page1 + page2] == ["Card", "User"] and "X-Next-Cursor" not in h2
    # sorting by a computed column still works (page-only subqueries do not apply there)
    by_fields, _ = lst(api, "/objects", filter={"presence": "live"}, sort=["fields", "DESC"])
    assert [o["name"] for o in by_fields] == ["User", "Card"]
    # group = full_path prefix
    assert [o["name"] for o in lst(api, "/objects", filter={"group": "grp"})[0]] == ["User"]
    assert lst(api, "/objects", filter={"group": "gr"})[0] == []
    assert lst(api, "/objects", filter={"group": "grp/proj"})[0] != []
    # react-admin getMany
    assert [o["id"] for o in lst(api, "/objects", filter={"id": [str(seed["user_key"])]})[0]] == [str(seed["user_key"])]
    # a manual label refreshes the presence flags of the new hit
    api.post(f"/objects/{seed['card_key']}/labels", json={"category": "pii", "severity": "high"})
    (flags,) = sql("SELECT in_main, in_open_mr FROM rule_hits h JOIN rules r ON r.id = h.rule_id "
                   "WHERE r.kind = 'manual' AND h.object_key = :k", k=seed["card_key"])
    assert tuple(flags) == (False, True)


def test_groups_autocompletes_and_project_filters(api, seed, sql):
    sql("INSERT INTO gitlab_projects (id, gitlab_id, project_name, full_path, visibility, created_at, updated_at) VALUES "
        "(3, 103, 'ledger', 'grp/payments/ledger', 'private', now(), now()), "
        "(4, 104, 'core', 'grp/payments/core', 'private', now(), now()), "
        "(5, 105, 'solo', 'other/solo', 'private', now(), now())")
    groups = api.get("/groups").json()["items"]
    by_path = {g["path"]: g for g in groups}
    assert by_path["grp"]["projects"] == 4 and by_path["grp"]["depth"] == 1 and by_path["grp"]["parent"] is None
    assert by_path["grp/payments"] == {"path": "grp/payments", "depth": 2, "projects": 2, "parent": "grp"}
    assert "grp/proj" not in by_path and "other/solo" not in by_path          # a project is not a group
    assert [g["path"] for g in api.get("/groups", params={"q": "pay"}).json()["items"]] == ["grp/payments"]
    assert [g["path"] for g in api.get("/groups", params={"parent": "grp"}).json()["items"]] == ["grp/payments"]

    projects, h = lst(api, "/projects", filter={"group": "grp/payments"}, sort=["full_path", "ASC"])
    assert [p["full_path"] for p in projects] == ["grp/payments/core", "grp/payments/ledger"]
    assert projects[0]["group_path"] == "grp/payments" and h["Content-Range"] == "projects 0-1/2"
    page1, h1 = lst(api, "/projects", range=[0, 1], sort=["full_path", "ASC"])
    page2, _ = lst(api, "/projects", range=[0, 1], sort=["full_path", "ASC"], after=h1["X-Next-Cursor"])
    assert [p["full_path"] for p in page1 + page2] == ["grp/other", "grp/payments/core", "grp/payments/ledger", "grp/proj"]
    # pending_hits is computed per row: no keyset cursor is handed out (the UI would send it back and get a 422)
    busy, hb = lst(api, "/projects", range=[0, 1], sort=["pending_hits", "DESC"])
    assert len(busy) == 2 and "X-Next-Cursor" not in hb and hb["Content-Range"].startswith("projects 0-1/")
    assert len(lst(api, "/projects", range=[2, 3], sort=["pending_hits", "DESC"])[0]) == 2
    # the children of a deep parent (below the depth cap of the global listing)
    sql("INSERT INTO gitlab_projects (id, gitlab_id, project_name, full_path, visibility, created_at, updated_at) VALUES "
        "(6, 106, 'deep', 'grp/a/b/c/d/deep', 'private', now(), now())")
    assert [g["path"] for g in api.get("/groups", params={"parent": "grp/a/b/c"}).json()["items"]] == ["grp/a/b/c/d"]
    assert "grp/a/b/c/d" not in {g["path"] for g in api.get("/groups", params={"depth": 9}).json()["items"]}
    assert [p["project_path"] for p in lst(api, "/hits", filter={"group": "grp/proj"})[0][:1]] == ["grp/proj"]
    assert lst(api, "/hits", filter={"group": "grp/payments"})[0] == []

    rules = api.get("/rules", params={"q": "user"}).json()
    assert [r["name"] for r in rules] == ["user-objects"] and rules[0]["kind"] == "keyword"
    assert {r["kind"] for r in api.get("/rules", params={"kind": "llm"}).json()} == {"llm"}
    assert api.get("/rules", params={"kind": "nope"}).status_code == 422
    categories = {c["category"]: c for c in api.get("/categories").json()["items"]}
    assert categories["finance"]["hits"] == 1 and categories["pii"]["hits"] == 3 and categories["pii"]["matches"] == 1
    assert categories["identity"]["rules"] == 1
    types = api.get("/object_types").json()
    assert types["items"] == [{"type": "dto", "n": 1}] and types["snapshot"] is False


def test_project_detail_and_project_jobs(api, seed, sql):
    sql("INSERT INTO jobs (kind, payload, dedup_key, status) VALUES "
        "('scan_branch', '{\"branch_id\": 1}', 'sb:1', 'done'), ('scan_mr', '{\"mr_id\": 1}', 'sm:1', 'pending'), "
        "('sync_branches_mrs', '{\"project_id\": 1}', 'sync:1', 'done'), ('scan_branch', '{\"branch_id\": 99}', 'sb:99', 'done')")
    detail = api.get("/projects/1").json()
    assert detail["pending_hits"] == 3 and detail["open_mrs"] == 1 and detail["objects_in_open_mrs"] == 1
    assert detail["objects_by_type"] == [{"type": "dto", "n": 1}]
    by_rule = {r["rule_name"]: r for r in detail["hits_by_rule"]}
    assert (by_rule["llm"]["open"], by_rule["llm"]["match"], by_rule["kw-fields"]["match"]) == (2, 0, 1)
    assert by_rule["user-objects"]["open"] == 1 and "scan" in detail and "llm" in detail
    assert sorted(j["kind"] for j in detail["jobs"]) == ["scan_branch", "scan_mr", "sync_branches_mrs"]
    jobs, h = lst(api, "/jobs", filter={"project_id": 1})
    assert len(jobs) == 3 and h["Content-Range"] == "jobs 0-2/3"
    assert api.get("/projects/42").status_code == 404


# ---- snapshots (contract 4) ------------------------------------------------------------------------------------

def _write_snapshot(sql, name, data, age="0 seconds"):
    sql("INSERT INTO stats_snapshots (name, data, computed_at) VALUES (:n, CAST(:d AS jsonb), now() - CAST(:a AS interval)) "
        "ON CONFLICT (name) DO UPDATE SET data = EXCLUDED.data, computed_at = EXCLUDED.computed_at",
        n=name, d=json.dumps(data), a=age)


def test_overview_and_health_from_snapshots_with_etag(api, seed, sql):
    live = api.get("/overview")
    assert live.json()["snapshot"] is False and live.json()["computed_at"] and "ETag" not in live.headers
    assert live.json()["objects_by_type"] == [{"type": "dto", "n": 1}]
    (row,) = live.json()["matches_by_project"]
    assert (row["project_path"], row["matches"], row["open"]) == ("grp/proj", 1, 4)     # every hit, gone ones too

    _write_snapshot(sql, "overview", {"hits_by_status": [{"status": "match", "n": 42}], "marker": "snap"})
    served = api.get("/overview")
    assert served.json()["snapshot"] is True and served.json()["marker"] == "snap" and served.json()["computed_at"]
    etag = served.headers["ETag"]
    assert etag.startswith('W/"overview:') and served.headers["Cache-Control"].startswith("private, max-age=")
    assert api.get("/overview", headers={"If-None-Match": etag}).status_code == 304
    assert api.get("/overview", headers={"If-None-Match": 'W/"other"'}).status_code == 200
    # filters and live=true bypass the snapshot; a stale snapshot is not served
    assert api.get("/overview", params={"category": "pii"}).json()["snapshot"] is False
    assert api.get("/overview", params={"live": "true"}).json()["snapshot"] is False
    _write_snapshot(sql, "overview", {"marker": "old"}, age="10 minutes")
    assert api.get("/overview").json()["snapshot"] is False

    _write_snapshot(sql, "job_health", {"kinds": {}, "totals": {"pending": 7}})
    health = api.get("/jobs/health")
    assert health.json()["totals"]["pending"] == 7 and health.json()["snapshot"] is True
    assert api.get("/jobs/health", headers={"If-None-Match": health.headers["ETag"]}).status_code == 304
    assert api.get("/jobs/health", params={"live": "true"}).json()["snapshot"] is False

    _write_snapshot(sql, "scan_progress", {"main": {"projects": 123}})
    assert api.get("/scan_progress", params={"projects": "false"}).json()["main"]["projects"] == 123
    with_list = api.get("/scan_progress").json()
    assert with_list["main"]["projects"] == 123 and with_list["projects"]["total"] == 2    # the list is live
    _write_snapshot(sql, "llm_quality", {"totals": {"samples": 5}, "rules": []})
    assert api.get("/llm_quality").json()["totals"]["samples"] == 5
    assert api.get("/llm_quality", params={"rule_id": seed["rules"]["llm"]}).json()["snapshot"] is False


def test_job_health_typical_times_use_started_at(api, sql):
    sql("INSERT INTO jobs (kind, payload, dedup_key, status, created_at, run_after, started_at, finished_at) VALUES "
        "('scan_branch', '{}', 'a', 'done', now() - interval '10 minutes', now() - interval '10 minutes', "
        " now() - interval '9 minutes', now() - interval '6 minutes'), "
        "('scan_branch', '{}', 'b', 'done', now() - interval '20 minutes', now() - interval '20 minutes', "
        " now() - interval '18 minutes', now() - interval '13 minutes'), "
        "('scan_branch', '{}', 'c', 'pending', now() - interval '1 minute', now() - interval '1 minute', NULL, NULL)")
    kind = api.get("/jobs/health", params={"live": "true"}).json()["kinds"]["scan_branch"]
    assert kind["typical_run_s"] == 240 and kind["typical_wait_s"] == 90 and kind["eta_s"] == 1800


# ---- aggregate, clusters, decide (contract 6) -----------------------------------------------------------------

def test_hits_aggregate_live_and_from_snapshot(api, seed, sql):
    agg = api.get("/hits/aggregate").json()
    assert agg["by"] == ["queue"] and agg["snapshot"] is False
    assert {r["queue"]: r["n"] for r in agg["rows"]} == {"pending": 3, "service": 1} and agg["total"] == 4
    by_rule = api.get("/hits/aggregate", params={"by": "rule_id,status", "filter": json.dumps({"presence": "all"})}).json()
    llm = [r for r in by_rule["rows"] if r["rule_id"] == seed["rules"]["llm"]]
    assert llm[0]["rule_name"] == "llm" and sum(r["n"] for r in llm) == 3
    by_project = api.get("/hits/aggregate", params={"by": "project_id"}).json()
    assert by_project["rows"] == [{"project_id": 1, "project_path": "grp/proj", "n": 4}]
    assert api.get("/hits/aggregate", params={"by": "nope"}).status_code == 422
    assert api.get("/hits/aggregate", params={"by": "presence", "filter": json.dumps({"group": "grp/proj"})}).json()["rows"] == [
        {"presence": "main", "n": 3}, {"presence": "mr", "n": 1}]

    # the snapshot cube answers filters / dimensions it holds; others compute live
    from services.aggregate_service import hits_cube
    from discovery_common import db
    with db.unit_of_work() as session:
        cube = hits_cube(session)
    assert sum(r["n"] for r in cube["rows"]) == 5 and set(cube["by"]) >= {"status", "field_mark", "in_main"}
    _write_snapshot(sql, "hits_aggregate", {"by": cube["by"], "rows": [{**r, "n": r["n"] * 10} for r in cube["rows"]]})
    snap = api.get("/hits/aggregate", params={"by": "status", "filter": json.dumps({"presence": "all"})}).json()
    assert snap["snapshot"] is True and snap["total"] == 50
    assert {r["status"]: r["n"] for r in snap["rows"]} == {"pending_review": 40, "match": 10}
    assert api.get("/hits/aggregate", params={"by": "queue", "filter": json.dumps({"kind": "llm"})}).json()["total"] == 20
    assert api.get("/hits/aggregate", params={"by": "project_id"}).json()["snapshot"] is False
    assert api.get("/hits/aggregate", params={"by": "status", "filter": json.dumps({"q": "x"})}).json()["snapshot"] is False
    assert api.get("/hits/aggregate", params={"live": "true"}).json()["snapshot"] is False


def test_clusters_and_decide_dry_run_apply_undo(api, seed, sql):
    # two more open llm field hits on User.email-like fields of another object: a field_pattern cluster of 2
    sql("INSERT INTO objects (content_hash, object_key, project_id, parser, type, name, file) VALUES "
        "(:h, :k, 1, 'go', 'dto', 'Profile', '/profile.go')", h="11111111-1111-1111-1111-111111111111",
        k="22222222-2222-2222-2222-222222222222")
    sql("INSERT INTO object_fields (content_hash, field_name, field_type, field_key, project_id) VALUES "
        "(:h, 'email', 'string', :f, 1)", h="11111111-1111-1111-1111-111111111111", f="33333333-3333-3333-3333-333333333333")
    sql("INSERT INTO branch_objects (branch_id, object_key, content_hash, is_main) VALUES (1, :k, :h, true)",
        h="11111111-1111-1111-1111-111111111111", k="22222222-2222-2222-2222-222222222222")
    sql("INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version, model, prompt_version, "
        "category, severity, status, reason, first_seen_at, last_seen_at, in_main) VALUES "
        "(:r, :f, 1, :k, 'email', 1, 'm', 'rule3', 'pii', 'medium', 'pending_review', 'mail', now(), now(), true)",
        r=seed["rules"]["llm"], f="33333333-3333-3333-3333-333333333333", k="22222222-2222-2222-2222-222222222222")
    profile_hit = f"{seed['rules']['llm']}:33333333-3333-3333-3333-333333333333"

    clusters = api.get("/hits/clusters", params={"by": "field_pattern"}).json()
    assert clusters["by"] == "field_pattern" and clusters["truncated"] is False and clusters["scanned"] == 4
    top = clusters["items"][0]
    assert (top["label"], top["n"], top["n_open"], top["projects"], top["in_main_share"]) == ("field email", 2, 2, 1, 1.0)
    assert top["cluster"] == f"field_pattern:{seed['rules']['llm']}|email" and len(top["sample_ids"]) == 2
    # the cluster filter addresses exactly these hits
    assert ids(lst(api, "/hits", filter={"cluster": top["cluster"]})[0]) == {seed["email_llm"], profile_hit}
    assert api.get("/hits", params={"filter": json.dumps({"cluster": "nope:x"})}).status_code == 422
    by_name = api.get("/hits/clusters", params={"by": "object_name", "limit": 1}).json()
    assert len(by_name["items"]) == 1 and by_name["next_cursor"]
    rest = api.get("/hits/clusters", params={"by": "object_name", "limit": 1, "after": by_name["next_cursor"]}).json()
    assert rest["items"] and rest["items"][0]["key"] != by_name["items"][0]["key"]
    schema = api.get("/hits/clusters", params={"by": "schema"}).json()["items"]
    assert {i["label"] for i in schema} >= {"dto {email, id}", "dto {email}", "dto {card_number}"}
    groups = api.get("/hits/clusters", params={"by": "rule_group"}).json()["items"]
    assert groups[0]["group"] == "grp/proj" and groups[0]["groups"] == ["grp/proj"]

    # a human decision inside the cluster is kept, a question of the model is skipped
    api.post(f"/hits/{seed['email_llm']}/review", json={"action": "request_info", "note": "which mail?"})
    sql("UPDATE rule_hits SET asked_by_model = true, decided_tier = 'harness', status = 'need_more_info' "
        "WHERE subject_key = :k", k=seed["card_number"])
    body = {"filter": {"rule_id": seed["rules"]["llm"], "status": ["pending_review", "need_more_info"]},
            "action": "confirm", "note": "same mail field", "category": "pii", "severity": "high"}
    dry = api.post("/hits/decide", json=body).json()
    assert dry["dry_run"] and dry["matched"] == 1 and dry["batch_id"] is None
    assert dry["kept"] == {"human": 1, "harness": 0, "questions": 1, "transition": 0}
    assert dry["by_status"] == {"pending_review": 1} and dry["sample"] == [profile_hit]
    assert dry["by_project"] == [{"project_id": 1, "project_path": "grp/proj", "n": 1}]
    # the apply needs the dry run's figure
    assert api.post("/hits/decide", json={**body, "dry_run": False}).status_code == 422
    assert api.post("/hits/decide", json={**body, "dry_run": False, "expected_total": 5}).status_code == 409
    assert api.post("/hits/decide", json={**body, "note": "", "dry_run": False, "expected_total": 1}).status_code == 422
    assert api.post("/hits/decide", json={**body, "filter": {"presence": "all"}}).status_code == 422
    applied = api.post("/hits/decide", json={**body, "dry_run": False, "expected_total": 1}).json()
    assert (applied["applied"], applied["cascaded"], applied["matched"]) == (1, 0, 1) and applied["batch_id"]
    hit = api.get(f"/hits/{profile_hit}").json()
    assert (hit["status"], hit["reviewer"], hit["category"], hit["severity"], hit["decided_tier"]) == (
        "match", ADMIN, "pii", "high", "human")
    assert api.get(f"/hits/{seed['email_llm']}").json()["status"] == "need_more_info"      # the human's stays
    history = api.get(f"/hits/{profile_hit}/history").json()["items"]
    assert history[0]["batch_id"] == applied["batch_id"] and history[0]["status"] == "match"
    batches = api.get("/review_batches").json()["items"]
    assert batches[0]["id"] == applied["batch_id"] and batches[0]["applied"] == 1 and batches[0]["undone_at"] is None
    assert api.get(f"/review_batches/{applied['batch_id']}").json()["filter"]["rule_id"] == seed["rules"]["llm"]

    # undo: a hit decided again after the batch keeps that decision
    api.post(f"/hits/{profile_hit}/review", json={"action": "reopen"})
    api.post(f"/hits/{profile_hit}/review", json={"action": "reject", "note": "not personal"})
    undone = api.post(f"/hits/decide/{applied['batch_id']}/undo").json()
    assert (undone["restored"], undone["skipped"]) == (0, 1)
    assert api.get(f"/hits/{profile_hit}").json()["status"] == "no_match"
    assert api.post(f"/hits/decide/{applied['batch_id']}/undo").status_code == 409
    assert api.post("/hits/decide/999/undo").status_code == 404

    # a batch that is undone in full
    api.post(f"/hits/{profile_hit}/review", json={"action": "reopen"})
    sql("UPDATE rule_hits SET reviewer = NULL, decided_tier = 'service' WHERE subject_key = :k",
        k="33333333-3333-3333-3333-333333333333")
    second = api.post("/hits/decide", json={**body, "action": "reject", "dry_run": False, "expected_total": 1}).json()
    assert second["applied"] == 1 and api.get(f"/hits/{profile_hit}").json()["status"] == "no_match"
    undone = api.post(f"/hits/decide/{second['batch_id']}/undo").json()
    assert (undone["restored"], undone["skipped"]) == (1, 0)
    restored = api.get(f"/hits/{profile_hit}").json()
    assert (restored["status"], restored["reviewer"], restored["decided_tier"]) == ("pending_review", None, "service")
    assert api.get(f"/hits/{profile_hit}/history").json()["items"][0]["source"] == "undo"


def test_decide_cascades_to_field_marks(api, seed, sql):
    # an LLM object rule with mark_fields: the object hit and a service-tier field mark on the same object
    created = api.post("/llm_rules", json={"name": "obj-marks", "category": "pii", "severity": "high", "target": "object",
                                           "prompt": "x" * 20, "mark_fields": True, "mode": "review"}).json()
    rid = created["id"]
    sql("INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version, model, prompt_version, "
        "category, severity, status, first_seen_at, last_seen_at, in_main, decided_tier) VALUES "
        "(:r, :o, 1, :o, NULL, 1, 'm', 'rule3', 'pii', 'high', 'pending_review', now(), now(), true, 'service'), "
        "(:r, :f, 1, :o, 'email', 1, 'm', 'rule3', 'pii', 'high', 'pending_review', now(), now(), true, 'service')",
        r=rid, o=seed["user_key"], f=seed["user_email"])
    body = {"filter": {"rule_id": rid, "field_marks": False}, "action": "confirm", "note": "ok", "dry_run": False,
            "expected_total": 1}
    result = api.post("/hits/decide", json=body).json()
    assert (result["applied"], result["cascaded"]) == (1, 1)
    assert sql("SELECT count(*) FROM rule_hits WHERE rule_id = :r AND status = 'match' AND decided_tier = 'human'", r=rid) == [(2,)]
    undone = api.post(f"/hits/decide/{result['batch_id']}/undo").json()
    assert undone["restored"] == 2
    assert sql("SELECT count(*) FROM rule_hits WHERE rule_id = :r AND status = 'pending_review' AND decided_tier = 'service'",
               r=rid) == [(2,)]


# ---- MCP tokens, cap, paging (contract 8) ---------------------------------------------------------------------

def test_service_tokens_with_mcp_scope_are_reviewers(api, seed, sql):
    assert api.post("/tokens", json={"name": "harness-a", "scopes": ["ingest"]}).status_code == 422   # needs prefixes
    assert api.post("/tokens", json={"name": "a:b", "scopes": ["mcp"]}).status_code == 422
    created = api.post("/tokens", json={"name": "harness-a", "scopes": ["mcp"]}).json()
    token = created["token"]
    client = {"Authorization": f"Bearer {token}"}
    assert api.get("/hits", headers=client).status_code == 200
    reviewed = api.post(f"/hits/{seed['card_llm']}/review", json={"action": "confirm"}, headers=client).json()
    assert reviewed["reviewer"] == "token:harness-a" and reviewed["decided_tier"] == "human"
    assert api.get("/tokens", headers=client).status_code == 403                  # admin only
    assert api.post("/tokens", json={"name": "x", "scopes": ["mcp"]}, headers=client).status_code == 403
    ingest_only = api.post("/tokens", json={"name": "collector", "project_prefixes": ["external/x"]}).json()["token"]
    assert api.get("/hits", headers={"Authorization": f"Bearer {ingest_only}"}).status_code == 403
    assert api.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    headers={**client, "Accept": "application/json, text/event-stream"}).status_code != 401
    assert api.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    headers={"Authorization": f"Bearer {ingest_only}", "Accept": "application/json, text/event-stream"}
                    ).status_code == 401
    api.delete(f"/tokens/{created['id']}")
    assert api.get("/hits", headers=client).status_code == 403


def test_mcp_rate_limiter_and_response_cap():
    from mcp_server import RateLimiter, _cap
    limiter = RateLimiter()
    assert limiter.allow("a", 2, now=60.0) == (True, 60) and limiter.allow("a", 2, now=61.0)[0] is True
    allowed, retry = limiter.allow("a", 2, now=62.0)
    assert allowed is False and 1 <= retry <= 58
    assert limiter.allow("b", 2, now=62.0)[0] is True                      # per client
    assert limiter.allow("a", 2, now=120.0)[0] is True                     # next minute
    assert limiter.allow("a", 0, now=120.0) == (True, 0)                   # 0 disables

    data = {"total": 100, "items": [{"id": i, "reason": "r" * 100} for i in range(100)], "note": "n"}
    assert _cap(data, limit=0) is data
    capped = _cap(data, limit=3000)
    assert capped["truncated"] is True and capped["hint"] and capped["items_returned"] < 100
    assert capped["items"][0]["id"] == 0 and len(json.dumps(capped)) <= 3000 and capped["total"] == 100
    tiny = _cap({"items": [{"id": 1}], "text": "x" * 5000}, limit=1000)
    assert tiny["truncated"] is True and tiny["text"].endswith("...[cut]")
    assert _cap({"text": "x" * 5000}, limit=50) == {"truncated": True, "hint": _cap.__globals__["CAP_HINT"]}
    nested = _cap({"projects": {"total": 3, "items": [{"id": i, "x": "y" * 500} for i in range(3)]}}, limit=900)
    assert nested["truncated"] is True and len(nested["projects"]["items"]) < 3


def test_mcp_cursor_paging_summaries_and_decide(live_api, seed, sql):
    from test_api_mcp import payload, run

    async def flow(client):
        tools = {t.name for t in (await client.list_tools()).tools}
        assert {"hits_aggregate", "hits_clusters", "decide_hits", "undo_decision", "review_batches", "list_groups",
                "get_project"} <= tools
        page = payload(await client.call_tool("search_hits", {"limit": 2, "status": ["pending_review"], "presence": "all",
                                                              "sort": "first_seen_at"}))
        assert page["total"] == 4 and page["total_is_estimate"] is False and page["next_cursor"] and len(page["items"]) == 2
        assert page["items"][0]["ui_url"].endswith("/show") and page["ui_url"].startswith("/hits?filter=")
        rest = payload(await client.call_tool("search_hits", {"limit": 2, "status": ["pending_review"], "presence": "all",
                                                              "sort": "first_seen_at", "after": page["next_cursor"]}))
        assert rest["next_cursor"] is None and {i["id"] for i in page["items"]} | {i["id"] for i in rest["items"]} == {
            seed["email_llm"], seed["card_llm"], seed["ssn_llm"], seed["user_obj"]}
        only_ids = payload(await client.call_tool("search_hits", {"view": "ids", "presence": "all"}))
        assert set(only_ids["items"][0]) == {"id", "ui_url"}
        summary = payload(await client.call_tool("get_hit", {"hit_id": seed["email_llm"], "view": "summary"}))
        assert "other_hits" not in summary and summary["object"]["fields_total"] == 2
        assert [f["name"] for f in summary["object"]["fields"]] == ["email"] and summary["ui_url"].endswith("/show")
        obj = payload(await client.call_tool("get_object", {"object_id": str(seed["user_key"]), "view": "summary"}))
        assert obj["fields_total"] == 2 and set(obj["fields"][0]) == {"name", "type", "hits"}
        progress = payload(await client.call_tool("scan_progress", {}))
        assert "projects" not in progress and progress["main"]["projects"] == 2         # include_projects=false
        with_projects = payload(await client.call_tool("scan_progress", {"include_projects": True, "limit": 1}))
        assert with_projects["projects"]["items"][0]["ui_url"].startswith("/projects/")
        objects = payload(await client.call_tool("list_objects", {"limit": 1, "presence": "live"}))
        assert objects["next_cursor"] and objects["items"][0]["ui_url"].startswith("/objects/")
        projects = payload(await client.call_tool("list_projects", {"summary": True}))
        assert set(projects["items"][0]) == {"id", "full_path", "group_path", "scan_mode", "pending_hits", "ui_url"}
        groups = payload(await client.call_tool("list_groups", {}))
        assert [g["path"] for g in groups["items"]] == ["grp"]
        project = payload(await client.call_tool("get_project", {"project_id": 1}))
        assert project["hits_by_rule"] and project["ui_url"] == "/projects/1/show"

        agg = payload(await client.call_tool("hits_aggregate", {"by": ["queue"]}))
        assert {r["queue"]: r["n"] for r in agg["rows"]} == {"pending": 3, "service": 1}
        clusters = payload(await client.call_tool("hits_clusters", {"by": "object_name"}))
        assert clusters["items"][0]["ui_url"].startswith("/hits?filter=") and clusters["items"][0]["cluster"]
        result = await client.call_tool("decide_hits", {"filter": {"rule_id": seed["rules"]["llm"]}, "action": "confirm",
                                                        "note": "all mail", "dry_run": False})
        assert result.is_error and "expected_total" in result.content[0].text
        dry = payload(await client.call_tool("decide_hits", {"filter": {"rule_id": seed["rules"]["llm"]}, "action": "confirm",
                                                             "note": "all mail"}))
        assert dry["matched"] == 2 and dry["dry_run"] is True and dry["sample"][0]["ui_url"]
        applied = payload(await client.call_tool("decide_hits", {"filter": {"rule_id": seed["rules"]["llm"]}, "action": "confirm",
                                                                 "note": "all mail", "dry_run": False, "expected_total": 2}))
        assert applied["applied"] == 2 and applied["batch_id"]
        batches = payload(await client.call_tool("review_batches", {}))
        assert batches["items"][0]["via"] == "mcp" and batches["items"][0]["reviewer"] == ADMIN
        undone = payload(await client.call_tool("undo_decision", {"batch_id": applied["batch_id"]}))
        assert undone["restored"] == 2
        bad = await client.call_tool("hits_aggregate", {"by": "queue", "filter": {"nope": 1}})
        assert bad.is_error

    run(live_api, flow)
    assert sql("SELECT count(*) FROM rule_hits WHERE decided_via = 'mcp' AND status = 'match'") == [(0,)]   # undone


def test_mcp_token_identity_and_rate_limit(live_api, api, seed):
    from test_api_mcp import payload, run
    token = api.post("/tokens", json={"name": "agent-7", "scopes": ["mcp"]}).json()["token"]

    async def flow(client):
        done = payload(await client.call_tool("confirm", {"hit_id": seed["email_llm"], "note": "ok"}))
        assert done["reviewer"] == "token:agent-7" and done["decided_via"] == "mcp"

    run(live_api, flow, bearer=token)

    import config
    import mcp_server
    settings = config.get_settings()
    config.set_settings(config.ApiSettings(**{**settings.__dict__, "mcp_rate_limit_per_minute": 1}))
    mcp_server.rate_limiter._counts.clear()
    try:
        import httpx2
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream"}
        first = httpx2.post(f"{live_api}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers=headers)
        second = httpx2.post(f"{live_api}/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=headers)
        assert first.status_code != 429 and second.status_code == 429 and second.headers["Retry-After"]
        # another client (the admin) is not affected
        admin = {"Authorization": f"Bearer {api.token}", "Accept": "application/json, text/event-stream"}
        assert httpx2.post(f"{live_api}/mcp", json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
                           headers=admin).status_code != 429
    finally:
        config.set_settings(settings)
        mcp_server.rate_limiter._counts.clear()


def test_trial_sample_uses_tablesample(api, seed, sql):
    from discovery_common import db
    from services import trials_service
    with db.unit_of_work() as session:
        rule = session.execute(__import__("sqlalchemy").text(
            "SELECT * FROM rules WHERE name = 'llm' AND deleted_at IS NULL")).mappings().one()
        rows = trials_service.sample_rows(session, trials_service.SAMPLE_FIELDS_SQL, {"ex": [], "limit": 50})
        assert {(str(r["object_key"]), r["field_name"]) for r in rows} == {(str(seed["user_key"]), "email"),
                                                                           (str(seed["user_key"]), "id")}
        sample = trials_service._sample(session, dict(rule), [], 1)
        assert len(sample) == 1 and sample[0]["role"] == "control"
