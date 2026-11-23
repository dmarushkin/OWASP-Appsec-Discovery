"""Progress of LLM rule runs and the external executor's work queue (REST + MCP), against a
real Postgres. Work items are synthetic rows here (the scanner's prepare / apply are tested in
discovery_scanner/tests/test_scanner_llm_work_pg.py)."""

import json

import pytest

pytest.importorskip("fastapi")
pydantic = pytest.importorskip("pydantic")
if not pydantic.VERSION.startswith("2"):
    pytest.skip("the API runs on pydantic v2", allow_module_level=True)

from conftest import ADMIN  # noqa: E402

LONG_PROMPT = "Rule: llm\n<object>\n" + "- field_x\n" * 400 + "</object>\nAnswer only with JSON"
SCHEMA = {"type": "object", "properties": {"verdict": {"type": "string"}}, "required": ["verdict"]}


def external_run(api, sql, seed):
    sql("UPDATE gitlab_branches SET scanned_commit = commit")
    llm = seed["rules"]["llm"]
    r = api.post(f"/llm_rules/{llm}/run", json={"project_ids": [1], "executor": "external"})
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["executor"] == "external" and body["queued"][0]["dedup_key"] == f"llm_rule:external:{llm}:v1:1:c1"
    job_id = body["queued"][0]["id"]
    # the prepare calls no model: a kind of its own, run by the scanner's control worker
    assert body["queued"][0]["kind"] == "llm_prepare"
    (payload, kind), = sql("SELECT payload, kind FROM jobs WHERE id = :j", j=job_id)
    assert kind == "llm_prepare"
    assert payload == {"branch_id": 1, "commit": "c1", "rule_ids": [llm], "requested_by": ADMIN, "executor": "external"}
    # what the scanner's prepare does: one item per model call, the job done, awaiting answers
    for key in ("user_key", "card_key", "gone_key"):
        sql("""INSERT INTO llm_work_items (job_id, rule_id, rule_version, project_id, branch_id, object_key, content_hash,
                                           prompt_hash, system_prompt, user_prompt, json_schema)
               VALUES (:j, :r, 1, 1, 1, :k, :h, 'hash', 'You are a bot', :u, CAST(:s AS jsonb))""",
            j=job_id, r=llm, k=seed[key], h=seed[key.replace("key", "hash")], u=LONG_PROMPT, s=json.dumps(SCHEMA))
    sql("""UPDATE jobs SET status = 'done', finished_at = now(),
                  progress = '{"executor": "external", "phase": "awaiting_answers", "total_objects": 3}' WHERE id = :j""",
        j=job_id)
    return job_id, llm


def test_external_run_claim_submit_and_progress(api, seed, sql):
    job_id, llm = external_run(api, sql, seed)
    # a service run of the same rules is another job (another dedup key)
    service = api.post(f"/llm_rules/{llm}/run", json={"project_ids": [1]}).json()
    assert service["queued"][0]["dedup_key"] == f"llm_rule:{llm}:v1:1:c1"
    assert api.post(f"/llm_rules/{llm}/run", json={"executor": "robot"}).status_code == 422

    runs = api.get("/llm_runs").json()
    by_id = {r["id"]: r for r in runs["active"]}
    assert by_id[job_id]["status"] == "awaiting_answers" and by_id[job_id]["executor"] == "external"
    assert by_id[job_id]["rules"] == [{"id": llm, "name": "llm"}] and by_id[job_id]["project_path"] == "grp/proj"
    assert by_id[service["queued"][0]["id"]]["executor"] == "service"
    assert (by_id[job_id]["kind"], by_id[service["queued"][0]["id"]]["kind"]) == ("llm_prepare", "llm_score")
    assert [j["id"] for j in api.get("/llm_work/jobs").json()] == [job_id]

    assert api.post("/llm_work/claim", json={"limit": 21}).status_code == 422
    first = api.post("/llm_work/claim", json={"job_id": job_id, "limit": 2}).json()
    assert len(first["items"]) == 2 and first["items"][0]["user_prompt"] == LONG_PROMPT
    assert first["items"][0]["json_schema"] == SCHEMA and "json_schema" in first["instruction"]
    assert first["items"][0]["rule"]["name"] == "llm" and first["items"][0]["object"]["name"] == "User"
    second = api.post("/llm_work/claim", json={"limit": 5}).json()
    assert len(second["items"]) == 1 and second["lease"] != first["lease"]
    assert {i["id"] for i in second["items"]}.isdisjoint({i["id"] for i in first["items"]})
    assert api.post("/llm_work/claim", json={}).json()["items"] == []          # nothing left
    p = api.get(f"/jobs/{job_id}").json()["progress"]
    assert (p["leased_objects"], p["pending_objects"], p["phase"]) == (3, 0, "awaiting_answers")

    a, b = first["items"]
    result = api.post("/llm_work/submit", json={"lease": first["lease"], "items": [
        {"id": a["id"], "answer": {"verdict": "match"}, "model": "claude-test"},
        {"id": b["id"], "answer": "not json", "model": "claude-test"},
        {"id": second["items"][0]["id"], "answer": "{}", "model": "x"},              # another lease
        {"id": 999999, "answer": "{}"},
    ]}).json()
    assert result["accepted"] == [a["id"]]
    assert {r["id"]: r["error"] for r in result["rejected"]} == {
        b["id"]: "answer is not valid JSON",
        second["items"][0]["id"]: "lease does not match: the lease expired and the item was claimed again",
        999999: "not found"}
    assert len(result["apply_jobs"]) == 1
    assert sql("SELECT status, answer, answer_model, answered_by FROM llm_work_items WHERE id = :i", i=a["id"]) == [
        ("answered", '{"verdict": "match"}', "claude-test via rest", ADMIN)]
    assert sql("SELECT kind, payload, dedup_key FROM jobs WHERE id = :j", j=result["apply_jobs"][0]) == [
        ("llm_apply", {"job_id": job_id}, f"llm_apply:{job_id}")]
    # answered twice: rejected; too long: rejected
    again = api.post("/llm_work/submit", json={"lease": first["lease"], "items": [
        {"id": a["id"], "answer": "{}"}, {"id": b["id"], "answer": "{\"x\": \"" + "y" * 70000 + "\"}"}]}).json()
    assert [r["error"] for r in again["rejected"]] == ["not leased (status answered)",
                                                       "answer is longer than 65536 characters"]

    # an expired lease: claimable again (new lease); the old lease cannot submit any more
    sql("UPDATE llm_work_items SET lease_until = now() - interval '1 second' WHERE id = :i", i=b["id"])
    reclaimed = api.post("/llm_work/claim", json={"job_id": job_id}).json()
    assert [i["id"] for i in reclaimed["items"]] == [b["id"]]
    late = api.post("/llm_work/submit", json={"items": [{"id": b["id"], "lease": first["lease"], "answer": "{}"}]})
    assert late.json()["accepted"] == []
    assert api.post("/llm_work/release", json={"ids": [b["id"]], "lease": reclaimed["lease"]}).json() == {
        "released": [b["id"]]}
    p = api.get(f"/jobs/{job_id}").json()["progress"]
    assert (p["answered_objects"], p["leased_objects"], p["pending_objects"]) == (1, 1, 1)

    # the scanner applied everything: the run is done
    sql("UPDATE llm_work_items SET status = 'applied' WHERE job_id = :j", j=job_id)
    from discovery_common import llm_work
    from discovery_common import db
    with db.unit_of_work() as s:
        llm_work.refresh_progress([job_id], s)
    assert api.get("/llm_work/jobs").json() == []
    runs = api.get("/llm_runs").json()
    done = [r for r in runs["recent"] if r["id"] == job_id][0]
    assert (done["status"], done["done_objects"], done["total_objects"]) == ("done", 3, 3) and done["finished_at"]


def test_llm_work_needs_the_admin_token(api, seed):
    token = api.post("/tokens", json={"name": "collector", "project_prefixes": ["external/x"]}).json()["token"]
    for method, path, body in (("get", "/llm_runs", None), ("get", "/llm_work/jobs", None),
                               ("post", "/llm_work/claim", {}),
                               ("post", "/llm_work/submit", {"items": [{"id": 1, "answer": "{}", "lease": "x"}]})):
        call = getattr(api, method)
        kwargs = {"json": body} if body is not None else {}
        assert call(path, headers={"Authorization": ""}, **kwargs).status_code == 401
        assert call(path, headers={"Authorization": f"Bearer {token}"}, **kwargs).status_code == 403


def test_mcp_external_executor_flow(live_api, seed, sql, api_settings):
    from fastapi.testclient import TestClient

    import main
    from test_api_mcp import payload, run

    with TestClient(main.create_app()) as client:
        from conftest import PASSWORD
        token = client.post("/token", data={"username": ADMIN, "password": PASSWORD}).json()["access_token"]
        client.headers["Authorization"] = f"Bearer {token}"
        job_id, llm = external_run(client, sql, seed)

    async def flow(client):
        names = {t.name for t in (await client.list_tools()).tools}
        jobs_ = payload(await client.call_tool("llm_work_jobs", {}))
        claimed = payload(await client.call_tool("llm_work_claim", {"job_id": job_id, "limit": 3}))
        submitted = payload(await client.call_tool("llm_work_submit", {"lease": claimed["lease"], "items": [
            {"id": i["id"], "answer": {"verdict": "no_match"}, "model": "claude-opus-5-5"} for i in claimed["items"]]}))
        runs = payload(await client.call_tool("llm_runs", {}))
        bad = await client.call_tool("llm_work_claim", {"limit": 50})
        queued = payload(await client.call_tool("run_score_rules", {"rule_ids": [llm], "project_ids": [1],
                                                                    "executor": "external"}))
        return names, jobs_, claimed, submitted, runs, bad, queued

    names, jobs_, claimed, submitted, runs, bad, queued = run(live_api, flow)
    assert {"llm_runs", "llm_work_jobs", "llm_work_claim", "llm_work_submit", "llm_work_release"} <= names
    assert [j["id"] for j in jobs_["items"]] == [job_id]
    assert len(claimed["items"]) == 3 and claimed["items"][0]["user_prompt"] == LONG_PROMPT     # not cut
    assert "untrusted data" in claimed["instruction"]
    assert sorted(submitted["accepted"]) == sorted(i["id"] for i in claimed["items"])
    assert {r[0] for r in sql("SELECT answer_model FROM llm_work_items WHERE job_id = :j", j=job_id)} == {
        "claude-opus-5-5 via mcp"}
    assert [r["answered_objects"] for r in runs["active"] if r["id"] == job_id] == [3]
    assert bad.is_error
    assert queued["executor"] == "external"


def test_take_over_pending_service_runs_and_release_the_rest(api, seed, sql):
    sql("UPDATE gitlab_branches SET scanned_commit = commit")
    llm = seed["rules"]["llm"]
    job_id = api.post(f"/llm_rules/{llm}/run", json={"project_ids": [1]}).json()["queued"][0]["id"]
    assert sql("SELECT kind FROM jobs WHERE id = :j", j=job_id) == [("llm_score",)]

    assert api.post("/llm_work/take_over", json={"limit": 6}).status_code == 422
    taken = api.post("/llm_work/take_over", json={"job_id": job_id}).json()
    (run,) = taken["taken_over"]
    assert (run["id"], run["kind"], run["executor"], run["taken_over_by"], run["phase"]) == (
        job_id, "llm_prepare", "external", ADMIN, "preparing")
    assert taken["retry_after_s"] == 3 and "llm_work_claim" in taken["note"]
    (kind, payload), = sql("SELECT kind, payload FROM jobs WHERE id = :j", j=job_id)
    assert kind == "llm_prepare" and payload["executor"] == "external" and payload["taken_over_by"] == ADMIN
    again = api.post("/llm_work/take_over", json={"job_id": job_id})
    assert again.status_code == 409 and "llm_prepare" in again.json()["detail"]
    assert api.post("/llm_work/take_over", json={"job_id": 999999}).status_code == 404
    (running,), = sql("""INSERT INTO jobs (kind, payload, dedup_key, status, locked_by, locked_at)
                         VALUES ('llm_score', '{"branch_id": 1}', 'busy', 'running', 'w', now()) RETURNING id""")
    assert api.post("/llm_work/take_over", json={"job_id": running}).status_code == 409
    assert api.post("/llm_work/take_over", json={}).json()["taken_over"] == []            # nothing pending

    # claim with take_over_pending: nothing claimable -> the oldest pending service run is taken over
    (other,), = sql("""INSERT INTO jobs (kind, payload, dedup_key) VALUES ('llm_score', '{"branch_id": 1, "commit": "c1"}',
                                                                         'llm_score:1:c1') RETURNING id""")
    plain = api.post("/llm_work/claim", json={}).json()
    assert plain["items"] == [] and "taken_over" not in plain
    claimed = api.post("/llm_work/claim", json={"take_over_pending": True}).json()
    assert claimed["items"] == [] and claimed["taken_over"] == [other] and claimed["retry_after_s"] == 3
    (payload,), = sql("SELECT payload FROM jobs WHERE id = :j", j=other)
    assert payload["rule_ids"] and payload["taken_over_by"] == ADMIN                       # every enabled rule

    runs = {r["id"]: r for r in api.get("/llm_runs").json()["active"]}
    assert runs[job_id]["taken_over_by"] == ADMIN and runs[job_id]["executor"] == "external"

    # give the rest back: refused while preparing; then pending / leased items expire, a service run is queued
    assert api.post("/llm_work/release", json={"all_unanswered": True}).status_code == 422
    assert api.post("/llm_work/release", json={}).status_code == 422
    early = api.post("/llm_work/release", json={"job_id": job_id, "all_unanswered": True})
    assert early.status_code == 422 and "still being prepared" in early.json()["detail"]
    for key in ("user_key", "card_key"):
        sql("""INSERT INTO llm_work_items (job_id, rule_id, rule_version, project_id, branch_id, object_key, content_hash,
                                           prompt_hash, user_prompt)
               VALUES (:j, :r, 1, 1, 1, :k, :h, 'hash', 'q')""",
            j=job_id, r=llm, k=seed[key], h=seed[key.replace("key", "hash")])
    sql("UPDATE jobs SET status = 'done', finished_at = now(), "
        "progress = progress || '{\"phase\": \"awaiting_answers\"}' WHERE id = :j", j=job_id)
    api.post("/llm_work/claim", json={"job_id": job_id, "limit": 1})
    released = api.post("/llm_work/release", json={"job_id": job_id, "all_unanswered": True}).json()
    assert len(released["released"]) == 2 and released["service_job"]
    assert {r[0] for r in sql("SELECT status FROM llm_work_items WHERE job_id = :j", j=job_id)} == {"expired"}
    (kind, payload, key), = sql("SELECT kind, payload, dedup_key FROM jobs WHERE id = :j", j=released["service_job"])
    assert kind == "llm_score" and key == f"llm_rule:{llm}:v1:1:c1"
    assert payload == {"branch_id": 1, "commit": "c1", "rule_ids": [llm], "requested_by": ADMIN,
                       "released_from": job_id}
    runs = {r["id"]: r for r in api.get("/llm_runs").json()["active"]}
    assert runs[released["service_job"]]["released_from"] == job_id


def test_mcp_take_over(live_api, seed, sql):
    from test_api_mcp import payload, run

    sql("UPDATE gitlab_branches SET scanned_commit = commit")
    (job_id,), = sql("""INSERT INTO jobs (kind, payload, dedup_key) VALUES ('llm_score', '{"branch_id": 1, "commit": "c1"}',
                                                                          'llm_score:1:c1') RETURNING id""")

    async def flow(client):
        taken = payload(await client.call_tool("llm_take_over", {}))
        again = await client.call_tool("llm_take_over", {"job_id": job_id})
        claimed = payload(await client.call_tool("llm_work_claim", {"take_over_pending": True}))
        bad = await client.call_tool("llm_work_release", {"all_unanswered": True})
        return taken, again, claimed, bad

    taken, again, claimed, bad = run(live_api, flow)
    assert [r["id"] for r in taken["taken_over"]] == [job_id] and taken["taken_over"][0]["taken_over_by"] == ADMIN
    assert again.is_error and "cannot be taken over" in again.content[0].text
    assert claimed["items"] == [] and claimed["taken_over"] == [] and claimed["retry_after_s"] is None
    assert bad.is_error


def test_llm_work_stats_by_purpose_sample_and_owner(api, seed, sql):
    """GET /llm_work/stats (UI "Harness work", MCP llm_work_stats): items by purpose / status, open verify items by
    sample, leases held by owner, answers of the last 24 hours by owner."""
    job = sql("INSERT INTO jobs (kind, payload, dedup_key, status, progress) VALUES ('llm_prepare', "
              "'{\"branch_id\": 1, \"executor\": \"external\"}', 'llm_rule:external:stats', 'done', "
              "'{\"phase\": \"awaiting_answers\"}') RETURNING id")[0][0]
    llm = seed["rules"]["llm"]
    base = ("INSERT INTO llm_work_items (job_id, rule_id, rule_version, project_id, branch_id, object_key, content_hash, "
            "prompt_hash, user_prompt, call_index, purpose, subject_key, field_name, verify, status, lease_owner, "
            "lease_token, lease_until, answered_by, answered_at, answer_model, created_at) VALUES "
            "(:j, :r, 1, 1, 1, :o, :h, :ph, 'p', :i, :p, :s, :f, CAST(:v AS jsonb), :st, :owner, :tok, :until, :by, :at, :m, :c)")
    rows = [
        # score: 1 pending (old), 1 leased by alice (lease ran out), 1 answered by alice an hour ago
        dict(i=0, p="score", s=None, f=None, v=None, st="pending", owner=None, tok=None, until=None, by=None, at=None,
             m=None, c="now() - interval '3 hours'"),
        dict(i=1, p="score", s=None, f=None, v=None, st="leased", owner="alice", tok="t1", until="now() - interval '1 minute'",
             by=None, at=None, m=None, c="now()"),
        dict(i=2, p="score", s=None, f=None, v=None, st="answered", owner=None, tok=None, until=None, by="alice",
             at="now() - interval '30 minutes'", m="opus", c="now()"),
        # verify: escalation pending, qa leased by bob, qa applied by bob yesterday-ish (within 24h)
        dict(i=3, p="verify", s=seed["user_email"], f="email", v='{"sample": "escalation"}', st="pending", owner=None,
             tok=None, until=None, by=None, at=None, m=None, c="now() - interval '1 hour'"),
        dict(i=4, p="verify", s=seed["user_id"], f="id", v='{"sample": "qa"}', st="leased", owner="bob", tok="t2",
             until="now() + interval '10 minutes'", by=None, at=None, m=None, c="now()"),
        dict(i=5, p="verify", s=seed["card_number"], f="card_number", v='{"sample": "qa"}', st="applied", owner=None,
             tok=None, until=None, by="bob", at="now() - interval '5 hours'", m="opus", c="now()"),
    ]
    for n, r in enumerate(rows):
        stmt = base.replace(":until", r.pop("until") or "NULL").replace(":at", r.pop("at") or "NULL").replace(":c", r.pop("c"))
        sql(stmt, j=job, r=llm, o=seed["user_key"] if r["i"] != 5 else seed["card_key"],
            h=seed["user_hash"] if r["i"] != 5 else seed["card_hash"], ph=f"hash{n}", **r)
    stats = api.get("/llm_work/stats").json()
    score, verify = stats["by_purpose"]["score"], stats["by_purpose"]["verify"]
    assert (score["pending"], score["leased"], score["answered"], score["open"]) == (1, 1, 1, 3)
    assert 10700 < score["oldest_pending_s"] < 10900 and 3500 < verify["oldest_pending_s"] < 3700
    assert (verify["pending"], verify["leased"], verify["applied"], verify["open"]) == (1, 1, 1, 2)
    assert stats["verify_by_sample"] == {"escalation": {"pending": 1, "leased": 0, "answered": 0, "total": 1},
                                         "qa": {"pending": 0, "leased": 1, "answered": 0, "total": 1}}
    leases = {(l["owner"], l["purpose"]): l for l in stats["leases"]}
    assert leases[("alice", "score")]["leased"] == 1 and leases[("alice", "score")]["expired"] == 1
    assert leases[("bob", "verify")]["expired"] == 0 and leases[("bob", "verify")]["job_ids"] == [job]
    owners = {(o["owner"], o["purpose"]): o for o in stats["owners_24h"]}
    assert owners[("alice", "score")]["answered_1h"] == 1 and owners[("alice", "score")]["models"] == ["opus"]
    assert owners[("bob", "verify")]["answered_24h"] == 1 and owners[("bob", "verify")]["answered_1h"] == 0
    assert stats["awaiting_apply"] == 1
    assert api.get("/llm_work/stats", headers={"Authorization": ""}).status_code == 401
