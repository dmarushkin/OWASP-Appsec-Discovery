"""LLM rule lifecycle over REST and MCP against a real Postgres: rule versions (list, diff, candidate, estimate,
activate, rollback), rollouts (list, actions; MCP read-only), the stale flag / filter of hits, the verdict history of
a hit and category / severity edits going to the machine hits."""

import pytest

pytest.importorskip("fastapi")
pydantic = pytest.importorskip("pydantic")
if not pydantic.VERSION.startswith("2"):
    pytest.skip("the API runs on pydantic v2", allow_module_level=True)

from test_api_mcp import payload, run  # noqa: E402


def _llm_hits(sql, rule):
    sql("UPDATE rule_hits SET prompt_version = 'classifier3' WHERE rule_id = :r", r=rule)


def test_versions_estimate_activate_stale_history_and_rollback(api, seed, sql):
    rule = seed["rules"]["llm"]
    _llm_hits(sql, rule)
    hits = {h["id"]: h for h in api.get("/hits", params={"filter": '{"rule_id": %d, "presence": "all"}' % rule}).json()}
    assert not any(h["stale"] for h in hits.values())
    listed = api.get(f"/llm_rules/{rule}/versions").json()
    assert [(v["version"], v["status"]) for v in listed["items"]] == [(1, "active")]
    assert listed["rule"]["core_prompt_version"] == "classifier3"

    created = api.post(f"/llm_rules/{rule}/versions", json={"prompt": "Personal data?", "note": "try"})
    assert created.status_code == 201, created.text
    cand = created.json()
    assert (cand["version"], cand["status"], cand["source"]) == (2, "candidate", "manual")
    assert "+Personal data?" in cand["diff"]["prompt"] and cand["same_content"] is False
    assert api.post(f"/llm_rules/{rule}/versions", json={}).status_code == 422             # nothing changed
    assert api.get("/llm_rules/{}".format(rule)).json()["version"] == 1                    # the rule is unchanged

    estimate = api.get(f"/llm_rule_versions/{cand['id']}/estimate").json()
    # three machine verdicts (email, card_number, ssn) are asked again by the rollout, one object each
    assert estimate["migration"]["subjects"] == 3 and estimate["migration"]["model_calls"] == 3
    assert estimate["est_calls"] >= 3 and estimate["protected_human"] == 0

    activated = api.post(f"/llm_rule_versions/{cand['id']}/activate", json={"budget": {"calls_per_hour": 50}})
    assert activated.status_code == 200, activated.text
    out = activated.json()
    assert out["rollout"]["status"] == "running" and out["rollout"]["budget"] == {"calls_per_hour": 50}
    assert api.post(f"/llm_rule_versions/{cand['id']}/activate", json={}).status_code == 409   # active already

    # the old verdicts stay (scoring) and are flagged stale
    email = api.get(f"/hits/{seed['email_llm']}").json()
    assert email["stale"] is True and email["stale_reason"] == "rule v1 -> v2 pending"
    stale = api.get("/hits", params={"filter": '{"stale": true, "presence": "all"}'}).json()
    assert {h["id"] for h in stale} == {seed["email_llm"], seed["card_llm"], seed["ssn_llm"]}
    assert api.get("/hits", params={"filter": '{"stale": "maybe"}'}).status_code == 422

    # rollouts: list, pause / resume / cancel by a human
    rollouts = api.get("/llm_rollouts", params={"rule_id": rule}).json()
    assert rollouts["open"] == 1 and rollouts["items"][0]["to_version"] == 2
    rid = rollouts["items"][0]["id"]
    assert api.post(f"/llm_rollouts/{rid}/pause", json={"reason": "check first"}).json()["status"] == "paused"
    assert api.post(f"/llm_rollouts/{rid}/start", json={}).status_code == 409             # paused: resume
    assert api.post(f"/llm_rollouts/{rid}/resume", json={}).json()["status"] == "running"
    assert api.post(f"/llm_rollouts/{rid}/jump", json={}).status_code == 422
    detail = api.get(f"/llm_rollouts/{rid}").json()
    assert detail["slices"] == [] and detail["rule_name"] == "llm"

    # the verdict history: the scanner's new verdict (v2) after the old one
    sql("UPDATE rule_hits SET status = 'no_match', rule_version = 2 WHERE rule_id = :r AND subject_key = :s",
        r=rule, s=seed["user_email"])
    history = api.get(f"/hits/{seed['email_llm']}/history").json()
    assert [(i["status"], i["rule_version"]) for i in history["items"]] == [("no_match", 2), ("pending_review", 1)]
    assert set(history["items"][0]["changed"]) >= {"status", "rule_version"}
    assert [v["rule_version"] for v in history["versions"]] == [1, 2]
    assert history["versions"][1]["diff_to_previous_version"]["status"] == ["pending_review", "no_match"]
    assert api.get("/hits/1:00000000-0000-0000-0000-000000000000/history").status_code == 404

    # rollback to v1: a new version (3) with the content of v1; its verdicts are adopted from the history
    v1 = next(v for v in api.get(f"/llm_rules/{rule}/versions").json()["items"] if v["version"] == 1)
    rolled = api.post(f"/llm_rule_versions/{v1['id']}/rollback", json={"start_rollout": False})
    assert rolled.status_code == 200, rolled.text
    assert rolled.json()["version"]["version"] == 3 and rolled.json()["adopted"] >= 1
    assert api.get(f"/hits/{seed['email_llm']}").json()["status"] == "pending_review"
    statuses = {v["version"]: v["status"] for v in api.get(f"/llm_rules/{rule}/versions").json()["items"]}
    assert statuses == {1: "retired", 2: "rolled_back", 3: "active"}


def test_accept_with_activate_and_put_edits_make_versions(api, seed, sql):
    rule = api.post("/llm_rules", json={"name": "secrets", "category": "secret", "target": "object",
                                        "prompt": "Secrets?"}).json()
    versions = api.get(f"/llm_rules/{rule['id']}/versions").json()["items"]
    assert [(v["version"], v["status"], v["core_prompt_version"]) for v in versions] == [(1, "active", "rule3")]
    edited = api.put(f"/llm_rules/{rule['id']}", json={**rule, "prompt": "Keys or secrets?"}).json()
    assert edited["version"] == 2 and edited["prompt"] == "Keys or secrets?"
    (rollout,) = api.get("/llm_rollouts", params={"rule_id": rule["id"]}).json()["items"]
    assert (rollout["status"], rollout["mode"]) == ("planned", "canary")      # LLM_ROLLOUT_DEFAULT: a human starts it
    assert api.post(f"/llm_rollouts/{rollout['id']}/start", json={}).json()["status"] == "running"


def test_category_and_severity_edits_go_to_the_machine_hits(api, seed, sql):
    rule = api.post("/llm_rules", json={"name": "cards", "category": "card", "severity": "medium",
                                        "target": "field", "prompt": "Cards?"}).json()
    for subject, reviewer in ((seed["user_email"], None), (seed["card_number"], "alice")):
        sql("""INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version,
                                      prompt_version, category, severity, status, reviewer, decided_tier)
               VALUES (:r, :s, 1, :s, 'f', 1, 'rule3', 'card', 'medium', 'match', :u, :t)""",
            r=rule["id"], s=subject, u=reviewer, t="human" if reviewer else "service")
    updated = api.put(f"/llm_rules/{rule['id']}", json={**rule, "category": "payment-card", "severity": "high"}).json()
    assert updated["version"] == 1                                        # metadata: no new version
    assert sql("SELECT category, severity, reviewer FROM rule_hits WHERE rule_id = :r ORDER BY reviewer NULLS FIRST",
               r=rule["id"]) == [("payment-card", "high", None), ("card", "medium", "alice")]   # human kept


def _proposal(sql, rule_id, prompt):
    (trial,), = sql("""INSERT INTO prompt_trials (rule_id, rule_version, prompt_version, candidate_prompt, prompt_hash,
                                                  status, finished_at)
                       VALUES (:r, 1, 'pv', :p, :p, 'done', now()) RETURNING id""", r=rule_id, p=prompt)
    (proposal,), = sql("""INSERT INTO prompt_proposals (rule_id, base_version, prompt, prompt_hash, trial_id, rationale,
                                                        created_by)
                          VALUES (:r, 1, :p, :p, :t, 'clearer wording', 'agent') RETURNING id""",
                       r=rule_id, p=prompt, t=trial)
    return proposal


def test_proposals_of_every_rule_in_one_list(api, seed, sql):
    """GET /prompt_proposals: what waits for a human across rules (Work desk), each with its rule."""
    llm = seed["rules"]["llm"]
    secrets = api.post("/llm_rules", json={"name": "secrets", "category": "secret", "target": "object",
                                           "prompt": "Secrets?"}).json()["id"]
    first, second = _proposal(sql, llm, "Personal data?"), _proposal(sql, secrets, "Keys or secrets?")
    body = api.get("/prompt_proposals").json()
    assert body["status"] == "open"
    assert [(p["id"], p["rule_id"], p["rule_name"], p["status"]) for p in body["items"]] == [
        (second, secrets, "secrets", "open"), (first, llm, "llm", "open")]
    assert "+Keys or secrets?" in body["items"][0]["diff"] and body["items"][0]["trial"]["status"] == "done"
    assert len(api.get("/prompt_proposals", params={"limit": 1}).json()["items"]) == 1
    assert api.get("/prompt_proposals", params={"status": "rejected"}).json()["items"] == []
    assert api.get("/prompt_proposals", params={"status": "bogus"}).status_code == 422
    assert api.post(f"/prompt_proposals/{first}/reject", json={"note": "no"}).status_code == 200
    assert [p["id"] for p in api.get("/prompt_proposals").json()["items"]] == [second]
    assert [p["status"] for p in api.get("/prompt_proposals", params={"status": "all"}).json()["items"]] == [
        "open", "rejected"]
    assert [p["id"] for p in api.get(f"/llm_rules/{llm}/proposals").json()["items"]] == [first]   # per rule as before


def test_trial_sample_of_a_new_rule_without_decisions(api, seed, sql):
    """A prompt trial may sample random subjects of the rule's scope (a new rule has no decisions to learn from):
    their expected verdict is the current one when a hit exists, else none - shown, not counted in the metrics."""
    from discovery_common import keys
    sql("UPDATE gitlab_branches SET scanned_commit = commit")
    for name in ("Alpha", "Bravo", "Charlie", "Delta", "Echo"):
        key = keys.object_key(1, "go", name)
        content = keys.content_hash(key, {"code": "string"}, {})
        sql("""INSERT INTO objects (content_hash, object_key, project_id, parser, type, name, file, props)
               VALUES (:h, :k, 1, 'go', 'dto', :n, :f, NULL)""", h=content, k=key, n=name, f=f"/{name.lower()}.go")
        sql("INSERT INTO branch_objects (branch_id, object_key, content_hash, is_main, line) VALUES (1, :k, :h, true, 1)",
            k=key, h=content)
    rule = api.post("/llm_rules", json={"name": "fresh", "category": "pii", "target": "object",
                                        "prompt": "Any personal data?"}).json()["id"]
    assert api.post(f"/llm_rules/{rule}/trials", json={"prompt": "Personal data of a client?"}).status_code == 422
    assert api.post(f"/llm_rules/{rule}/trials", json={"prompt": "p", "sample": 500}).status_code == 422

    r = api.post(f"/llm_rules/{rule}/trials", json={"prompt": "Personal data of a client?", "sample": 5,
                                                    "include_controls": 0})
    assert r.status_code == 202, r.text
    trial = r.json()
    assert trial["planned_calls"] == 5 and trial["metrics"]["targets"]["total"] == 0
    assert trial["metrics"]["samples"] == {"total": 5, "pending": 5, "failed": 0, "match": 0, "no_match": 0,
                                           "need_more_info": 0}
    items = api.get(f"/prompt_trials/{trial['id']}").json()["items"]
    assert len(items) == 5 and {(i["role"], i["expected"], i["current"]["status"]) for i in items} == {
        ("sample", None, None)}
    assert len({i["object_key"] for i in items}) == 5
    assert api.get(f"/prompt_trials/{trial['id']}", params={"only": "wrong"}).json()["items"] == []

    # a sampled subject with a current verdict is a control: expected = that verdict
    alpha = keys.object_key(1, "go", "Alpha")
    sql("""INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, rule_version, model, status, category,
                                  severity, decided_tier)
           VALUES (:r, :k, 1, :k, 1, 'm', 'match', 'pii', 'medium', 'service')""", r=rule, k=alpha)
    trial = api.post(f"/llm_rules/{rule}/trials", json={"prompt": "Client data?", "sample": 10,
                                                        "include_controls": 0}).json()
    items = api.get(f"/prompt_trials/{trial['id']}").json()["items"]
    assert len(items) == 6                                               # User + 5 synthetic objects: all in scope
    (control,) = [i for i in items if i["role"] == "control"]
    assert (control["object_key"], control["expected"], control["current"]["verdict"]) == (str(alpha), "match", "match")
    assert sum(1 for i in items if i["role"] == "sample") == 5
    assert trial["metrics"]["controls"]["total"] == 1 and trial["metrics"]["samples"]["total"] == 5


def test_mcp_reads_versions_rollouts_and_history(live_api, seed, sql):
    rule = seed["rules"]["llm"]
    _llm_hits(sql, rule)
    sql("UPDATE rules SET version = 2 WHERE id = :r", r=rule)
    sql("INSERT INTO llm_rollouts (rule_id, from_version, to_version, status) VALUES (:r, 1, 2, 'planned')", r=rule)

    async def flow(client):
        return {
            "versions": payload(await client.call_tool("llm_rule_versions", {"rule_id": rule})),
            "rollouts": payload(await client.call_tool("llm_rollouts", {"status": "open"})),
            "history": payload(await client.call_tool("hit_history", {"hit_id": seed["email_llm"]})),
            "hit": payload(await client.call_tool("get_hit", {"hit_id": seed["email_llm"]})),
        }
    out = run(live_api, flow)
    assert out["versions"]["items"][0]["status"] == "active"
    assert [r["status"] for r in out["rollouts"]["items"]] == ["planned"]
    assert out["history"]["items"][0]["source"] == "service"
    assert out["hit"]["stale"] is True
