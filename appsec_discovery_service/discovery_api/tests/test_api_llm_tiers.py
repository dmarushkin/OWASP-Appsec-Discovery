"""Tiered LLM workflow and prompt trials over REST and MCP, against a real Postgres: verify items (synthetic rows;
the scanner's llm_verify job is tested in discovery_scanner/tests/test_scanner_llm_tiers_pg.py) claimed and
submitted by a simulated harness, tier precedence with human reviews, questions for a human, QA metrics, prompt
trials (validation, controls, daily budget) and proposals (a finished trial needed, a human accepts)."""

import dataclasses
import json

import pytest

pytest.importorskip("fastapi")
pydantic = pytest.importorskip("pydantic")
if not pydantic.VERSION.startswith("2"):
    pytest.skip("the API runs on pydantic v2", allow_module_level=True)

from conftest import ADMIN  # noqa: E402

SCHEMA = {"type": "object", "properties": {"verdict": {"type": "string"}, "confidence": {"type": "string"}},
          "required": ["verdict", "confidence"]}


def verify_item(sql, seed, hit_key, rule_id, field_name, service_status, sample="qa", job=None):
    if job is None:
        job = sql("INSERT INTO jobs (kind, payload, dedup_key, status, progress) VALUES ('llm_verify', "
                  "'{\"branch_id\": 1, \"executor\": \"external\", \"purpose\": \"verify\"}', :k, 'done', "
                  "'{\"phase\": \"awaiting_answers\"}') RETURNING id", k=f"llm_verify:t:{hit_key}")[0][0]
    obj = "user" if field_name in ("email", "id") else "card"
    context = {"sample": sample, "service_status": service_status, "service_reason": "service reason", "service_model": "m",
               "subject_hash": None, "rule_version": 1, "prompt_version": None}
    return job, sql("""
        INSERT INTO llm_work_items (job_id, rule_id, rule_version, project_id, branch_id, object_key, content_hash,
                                    prompt_hash, system_prompt, user_prompt, json_schema, purpose, subject_key,
                                    field_name, verify)
        VALUES (:j, :r, 1, 1, 1, :o, :h, 'hash', 'sys', '<object>x</object> <assessment>y</assessment>',
                CAST(:schema AS jsonb), 'verify', :s, :f, CAST(:v AS jsonb)) RETURNING id""",
        j=job, r=rule_id, o=seed[f"{obj}_key"], h=seed[f"{obj}_hash"], s=seed[hit_key], f=field_name,
        schema=json.dumps(SCHEMA), v=json.dumps(context))[0][0]


def test_harness_verification_over_rest_then_a_human_overrides_it(api, seed, sql):
    llm = seed["rules"]["llm"]
    job, item_id = verify_item(sql, seed, "user_email", llm, "email", "pending_review")
    assert api.post("/llm_work/claim", json={}).json()["items"] == []        # score items only by default
    claimed = api.post("/llm_work/claim", json={"purpose": "verify", "limit": 5}).json()
    assert claimed["purpose"] == "verify" and "harness model" in claimed["instruction"]
    item = claimed["items"][0]
    assert (item["id"], item["hit_id"], item["purpose"], item["sample"]) == (item_id, seed["email_llm"], "verify", "qa")
    assert item["previous"]["verdict"] == "match" and item["previous"]["reason"] == "service reason"
    assert api.post("/llm_work/claim", json={"purpose": "judge"}).status_code == 422

    bad = api.post("/llm_work/submit", json={"lease": claimed["lease"], "items": [
        {"id": item_id, "model": "opus", "answer": {"verdict": "match"}}]}).json()
    assert "confidence" in bad["rejected"][0]["error"]
    result = api.post("/llm_work/submit", json={"lease": claimed["lease"], "items": [
        {"id": item_id, "model": "opus", "answer": {"verdict": "no_match", "confidence": "high", "reason": "work mail"}}]})
    body = result.json()
    assert body["accepted"] == [item_id] and body["apply_jobs"] == [] and body["verified"][0]["outcome"] == "final"
    hit = api.get(f"/hits/{seed['email_llm']}").json()
    assert (hit["status"], hit["decided_tier"], hit["verifier_model"], hit["machine_status"], hit["decided_by"]) == (
        "no_match", "harness", "opus via rest", "pending_review", "machine")
    assert api.get("/jobs/%d" % job).json()["progress"]["phase"] == "done"
    harness = api.get("/hits", params={"filter": json.dumps({"decided_tier": "harness", "presence": "all"})}).json()
    assert [h["id"] for h in harness] == [seed["email_llm"]]
    # the tiers' old names (before migration 0021) are accepted as filter aliases for one release; output: new names
    old = api.get("/hits", params={"filter": json.dumps({"decided_tier": "strong", "presence": "all"})}).json()
    assert [(h["id"], h["decided_tier"]) for h in old] == [(seed["email_llm"], "harness")]
    by_service = api.get("/hits", params={"filter": json.dumps({"decided_tier": ["service"], "presence": "all"})})
    by_weak = api.get("/hits", params={"filter": json.dumps({"decided_tier": ["weak"], "presence": "all"})})
    assert by_weak.json() == by_service.json() and {h["decided_tier"] for h in by_weak.json()} == {"service"}
    assert api.get("/hits", params={"filter": json.dumps({"decided_tier": "medium"})}).status_code in (400, 422)

    # a human overrides the harness decision: tier human, the service verdict stays recorded
    assert api.post(f"/hits/{seed['email_llm']}/review", json={"action": "reopen"}).status_code == 200
    assert api.post(f"/hits/{seed['email_llm']}/review", json={"action": "confirm"}).status_code == 200
    hit = api.get(f"/hits/{seed['email_llm']}").json()
    assert (hit["status"], hit["decided_tier"], hit["reviewer"], hit["machine_status"]) == (
        "match", "human", ADMIN, "pending_review")
    # the harness model cannot touch it any more
    assert api.post(f"/hits/{seed['email_llm']}/request_human", json={"question": "sure?"}).status_code == 409


def test_questions_from_the_model_and_low_confidence_rounds(api, seed, sql):
    llm = seed["rules"]["llm"]
    _, item_id = verify_item(sql, seed, "card_number", llm, "card_number", "pending_review", sample="escalation")
    lease = api.post("/llm_work/claim", json={"purpose": "verify"}).json()["lease"]
    low = api.post("/llm_work/submit", json={"lease": lease, "items": [
        {"id": item_id, "model": "opus", "answer": {"verdict": "match", "confidence": "low"}}]}).json()
    assert low["investigate"][0]["round"] == 1
    assert sql("SELECT status FROM llm_work_items WHERE id = :i", i=item_id) == [("leased",)]
    assert api.get(f"/hits/{seed['card_llm']}").json()["decided_tier"] == "service"

    quality = next(r for r in api.get("/llm_quality").json()["rules"] if r["rule_id"] == llm)
    assert (quality["escalation_pending"], quality["backlog"], quality["oldest_question_s"]) == (1, 1, None)

    asked = api.post(f"/hits/{seed['card_llm']}/request_human",
                     json={"question": "Is card_number a PAN or a masked number?", "model": "opus"}).json()
    assert asked["status"] == "need_more_info" and asked["closed_items"] == [item_id]
    questions = api.get("/hits", params={"filter": json.dumps({"asked_by_model": True,
                                                               "status": ["need_more_info"]})}).json()
    assert [h["id"] for h in questions] == [seed["card_llm"]]
    assert "Question from opus via rest: Is card_number a PAN" in questions[0]["note"]
    assert questions[0]["decided_tier"] == "harness" and questions[0]["asked_by_model"] is True
    assert questions[0]["allowed_actions"] == ["confirm", "reject", "reopen"]
    # the question's age (from when the model asked): the escalation item is closed, the question waits
    sql("UPDATE rule_hits SET verified_at = now() - interval '2 hours' WHERE rule_id = :r AND subject_key = :s",
        r=llm, s=seed["card_number"])
    body = api.get("/llm_quality").json()
    quality = next(r for r in body["rules"] if r["rule_id"] == llm)
    assert quality["questions_open"] == 1 and 7000 < quality["oldest_question_s"] < 7400
    assert body["totals"]["oldest_question_s"] == quality["oldest_question_s"]
    assert (quality["escalation_pending"], quality["backlog"]) == (0, 0)
    # a human answers it: tier human, out of the questions tab
    assert api.post(f"/hits/{seed['card_llm']}/review", json={"action": "confirm"}).status_code == 200
    assert api.get("/hits", params={"filter": json.dumps({"asked_by_model": True})}).json() == []
    assert api.get("/hits", params={"filter": json.dumps({"asked_by_model": "maybe"})}).status_code == 422
    body = api.get("/llm_quality").json()
    assert body["totals"]["oldest_question_s"] is None and body["totals"]["questions_open"] == 0


def test_llm_quality_metrics_and_the_needs_improvement_flag(api, seed, sql):
    llm = seed["rules"]["llm"]
    rows = [("qa", "match", "match")] * 20 + [("qa", "no_match", "no_match")] * 7 + [("qa", "no_match", "match")] * 8 \
        + [("escalation", "need_more_info", "match")] * 3
    for i, (sample, service, harness) in enumerate(rows):
        sql("""INSERT INTO llm_verifications (rule_id, rule_version, subject_key, object_key, project_id, sample,
                                              service_status, service_verdict, verdict, confidence, outcome)
               VALUES (:r, 1, gen_random_uuid(), gen_random_uuid(), 1, :s, 'x', :w, :v, 'high', 'final')""",
            r=llm, s=sample, w=service, v=harness)
    sql("""INSERT INTO llm_verifications (rule_id, rule_version, subject_key, object_key, project_id, sample,
                                          service_status, service_verdict, confidence, needs_human, outcome)
           VALUES (:r, 1, gen_random_uuid(), gen_random_uuid(), 1, 'qa', 'no_match', 'no_match', 'low', true,
                   'asked_human')""", r=llm)
    verify_item(sql, seed, "card_number", llm, "card_number", "pending_review")
    quality = api.get("/llm_quality").json()
    rule = next(r for r in quality["rules"] if r["rule_id"] == llm)
    assert rule["qa"]["samples"] == 35 and rule["qa"]["agreement"] == round(27 / 35, 4)
    assert rule["qa"]["by_verdict"]["match"] == {"samples": 20, "agreement": 1.0}
    assert rule["qa"]["by_verdict"]["no_match"] == {"samples": 15, "agreement": round(7 / 15, 4)}
    assert rule["qa"]["last_7d"]["samples"] == 35 and rule["qa"]["unsure"] == 1
    assert rule["escalations_30d"] == 3 and rule["asked_human_30d"] == 1 and rule["backlog"] == 1
    assert rule["needs_improvement"] is True and rule["health"] == "needs_improvement"
    assert quality["agreement_min"] == 0.9 and quality["totals"]["needs_improvement"] >= 1
    assert quality["backlog"]["total"] == 1 and quality["backlog"]["by_sample"] == {"qa": 1}
    assert api.get("/llm_quality", params={"rule_id": llm}).json()["rules"][0]["rule_id"] == llm
    assert api.get("/llm_quality", params={"rule_id": 999999}).status_code == 404


def _field_rule(sql, seed):
    """A pii field rule with a harness decision that disagrees with the service verdict (email) and one that agrees
    (id): a mislabelled subject and an agreed control."""
    rule = sql("""INSERT INTO rules (kind, name, category, severity, target, mode, scope, prompt, version, enabled)
                  VALUES ('llm', 'pii-fields', 'pii', 'high', 'field', 'review', '{}', 'old prompt', 1, true)
                  RETURNING id""")[0][0]
    sql("""INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version, model, status,
                                  machine_status, decided_tier, verifier_model, verified_at, prompt_version)
           VALUES (:r, :e, 1, :u, 'email', 1, 'm', 'match', 'no_match', 'harness', 'opus via mcp', now(), 'pv'),
                  (:r, :i, 1, :u, 'id', 1, 'm', 'no_match', 'no_match', 'harness', 'opus via mcp', now(), 'pv')""",
        r=rule, e=seed["user_email"], i=seed["user_id"], u=seed["user_key"])
    return rule


def test_prompt_trials_validation_controls_and_budget(api, seed, sql, api_settings):
    import config

    rule = _field_rule(sql, seed)
    found = api.get(f"/llm_rules/{rule}/mislabeled", params={"source": "verification"}).json()
    assert [(i["field_name"], i["machine_verdict"], i["expected_verdict"], i["trial_ready"]) for i in found["items"]] == [
        ("email", "no_match", "match", True)]
    assert api.get(f"/llm_rules/{rule}/mislabeled").json()["total"] == 0          # no human decision
    assert api.get(f"/llm_rules/{rule}/mislabeled", params={"source": "robot"}).status_code == 422

    hits_before = sql("SELECT rule_id, subject_key, status, decided_tier FROM rule_hits ORDER BY 1, 2")
    trial = api.post(f"/llm_rules/{rule}/trials", json={"prompt": "new prompt", "from_mislabeled": "verification",
                                                        "include_controls": 5})
    assert trial.status_code == 202, trial.text
    body = trial.json()
    assert body["status"] == "queued" and body["planned_calls"] == 2        # one object: candidate + current prompt
    assert body["metrics"]["targets"]["total"] == 1 and body["metrics"]["controls"]["total"] == 1
    items = api.get(f"/prompt_trials/{body['id']}").json()["items"]
    assert {(i["role"], i["field_name"], i["expected"], i["current"]["verdict"]) for i in items} == {
        ("target", "email", "match", "no_match"), ("control", "id", "no_match", "no_match")}
    assert sql("SELECT kind, payload->>'trial_id' FROM jobs WHERE id = :j", j=body["job_id"]) == [
        ("llm_trial", str(body["id"]))]
    assert sql("SELECT rule_id, subject_key, status, decided_tier FROM rule_hits ORDER BY 1, 2") == hits_before

    assert api.post(f"/llm_rules/{rule}/trials", json={"prompt": "x" * 20001, "subjects": []}).status_code == 422
    subjects = [{"object_key": str(seed["user_key"]), "field_name": "email", "expected": "match"}]
    assert api.post(f"/llm_rules/{rule}/trials", json={"prompt": "p", "subjects": [
        {"object_key": str(seed["user_key"]), "expected": "match"}]}).status_code == 422          # field rule
    config.set_settings(dataclasses.replace(api_settings, llm_trial_max_subjects=1))
    too_many = api.post(f"/llm_rules/{rule}/trials", json={"prompt": "p", "subjects": subjects + [
        {"object_key": str(seed["user_key"]), "field_name": "id", "expected": "no_match"}]})
    assert too_many.status_code == 422 and "LLM_TRIAL_MAX_SUBJECTS" in too_many.text
    config.set_settings(dataclasses.replace(api_settings, llm_trial_daily_calls=3))
    over = api.post(f"/llm_rules/{rule}/trials", json={"prompt": "p2", "subjects": subjects, "include_controls": 0})
    assert over.status_code == 429 and "LLM_TRIAL_DAILY_CALLS" in over.text      # 2 planned today + 2 > 3
    budget = api.get(f"/llm_rules/{rule}/trials").json()["budget"]
    assert budget == {"daily_calls": 3, "used_today": 2, "left_today": 1}


def test_proposals_need_a_finished_trial_and_only_a_human_accepts(api, seed, sql):
    rule = _field_rule(sql, seed)
    trial = api.post(f"/llm_rules/{rule}/trials", json={"prompt": "better prompt", "from_mislabeled": True}).json()
    early = api.post(f"/llm_rules/{rule}/proposals", json={"prompt": "better prompt", "trial_id": trial["id"],
                                                           "rationale": "fixes email"})
    assert early.status_code == 409                                           # the trial is still queued
    sql("UPDATE prompt_trials SET status = 'done', finished_at = now() WHERE id = :t", t=trial["id"])
    other = api.post(f"/llm_rules/{rule}/proposals", json={"prompt": "another prompt", "trial_id": trial["id"],
                                                           "rationale": "x"})
    assert other.status_code == 422                                           # not the tried text
    created = api.post(f"/llm_rules/{rule}/proposals", json={"prompt": "better prompt", "trial_id": trial["id"],
                                                             "rationale": "fixes email"})
    assert created.status_code == 201, created.text
    proposal = created.json()
    assert proposal["status"] == "open" and "+better prompt" in proposal["diff"] and proposal["stale"] is False
    assert api.get(f"/llm_rules/{rule}").json()["prompt"] == "old prompt"    # nothing changed yet

    cost = api.get(f"/prompt_proposals/{proposal['id']}/reask").json()
    assert cost["subjects_to_send"] == 0 and cost["model_calls"] == 0          # harness decisions are kept
    accepted = api.post(f"/prompt_proposals/{proposal['id']}/accept", json={"note": "ok"})
    assert accepted.status_code == 200, accepted.text
    out = accepted.json()
    # a candidate version: the rule is unchanged until a human activates it
    assert out["rule"]["version"] == 1 and out["rule"]["prompt"] == "old prompt" and out["activation"] is None
    assert (out["version"]["version"], out["version"]["status"], out["version"]["source"]) == (
        2, "candidate", f"proposal:{proposal['id']}")
    assert out["proposal"]["status"] == "accepted" and out["proposal"]["accepted_version"] == 2
    estimate = api.get(f"/llm_rule_versions/{out['version']['id']}/estimate").json()
    assert estimate["migration"]["subjects"] == 0 and estimate["protected_harness"] == 2   # harness decisions kept
    activated = api.post(f"/llm_rule_versions/{out['version']['id']}/activate", json={"start_rollout": False})
    assert activated.status_code == 200, activated.text
    assert activated.json()["rollout"]["status"] == "planned"
    rule_now = api.get(f"/llm_rules/{rule}").json()
    assert rule_now["version"] == 2 and rule_now["prompt"] == "better prompt"
    assert api.post(f"/prompt_proposals/{proposal['id']}/reject", json={}).status_code == 409
    # harness decisions survive the version bump (the service model is not asked about them again)
    assert sql("SELECT status, decided_tier FROM rule_hits WHERE rule_id = :r ORDER BY field_name", r=rule) == [
        ("match", "harness"), ("no_match", "harness")]


def test_trial_metrics_fixed_still_wrong_newly_wrong_and_control_regressions(api_settings):
    from services.trials_service import metrics

    def item(role, expected, current, new, rerun=None, asked=True):
        return {"role": role, "expected": expected, "current_verdict": current, "rerun_verdict": rerun,
                "new_verdict": new, "asked_at": "t" if asked else None}

    m = metrics([
        item("target", "match", "no_match", "match"),                       # fixed
        item("target", "match", "no_match", "no_match"),                    # still wrong
        item("target", "no_match", "match", "no_match", rerun="no_match"),  # kept right (the re-run counts) + drift
        item("target", "no_match", "no_match", "match"),                    # newly wrong
        item("target", "match", "no_match", None),                          # the candidate failed
        item("control", "match", "match", "match"),
        item("control", "no_match", "no_match", "match"),                   # regression
        item("control", "match", "match", None, asked=False),               # pending
    ])
    t, c = m["targets"], m["controls"]
    assert (t["fixed"], t["still_wrong"], t["newly_wrong"], t["kept_right"], t["failed"], t["current_drift"]) == (
        1, 1, 1, 1, 1, 1)
    assert (t["accuracy_before"], t["accuracy_after"]) == (0.4, 0.5)
    assert (c["kept"], c["regressions"], c["pending"], c["accuracy_before"], c["accuracy_after"]) == (1, 1, 1, 1.0, 0.5)
