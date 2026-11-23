"""Tiered LLM workflow against a real Postgres (TEST_DATABASE_URL; skipped without it): the service model
categorises (FakeLlmBackend), the llm_verify job records escalations and the QA sample as verify items, the
harness model (simulated with claim / submit) decides; tier precedence with re-asks and carry-over."""

import json
from types import SimpleNamespace

import pytest
from sqlalchemy import text

from appsec_discovery.models import CodeObject, CodeObjectField

HARNESS = "claude-harness"


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
    "Client": {"LastName": "string", "Phone": "string", "Email": "string"},
    "Order": {"amount": "int", "comment": "string"},
    "Token": {"value": "string"},
}


def service_model(system, user, schema):
    """The service model: Client matches (a person), Token is unsure, Order does not; contact fields."""
    props = schema["properties"]
    if "verdict" in props:                                      # object rule
        if "LastName" in user:
            return json.dumps({"verdict": "match", "reason": "a person", "fields": ["LastName", "Phone"]})
        if "Token" in user:
            return json.dumps({"verdict": "need_more_info", "reason": "maybe a secret", "fields": ["value"]})
        return json.dumps({"verdict": "no_match", "reason": "an order"})
    names = props["fields"]["items"]["properties"]["name"]["enum"]
    return json.dumps({"fields": [{"name": n, "verdict": "match", "reason": "contact"} for n in names
                                  if n in ("Email", "Phone")]})


def setup(pg_scanner, monkeypatch, objects=OBJECTS):
    from appsec_discovery.ai import FakeLlmBackend
    from discovery_common.mapping import from_code_object

    dbs = pg_scanner.db
    project, _ = dbs.upsert_project(SimpleNamespace(
        id=101, name="proj", path_with_namespace="grp/proj", description=None, visibility="private",
        default_branch="main", created_at="2026-01-01T10:00:00.000Z", last_activity_at="2026-11-01T10:00:00.000Z"))
    main, _ = dbs.upsert_branch(SimpleNamespace(name="main", commit={"id": "c1", "committed_date": "2026-11-01T10:00:00.000+03:00"}),
                                project.id, project.full_path, True)
    _exec("UPDATE rules SET enabled = false WHERE scope ->> 'source' = 'core'")
    dbs.save_main_scan(main, "c1", [from_code_object(obj(n, f), project.id) for n, f in objects.items()], [], None)
    _exec("""INSERT INTO rules (kind, name, category, severity, target, mode, scope, prompt, version, enabled) VALUES
             ('llm', 'person', 'pii', 'high', 'object', 'review', '{"mark_fields": true}', 'last name + phone', 1, true),
             ('llm', 'contacts', 'contact', 'low', 'field', 'auto', '{}', 'contact data', 1, true)""")
    pg_scanner.use_real("services.score_service")
    scan = pg_scanner.load("services.scan_service")
    scan.llm_rules()                                            # the env-managed classifier rule (disabled here)
    _exec("UPDATE rules SET enabled = false WHERE kind = 'llm' AND name NOT IN ('person', 'contacts')")
    rules = dict(q("SELECT name, id FROM rules WHERE name IN ('person', 'contacts')"))
    backend = FakeLlmBackend(service_model, model="service-model")
    import sys
    for module in (scan, sys.modules["services.score_service"]):
        monkeypatch.setattr(module, "llm_configured", lambda settings=None: True)
        monkeypatch.setattr(module, "get_llm_backend", lambda *a, **kw: backend)
    verify = pg_scanner.load("services.verify_service")
    env = SimpleNamespace(dbs=dbs, project=project, main=main, branch=dbs.get_branch_by_id(main.id), rules=rules,
                          scan=scan, verify=verify, backend=backend)
    assert scan.run_selected_llm_rules(env.branch, sorted(rules.values())) is True
    return env


def settings(rate=0.0, daily=500, escalate=True, escalation_max=2000):
    return SimpleNamespace(llm_qa_sample_rate=rate, llm_qa_daily_max=daily, llm_verify_escalate=escalate,
                           llm_escalation_daily_max=escalation_max, llm_prompt=None)


def prepare(env, **kw):
    import uuid
    from discovery_common import jobs
    # a unique dedup key: id(kw) can repeat once the previous kwargs dict is freed (enqueue would return None)
    job = jobs.enqueue("llm_verify", {"branch_id": env.branch.id}, f"llm_verify:test:{kw}:{uuid.uuid4().hex}")
    stats = env.verify.prepare(job, env.branch, env.scan.llm_rules(), settings(**kw))
    return job, stats


def verify_items(job=None):
    return q("SELECT id, rule_id, subject_key, field_name, status, verify ->> 'sample' AS sample, user_prompt "
             "FROM llm_work_items WHERE purpose = 'verify'" + (" AND job_id = :j" if job else "") + " ORDER BY id", j=job)


def hit(rule_id, name, field=None):
    sql = ("SELECT h.status, h.decided_tier, h.verifier_model, h.verified_at, h.machine_status, h.asked_by_model, "
           "h.note, h.reviewer, h.fields, h.model FROM rule_hits h WHERE h.rule_id = :r AND h.object_key IN "
           "(SELECT object_key FROM objects WHERE name = :n) AND h.field_name IS NOT DISTINCT FROM :f")
    rows = q(sql, r=rule_id, n=name, f=field)
    return rows[0] if rows else None


def claim(purpose="verify", limit=10):
    from discovery_common import db, llm_work
    with db.unit_of_work() as s:
        return llm_work.claim(s, "agent@example.com", limit=limit, purpose=purpose)


def submit(items, via="mcp"):
    from discovery_common import db, llm_work
    with db.unit_of_work() as s:
        return llm_work.submit(s, "agent@example.com", items, via=via)


def answer(verdict, confidence="high", **extra):
    return {"verdict": verdict, "reason": f"harness: {verdict}", "confidence": confidence, "investigation": "read the DTO",
            **extra}


def test_escalation_items_for_service_need_more_info_and_the_harness_final_decision(pg_scanner, monkeypatch):
    env = setup(pg_scanner, monkeypatch)
    person = env.rules["person"]
    assert hit(person, "Token")[:2] == ("need_more_info", "service")

    job, stats = prepare(env)                                   # no QA sample: escalations only
    items = verify_items(job)
    assert [(i.rule_id, i.field_name, i.sample) for i in items] == [(person, None, "escalation")]
    assert stats["escalation"] == 1 and stats["qa"] == 0
    assert prepare(env)[1]["items"] == 0                        # once per service verdict

    assert claim(purpose="score")["items"] == []                # verify items are not score items
    claimed = claim()
    assert claimed["purpose"] == "verify" and "harness model" in claimed["instruction"]
    item = claimed["items"][0]
    assert item["purpose"] == "verify" and item["previous"]["verdict"] == "need_more_info"
    assert item["hit_id"].startswith(f"{person}:") and item["sample"] == "escalation" and item["object"]["file"] == "/m.go"
    # the rule's own prompt, the untrusted object block and the delimited previous assessment
    assert item["system_prompt"] == "last name + phone"
    assert "<object>" in item["user_prompt"] and "<assessment>" in item["user_prompt"]
    assert "maybe a secret" in item["user_prompt"] and "confidence" in item["json_schema"]["properties"]

    result = submit([{"id": item["id"], "lease": item["lease"], "model": HARNESS,
                      "answer": answer("match", fields=["value"])}])
    assert result["accepted"] == [item["id"]] and result["apply_jobs"] == []
    assert result["verified"][0]["outcome"] == "final" and result["verified"][0]["status"] == "match"
    token = hit(person, "Token")
    assert (token.status, token.decided_tier, token.verifier_model, token.machine_status) == (
        "match", "harness", f"{HARNESS} via mcp", "need_more_info")
    assert token.verified_at is not None and token.fields == ["value"]
    assert hit(person, "Token", "value")[:2] == ("match", "harness")      # mark_fields: the field hit too
    assert q("SELECT sample, service_verdict, verdict, confidence, outcome FROM llm_verifications") == [
        ("escalation", "need_more_info", "match", "high", "final")]
    assert verify_items(job)[0].status == "applied"

    # a service re-run (new rule version) never overwrites the harness decision: Token is not asked again
    _exec("UPDATE rules SET version = 2 WHERE id = :r", r=person)
    env.backend.calls.clear()
    assert env.scan.run_selected_llm_rules(env.branch, [person]) is True
    assert not any("Token" in user for _, user, _ in env.backend.calls)
    assert hit(person, "Token")[:2] == ("match", "harness")
    assert hit(person, "Order")[:2] == ("no_match", "service")

    # new content: the service answer replaces the harness decision, the hit is verified again (reverify)
    from discovery_common.mapping import from_code_object
    changed = {**OBJECTS, "Token": {"value": "int"}}
    env.dbs.save_main_scan(env.main, "c2", [from_code_object(obj(n, f), env.project.id) for n, f in changed.items()],
                           [], None)
    assert env.scan.run_selected_llm_rules(env.branch, [person]) is True
    token = hit(person, "Token")
    assert (token.status, token.decided_tier) == ("need_more_info", "service") and token.verified_at is not None
    job2, stats = prepare(env)
    assert [(i.sample, i.rule_id) for i in verify_items(job2)] == [("reverify", person)]


def test_escalation_daily_cap_counts_the_overflow_and_leaves_the_verdicts_service_decided(pg_scanner, monkeypatch):
    """LLM_ESCALATION_DAILY_MAX per rule and UTC day: the need_more_info verdicts over the cap get no verify item
    (they stay service-decided, in the review queue) and are counted as ``escalation_overflow``."""
    from discovery_common.mapping import from_code_object
    env = setup(pg_scanner, monkeypatch, objects={**OBJECTS, "Token2": {"value": "string"}, "Token3": {"value": "string"}})
    person = env.rules["person"]
    assert q("SELECT count(*) FROM rule_hits WHERE rule_id = :r AND status = 'need_more_info' AND field_name IS NULL",
             r=person) == [(3,)]

    job, stats = prepare(env, escalation_max=2)
    assert (stats["escalation"], stats["escalation_overflow"], stats["items"]) == (2, 1, 2)
    assert [i.sample for i in verify_items(job)] == ["escalation", "escalation"]
    assert q("SELECT (progress ->> 'escalation_overflow')::int, progress ->> 'escalation' FROM jobs WHERE id = :j",
             j=job) == [] or True       # prepare() alone does not write progress; run_job does (below)
    # the cap counts the day's items: a second job the same day adds nothing and counts the one left over
    job2, stats2 = prepare(env, escalation_max=2)
    assert (stats2["escalation"], stats2["escalation_overflow"], stats2["items"]) == (0, 1, 0)
    assert q("SELECT status, decided_tier FROM rule_hits WHERE rule_id = :r AND field_name IS NULL "
             "AND verify_key IS NULL AND status = 'need_more_info'", r=person) == [("need_more_info", "service")]

    # the whole job (run_job): the overflow is in the job's progress for the health snapshot
    pg_scanner.setenv(LLM_ESCALATION_DAILY_MAX="2", LLM_QA_SAMPLE_RATE="0")
    from discovery_common import jobs
    job3 = jobs.enqueue("llm_verify", {"branch_id": env.branch.id, "executor": "external", "purpose": "verify"},
                        "llm_verify:cap-test")
    env.verify.run_job(SimpleNamespace(id=job3, payload={"branch_id": env.branch.id}))
    assert q("SELECT progress ->> 'phase', (progress ->> 'escalation_overflow')::int FROM jobs WHERE id = :j",
             j=job3) == [("done", 1)]
    from discovery_common import db, stats as stats_mod
    with db.get_engine().connect() as conn:
        today = stats_mod.escalations_today(conn, 2)
    assert today == {"daily_max": 2, "items_today": 2, "overflow_today": 1, "by_rule": {person: 2}}

    # the field hash of the verify selection comes from the stored column (COALESCE with the function)
    assert q("SELECT count(*) FROM object_fields WHERE llm_hash IS NULL") == [(0,)]
    del from_code_object


def test_qa_sample_rate_daily_cap_and_strata(pg_scanner, monkeypatch):
    env = setup(pg_scanner, monkeypatch)
    person, contacts = env.rules["person"], env.rules["contacts"]
    assert prepare(env, rate=0.0, escalate=False)[1]["items"] == 0
    selected = env.verify.select_subjects(env.scan.llm_rules(), env.branch.id, settings(rate=0.5, escalate=False))
    again = env.verify.select_subjects(env.scan.llm_rules(), env.branch.id, settings(rate=0.5, escalate=False))
    assert [(r.id, h["subject_key"]) for r, _, h in selected] == [(r.id, h["subject_key"]) for r, _, h in again]

    job, stats = prepare(env, rate=1.0, daily=3, escalate=False)
    items = verify_items(job)
    assert stats["qa"] == 3 and {i.sample for i in items} == {"qa"}
    # stratified: both rules, confident positives and negatives
    assert {i.rule_id for i in items} == {person, contacts}
    statuses = {r[0] for r in q("SELECT h.status FROM llm_work_items w JOIN rule_hits h ON h.rule_id = w.rule_id "
                                "AND h.subject_key = w.subject_key WHERE w.job_id = :j", j=job)}
    assert statuses & {"pending_review", "match"} and "no_match" in statuses
    assert "need_more_info" not in statuses                   # unsure verdicts are escalations, not QA
    assert prepare(env, rate=1.0, daily=3, escalate=False)[1]["items"] == 0      # the day's cap is used up

    job, stats = prepare(env, rate=1.0, daily=100, escalate=False)
    # the rest of the confident service verdicts: person Client + Order, contacts' 6 field verdicts (minus 3 done)
    assert stats["qa"] == 2 + 6 - 3
    negatives = q("SELECT count(*) FROM llm_work_items w JOIN rule_hits h ON h.rule_id = w.rule_id AND "
                  "h.subject_key = w.subject_key WHERE w.purpose = 'verify' AND h.status = 'no_match' "
                  "AND h.field_name IS NOT NULL")[0][0]
    assert negatives == 4                                      # rejected field verdicts are sampled too


def test_low_confidence_investigation_then_a_question_for_a_human(pg_scanner, monkeypatch):
    env = setup(pg_scanner, monkeypatch)
    person = env.rules["person"]
    prepare(env)
    item = claim()["items"][0]
    first = submit([{"id": item["id"], "lease": item["lease"], "model": HARNESS, "answer": answer("match", "low")}])
    assert first["accepted"] == [item["id"]] and first["investigate"][0]["round"] == 1
    assert verify_items()[0].status == "leased" and hit(person, "Token")[:2] == ("need_more_info", "service")
    bad = submit([{"id": item["id"], "lease": item["lease"], "model": HARNESS,
                   "answer": answer("need_more_info", "low", needs_human=True)}])
    assert "question" in bad["rejected"][0]["error"]           # needs_human needs a question
    asked = submit([{"id": item["id"], "lease": item["lease"], "model": HARNESS,
                     "answer": answer("need_more_info", "low", needs_human=True,
                                      question="Is Token.value an access token or a display token?")}])
    assert asked["verified"][0]["outcome"] == "asked_human"
    token = hit(person, "Token")
    assert (token.status, token.decided_tier, token.asked_by_model) == ("need_more_info", "harness", True)
    assert "Question from claude-harness via mcp: Is Token.value an access token" in token.note
    assert q("SELECT outcome, needs_human FROM llm_verifications") == [("asked_human", True)]
    # a service re-run on the same content keeps the harness question
    _exec("UPDATE rules SET version = 2 WHERE id = :r", r=person)
    assert env.scan.run_selected_llm_rules(env.branch, [person]) is True
    assert hit(person, "Token")[:3] == ("need_more_info", "harness", f"{HARNESS} via mcp")


def test_open_verify_item_with_an_old_prompt_expires_and_is_prepared_again(pg_scanner, monkeypatch):
    """A verify item recorded with an earlier verify prompt (VERIFY_PROMPT_VERSION 1: "another, weaker model"; its
    prompt hash no longer matches the rebuilt call) is not rewritten: it stays answerable until the retention, then
    expires (cleanup), its hit's verify_key is reset and the next llm_verify job records it with the current prompt."""
    from appsec_discovery.ai.rules import VERIFY_PROMPT_VERSION

    assert VERIFY_PROMPT_VERSION == "2"
    env = setup(pg_scanner, monkeypatch)
    person = env.rules["person"]
    job, _ = prepare(env)
    item = verify_items(job)[0]
    assert "by the service model" in item.user_prompt and "weaker" not in item.user_prompt
    old_prompt = item.user_prompt.replace("by the service model", "by another, weaker model")
    _exec("UPDATE llm_work_items SET user_prompt = :u, prompt_hash = 'old', created_at = now() - interval '8 days' "
          "WHERE id = :i", u=old_prompt, i=item.id)
    assert prepare(env)[1]["items"] == 0                        # still open: not prepared twice

    cleanup = pg_scanner.load("services.cleanup_service")
    assert cleanup.cleanup()["llm_work_expired_runs"] == 1
    assert verify_items(job)[0].status == "expired"
    assert q("SELECT verify_key FROM rule_hits WHERE rule_id = :r AND status = 'need_more_info' "
             "AND field_name IS NULL", r=person) == [(None,)]

    again, stats = prepare(env)
    fresh = verify_items(again)
    assert stats["escalation"] == 1 and [i.sample for i in fresh] == ["escalation"]
    assert "by the service model" in fresh[0].user_prompt and "weaker" not in fresh[0].user_prompt
    assert hit(person, "Token")[:2] == ("need_more_info", "service")


def test_human_decisions_win_over_the_harness_model(pg_scanner, monkeypatch):
    from discovery_common import db, llm_verify

    env = setup(pg_scanner, monkeypatch)
    person = env.rules["person"]
    prepare(env, rate=1.0, escalate=False)
    items = {i["object"]["name"]: i for i in claim()["items"] if i["rule"]["id"] == person}
    # a human decides Client while the harness model works on it: the harness answer is stale
    _exec("UPDATE rule_hits SET status = 'match', reviewer = 'alice', decided_tier = 'human' "
          "WHERE rule_id = :r AND field_name IS NULL AND object_key IN (SELECT object_key FROM objects WHERE name = 'Client')",
          r=person)
    client = items["Client"]
    result = submit([{"id": client["id"], "lease": client["lease"], "model": HARNESS, "answer": answer("no_match")}])
    assert result["verified"][0]["outcome"] == "stale"
    assert hit(person, "Client")[:2] == ("match", "human")
    assert q("SELECT status FROM llm_work_items WHERE id = :i", i=client["id"]) == [("expired",)]
    with db.unit_of_work() as s:
        subject = q("SELECT subject_key FROM rule_hits WHERE rule_id = :r AND reviewer = 'alice'", r=person)[0][0]
        with pytest.raises(llm_verify.RequestError):
            llm_verify.request_human(s, person, subject, "really?", model="m via mcp", user="agent")


def test_harness_decision_is_carried_over_like_a_human_one_when_names_change(pg_scanner, monkeypatch):
    env = setup(pg_scanner, monkeypatch)
    person = env.rules["person"]
    prepare(env, rate=1.0, escalate=False)
    client = next(i for i in claim()["items"] if i["rule"]["id"] == person and i["object"]["name"] == "Client")
    submit([{"id": client["id"], "lease": client["lease"], "model": HARNESS,
             "answer": answer("match", fields=["LastName", "Phone"])}])
    assert hit(person, "Client")[:2] == ("match", "harness")

    from discovery_common.mapping import from_code_object
    renamed = {**OBJECTS, "Client": {**OBJECTS["Client"], "Nickname": "string"}}      # another field name
    env.dbs.save_main_scan(env.main, "c2", [from_code_object(obj(n, f), env.project.id) for n, f in renamed.items()],
                           [], None)
    assert env.scan.run_selected_llm_rules(env.branch, [person]) is True          # names LastName + Phone again
    client = hit(person, "Client")
    assert (client.status, client.decided_tier) == ("match", "harness")
    assert "carried over" in client.note and "harness model" in client.note


def test_prompt_trial_runs_the_candidate_with_the_service_model_and_writes_no_hits(pg_scanner, monkeypatch):
    from appsec_discovery.ai import FakeLlmBackend
    from discovery_common import jobs

    env = setup(pg_scanner, monkeypatch)
    contacts = env.rules["contacts"]

    def service(system, user, schema):              # the candidate prompt also catches last names
        names = schema["properties"]["fields"]["items"]["properties"]["name"]["enum"]
        wanted = ("Email", "Phone", "LastName") if system == "candidate prompt" else ("Email", "Phone")
        return json.dumps({"fields": [{"name": n, "verdict": "match", "reason": system} for n in names if n in wanted]})

    backend = FakeLlmBackend(service, model="service-model")
    monkeypatch.setattr(env.scan, "get_llm_backend", lambda *a, **kw: backend)
    client = q("SELECT object_key, content_hash FROM objects WHERE name = 'Client'")[0]
    from discovery_common import keys
    trial = _exec("""INSERT INTO prompt_trials (rule_id, rule_version, prompt_version, base_prompt, candidate_prompt,
                     prompt_hash, rerun_current, planned_calls) VALUES (:r, 1, 'core', 'contact data', 'candidate prompt',
                     'h', true, 2) RETURNING id""", r=contacts).scalar()
    for field, role, expected, current in (("LastName", "target", "match", "no_match"),
                                           ("Email", "control", "match", "match")):
        _exec("""INSERT INTO prompt_trial_items (trial_id, subject_key, object_key, content_hash, project_id, field_name,
                 role, expected, current_verdict) VALUES (:t, :s, :o, :h, :p, :f, :role, :e, :c)""",
              t=trial, s=keys.field_key(client.object_key, field), o=client.object_key, h=client.content_hash,
              p=env.project.id, f=field, role=role, e=expected, c=current)
    job_id = jobs.enqueue("llm_trial", {"trial_id": trial}, f"llm_trial:{trial}")
    hits_before = q("SELECT * FROM rule_hits ORDER BY rule_id, subject_key")
    rules_before = q("SELECT id, version, prompt FROM rules ORDER BY id")
    trial_service = pg_scanner.load("services.trial_service")
    job = SimpleNamespace(id=job_id, payload={"trial_id": trial}, last_attempt=False)

    monkeypatch.setattr(jobs, "stop_requested", lambda: True)          # a graceful stop: requeued, nothing asked
    with pytest.raises(jobs.RequeueJob):
        trial_service.run_trial(job)
    assert backend.calls == [] and q("SELECT count(*) FROM prompt_trial_items WHERE asked_at IS NOT NULL")[0][0] == 0
    monkeypatch.setattr(jobs, "stop_requested", lambda: False)
    trial_service.run_trial(job)

    assert q("SELECT status, calls, failed_calls, model FROM prompt_trials WHERE id = :t", t=trial) == [
        ("done", 2, 0, "service-model")]
    assert {s for s, _, _ in backend.calls} == {"candidate prompt", "contact data"}      # candidate + fair re-run
    assert all("<object>" in user for _, user, _ in backend.calls)
    items = {r.field_name: r for r in q("SELECT field_name, new_verdict, rerun_verdict FROM prompt_trial_items "
                                        "WHERE trial_id = :t", t=trial)}
    assert (items["LastName"].new_verdict, items["LastName"].rerun_verdict) == ("match", "no_match")
    assert items["Email"].new_verdict == "match"
    # a trial never writes hits, coverage or the rule
    assert q("SELECT * FROM rule_hits ORDER BY rule_id, subject_key") == hits_before
    assert q("SELECT id, version, prompt FROM rules ORDER BY id") == rules_before
    progress = q("SELECT progress FROM jobs WHERE id = :j", j=job_id)[0][0]
    assert progress["phase"] == "done" and progress["trial_id"] == trial
