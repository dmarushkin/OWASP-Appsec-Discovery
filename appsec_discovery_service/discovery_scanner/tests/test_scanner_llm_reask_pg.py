"""Re-ask semantics of LLM rules (rule_hits.names_hash / subject_hash, migration 0018) against a real
Postgres (TEST_DATABASE_URL; skipped without it): content changes re-ask machine verdicts, a renamed
object or another set of field names re-asks object rules even about human decisions, which are then
carried over or sent back to review; deleted fields lose their machine hits; graceful stop of a run."""

import json

from appsec_discovery.models import CodeObject, CodeObjectField

from test_scanner_llm_work_pg import OBJECTS, _exec, answer, q, setup, use_backend


def code_object(name, fields, ident=None, types=None):
    """``ident``: the identity hash (a rename keeps it, so the object key stays)."""
    types = types or {}
    return CodeObject(
        hash=f"id-{ident or name}", object_name=name, object_type="dto", parser="go", file="/m.go", line=1,
        properties={}, fields={f: CodeObjectField(field_name=f, field_type=types.get(f, t), file="/m.go", line=i + 2)
                               for i, (f, t) in enumerate(fields.items())})


def save(env, commit, objects):
    """A new main snapshot: ``objects`` = {name: (fields, ident)}."""
    from discovery_common.mapping import from_code_object
    recs = [from_code_object(code_object(name, fields, ident), env.project.id) for name, (fields, ident) in objects.items()]
    env.dbs.save_main_scan(env.branch, commit, recs, [], None)
    return {r.name: r for r in recs}


def snapshot(**changes):
    objects = {name: (dict(fields), None) for name, fields in OBJECTS.items()}
    objects.update(changes)
    return {name: value for name, value in objects.items() if value is not None}


def hit(rule_id, object_name=None, field=None, key=None):
    rows = q("""SELECT h.* FROM rule_hits h
                WHERE h.rule_id = :r AND h.field_name IS NOT DISTINCT FROM :f
                  AND (CAST(:k AS uuid) IS NULL OR h.object_key = CAST(:k AS uuid))
                  AND (CAST(:n AS text) IS NULL OR h.object_key IN (SELECT object_key FROM objects WHERE name = :n))""",
             r=rule_id, f=field, k=str(key) if key else None, n=object_name)
    assert len(rows) <= 1, rows
    return rows[0] if rows else None


def candidates(env, name):
    """What a run of the rule would ask (the classifier never sends ineligible fields such as "id")."""
    import sys
    eligible = sys.modules["services.score_service"].llm_eligible_field
    rule = next(r for r in env.dbs.get_rules("llm") if r.name == name)
    return sorted((row["name"], row["field_name"]) for row in env.dbs.get_llm_candidates(env.branch.id, rule)
                  if name != "llm" or eligible(row["field_name"], row["field_type"]))


class Model:
    """``answer``, with object rule verdicts the test sets per marker (a text of the object's prompt)."""

    def __init__(self):
        self.objects = {}
        self.calls = []

    def __call__(self, system, user, schema):
        self.calls.append(user)
        if "verdict" in schema["properties"]:
            for marker, verdict in self.objects.items():
                if marker in user:
                    return json.dumps(verdict)
        return answer(system, user, schema)


def run(env, monkeypatch, model, names=("person", "contacts", "llm")):
    from appsec_discovery.ai import FakeLlmBackend
    use_backend(monkeypatch, env, FakeLlmBackend(model, model="m"))
    model.calls.clear()
    assert env.scan.run_selected_llm_rules(env.branch, [env.rules[n] for n in names]) is True
    return list(model.calls)


def test_reask_rules_and_carry_over_of_human_decisions(pg_scanner, monkeypatch):
    from discovery_common import keys

    env = setup(pg_scanner, monkeypatch)
    person, contacts = env.rules["person"], env.rules["contacts"]
    model = Model()
    assert len(run(env, monkeypatch, model)) == 9
    # every hit records what the model saw: nothing is asked again while nothing changes
    assert candidates(env, "person") == candidates(env, "contacts") == candidates(env, "llm") == []
    client = hit(person, "Client")
    assert (client.status, client.fields, client.reviewer) == ("pending_review", ["LastName", "Phone"], None)
    assert client.names_hash == keys.names_hash("Client", ["LastName", "Phone", "Email", "id"])
    assert client.subject_hash == str(client.object_key and q(
        "SELECT content_hash FROM branch_objects WHERE object_key = :k", k=client.object_key)[0][0])
    email = hit(contacts, field="Email")
    assert email.subject_hash == keys.field_subject_hash("Email", "string", None, None)
    assert email.names_hash == keys.names_hash("Client", ["Email"])
    assert run(env, monkeypatch, model) == []

    # people decide: Client confirmed (alice), its LastName mark confirmed (bob), Order rejected (eve),
    # the contacts Phone hit rejected (dave)
    _exec("UPDATE rule_hits SET status = 'match', reviewer = 'alice', decided_via = 'rest', reviewed_at = now(), "
          "note = 'looks right' WHERE rule_id = :r AND subject_key = :k", r=person, k=client.subject_key)
    _exec("UPDATE rule_hits SET status = 'match', reviewer = 'bob' WHERE rule_id = :r AND field_name = 'LastName'",
          r=person)
    order = hit(person, "Order")
    _exec("UPDATE rule_hits SET reviewer = 'eve', decided_via = 'mcp' WHERE rule_id = :r AND subject_key = :k",
          r=person, k=order.subject_key)
    _exec("UPDATE rule_hits SET status = 'no_match', reviewer = 'dave' WHERE rule_id = :r AND field_name = 'Phone'",
          r=contacts)

    # content-only change (types of Email and Phone): machine field verdicts are asked again, the human
    # decisions (Phone of contacts, the Client object of person: same field names) are kept
    client_fields = dict(OBJECTS["Client"], Email="str", Phone="str")
    save(env, "c2", snapshot(Client=(client_fields, None)))
    assert candidates(env, "person") == []
    assert candidates(env, "contacts") == [("Client", "Email")]
    assert ("Client", "Phone") in candidates(env, "llm") and ("Client", "Phone") not in candidates(env, "contacts")
    run(env, monkeypatch, model)
    assert candidates(env, "contacts") == candidates(env, "llm") == []
    assert hit(contacts, field="Email").subject_hash == keys.field_subject_hash("Email", "str", None, None)
    assert (hit(contacts, field="Phone").status, hit(contacts, field="Phone").reviewer) == ("no_match", "dave")

    # a field added to Client: person asks again despite the confirmation; the model names only fields
    # confirmed before -> the confirmation is carried over (no review needed)
    client_fields["Address"] = "string"
    # a field removed from Order: asked again, the model says no_match -> the rejection stays
    # (a renamed object is a new object key - the identity includes the name - so it is asked anyway)
    order_fields = {"amount": "int"}
    save(env, "c3", snapshot(Client=(client_fields, None), Order=(order_fields, None)))
    assert candidates(env, "person") == [("Client", None), ("Order", None)]
    model.objects = {"LastName": {"verdict": "match", "reason": "a person again", "fields": ["LastName", "Phone"]},
                     "amount": {"verdict": "no_match", "reason": "an order"}}
    calls = run(env, monkeypatch, model, names=("person",))
    assert len(calls) == 2
    carried = hit(person, key=client.object_key)
    assert (carried.status, carried.reviewer, carried.decided_via, carried.reason) == (
        "match", "alice", "rest", "a person again")
    assert carried.names_hash == keys.names_hash("Client", list(client_fields))
    assert carried.prompt_version and carried.rule_version == 1 and carried.fields == ["LastName", "Phone"]
    assert carried.note.startswith("looks right\n") and "confirmation carried over to the new version" in carried.note
    rejected = hit(person, key=order.object_key)
    assert (rejected.status, rejected.reviewer, rejected.decided_via) == ("no_match", "eve", "mcp")
    assert "rejection carried over" in rejected.note
    assert rejected.names_hash == keys.names_hash("Order", ["amount"])
    assert candidates(env, "person") == []
    assert run(env, monkeypatch, model, names=("person",)) == []                        # nothing left

    # another field, and the model names it: the object goes back to review, the new field's mark is
    # pending (even in mode auto), the field hit bob confirmed stays confirmed
    _exec("UPDATE rules SET mode = 'auto' WHERE id = :r", r=person)
    client_fields["Passport"] = "string"
    save(env, "c4", snapshot(Client=(client_fields, None), Order=(order_fields, None)))
    model.objects["LastName"] = {"verdict": "match", "reason": "a person with a passport",
                               "fields": ["LastName", "Phone", "Passport"]}
    run(env, monkeypatch, model, names=("person",))
    again = hit(person, key=client.object_key)
    assert (again.status, again.reviewer, again.decided_via, again.reason) == (
        "pending_review", None, None, "a person with a passport")
    assert "re-review: new fields Passport (was confirmed by alice)" in again.note
    marks = {r.field_name: (r.status, r.reviewer) for r in q(
        "SELECT field_name, status, reviewer FROM rule_hits WHERE rule_id = :r AND object_key = :k "
        "AND field_name IS NOT NULL", r=person, k=client.object_key)}
    assert marks == {"LastName": ("match", "bob"), "Phone": ("match", None), "Passport": ("pending_review", None)}
    assert candidates(env, "person") == []


def test_human_rejection_and_review_again_with_mark_fields_set(pg_scanner, monkeypatch):
    """A rejected object has no confirmed fields: a re-ask naming any field sends it back to review."""
    env = setup(pg_scanner, monkeypatch)
    person = env.rules["person"]
    model = Model()
    run(env, monkeypatch, model, names=("person",))
    _exec("UPDATE rule_hits SET status = 'no_match', reviewer = 'eve' WHERE rule_id = :r AND field_name IS NULL "
          "AND object_key IN (SELECT object_key FROM objects WHERE name = 'Client')", r=person)
    save(env, "c2", snapshot(Client=(dict(OBJECTS["Client"], Nick="string"), None)))
    run(env, monkeypatch, model, names=("person",))      # answer(): match LastName, Phone
    client = hit(person, "Client")
    assert (client.status, client.reviewer) == ("pending_review", None)
    assert client.note == "re-review: new fields LastName, Phone (was rejected by eve)"


def test_deleted_fields_lose_machine_hits_and_keep_human_ones(pg_scanner, monkeypatch):
    env = setup(pg_scanner, monkeypatch)
    contacts, llm = env.rules["contacts"], env.rules["llm"]
    run(env, monkeypatch, Model())
    assert hit(contacts, field="Email") is not None and hit(llm, field="Email") is not None
    _exec("UPDATE rule_hits SET status = 'match', reviewer = 'carol' WHERE rule_id = :r AND field_name = 'Email'",
          r=llm)
    client = {k: v for k, v in OBJECTS["Client"].items() if k != "Email"}
    save(env, "c2", snapshot(Client=(client, None)))
    assert hit(contacts, field="Email") is None                                         # machine: removed
    assert (hit(llm, field="Email").status, hit(llm, field="Email").reviewer) == ("match", "carol")
    assert hit(contacts, field="Phone") is not None                                     # still in the object
    # keyword hits are not touched; nothing is asked again for the fields left
    assert candidates(env, "contacts") == []


def test_graceful_stop_requeues_after_the_chunk(pg_scanner, monkeypatch):
    """A stopping worker: the run stores the verdicts of the objects asked so far, the job goes back to
    pending without using an attempt, the next run asks only what is left."""
    from appsec_discovery.ai import FakeLlmBackend
    from discovery_common import jobs

    env = setup(pg_scanner, monkeypatch)
    handlers = pg_scanner.load("services.job_handlers")
    person = env.rules["person"]
    calls = []

    def model(system, user, schema):
        calls.append(user)
        if len(calls) == 1:
            jobs.request_stop()                     # SIGTERM while the first model call runs
        return answer(system, user, schema)

    use_backend(monkeypatch, env, FakeLlmBackend(model, model="m"))
    job_id = jobs.enqueue("llm_score", {"branch_id": env.branch.id, "rule_ids": [person]}, "llm_rule:stop")
    worker = jobs.Worker("w-test", {"llm_score": handlers.llm_score_job}, jobs.WorkerConfig(kinds=["llm_score"]))
    try:
        assert worker.run_once() == "pending"
    finally:
        jobs.stop_event().clear()
    assert len(calls) == 1
    (status, attempts, locked), = q("SELECT status, attempts, locked_by FROM jobs WHERE id = :j", j=job_id)
    assert (status, attempts, locked) == ("pending", 0, None)
    assert len(q("SELECT 1 FROM rule_hits WHERE rule_id = :r AND field_name IS NULL", r=person)) == 1
    assert len(candidates(env, "person")) == 2

    assert worker.run_once() == "done"
    assert len(calls) == 3 and len(set(calls)) == 3                     # the first object is not asked again
    assert candidates(env, "person") == []
    (status, attempts), = q("SELECT status, attempts FROM jobs WHERE id = :j", j=job_id)
    assert (status, attempts) == ("done", 1)


def test_stop_before_a_scan_phase_requeues(pg_scanner):
    import pytest
    from discovery_common import jobs

    scan = pg_scanner.load("services.scan_service")
    jobs.request_stop()
    try:
        with pytest.raises(jobs.RequeueJob, match="stopping: scan requeued before parse"):
            scan._phase("parse")
        scan._phase("done")                         # a final phase is written as usual
    finally:
        jobs.stop_event().clear()


def test_stop_ends_control_slices_early(pg_scanner, monkeypatch):
    """llm_prepare (and llm_apply / llm_coverage) end their slice at the next object when stopping: the
    handler requeues the job as after a full slice, the next run goes on."""
    from discovery_common import jobs

    from test_scanner_llm_work_pg import items, new_job

    env = setup(pg_scanner, monkeypatch)
    rule_ids = sorted(env.rules.values())
    job_id = new_job(rule_ids)
    jobs.request_stop()
    try:
        stats = env.work.prepare_external_run(job_id, env.branch, rule_ids, max_objects=500, max_seconds=60)
    finally:
        jobs.stop_event().clear()
    assert (stats["objects"], stats["more"]) == (1, True)
    stats = env.work.prepare_external_run(job_id, env.branch, rule_ids, max_objects=500, max_seconds=60)
    assert (stats["objects"], stats["more"]) == (8, False) and len(items(job_id)) == 9
