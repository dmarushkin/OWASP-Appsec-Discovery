"""LLM rule lifecycle against a real Postgres (TEST_DATABASE_URL; skipped without it): verdict history, fresh vs
migration candidates, rule versions (activation, relabel, rollback with adoption from the history), the core prompts
pin and the scanner's version sync, the rollout controller (budget, priority, fresh work first, pause / cancel,
quality auto-pause, done, MR deltas left to scan_mr), verify items of older versions expiring."""

import json

from test_scanner_llm_work_pg import OBJECTS, _exec, answer, q, setup, use_backend


def backend(monkeypatch, env, respond=answer, model="m"):
    from appsec_discovery.ai import FakeLlmBackend
    calls = []

    def model_fn(system, user, schema):
        calls.append(user)
        return respond(system, user, schema)
    use_backend(monkeypatch, env, FakeLlmBackend(model_fn, model=model))
    return calls


def run(env, monkeypatch, names=("contacts",), migration=None, respond=answer):
    calls = backend(monkeypatch, env, respond)
    kw = {} if migration is None else {"migration": migration}
    assert env.scan.run_selected_llm_rules(env.branch, [env.rules[n] for n in names], **kw) is True
    return calls


def history(rule_id, field=None):
    return q("""SELECT v.status, v.rule_version, v.source, v.rollout_id, v.reviewer FROM hit_verdicts v
                WHERE v.rule_id = :r AND v.field_name IS NOT DISTINCT FROM :f ORDER BY v.id""", r=rule_id, f=field)


def new_version(rule_id, prompt, start=False, user="alice"):
    """A human edit: a candidate with another prompt, activated (its rollout planned / running)."""
    from discovery_common import db, lifecycle
    with db.unit_of_work() as s:
        active = lifecycle.ensure_active_version(s, rule_id, user)
        version = lifecycle.create_version(s, rule_id, prompt=prompt, target=active["target"],
                                           matchers=active["matchers"], core_prompt_version=active["core_prompt_version"],
                                           model=active["model"], created_by=user)
        return lifecycle.activate_version(s, version["id"], user=user, start_rollout=start)


def rule_obj(env, name):
    return next(r for r in env.dbs.get_rules("llm") if r.name == name)


def test_history_is_written_only_when_the_verdict_changes(pg_scanner, monkeypatch):
    env = setup(pg_scanner, monkeypatch)
    contacts = env.rules["contacts"]
    assert len(run(env, monkeypatch)) == 3                          # one call per object
    assert history(contacts, "Email") == [("match", 1, "service", None, None)]
    assert run(env, monkeypatch) == []                              # nothing to ask, nothing logged
    _exec("UPDATE rule_hits SET note = 'n', category = 'x', severity = 'low', last_seen_at = now() "
          "WHERE rule_id = :r", r=contacts)
    assert len(history(contacts, "Email")) == 1                     # metadata only: no history row
    _exec("UPDATE rule_hits SET status = 'no_match', reviewer = 'bob', decided_tier = 'human' "
          "WHERE rule_id = :r AND field_name = 'Email'", r=contacts)
    assert history(contacts, "Email")[-1] == ("no_match", 1, "human", None, "bob")
    # every LLM hit has its history; keyword hits none
    assert q("SELECT count(*) FROM rule_hits h WHERE h.prompt_version IS NOT NULL AND NOT EXISTS "
             "(SELECT 1 FROM hit_verdicts v WHERE v.rule_id = h.rule_id AND v.subject_key = h.subject_key)") == [(0,)]


def test_a_new_version_keeps_the_old_verdicts_stale_until_a_migration_run(pg_scanner, monkeypatch):
    from discovery_common.mapping import from_code_object
    from test_scanner_llm_work_pg import obj
    env = setup(pg_scanner, monkeypatch)
    contacts = env.rules["contacts"]
    run(env, monkeypatch)
    result = new_version(contacts, "contact data v2")
    assert result["version"]["version"] == 2 and result["rollout"]["status"] == "planned"
    assert q("SELECT version, prompt FROM rules WHERE id = :r", r=contacts) == [(2, "contact data v2")]
    assert q("SELECT version, status FROM rule_versions WHERE rule_id = :r ORDER BY version", r=contacts) == [
        (1, "retired"), (2, "active")]
    # a normal run asks nothing: the v1 verdicts are stale, kept and scoring (stale-while-revalidate)
    assert run(env, monkeypatch) == []
    assert q("SELECT count(*), min(rule_version) FROM rule_hits WHERE rule_id = :r", r=contacts) == [(7, 1)]
    # FRESH work is still asked: a new object
    recs = [from_code_object(obj(name, fields), env.project.id)
            for name, fields in {**OBJECTS, "Lead": {"Phone": "string"}}.items()]
    env.dbs.save_main_scan(env.branch, "c2", recs, [], None)
    env.branch = env.dbs.get_branch_by_id(env.branch.id)
    calls = run(env, monkeypatch)
    assert len(calls) == 1 and "Lead" in calls[0]
    cov = pg_scanner.use_real("services.llm_coverage_service")
    cov.refresh(env.branch.id)
    assert q("SELECT candidates_total, answered, answered_stale FROM llm_coverage WHERE rule_id = :r",
             r=contacts) == [(8, 1, 7)]
    # LLM_REASK_INLINE (the behaviour before the lifecycle): a normal run asks the stale ones too
    pg_scanner.setenv(LLM_REASK_INLINE="true")
    assert len(run(env, monkeypatch)) == 3
    assert q("SELECT count(*) FROM rule_hits WHERE rule_id = :r AND rule_version = 2", r=contacts) == [(8,)]
    assert history(contacts, "Email")[-1][:2] == ("match", 2)


def test_rollout_controller_budget_priority_fresh_first_pause_and_done(pg_scanner, monkeypatch):
    from discovery_common import jobs
    env = setup(pg_scanner, monkeypatch)
    person = env.rules["person"]
    run(env, monkeypatch, names=("person",))                       # Client match, Token need_more_info, Order no_match
    # an open MR: rollouts migrate main snapshots only
    feature = _exec("""INSERT INTO gitlab_branches (branch_name, is_main, commit, scanned_commit, project_id, project_path,
                                                   created_at, updated_at)
                       VALUES ('feature', false, 'f1', 'f1', :p, 'grp/proj', now(), now()) RETURNING id""",
                    p=env.project.id).scalar()
    pg_scanner.setenv(LLM_API_URL="https://llm.example", LLM_ROLLOUT_SLICE_OBJECTS="1",
                      LLM_ROLLOUT_CALLS_PER_HOUR="2", LLM_ROLLOUT_FRESH_BACKLOG_MAX="2")
    lc = pg_scanner.load("services.lifecycle_service")
    handlers = pg_scanner.load("services.job_handlers")
    monkeypatch.setattr(handlers, "_enqueue_verify", lambda *a, **kw: None)
    result = new_version(person, "last name + phone, v2", start=True)
    rollout = result["rollout"]["id"]

    # fresh work first: more pending fresh llm_score jobs than LLM_ROLLOUT_FRESH_BACKLOG_MAX -> the rollout waits
    fresh = [jobs.enqueue("llm_score", {"branch_id": env.branch.id, "commit": f"x{i}"}, f"fresh:{i}") for i in range(3)]
    stats = lc.tick()
    assert stats["queued"] == 0 and "fresh work first" in stats["waiting"][rollout]
    _exec("UPDATE jobs SET status = 'done', finished_at = now() WHERE id = ANY(:ids)", ids=fresh)

    stats = lc.tick()
    assert stats["queued"] == 1
    (slice_job,) = q("SELECT id, payload, priority FROM jobs WHERE payload ? 'rollout_id'")
    assert slice_job.priority == -10 and slice_job.payload["branch_id"] == env.branch.id != feature
    assert slice_job.payload == {"branch_id": env.branch.id, "rule_ids": [person], "rollout_id": rollout,
                                 "max_objects": 1, "migration": True}
    assert lc.tick()["queued"] == 0                                 # one slice at a time (MAX_PARALLEL_JOBS 1)
    # a fresh job queued later is claimed before the slice (jobs.priority)
    other = jobs.enqueue("llm_score", {"branch_id": env.branch.id, "commit": "late"}, "fresh:late")
    assert jobs.claim("w", kinds=["llm_score"]).id == other
    _exec("UPDATE jobs SET status = 'done', finished_at = now() WHERE id = :i", i=other)

    calls = backend(monkeypatch, env)
    claimed = jobs.claim("w", kinds=["llm_score"])
    assert claimed.id == slice_job.id
    handlers.llm_score_job(claimed)
    jobs.complete(claimed.id, "w")
    # priority: the stale need_more_info verdict (Token) first
    assert len(calls) == 1 and "Token" in calls[0]
    token = q("""SELECT h.rule_version FROM rule_hits h JOIN objects o ON o.object_key = h.object_key
                 WHERE h.rule_id = :r AND o.name = 'Token' AND h.field_name IS NULL""", r=person)
    assert token == [(2,)]
    assert q("SELECT rollout_id FROM hit_verdicts WHERE rule_id = :r AND rule_version = 2 AND field_name IS NULL",
             r=person) == [(rollout,)]
    # budget: 2 calls an hour - one slice done, one more allowed, then the hour's budget is used
    assert lc.tick()["queued"] == 1
    claimed = jobs.claim("w", kinds=["llm_score"])
    handlers.llm_score_job(claimed)
    jobs.complete(claimed.id, "w")
    stats = lc.tick()
    assert stats["queued"] == 0 and "calls budget" in stats["waiting"][rollout]
    progress = q("SELECT progress FROM llm_rollouts WHERE id = :i", i=rollout)[0][0]
    assert progress["calls"] == 2 and progress["remaining_objects"] == 1 and progress["planned_objects"] == 3

    # pause / resume (humans); a paused rollout queues nothing; done once nothing is stale
    from discovery_common import db, lifecycle
    with db.unit_of_work() as s:
        assert lifecycle.rollout_action(s, rollout, "pause", user="alice", reason="look first")["status"] == "paused"
    _exec("UPDATE jobs SET finished_at = now() - interval '2 hours' WHERE payload ? 'rollout_id'")   # a new hour
    assert lc.tick()["queued"] == 0
    with db.unit_of_work() as s:
        lifecycle.rollout_action(s, rollout, "resume", user="alice")
    assert lc.tick()["queued"] == 1
    claimed = jobs.claim("w", kinds=["llm_score"])
    handlers.llm_score_job(claimed)
    jobs.complete(claimed.id, "w")
    assert lc.tick()["done"] == 1
    assert q("SELECT status, finished_at IS NOT NULL FROM llm_rollouts WHERE id = :i", i=rollout) == [("done", True)]
    assert q("SELECT count(*) FROM rule_hits WHERE rule_id = :r AND field_name IS NULL AND rule_version = 1",
             r=person) == [(0,)]


def test_rollout_slice_without_candidates_exhausts_the_branch_and_cancel_drops_slices(pg_scanner, monkeypatch):
    from discovery_common import db, jobs, lifecycle
    env = setup(pg_scanner, monkeypatch)
    contacts = env.rules["contacts"]
    run(env, monkeypatch)
    pg_scanner.setenv(LLM_API_URL="https://llm.example")
    lc = pg_scanner.load("services.lifecycle_service")
    handlers = pg_scanner.load("services.job_handlers")
    monkeypatch.setattr(handlers, "_enqueue_verify", lambda *a, **kw: None)
    rollout = new_version(contacts, "v2", start=True)["rollout"]["id"]
    # the stale verdicts are out of the new scope (another project): the slice finds nothing to ask
    _exec("UPDATE rule_hits SET project_id = :p WHERE rule_id = :r", p=env.project.id, r=contacts)
    _exec("""UPDATE rules SET scope = '{"object_re": "Nothing"}' WHERE id = :r""", r=contacts)
    assert lc.tick()["queued"] == 1
    backend(monkeypatch, env)
    claimed = jobs.claim("w", kinds=["llm_score"])
    handlers.llm_score_job(claimed)
    jobs.complete(claimed.id, "w")
    progress = q("SELECT progress FROM llm_rollouts WHERE id = :i", i=rollout)[0][0]
    assert list(progress["exhausted"]) == [str(env.branch.id)]
    assert lc.tick()["done"] == 1                                   # nothing left that can be asked

    rollout = new_version(contacts, "v3", start=True)["rollout"]["id"]
    _exec("""UPDATE rules SET scope = '{}' WHERE id = :r""", r=contacts)
    assert lc.tick()["queued"] == 1
    with db.unit_of_work() as s:
        assert lifecycle.rollout_action(s, rollout, "cancel", user="alice")["status"] == "cancelled"
    assert q("SELECT status FROM jobs WHERE payload ->> 'rollout_id' = :i", i=str(rollout)) == [("failed",)]
    # an activation supersedes the open rollout of the rule
    first = new_version(contacts, "v4")["rollout"]["id"]
    new_version(contacts, "v5")
    assert q("SELECT status FROM llm_rollouts WHERE id = :i", i=first) == [("cancelled",)]


def test_rollout_pauses_when_the_harness_agreement_drops(pg_scanner, monkeypatch):
    env = setup(pg_scanner, monkeypatch)
    contacts = env.rules["contacts"]
    run(env, monkeypatch)
    pg_scanner.setenv(LLM_API_URL="https://llm.example", LLM_ROLLOUT_QA_MIN_SAMPLES="5")
    lc = pg_scanner.load("services.lifecycle_service")
    rollout = new_version(contacts, "v2", start=True)["rollout"]["id"]
    for i in range(5):                                              # QA of v2: 1 of 5 agree
        _exec("""INSERT INTO llm_verifications (rule_id, rule_version, subject_key, object_key, project_id, sample,
                                                service_status, service_verdict, verdict, confidence, outcome)
                 VALUES (:r, 2, gen_random_uuid(), gen_random_uuid(), 1, 'qa', 'match', 'match', :v, 'high', 'final')""",
              r=contacts, v="match" if i == 0 else "no_match")
    assert lc.tick()["paused"] == 1
    status, reason = q("SELECT status, paused_reason FROM llm_rollouts WHERE id = :i", i=rollout)[0]
    assert status == "paused" and "agreement" in reason


def test_rollback_adopts_the_verdicts_of_the_old_version_without_model_calls(pg_scanner, monkeypatch):
    from discovery_common import db, lifecycle
    env = setup(pg_scanner, monkeypatch)
    contacts = env.rules["contacts"]
    run(env, monkeypatch)                                           # v1: Email, Phone match; the rest no_match
    new_version(contacts, "v2")

    def says_no(system, user, schema):
        names = schema["properties"]["fields"]["items"]["properties"]["name"]["enum"]
        return json.dumps({"fields": [{"name": n, "verdict": "no_match"} for n in names]})
    assert len(run(env, monkeypatch, migration=True, respond=says_no)) == 3
    assert q("SELECT count(*) FROM rule_hits WHERE rule_id = :r AND status = 'match'", r=contacts) == [(0,)]
    with db.unit_of_work() as s:
        result = lifecycle.rollback(s, contacts, 1, user="alice", start_rollout=True)
    assert result["version"]["version"] == 3 and result["version"]["source"] == "rollback:1" and result["adopted"] == 7
    assert q("SELECT version, status FROM rule_versions WHERE rule_id = :r ORDER BY version", r=contacts) == [
        (1, "retired"), (2, "rolled_back"), (3, "active")]
    assert q("SELECT prompt, version FROM rules WHERE id = :r", r=contacts) == [("contact data", 3)]
    assert q("SELECT field_name, status, rule_version FROM rule_hits WHERE rule_id = :r AND status = 'match' "
             "ORDER BY field_name", r=contacts) == [("Email", "match", 3), ("Phone", "match", 3)]
    assert history(contacts, "Email")[-1][:3] == ("match", 3, "adopt")
    assert run(env, monkeypatch, migration=True) == []              # nothing left to migrate: no model call


def test_rollback_with_batch_jobs_adopts_through_the_llm_relabel_job(pg_scanner, monkeypatch):
    """``batch_jobs=True`` (the API at scale): the rollback queues an ``llm_relabel`` adopt job instead of one UPDATE in
    its transaction; the job adopts the same verdicts in slices with the same history source, and the rollout
    controller waits for it."""
    from discovery_common import db, jobs, lifecycle
    env = setup(pg_scanner, monkeypatch)
    contacts = env.rules["contacts"]
    run(env, monkeypatch)
    new_version(contacts, "v2")

    def says_no(system, user, schema):
        names = schema["properties"]["fields"]["items"]["properties"]["name"]["enum"]
        return json.dumps({"fields": [{"name": n, "verdict": "no_match"} for n in names]})
    assert len(run(env, monkeypatch, migration=True, respond=says_no)) == 3
    with db.unit_of_work() as s:
        result = lifecycle.rollback(s, contacts, 1, user="alice", start_rollout=True, batch_jobs=True)
    assert result["adopted"] is None and result["adopt_job_id"] is not None and result["relabelled"] == 0
    assert q("SELECT kind, status, payload ->> 'action', (payload ->> 'rollout_id')::int FROM jobs WHERE id = :j",
             j=result["adopt_job_id"]) == [("llm_relabel", "pending", "adopt", result["rollout"]["id"])]
    assert q("SELECT count(*) FROM rule_hits WHERE rule_id = :r AND status = 'match'", r=contacts) == [(0,)]

    lifecycle_service = pg_scanner.load("services.lifecycle_service")
    stats = lifecycle_service.tick(pg_scanner.settings())            # the rollout waits for the adopt job
    assert stats["waiting"] == {result["rollout"]["id"]: "a relabel / adopt job of the rule is running"}

    handlers = pg_scanner.load("services.job_handlers")
    job = jobs.claim("control", kinds=["llm_relabel"], lease_seconds=None)
    handlers.llm_relabel_job(job)
    assert q("SELECT (progress ->> 'rows')::int, progress ->> 'phase' FROM jobs WHERE id = :j", j=job.id) == [(7, "done")]
    assert q("SELECT field_name, status, rule_version FROM rule_hits WHERE rule_id = :r AND status = 'match' "
             "ORDER BY field_name", r=contacts) == [("Email", "match", 3), ("Phone", "match", 3)]
    assert history(contacts, "Email")[-1][:4] == ("match", 3, "adopt", result["rollout"]["id"])
    jobs.complete(job.id, "control")
    assert run(env, monkeypatch, migration=True) == []              # nothing left to migrate: no model call


def test_core_prompts_pin_sync_candidate_and_relabel_on_activation(pg_scanner, monkeypatch):
    from discovery_common import db, lifecycle
    env = setup(pg_scanner, monkeypatch)
    contacts = env.rules["contacts"]
    run(env, monkeypatch)
    lc = pg_scanner.load("services.lifecycle_service")
    lc.sync_versions()
    assert q("SELECT core_prompt_version FROM rules WHERE id = :r", r=contacts) == [("rule3",)]
    # the verdicts were made by older rule prompts (rule2) and the active version is pinned to them (a deploy with
    # the new core prompts rule3): nothing is stale, a candidate is made
    _exec("UPDATE rule_hits SET prompt_version = 'rule2' WHERE rule_id = :r", r=contacts)
    _exec("UPDATE rules SET core_prompt_version = 'rule2' WHERE id = :r", r=contacts)
    _exec("UPDATE rule_versions SET core_prompt_version = 'rule2' WHERE rule_id = :r", r=contacts)
    assert env.dbs.get_llm_candidates(env.branch.id, rule_obj(env, "contacts"), migration=True) == []
    stats = lc.sync_versions()
    assert stats["candidates"] >= 1 and stats["activated"] == 0
    (cand,) = q("SELECT id, version, status, source, core_prompt_version, prompt FROM rule_versions "
                "WHERE rule_id = :r AND status = 'candidate'", r=contacts)
    assert (cand.version, cand.source, cand.core_prompt_version, cand.prompt) == (2, "core_bump", "rule3", "contact data")
    assert lc.sync_versions()["candidates"] == 0                    # one candidate, not one per tick
    # a classifier change does not touch the rule prompts family
    assert q("SELECT count(*) FROM rule_versions WHERE rule_id = :r AND status = 'candidate'",
             r=env.rules["llm"]) == [(0,)]
    # one verdict was asked by the new core prompts meanwhile: relabelled on activation, the others stale
    _exec("UPDATE rule_hits SET prompt_version = 'rule3' WHERE rule_id = :r AND field_name = 'Email'", r=contacts)
    with db.unit_of_work() as s:
        result = lifecycle.activate_version(s, cand.id, user="alice", start_rollout=False)
    assert result["relabelled"] == 1
    assert q("SELECT field_name FROM rule_hits WHERE rule_id = :r AND rule_version = 2", r=contacts) == [("Email",)]
    stale = env.dbs.get_llm_candidates(env.branch.id, rule_obj(env, "contacts"), migration=True)
    assert len(stale) == 6 and env.dbs.get_llm_candidates(env.branch.id, rule_obj(env, "contacts")) == []

    # LLM_CORE_BUMP_MODE=immediate: activated at once, its rollout running
    _exec("UPDATE rules SET core_prompt_version = 'rule2' WHERE id = :r", r=env.rules["person"])
    _exec("UPDATE rule_versions SET core_prompt_version = 'rule2' WHERE rule_id = :r", r=env.rules["person"])
    pg_scanner.setenv(LLM_CORE_BUMP_MODE="immediate")
    lc = pg_scanner.load("services.lifecycle_service")
    assert lc.sync_versions()["activated"] == 1
    assert q("SELECT version, core_prompt_version FROM rules WHERE id = :r", r=env.rules["person"]) == [(2, "rule3")]
    assert q("SELECT status, source FROM llm_rollouts WHERE rule_id = :r", r=env.rules["person"]) == [
        ("running", "core_bump")]


def test_model_change_policy(pg_scanner, monkeypatch):
    env = setup(pg_scanner, monkeypatch)
    contacts = env.rules["contacts"]
    pg_scanner.setenv(LLM_API_URL="https://llm.example", LLM_API_MODEL="model-a")
    lc = pg_scanner.load("services.lifecycle_service")
    lc.sync_versions()
    assert q("SELECT llm_model FROM rules WHERE id = :r", r=contacts) == [("model-a",)]
    assert q("SELECT value FROM llm_runtime WHERE key = 'service_model'") == [("model-a",)]
    pg_scanner.setenv(LLM_API_MODEL="model-b")                       # a deploy with another service model
    lc = pg_scanner.load("services.lifecycle_service")
    lc.sync_versions()
    assert q("SELECT source, model, status FROM rule_versions WHERE rule_id = :r AND status = 'candidate'",
             r=contacts) == [("model_change", "model-b", "candidate")]
    assert q("SELECT llm_model FROM rules WHERE id = :r", r=contacts) == [("model-a",)]     # still pinned
    pg_scanner.setenv(LLM_API_MODEL="model-c", LLM_MODEL_CHANGE_POLICY="ignore")
    lc = pg_scanner.load("services.lifecycle_service")
    lc.sync_versions()
    assert q("SELECT llm_model FROM rules WHERE id = :r", r=contacts) == [("model-c",)]     # recorded, nothing stale


def test_activation_expires_the_open_verify_items_of_older_versions_and_items_record_the_verify_prompt(
        pg_scanner, monkeypatch):
    from discovery_common import jobs
    env = setup(pg_scanner, monkeypatch)
    contacts = env.rules["contacts"]
    run(env, monkeypatch)
    verify = pg_scanner.load("services.verify_service")
    job = jobs.enqueue("llm_verify", {"branch_id": env.branch.id}, "v:1")
    pg_scanner.setenv(LLM_QA_SAMPLE_RATE="1")
    stats = verify.prepare(job, env.branch, [rule_obj(env, "contacts")])
    assert stats["items"] > 0
    contexts = q("SELECT verify FROM llm_work_items WHERE purpose = 'verify' AND rule_id = :r", r=contacts)
    assert all(c[0]["verify_prompt_version"] == verify.VERIFY_PROMPT_VERSION for c in contexts)
    result = new_version(contacts, "v2")
    assert result["expired_verify_items"] == stats["items"]
    assert q("SELECT DISTINCT status, error FROM llm_work_items WHERE purpose = 'verify' AND rule_id = :r",
             r=contacts) == [("expired", "superseded by rule v2")]


def test_take_over_leaves_rollout_slices_to_the_service(pg_scanner, monkeypatch):
    from discovery_common import db, jobs, llm_work
    env = setup(pg_scanner, monkeypatch)
    slice_id = jobs.enqueue("llm_score", {"branch_id": env.branch.id, "rule_ids": [env.rules["contacts"]],
                                          "rollout_id": 1, "max_objects": 5, "migration": True}, "s", priority=-10)
    with db.unit_of_work() as s:
        assert llm_work.take_over(s, "agent", job_id=slice_id) == []
