"""LLM rule coverage (table llm_coverage, GET /llm_progress) against a real Postgres
(TEST_DATABASE_URL; skipped without it): rows after a run, after a snapshot change (stale until
recounted), the llm_coverage job's bounded recount, external runs and the scheduler."""

import pytest
from types import SimpleNamespace

from test_scanner_llm_work_pg import OBJECTS, _exec, answer, claim_and_submit, new_job, obj, q, setup, use_backend


def coverage(branch_id):
    return {r.name: (r.candidates_total, r.answered, r.pending_external, r.failed, r.commit, r.rule_version)
            for r in q("SELECT r.name, c.* FROM llm_coverage c JOIN rules r ON r.id = c.rule_id "
                       "WHERE c.branch_id = :b", b=branch_id)}


@pytest.fixture
def env(pg_scanner, monkeypatch):
    env = setup(pg_scanner, monkeypatch)
    env.cov = pg_scanner.use_real("services.llm_coverage_service")
    env.ids = sorted(env.rules.values())
    return env


def flaky(system, user, schema):
    if "Token" in user:
        raise RuntimeError("model down")
    return answer(system, user, schema)


def test_candidate_condition_is_the_one_of_the_runs(pg_scanner):
    dbs = pg_scanner.db
    norm = lambda sql: " ".join(sql.split())                    # noqa: E731
    for sql in (dbs.LLM_CANDIDATES_SQL, dbs.LLM_OBJECT_CANDIDATES_SQL):
        assert norm(dbs.LLM_CANDIDATE_COND) in norm(sql.text)
    # the coverage counts both classes with the same literal conditions (stale = MIGRATION and not FRESH)
    from discovery_common import lifecycle
    cov = pg_scanner.use_real("services.llm_coverage_service")
    for sql in (cov.FIELD_COUNTS_SQL, cov.OBJECT_COUNTS_SQL):
        assert norm(lifecycle.FRESH_COND) in norm(sql.text) and norm(lifecycle.MIGRATION_COND) in norm(sql.text)


def test_counts_sql_groups_only_by_what_the_rule_matches(pg_scanner):
    """The fully grouped FIELD_COUNTS_SQL / OBJECT_COUNTS_SQL make one group per field of every object; the query of
    a rule groups only by the columns its patterns (or the classifier's field filter) look at."""
    cov = pg_scanner.use_real("services.llm_coverage_service")
    norm = lambda sql: " ".join(sql.text.split())                   # noqa: E731
    rule = lambda **kw: SimpleNamespace(**{"target": "field", "category": "pii", "scope": {}, **kw})   # noqa: E731
    classifier = norm(cov.counts_sql(rule(category=None)))
    assert "f.field_name AS field_name, f.field_type AS field_type, NULL::text AS name, NULL::text AS type" in classifier
    plain = norm(cov.counts_sql(rule()))
    assert "NULL::text AS field_name, NULL::text AS field_type, NULL::text AS name, NULL::text AS type" in plain
    assert "JOIN object_fields f" in plain
    by_object = norm(cov.counts_sql(rule(target="object", scope={"object_type_re": "table"})))
    assert "NULL::text AS field_name, NULL::text AS field_type, o.name AS name, o.type AS type" in by_object
    assert "JOIN object_fields f" not in by_object
    by_field = norm(cov.counts_sql(rule(scope={"field_re": "pass", "object_re": "User"})))
    assert "f.field_name AS field_name, f.field_type AS field_type, o.name AS name, o.type AS type" in by_field
    assert norm(cov.FIELD_COUNTS_SQL) == by_field
    # all of them count the same classes as the runs
    from discovery_common import lifecycle
    for sql in (classifier, plain, by_object, by_field):
        assert " ".join(lifecycle.FRESH_COND.split()) in sql and " ".join(lifecycle.MIGRATION_COND.split()) in sql


def test_coverage_after_runs_snapshot_change_and_recount(env, monkeypatch):
    from appsec_discovery.ai import FakeLlmBackend
    from discovery_common.mapping import from_code_object

    branch = env.branch
    # nothing asked yet: person (object rule) 3 objects, contacts (field rule) 7 fields, the
    # classifier only the 6 fields it sends (not "id")
    assert env.cov.refresh(branch.id) == 3
    assert coverage(branch.id) == {"person": (3, 0, 0, 0, "c1", 1), "contacts": (7, 0, 0, 0, "c1", 1),
                                   "llm": (6, 0, 0, 0, "c1", coverage(branch.id)["llm"][5])}
    assert env.cov.stale_pairs(env.scan.llm_rules()) == []

    # a service run whose model fails on Token: its subjects stay unanswered, counted as failed
    use_backend(monkeypatch, env, FakeLlmBackend(flaky))
    with pytest.raises(env.scan.ScanError, match=r"LLM rule 'person': 1 of 3 objects failed: RuntimeError: model down \(1\)"):
        env.scan.run_selected_llm_rules(branch, env.ids)
    cov = coverage(branch.id)
    assert {n: c[:4] for n, c in cov.items()} == {"person": (3, 2, 0, 1), "contacts": (7, 6, 0, 1),
                                                  "llm": (6, 5, 0, 1)}
    # a recount without a run keeps the failed count while the row is fresh
    env.cov.refresh(branch.id)
    assert coverage(branch.id)["person"][:4] == (3, 2, 0, 1)

    use_backend(monkeypatch, env, FakeLlmBackend(answer))
    assert env.scan.run_selected_llm_rules(branch, env.ids) is True
    assert {n: c[:4] for n, c in coverage(branch.id).items()} == {
        "person": (3, 3, 0, 0), "contacts": (7, 7, 0, 0), "llm": (6, 6, 0, 0)}

    # a new snapshot (commit c2, one more object): the rows are stale until recounted
    recs = [from_code_object(obj(name, fields), env.project.id) for name, fields in
            {**OBJECTS, "Account": {"iban": "string"}}.items()]
    env.dbs.save_main_scan(branch, "c2", recs, [], None)
    stale = env.cov.stale_pairs(env.scan.llm_rules())
    assert sorted((b, r, rank) for b, r, rank in stale) == [(branch.id, r, 1) for r in env.ids]
    stats = env.cov.refresh_stale(max_pairs=2)
    assert (stats["pairs"], stats["recounted"], stats["more"]) == (2, 2, True)     # bounded: requeued
    assert env.cov.refresh_stale() == {"pairs": 1, "recounted": 1, "failed": 0, "more": False}
    assert {n: c[:5] for n, c in coverage(branch.id).items()} == {
        "person": (4, 3, 0, 0, "c2"), "contacts": (8, 7, 0, 0, "c2"), "llm": (7, 6, 0, 0, "c2")}
    assert env.cov.stale_pairs(env.scan.llm_rules()) == []

    # a rule edit (new version): its machine verdicts are asked again, a human decision stays answered
    _exec("UPDATE rule_hits SET reviewer = 'alice', status = 'match' WHERE rule_id = :r AND field_name = 'Email'",
          r=env.rules["contacts"])
    _exec("UPDATE rules SET version = 2 WHERE id = :r", r=env.rules["contacts"])
    assert [(r, rank) for _, r, rank in env.cov.stale_pairs(env.scan.llm_rules())] == [(env.rules["contacts"], 1)]
    env.cov.refresh_stale()
    assert coverage(branch.id)["contacts"] == (8, 1, 0, 0, "c2", 2)

    # the 6 machine verdicts of v1 are stale (kept, scoring) until a rollout asks them again: a normal run does not
    # (of the 7 remaining, the new field iban has no verdict yet: fresh)
    assert q("SELECT answered_stale FROM llm_coverage WHERE branch_id = :b AND rule_id = :r",
             b=branch.id, r=env.rules["contacts"]) == [(6,)]
    # an external run (LLM_REASK_INLINE: the stale verdicts too) holds the remaining objects (counted after the
    # prepare), its answers fill them
    env.scan.get_settings().llm_reask_inline = True
    job_id = new_job([env.rules["contacts"]], branch_id=branch.id)
    env.work.prepare_external_run(job_id, branch, [env.rules["contacts"]])
    assert coverage(branch.id)["contacts"][:4] == (8, 1, 7, 0)
    claim_and_submit(job_id)
    env.work.apply_answers(job_id)
    assert coverage(branch.id)["contacts"][:4] == (8, 8, 0, 0)

    # rows with remaining subjects are recounted after RECHECK_H (verdicts stored through another branch)
    _exec("UPDATE llm_coverage SET answered = 2, computed_at = now() - interval '7 hours' WHERE rule_id = :r",
          r=env.rules["person"])
    assert [(r, rank) for _, r, rank in env.cov.stale_pairs(env.scan.llm_rules())] == [(env.rules["person"], 2)]
    env.cov.refresh_stale()
    assert coverage(branch.id)["person"][:2] == (4, 3)


def test_coverage_scope_inventory_and_snapshot_hook(env, monkeypatch):
    branch = env.branch
    # a rule whose project_re does not match the project: nothing to ask (total 0, current)
    _exec("""UPDATE rules SET scope = '{"project_re": "other/"}' WHERE id = :r""", r=env.rules["person"])
    _exec("""UPDATE rules SET scope = '{"field_re": "Phone|Email"}' WHERE id = :r""", r=env.rules["contacts"])
    env.scan.record_llm_coverage(branch.id)
    cov = coverage(branch.id)
    assert cov["person"][:2] == (0, 0) and cov["contacts"][:2] == (2, 0)

    # inventory projects get no coverage rows (no LLM rules run there) and are not recounted
    _exec("DELETE FROM llm_coverage")
    _exec("UPDATE gitlab_projects SET scan_mode = 'inventory'")
    assert env.cov.refresh(branch.id) == 0 and coverage(branch.id) == {}
    assert env.cov.stale_pairs(env.scan.llm_rules()) == []


def test_llm_coverage_job_and_scheduler(env, pg_scanner):
    from discovery_common import jobs
    from discovery_common.jobs import Job

    handlers = pg_scanner.load("services.job_handlers")
    env.cov.SLICE_PAIRS = 1
    with pytest.raises(jobs.RequeueJob):
        handlers.llm_coverage_job(Job(id=0, kind="llm_coverage", payload={}))
    env.cov.SLICE_PAIRS = 200
    handlers.llm_coverage_job(Job(id=0, kind="llm_coverage", payload={}))      # the rest: done
    assert len(coverage(env.branch.id)) == 3

    pg_scanner.setenv(GC_INTERVAL_HOURS="0", LLM_COVERAGE_INTERVAL_S="300")
    supervisor = pg_scanner.load("supervisor")
    now = [0.0]
    scheduler = supervisor.Scheduler(pg_scanner.settings(), every=10, clock=lambda: now[0])
    scheduler.tick()
    now[0] = 10
    scheduler.tick()                                             # still pending: deduplicated
    assert q("SELECT kind, status FROM jobs WHERE kind = 'llm_coverage'") == [("llm_coverage", "pending")]
    assert "llm_coverage" in supervisor.CONTROL_KINDS
