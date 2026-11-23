"""Alembic migrations: baseline adoption of a create_all database, 0002 data migration,
models == migrated schema, offline SQL generation."""

import io

import pytest

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from sqlmodel import SQLModel

import discovery_common.models  # noqa: F401
from discovery_common import keys, testing
from discovery_common.migrate import alembic_config

LEGACY_SEED = """
INSERT INTO gitlab_projects (id, project_name, full_path, visibility, created_at, updated_at)
VALUES (1, 'proj', 'grp/proj', 'private', now(), now()), (2, 'other', 'grp/other', 'private', now(), now());

INSERT INTO gitlab_branches (id, branch_name, is_main, commit, project_id, project_path, created_at, updated_at) VALUES
  (1, 'main',    true,  'c1', 1, 'grp/proj', now(), now()),
  (2, 'feature', false, 'c2', 1, 'grp/proj', now(), now()),
  (3, 'merged',  false, 'c3', 1, 'grp/proj', now(), now()),
  (4, 'feature', false, 'c0', 1, 'grp/proj', now() - interval '2 days', now() - interval '2 days'),
  (5, 'master',  true,  'c5', 1, 'grp/proj', now() - interval '9 days', now() - interval '9 days'),
  (6, 'main',    true,  'd1', 2, 'grp/other', now(), now());
SELECT setval('gitlab_branches_id_seq', 6);

INSERT INTO gitlab_mrs (id, project_id, project_path, source_branch_id, source_branch, source_branch_commit,
                        target_branch_id, target_branch, target_branch_commit, mr_id, title, state, created_at, updated_at) VALUES
  (1, 1, 'grp/proj', 2, 'feature', 'c2', 1, 'main', 'c1', 1, 'mr', 'opened', now(), now()),
  (2, 1, 'grp/proj', 4, 'feature', 'c0', 1, 'main', 'c1', 1, 'mr old row', 'opened', now() - interval '1 day', now() - interval '1 day'),
  (3, 1, 'grp/proj', 3, 'merged', 'c3', 1, 'main', 'c1', 2, 'merged mr', 'merged', now(), now());

INSERT INTO discovery_objects (id, project_id, branch_id, hash, name, type, parser, props, file, line) VALUES
  (1, 1, 1, 'h1', 'User', 'dto', 'go', '{"path": "/x", "a": "b"}', '/u.go', 3),
  (2, 1, 2, 'h2', 'Feature', 'dto', 'go', '{}', '/f.go', 1),
  (3, 1, 5, 'h3', 'Old', 'dto', 'go', NULL, '/o.go', 1),
  (4, 2, 6, 'h4', 'Empty', 'route', 'swagger', 'null', '/s.yaml', 1);

INSERT INTO discovery_object_fields (id, object_id, name, type, file, line) VALUES
  (1, 1, 'email', 'string', '/u.go', 5),
  (2, 1, 'id', 'int', '/u.go', NULL),
  (3, 2, 'secret', 'string', '/f.go', 2);

INSERT INTO discovery_llm_scores (field_id, model, prompt_ver, severity, tag, status, created_at, updated_at) VALUES
  (1, 'model-a', '1.0.0', 'medium', 'pii', 'tp',  now() - interval '3 days', now() - interval '3 days'),
  (1, 'model-b', '1.0.1', 'medium', 'pii', 'new', now(), now()),
  (2, 'model-b', '1.0.1', 'medium', 'auth', 'new', now(), now()),
  (3, 'model-b', '1.0.1', 'high', 'pii', 'fp', now(), now());

INSERT INTO discovery_score_rules (project, object, object_type, field, field_type, severity, tag, status) VALUES
  ('grp/', NULL, NULL, 'email', '', 'high', 'pii', 'mark'),
  ('', 'Foo', 'dto', NULL, NULL, NULL, NULL, 'skip');

INSERT INTO scorerule (service_re, object_type_re, object_re, field_re, field_type_re, risk_score, status) VALUES
  ('grp/.*', NULL, 'User', 'pass', '', 8, 'active'),
  ('', '', 'Tmp', NULL, NULL, 0, 'skip');

INSERT INTO discovery_scans (project_id, branch_id, project_path, branch_name, branch_commit, scanner, rules_version, parsers, scanned_at) VALUES
  (1, 1, 'grp/proj', 'main', 'c1', 'discovery', '1.0.0', '{all}', now()),
  (1, 1, 'grp/proj', 'main', 'c1', 'discovery', '1.0.0', '{all}', now()),
  (1, 3, 'grp/proj', 'merged', 'c3', 'discovery', '1.0.0', NULL, now());
"""


def _create_legacy_schema(url):
    """What the services used to create with create_all: the baseline revision without
    alembic_version (= an unmigrated legacy database)."""
    testing.migrate(url, "0001_baseline")
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE alembic_version"))
        conn.execute(text(LEGACY_SEED))
    return engine


def test_legacy_database_is_adopted_and_migrated(pg_url, monkeypatch):
    monkeypatch.setenv("LLM_PROMPT", "Is it private? It's a test")
    monkeypatch.setenv("LLM_PROMPT_VER", "1.0.1")
    engine = _create_legacy_schema(pg_url)

    testing.migrate(pg_url)    # baseline is idempotent: adopts the existing tables

    with engine.connect() as conn:
        q = lambda sql, **p: conn.execute(text(sql), p).all()   # noqa: E731

        # at the head of the migration chain, with exactly the tables of the models (no leftovers of the legacy schema)
        head = ScriptDirectory.from_config(alembic_config()).get_current_head()
        assert q("SELECT version_num FROM alembic_version") == [(head,)]
        tables = {r[0] for r in q("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")}
        assert tables == set(SQLModel.metadata.tables) | {"alembic_version"}
        assert tables >= {"gitlab_projects", "gitlab_branches", "gitlab_mrs", "discovery_scans", "objects",
                          "object_fields", "branch_objects", "rules", "rule_hits", "jobs", "ingest_batches",
                          "ingest_chunks", "api_tokens", "llm_work_items", "llm_coverage", "prompt_trials",
                          "prompt_trial_items", "prompt_proposals", "llm_verifications", "rule_versions", "llm_runtime",
                          "hit_verdicts", "llm_rollouts", "stats_snapshots", "llm_rate_buckets"}
        assert {r[0] for r in q("SELECT typname FROM pg_type WHERE typtype = 'e'")} == set()

        # objects of main branches only (branch 5 was demoted: older second main)
        user_key = keys.object_key(1, "go", "h1")
        user_hash = keys.content_hash(user_key, {"email": "string", "id": "int"}, {"path": "/x", "a": "b"})
        empty_key = keys.object_key(2, "swagger", "h4")
        assert sorted(q("SELECT content_hash, object_key, name, props FROM objects ORDER BY name")) == sorted([
            (keys.content_hash(empty_key, {}, {}), empty_key, "Empty", None),
            (user_hash, user_key, "User", {"path": "/x", "a": "b"}),
        ])
        assert sorted(q("SELECT field_name, field_type, field_key, project_id FROM object_fields WHERE content_hash = :h",
                        h=user_hash)) == [
            ("email", "string", keys.field_key(user_key, "email"), 1), ("id", "int", keys.field_key(user_key, "id"), 1)]
        assert q("SELECT branch_id, is_main, change, line, field_lines FROM branch_objects WHERE object_key = :k",
                 k=user_key) == [(1, True, None, 3, {"email": 5})]
        assert q("SELECT count(*) FROM branch_objects")[0][0] == 2

        # rules
        # (0013 adds the default rule db-tables-with-client-data: not part of the legacy data)
        rules = {r.name: r for r in conn.execute(text(
            "SELECT * FROM rules WHERE updated_by IS DISTINCT FROM 'migration:0013_example_rules'")).all()}
        assert set(rules) == {"score_rule:1", "score_rule:2", "kw-fields", "kw-props", "llm",       # 0028: short names
                              "scorerule:1", "scorerule:2", "manual:labels"}
        # an existing install (it has projects) keeps the keyword scoring on (0028 disables it on new ones only)
        assert rules["kw-fields"].enabled and rules["kw-props"].enabled
        assert (rules["manual:labels"].kind, rules["manual:labels"].enabled) == ("manual", True)     # 0005
        assert q("SELECT DISTINCT scan_mode FROM gitlab_projects") == [("rules",)]
        assert all(r.deleted_at is None and r.created_at is not None for name, r in rules.items() if name != "llm")
        r1, r2, llm = rules["score_rule:1"], rules["score_rule:2"], rules["llm"]
        assert (r1.kind, r1.mode, r1.target, r1.severity, r1.category) == ("keyword", "auto", "field", "high", "pii")
        assert r1.scope == {"project_re": "grp/", "field_re": "email", "legacy_status": "mark"}
        assert (r2.target, r2.scope) == ("object", {"object_re": "Foo", "object_type_re": "dto", "action": "exclude",
                                                    "legacy_status": "skip"})
        assert (llm.kind, llm.mode, llm.target, llm.prompt, llm.scope, llm.version) == (
            "llm", "review", "field", "Is it private? It's a test", {"prompt_ver": "1.0.1", "source": "env"}, 1)
        # 0028: the env-managed rule is gone - soft-deleted (no human decision) or disabled (decided hits kept)
        assert llm.enabled is False and llm.updated_by == "migration:0028_builtin_rules"
        decided = q("SELECT count(*) FROM rule_hits WHERE rule_id = :r AND reviewer IS NOT NULL", r=llm.id)[0][0]
        assert (llm.deleted_at is None) == bool(decided)
        # the API's legacy scorerule rows (0003): regexes -> scope, risk_score -> severity, skip -> exclude
        s1, s2 = rules["scorerule:1"], rules["scorerule:2"]
        assert (s1.kind, s1.mode, s1.target, s1.severity, s1.updated_by) == ("keyword", "auto", "field", "high", "migrated")
        assert s1.scope == {"project_re": "grp/.*", "object_re": "User", "field_re": "pass", "action": "score",
                            "legacy_risk_score": 8}
        assert (s2.target, s2.severity, s2.scope) == ("object", "info", {"object_re": "Tmp", "action": "exclude",
                                                                         "legacy_risk_score": 0})

        # LLM scores -> hits (main objects only; decided rows win over newer 'new' rows)
        hits = {r.field_name: r for r in conn.execute(text("SELECT * FROM rule_hits")).all()}
        assert set(hits) == {"email", "id"}
        email, id_ = hits["email"], hits["id"]
        assert (email.rule_id, email.subject_key, email.object_key, email.project_id) == (
            llm.id, keys.field_key(user_key, "email"), user_key, 1)
        assert (email.status, email.reviewer, email.model, email.category) == ("match", "migrated", "model-a", "pii")
        assert (id_.status, id_.reviewer, id_.category) == ("pending_review", None, "auth")
        assert "alerted_at" not in email._mapping                         # 0022: alerting removed
        # 0018: the hashes of what the model saw, from the current snapshot (no re-ask by the migration)
        assert (email.names_hash, email.subject_hash) == (
            keys.names_hash("User", ["email"]), keys.field_subject_hash("email", "string", None, None))
        assert (id_.names_hash, id_.subject_hash) == (
            keys.names_hash("User", ["id"]), keys.field_subject_hash("id", "int", None, None))

        # branches: duplicates, demoted second main and untracked branches are gone
        assert q("SELECT id, branch_name, is_main, scanned_commit, processed_at FROM gitlab_branches ORDER BY id") == [
            (1, "main", True, None, None), (2, "feature", False, None, None), (6, "main", True, None, None)]
        # MRs: deduplicated, merged one closed, its released branch reference nulled
        assert q("SELECT id, mr_id, state, source_branch_id, closed_at IS NOT NULL FROM gitlab_mrs ORDER BY id") == [
            (1, 1, "opened", 2, False), (3, 2, "merged", None, True)]
        # scans of removed branches cascade away, duplicates removed
        assert q("SELECT branch_id, count(*) FROM discovery_scans GROUP BY branch_id") == [(1, 1)]
        assert q("SELECT count(*) FROM information_schema.columns "
                 "WHERE table_name = 'gitlab_projects' AND column_name = 'gitlab_id'") == [(1,)]

        # the models describe exactly the migrated schema
        context = MigrationContext.configure(conn, opts={"compare_type": True})
        assert compare_metadata(context, SQLModel.metadata) == []

    engine.dispose()


def test_fresh_database_migrates_and_matches_models(pg_url):
    testing.migrate(pg_url)
    engine = create_engine(pg_url)
    with engine.connect() as conn:
        assert compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), SQLModel.metadata) == []
        indexes = {r[0] for r in conn.execute(text("SELECT indexname FROM pg_indexes WHERE schemaname = 'public'"))}
        assert {"objects_key", "objects_proj_name", "fields_proj_name", "fields_key", "fields_name_trgm", "bo_content",
                "bo_mr_rows", "hits_subject", "hits_queue", "branches_one_main", "mrs_open", "mrs_source",
                "mrs_target_open", "gitlab_projects_gitlab_id_key", "gitlab_branches_project_id_branch_name_key",
                "gitlab_mrs_project_id_mr_id_key", "branch_objects_pkey", "rule_hits_pkey", "object_fields_pkey",
                "rules_name_live", "jobs_pkey", "jobs_dedup_active", "jobs_ready", "jobs_lease",
                "jobs_kind_created", "llm_work_claim", "llm_work_job", "llm_work_open", "jobs_scan_branch_subject",
                "jobs_scan_mr_subject", "jobs_llm_branch_subject", "llm_coverage_pkey",
                # 0030 (scale): hits by object / project, presence and retention, name-ordered objects, claim by kind
                "hits_object", "hits_project_rule", "hits_live_seen", "hits_live_queue", "hits_seen", "objects_name_key",
                "jobs_ready_kind", "stats_snapshots_pkey"} <= indexes
        assert conn.execute(text("SELECT reloptions FROM pg_class WHERE relname = 'branch_objects'")).scalar() == ["fillfactor=80"]
        assert set(conn.execute(text("SELECT reloptions FROM pg_class WHERE relname = 'rule_hits'")).scalar()) == {
            "fillfactor=85", "autovacuum_vacuum_scale_factor=0.02", "autovacuum_analyze_scale_factor=0.01"}
    engine.dispose()


def test_0016_moves_external_llm_runs_to_llm_prepare(pg_url):
    testing.migrate(pg_url, "0015_jobs_subject")
    engine = create_engine(pg_url)
    with engine.begin() as conn:
        conn.execute(text("""INSERT INTO jobs (kind, payload, dedup_key, status) VALUES
            ('llm_score', '{"branch_id": 1, "rule_ids": [5], "executor": "external"}', 'ext', 'pending'),
            ('llm_score', '{"branch_id": 1, "rule_ids": [5], "executor": "external"}', 'ext-old', 'done'),
            ('llm_score', '{"branch_id": 1, "rule_ids": [5]}', 'service', 'pending'),
            ('llm_score', '{"branch_id": 1, "commit": "c1"}', 'auto', 'pending')"""))
    testing.migrate(pg_url)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT dedup_key, kind, status FROM jobs ORDER BY id")).all() == [
            ("ext", "llm_prepare", "pending"), ("ext-old", "llm_prepare", "done"),
            ("service", "llm_score", "pending"), ("auto", "llm_score", "pending")]
    engine.dispose()


def test_0017_llm_coverage_table_and_kind(pg_url):
    testing.migrate(pg_url)
    engine = create_engine(pg_url)
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO gitlab_projects (id, project_name, full_path, visibility, created_at, updated_at)
                VALUES (1, 'p', 'g/p', 'private', now(), now());
            INSERT INTO gitlab_branches (id, branch_name, is_main, commit, scanned_commit, project_id, project_path,
                                         created_at, updated_at) VALUES (1, 'main', true, 'c1', 'c1', 1, 'g/p', now(), now());
            INSERT INTO llm_coverage (branch_id, rule_id, rule_version, prompt_version, commit, candidates_total, answered)
                SELECT 1, id, version, 'core', 'c1', 10, 4 FROM rules WHERE kind = 'llm' LIMIT 1;
            INSERT INTO jobs (kind, payload, dedup_key) VALUES ('llm_coverage', '{}', 'llm_coverage')"""))
    with engine.begin() as conn:
        assert conn.execute(text("SELECT candidates_total, answered, pending_external, failed FROM llm_coverage")).all() \
            == [(10, 4, 0, 0)]
        conn.execute(text("DELETE FROM gitlab_branches"))            # rows go with their branch
        assert conn.execute(text("SELECT count(*) FROM llm_coverage")).scalar() == 0
    with engine.begin() as connection:                               # downgrade
        config = alembic_config()
        config.attributes["connection"] = connection
        command.downgrade(config, "0016_llm_prepare")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM jobs WHERE kind = 'llm_coverage'")).scalar() == 0
        assert conn.execute(text("SELECT to_regclass('llm_coverage')")).scalar() is None
    engine.dispose()


def test_upgrade_is_idempotent_at_head(pg_url):
    testing.migrate(pg_url)
    testing.migrate(pg_url)


def test_0019_prompt_trials_tables_and_kind(pg_url):
    testing.migrate(pg_url)
    engine = create_engine(pg_url)
    with engine.begin() as conn:
        rule = conn.execute(text("SELECT id FROM rules WHERE kind = 'llm' LIMIT 1")).scalar()
        conn.execute(text("INSERT INTO jobs (kind, payload, dedup_key) VALUES ('llm_trial', '{}', 'llm_trial:1')"))
        trial = conn.execute(text("""INSERT INTO prompt_trials (rule_id, rule_version, prompt_version, candidate_prompt,
                                     prompt_hash) VALUES (:r, 1, 'core', 'p', 'h') RETURNING id"""), {"r": rule}).scalar()
        conn.execute(text("""INSERT INTO prompt_trial_items (trial_id, subject_key, object_key, content_hash, project_id,
                             role, expected) VALUES (:t, gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), 1,
                             'target', 'match')"""), {"t": trial})
        conn.execute(text("""INSERT INTO prompt_proposals (rule_id, base_version, prompt, prompt_hash, trial_id, rationale)
                             VALUES (:r, 1, 'p', 'h', :t, 'why')"""), {"r": rule, "t": trial})
        assert conn.execute(text("SELECT status, rerun_current FROM prompt_trials")).all() == [("queued", True)]
        assert conn.execute(text("SELECT status FROM prompt_proposals")).all() == [("open",)]
    with engine.begin() as conn:
        with pytest.raises(Exception):
            conn.execute(text("INSERT INTO prompt_trial_items (trial_id, subject_key, object_key, content_hash, "
                              "project_id, role, expected) VALUES (:t, gen_random_uuid(), gen_random_uuid(), "
                              "gen_random_uuid(), 1, 'target', 'yes')"), {"t": trial})
    with engine.begin() as connection:                               # downgrade
        config = alembic_config()
        config.attributes["connection"] = connection
        command.downgrade(config, "0018_llm_reask")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM jobs WHERE kind = 'llm_trial'")).scalar() == 0
        assert conn.execute(text("SELECT to_regclass('prompt_trials')")).scalar() is None
        assert conn.execute(text("SELECT count(*) FROM information_schema.columns WHERE table_name = 'rule_hits' "
                                 "AND column_name = 'machine_status'")).scalar() == 0
    engine.dispose()


def test_0020_llm_tiers_backfill_and_indexes(pg_url):
    """decided_tier: human for reviewed hits, weak otherwise (0020; 0021 renames the tiers); verify items have
    their own open-item index (one per hit) and do not collide with the score items of the same object."""
    testing.migrate(pg_url, "0019_prompt_trials")
    engine = create_engine(pg_url)
    with engine.begin() as conn:
        rule = conn.execute(text("SELECT id FROM rules WHERE kind = 'llm' LIMIT 1")).scalar()
        conn.execute(text("""INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, rule_version, status,
                             reviewer) VALUES (:r, gen_random_uuid(), 1, gen_random_uuid(), 1, 'confirmed', 'alice'),
                             (:r, gen_random_uuid(), 1, gen_random_uuid(), 1, 'rejected', NULL)"""), {"r": rule})
    testing.migrate(pg_url, "0020_llm_tiers")
    with engine.begin() as conn:
        assert sorted(conn.execute(text("SELECT reviewer IS NOT NULL, decided_tier, asked_by_model FROM rule_hits "
                                        "WHERE rule_id = :r"), {"r": rule}).all()) == [(False, "weak", False),
                                                                                       (True, "human", False)]
        job = conn.execute(text("INSERT INTO jobs (kind, payload, dedup_key) VALUES ('llm_verify', '{}', 'v:1') "
                                "RETURNING id")).scalar()
        run = conn.execute(text("INSERT INTO jobs (kind, payload, dedup_key) VALUES ('llm_prepare', '{}', 'p:1') "
                                "RETURNING id")).scalar()
        item = ("INSERT INTO llm_work_items (job_id, rule_id, rule_version, project_id, branch_id, object_key, "
                "content_hash, prompt_hash, user_prompt, purpose, subject_key) VALUES (:j, :r, 1, 1, 1, :o, :o, 'h', "
                "'u', :p, :s)")
        o = "00000000-0000-0000-0000-000000000001"
        conn.execute(text(item), {"j": run, "r": rule, "o": o, "p": "score", "s": None})
        conn.execute(text(item), {"j": job, "r": rule, "o": o, "p": "verify", "s": o})
    with engine.begin() as conn:
        with pytest.raises(Exception):          # one open verify item per hit
            conn.execute(text(item), {"j": job, "r": rule, "o": o, "p": "verify", "s": o})
    with engine.begin() as connection:                               # downgrade
        config = alembic_config()
        config.attributes["connection"] = connection
        command.downgrade(config, "0019_prompt_trials")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT to_regclass('llm_verifications')")).scalar() is None
        assert conn.execute(text("SELECT count(*) FROM llm_work_items")).scalar() == 1
        assert conn.execute(text("SELECT count(*) FROM information_schema.columns WHERE table_name = 'rule_hits' "
                                 "AND column_name = 'decided_tier'")).scalar() == 0
    engine.dispose()


def test_0021_renames_the_tiers_and_the_service_verdict_columns(pg_url):
    """weak -> service, strong -> harness (rows, default, CHECK), llm_verifications weak_* -> service_*, the verify
    items' weak_* context keys -> service_*; the downgrade reverses all of it."""
    testing.migrate(pg_url, "0020_llm_tiers")
    engine = create_engine(pg_url)
    o = "00000000-0000-0000-0000-000000000001"
    with engine.begin() as conn:
        rule = conn.execute(text("SELECT id FROM rules WHERE kind = 'llm' LIMIT 1")).scalar()
        conn.execute(text("""INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, rule_version, status,
                             reviewer, decided_tier) VALUES
                             (:r, '00000000-0000-0000-0000-00000000000a', 1, :o, 1, 'rejected', NULL, 'weak'),
                             (:r, '00000000-0000-0000-0000-00000000000b', 1, :o, 1, 'confirmed', NULL, 'strong'),
                             (:r, '00000000-0000-0000-0000-00000000000c', 1, :o, 1, 'confirmed', 'alice', 'human')"""),
                     {"r": rule, "o": o})
        conn.execute(text("""INSERT INTO llm_verifications (rule_id, rule_version, subject_key, object_key, project_id,
                             sample, weak_status, weak_verdict, weak_model, verdict, outcome)
                             VALUES (:r, 1, :o, :o, 1, 'qa', 'rejected', 'no_match', 'svc', 'match', 'final')"""),
                     {"r": rule, "o": o})
        job = conn.execute(text("INSERT INTO jobs (kind, payload, dedup_key) VALUES ('llm_verify', '{}', 'v:1') "
                                "RETURNING id")).scalar()
        conn.execute(text("""INSERT INTO llm_work_items (job_id, rule_id, rule_version, project_id, branch_id,
                             object_key, content_hash, prompt_hash, user_prompt, purpose, subject_key, verify)
                             VALUES (:j, :r, 1, 1, 1, :o, :o, 'h', 'u', 'verify', :o, CAST(:v AS jsonb))"""),
                     {"j": job, "r": rule, "o": o, "v": '{"sample": "qa", "weak_status": "rejected", '
                                                       '"weak_reason": null, "weak_fields": ["a"], "weak_model": "svc"}'})
    testing.migrate(pg_url)
    tiers = text("SELECT decided_tier FROM rule_hits WHERE rule_id = :r ORDER BY subject_key")
    with engine.begin() as conn:
        assert [r[0] for r in conn.execute(tiers, {"r": rule})] == ["service", "harness", "human"]
        assert conn.execute(text("SELECT service_status, service_verdict, service_model FROM llm_verifications")
                            ).all() == [("no_match", "no_match", "svc")]                # 0023: the status renamed
        assert conn.execute(text("SELECT verify FROM llm_work_items")).scalar() == {
            "sample": "qa", "service_status": "no_match", "service_reason": None, "service_fields": ["a"],
            "service_model": "svc"}
        conn.execute(text("INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, rule_version, status) "
                          "VALUES (:r, '00000000-0000-0000-0000-00000000000d', 1, :o, 1, 'no_match')"),
                     {"r": rule, "o": o})
        assert conn.execute(text("SELECT decided_tier FROM rule_hits WHERE subject_key = "
                                 "'00000000-0000-0000-0000-00000000000d'")).scalar() == "service"   # the default
    with engine.begin() as conn:
        with pytest.raises(Exception):          # the old names are refused
            conn.execute(text("UPDATE rule_hits SET decided_tier = 'weak'"))
    with engine.begin() as connection:                               # downgrade
        config = alembic_config()
        config.attributes["connection"] = connection
        command.downgrade(config, "0020_llm_tiers")
    with engine.begin() as conn:
        assert [r[0] for r in conn.execute(tiers, {"r": rule})] == ["weak", "strong", "human", "weak"]
        assert conn.execute(text("SELECT weak_status, weak_verdict, weak_model FROM llm_verifications")).all() == [
            ("rejected", "no_match", "svc")]
        assert set(conn.execute(text("SELECT verify FROM llm_work_items")).scalar()) == {
            "sample", "weak_status", "weak_reason", "weak_fields", "weak_model"}
        assert conn.execute(text("SELECT column_default FROM information_schema.columns WHERE table_name = "
                                 "'rule_hits' AND column_name = 'decided_tier'")).scalar() == "'weak'::text"
    with engine.begin() as conn:
        with pytest.raises(Exception):
            conn.execute(text("UPDATE rule_hits SET decided_tier = 'service'"))
    engine.dispose()


def test_offline_sql_generation(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@localhost/x")
    buf = io.StringIO()
    config = alembic_config()
    config.output_buffer = buf
    command.upgrade(config, "head", sql=True)
    sql = buf.getvalue()
    assert "CREATE TABLE IF NOT EXISTS gitlab_projects" in sql
    assert "CREATE INDEX bo_mr_rows ON branch_objects (content_hash) INCLUDE (branch_id, change) WHERE NOT is_main" in sql
    assert "CREATE INDEX fields_name_trgm ON object_fields USING gin (field_name gin_trgm_ops)" in sql
    assert "DROP TABLE discovery_llm_scores" in sql
    assert "DROP TABLE scorerule" in sql
    assert "CREATE UNIQUE INDEX rules_name_live ON rules (name) WHERE deleted_at IS NULL" in sql
    assert "CREATE TABLE jobs (" in sql
    assert "CREATE UNIQUE INDEX jobs_dedup_active ON jobs (dedup_key) WHERE status IN ('pending', 'running')" in sql
    head = ScriptDirectory.from_config(config).get_current_head()
    assert f"UPDATE alembic_version SET version_num='{head}'" in sql
    assert "CREATE TABLE IF NOT EXISTS stats_snapshots (" in sql
    assert "review_batches" in sql
    assert "ALTER TABLE rule_hits ADD COLUMN IF NOT EXISTS in_main boolean NOT NULL DEFAULT false" in sql
    assert "CREATE TABLE IF NOT EXISTS llm_verifications (" in sql
    assert "CREATE TABLE IF NOT EXISTS prompt_trials (" in sql
    assert "CREATE OR REPLACE FUNCTION llm_names_hash" in sql
    assert "CREATE TABLE IF NOT EXISTS llm_coverage (" in sql


def _candidate_sql(name):
    """A candidate query of the scanner, read from its source (importing it needs its settings)."""
    import re
    from pathlib import Path
    source = (Path(__file__).resolve().parents[2] / "discovery_scanner" / "services" / "db_service.py").read_text()
    return re.search(rf'{name} = text\("""(.*?)"""\)', source, re.S).group(1)


SEED_0018 = """
    INSERT INTO gitlab_projects (id, project_name, full_path, visibility, created_at, updated_at)
        VALUES (1, 'p', 'g/p', 'private', now(), now());
    INSERT INTO gitlab_branches (id, branch_name, is_main, commit, scanned_commit, project_id, project_path, created_at,
                                 updated_at) VALUES
        (1, 'main', true, 'c1', 'c1', 1, 'g/p', now(), now()), (2, 'feature', false, 'c2', 'c2', 1, 'g/p', now(), now());
    INSERT INTO objects (content_hash, object_key, project_id, parser, type, name, file) VALUES
        (:user_main, :user, 1, 'go', 'dto', 'User', '/u.go'), (:user_mr, :user, 1, 'go', 'dto', 'User', '/u.go'),
        (:only_mr, :new, 1, 'go', 'dto', 'New', '/n.go'), (:gone_v, :gone, 1, 'go', 'dto', 'Gone', '/g.go');
    INSERT INTO object_fields (content_hash, field_name, field_type, field_key, project_id, comment, samples) VALUES
        (:user_main, 'email', 'string', :email, 1, 'work address', '["a@example.com"]'),
        (:user_main, 'id', 'int', :id, 1, NULL, NULL),
        (:user_mr, 'email', 'text', :email, 1, NULL, NULL), (:user_mr, 'id', 'int', :id, 1, NULL, NULL),
        (:user_mr, 'phone', 'string', :phone, 1, NULL, NULL),
        (:only_mr, 'token', 'string', :token, 1, NULL, NULL), (:gone_v, 'x', 'int', :gone_x, 1, NULL, NULL);
    INSERT INTO branch_objects (branch_id, object_key, content_hash, is_main, change) VALUES
        (1, :user, :user_main, true, NULL), (2, :user, :user_mr, false, 'modified'), (2, :new, :only_mr, false, 'added');
    INSERT INTO rules (id, kind, name, target, mode, version, enabled) VALUES
        (901, 'llm', 'obj', 'object', 'review', 1, true), (902, 'llm', 'fld', 'field', 'review', 1, true),
        (903, 'keyword', 'kw', 'field', 'auto', 1, true);
    INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version, prompt_version, status,
                           reviewer) VALUES
        (901, :user, 1, :user, NULL, 1, 'pv', 'confirmed', 'alice'),
        (901, :new, 1, :new, NULL, 1, 'pv', 'rejected', NULL),
        (901, :gone, 1, :gone, NULL, 1, 'pv', 'rejected', NULL),
        (902, :email, 1, :user, 'email', 1, 'pv', 'rejected', NULL),
        (902, :id, 1, :user, 'id', 1, 'pv', 'rejected', NULL),
        (902, :phone, 1, :user, 'phone', 1, 'pv', 'pending_review', NULL),
        (903, :email, 1, :user, 'email', 1, NULL, 'confirmed', NULL);
"""


def test_0018_fills_the_llm_hashes_from_the_current_snapshot(pg_url):
    """The backfill computes in SQL what the scanner computes in Python, from the stored versions (the
    main snapshot's first, else an MR delta's): an unchanged snapshot has no candidate afterwards."""
    import uuid

    testing.migrate(pg_url, "0017_llm_coverage")
    user, new, gone = keys.object_key(1, "go", "user"), keys.object_key(1, "go", "new"), keys.object_key(1, "go", "gone")
    ids = {"user": user, "new": new, "gone": gone, "user_main": uuid.uuid4(), "user_mr": uuid.uuid4(),
           "only_mr": uuid.uuid4(), "gone_v": uuid.uuid4(), "email": keys.field_key(user, "email"),
           "id": keys.field_key(user, "id"), "phone": keys.field_key(user, "phone"),
           "token": keys.field_key(new, "token"), "gone_x": keys.field_key(gone, "x")}
    engine = create_engine(pg_url)
    with engine.begin() as conn:
        conn.execute(text(SEED_0018), {k: str(v) for k, v in ids.items()})
    testing.migrate(pg_url)
    with engine.connect() as conn:
        hits = {(r.rule_id, r.field_name, r.object_key): (r.names_hash, r.subject_hash) for r in conn.execute(text(
            "SELECT rule_id, field_name, object_key, names_hash, subject_hash FROM rule_hits"))}
        assert hits == {
            (901, None, user): (keys.names_hash("User", ["email", "id"]), str(ids["user_main"])),      # main version
            (901, None, new): (keys.names_hash("New", ["token"]), str(ids["only_mr"])),                 # MR only
            (901, None, gone): (None, None),                                                            # in no branch
            (902, "email", user): (keys.names_hash("User", ["email"]),
                                   keys.field_subject_hash("email", "string", "work address", ["a@example.com"])),
            (902, "id", user): (keys.names_hash("User", ["id"]), keys.field_subject_hash("id", "int", None, None)),
            (902, "phone", user): (keys.names_hash("User", ["phone"]),                                   # MR only
                                   keys.field_subject_hash("phone", "string", None, None)),
            (903, "email", user): (None, None),                                                         # keyword hit
        }
        # no re-ask by the migration: the main snapshot has no candidate of either rule
        params = {"branch_id": 1, "rule_version": 1, "pinned_pv": "pv", "code_pv": "pv", "pinned_model": None,
                  "code_model": None, "migration": False}
        assert conn.execute(text(_candidate_sql("LLM_OBJECT_CANDIDATES_SQL")), {**params, "rule_id": 901}).all() == []
        assert conn.execute(text(_candidate_sql("LLM_CANDIDATES_SQL")), {**params, "rule_id": 902}).all() == []
        # the MR delta's other version of User (another field set) is asked: its content is not what the model saw
        mr = conn.execute(text(_candidate_sql("LLM_OBJECT_CANDIDATES_SQL")), {**params, "branch_id": 2, "rule_id": 901})
        assert [r.name for r in mr] == ["User"]
    with engine.begin() as connection:                               # downgrade
        config = alembic_config()
        config.attributes["connection"] = connection
        command.downgrade(config, "0017_llm_coverage")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM information_schema.columns WHERE table_name = 'rule_hits' "
                                 "AND column_name IN ('names_hash', 'subject_hash')")).scalar() == 0
        assert conn.execute(text("SELECT to_regproc('llm_names_hash')")).scalar() is None
    engine.dispose()


def test_0013_seeds_only_the_default_rules_in_auto_mode(pg_url):
    testing.migrate(pg_url)
    engine = create_engine(pg_url)
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT kind, name, category, severity, target, mode, enabled, scope, tags, version, "
                                 "prompt FROM rules WHERE updated_by = 'migration:0013_example_rules' "
                                 "ORDER BY name DESC")).all()
        builtin = conn.execute(text("SELECT name, enabled FROM rules WHERE scope ->> 'source' = 'core' "
                                    "ORDER BY name")).all()
        env = conn.execute(text("SELECT count(*) FROM rules WHERE scope ->> 'source' = 'env' "
                                "AND deleted_at IS NULL")).scalar()
    assert builtin == [("kw-fields", False), ("kw-props", False)] and env == 0     # 0028 on a new install
    assert len(rows) == 2
    auth = rows[1]
    assert (auth.name, auth.category, auth.severity, auth.target, auth.mode, auth.enabled, auth.tags) == (
        "api-with-auth", "auth", "critical", "object", "auto", False, ["auth-data"])
    assert auth.scope == {"object_type_re": "route|rpc|query|mutation", "mark_fields": True}
    assert auth.prompt.startswith("You are an application security reviewer.")
    (kind, name, category, severity, target, mode, enabled, scope, tags, version, prompt) = rows[0]
    assert (kind, name, category, severity, target, mode, enabled, version) == (
        "llm", "db-tables-with-client-data", "pii", "high", "object", "auto", True, 1)
    assert scope == {"object_type_re": "table", "mark_fields": True} and tags == ["personal-data"]
    assert prompt.startswith("You are a data protection reviewer for a bank. The object is a database table")
    engine.dispose()


def test_0013_keeps_a_live_rule_of_the_same_name_and_downgrade_keeps_rules_with_hits(pg_url):
    testing.migrate(pg_url, "0012_llm_work")
    engine = create_engine(pg_url)
    with engine.begin() as conn:
        conn.execute(text("""INSERT INTO rules (kind, name, category, severity, target, mode, scope, prompt, version,
                             enabled, updated_by) VALUES ('llm', 'db-tables-with-client-data', 'own', 'low',
                             'object', 'review', '{}', 'mine', 3, false, 'alice')"""))
    testing.migrate(pg_url, "0013_example_rules")
    rule = text("SELECT category, mode, enabled, updated_by FROM rules WHERE name = 'db-tables-with-client-data'")
    with engine.begin() as conn:
        assert conn.execute(rule).all() == [("own", "review", False, "alice")]          # kept as it is
        conn.execute(text("DELETE FROM rules WHERE name = 'db-tables-with-client-data'"))
    with engine.begin() as connection:
        config = alembic_config()
        config.attributes["connection"] = connection
        command.downgrade(config, "0012_llm_work")
    testing.migrate(pg_url, "0013_example_rules")
    with engine.begin() as conn:
        assert conn.execute(rule).all() == [("pii", "auto", True, "migration:0013_example_rules")]
        rule_id = conn.execute(text("SELECT id FROM rules WHERE name = 'db-tables-with-client-data'")).scalar()
        conn.execute(text("""INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, rule_version, status)
                             VALUES (:r, gen_random_uuid(), 1, gen_random_uuid(), 1, 'confirmed')"""), {"r": rule_id})
    with engine.begin() as connection:                               # a rule with hits survives the downgrade
        config = alembic_config()
        config.attributes["connection"] = connection
        command.downgrade(config, "0012_llm_work")
    with engine.connect() as conn:
        assert conn.execute(rule).all() == [("pii", "auto", True, "migration:0013_example_rules")]
    engine.dispose()


def test_0022_turns_alert_rules_into_score_rules_and_drops_alerted_at(pg_url):
    testing.migrate(pg_url, "0021_service_tier")
    engine = create_engine(pg_url)
    columns = text("SELECT table_name FROM information_schema.columns WHERE column_name = 'alerted_at' "
                   "AND table_name IN ('rule_hits', 'gitlab_mrs') ORDER BY 1")
    with engine.begin() as conn:
        assert [r[0] for r in conn.execute(columns)] == ["gitlab_mrs", "rule_hits"]
        conn.execute(text("""INSERT INTO rules (kind, name, category, severity, target, mode, scope, version, enabled)
                             VALUES ('keyword', 'a', 'pii', 'high', 'field', 'auto',
                                     '{"field_re": "phone", "action": "alert"}', 4, true),
                                    ('keyword', 'e', NULL, 'info', 'object', 'auto',
                                     '{"object_re": "Tmp", "action": "exclude"}', 1, true)"""))
    testing.migrate(pg_url)
    scopes = text("SELECT name, scope, version FROM rules WHERE name IN ('a', 'e') ORDER BY name")
    with engine.begin() as conn:
        assert conn.execute(scopes).all() == [("a", {"field_re": "phone", "action": "score"}, 4),
                                              ("e", {"object_re": "Tmp", "action": "exclude"}, 1)]
        assert conn.execute(columns).all() == []
        assert conn.execute(text("SELECT count(*) FROM pg_indexes WHERE indexdef LIKE '%alerted_at%'")).scalar() == 0
        assert conn.execute(text("SELECT count(*) FROM rules WHERE scope ->> 'action' = 'alert'")).scalar() == 0
    with engine.begin() as connection:                               # downgrade: the columns come back, NULL
        config = alembic_config()
        config.attributes["connection"] = connection
        command.downgrade(config, "0021_service_tier")
    with engine.begin() as conn:
        assert [r[0] for r in conn.execute(columns)] == ["gitlab_mrs", "rule_hits"]
        assert conn.execute(text("SELECT count(*) FROM rule_hits WHERE alerted_at IS NOT NULL")).scalar() == 0
        assert conn.execute(scopes).all()[0][1]["action"] == "score"                # not restored
    engine.dispose()


def test_0023_renames_the_hit_statuses_everywhere_and_downgrade_reverses(pg_url):
    """confirmed -> match, rejected -> no_match in rule_hits (status, CHECK, machine_status, verify_key suffix),
    llm_verifications.service_status, prompt_trial_items.current_status and the verify items' service_status; the
    verdict columns (already match / no_match) are untouched; the downgrade maps everything back."""
    testing.migrate(pg_url, "0022_no_alerts")
    engine = create_engine(pg_url)
    o = "00000000-0000-0000-0000-000000000001"
    hit = "00000000-0000-0000-0000-0000000000{:02d}"
    with engine.begin() as conn:
        rule = conn.execute(text("SELECT id FROM rules WHERE kind = 'llm' LIMIT 1")).scalar()
        conn.execute(text("""INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, rule_version, status,
                             reviewer, machine_status, verify_key, decided_tier) VALUES
                             (:r, :a, 1, :o, 1, 'confirmed', 'alice', 'rejected', NULL, 'human'),
                             (:r, :b, 1, :o, 1, 'rejected', NULL, NULL, '1:pv:h:rejected', 'service'),
                             (:r, :c, 1, :o, 1, 'pending_review', NULL, NULL, '1:pv:h:pending_review', 'service'),
                             (:r, :d, 1, :o, 1, 'need_more_info', NULL, 'confirmed', '1:pv:h:confirmed', 'harness')"""),
                     {"r": rule, "o": o, "a": hit.format(10), "b": hit.format(11), "c": hit.format(12),
                      "d": hit.format(13)})
        conn.execute(text("""INSERT INTO llm_verifications (rule_id, rule_version, subject_key, object_key, project_id,
                             sample, service_status, service_verdict, service_model, verdict, outcome) VALUES
                             (:r, 1, :o, :o, 1, 'qa', 'confirmed', 'match', 'svc', 'no_match', 'final'),
                             (:r, 1, :o, :o, 1, 'qa', 'pending_review', 'match', 'svc', 'match', 'final')"""),
                     {"r": rule, "o": o})
        trial = conn.execute(text("INSERT INTO prompt_trials (rule_id, rule_version, prompt_version, candidate_prompt, "
                                  "prompt_hash) VALUES (:r, 1, 'pv', 'p', 'h') RETURNING id"),
                             {"r": rule}).scalar()
        conn.execute(text("""INSERT INTO prompt_trial_items (trial_id, subject_key, object_key, content_hash, project_id,
                             role, expected, current_verdict, current_status) VALUES
                             (:t, :a, :o, :o, 1, 'target', 'no_match', 'match', 'rejected'),
                             (:t, :b, :o, :o, 1, 'control', 'match', 'match', 'confirmed')"""),
                     {"t": trial, "o": o, "a": hit.format(10), "b": hit.format(11)})
        job = conn.execute(text("INSERT INTO jobs (kind, payload, dedup_key) VALUES ('llm_verify', '{}', 'v:1') "
                                "RETURNING id")).scalar()
        conn.execute(text("""INSERT INTO llm_work_items (job_id, rule_id, rule_version, project_id, branch_id,
                             object_key, content_hash, prompt_hash, user_prompt, purpose, subject_key, verify)
                             VALUES (:j, :r, 1, 1, 1, :o, :o, 'h', 'u', 'verify', :s, CAST(:v AS jsonb))"""),
                     {"j": job, "r": rule, "o": o, "s": hit.format(11),
                      "v": '{"sample": "qa", "service_status": "rejected", "service_fields": ["a"]}'})
    hits = text("SELECT status, machine_status, verify_key FROM rule_hits WHERE rule_id = :r AND object_key = :o "
                "ORDER BY subject_key")
    verifications = text("SELECT service_status, service_verdict, verdict FROM llm_verifications ORDER BY id")
    trial_items = text("SELECT expected, current_verdict, current_status FROM prompt_trial_items ORDER BY id")
    verify = text("SELECT verify FROM llm_work_items WHERE purpose = 'verify'")

    testing.migrate(pg_url)
    with engine.begin() as conn:
        assert conn.execute(hits, {"r": rule, "o": o}).all() == [
            ("match", "no_match", None), ("no_match", None, "1:pv:h:no_match"),
            ("pending_review", None, "1:pv:h:pending_review"), ("need_more_info", "match", "1:pv:h:match")]
        assert conn.execute(verifications).all() == [("match", "match", "no_match"), ("pending_review", "match", "match")]
        assert conn.execute(trial_items).all() == [("no_match", "match", "no_match"), ("match", "match", "match")]
        assert conn.execute(verify).scalar() == {"sample": "qa", "service_status": "no_match", "service_fields": ["a"]}
    with engine.begin() as conn:
        with pytest.raises(Exception):          # the old statuses are refused by the CHECK
            conn.execute(text("UPDATE rule_hits SET status = 'confirmed' WHERE subject_key = :a"), {"a": hit.format(10)})

    with engine.begin() as connection:                               # downgrade
        config = alembic_config()
        config.attributes["connection"] = connection
        command.downgrade(config, "0022_no_alerts")
    with engine.begin() as conn:
        assert conn.execute(hits, {"r": rule, "o": o}).all() == [
            ("confirmed", "rejected", None), ("rejected", None, "1:pv:h:rejected"),
            ("pending_review", None, "1:pv:h:pending_review"), ("need_more_info", "confirmed", "1:pv:h:confirmed")]
        assert conn.execute(verifications).all() == [("confirmed", "match", "no_match"),
                                                     ("pending_review", "match", "match")]
        assert conn.execute(trial_items).all() == [("no_match", "match", "rejected"), ("match", "match", "confirmed")]
        assert conn.execute(verify).scalar()["service_status"] == "rejected"
    with engine.begin() as conn:
        with pytest.raises(Exception):          # and the new ones before 0023
            conn.execute(text("UPDATE rule_hits SET status = 'match' WHERE subject_key = :a"), {"a": hit.format(10)})
    engine.dispose()


LIFECYCLE_SEED = """
    INSERT INTO rules (id, kind, name, category, target, mode, scope, prompt, version, enabled) VALUES
        (801, 'llm', 'classifier-like', NULL, 'field', 'review', '{"field_re": "mail", "object_re": "", "source": "env"}',
         'p1', 3, true),
        (802, 'llm', 'objects', 'pii', 'object', 'review', '{"mark_fields": true, "project_re": "g/"}', 'p2', 1, true);
    INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version, prompt_version, status,
                           reviewer, verify_key, decided_tier) VALUES
        (801, :a, 1, :o, 'email', 3, 'core3.3', 'match', NULL, '3:core3.3:h:match', 'service'),
        (802, :o, 1, :o, NULL, 1, 'core3.3', 'no_match', 'alice', NULL, 'human'),
        (802, :b, 1, :o, 'x', 1, 'core2.7', 'match', NULL, '1:core2.7:h2:match', 'service');
    INSERT INTO llm_coverage (branch_id, rule_id, rule_version, prompt_version, commit)
        SELECT id, 801, 3, 'core3.3', 'c1' FROM gitlab_branches LIMIT 1;
"""


def test_0024_to_0026_versions_families_history_rollouts_and_downgrade(pg_url):
    """0024: one active version per live LLM rule (its matchers, the current core prompts family pinned), the hits'
    core prompts version split by family (``classifier3`` / ``rule3``, also in the verify key and the coverage
    rows); 0025: the history of the current LLM hits and of every later change of a verdict (not of category /
    severity / note edits); 0026: rollouts, job priority, llm_rollout kind. Downgrade to 0023 reverses it."""
    testing.migrate(pg_url, "0023_match_statuses")
    engine = create_engine(pg_url)
    o, a, b = (f"00000000-0000-0000-0000-00000000000{i}" for i in (1, 2, 3))
    with engine.begin() as conn:
        conn.execute(text("""INSERT INTO gitlab_projects (id, project_name, full_path, visibility, created_at, updated_at)
                             VALUES (1, 'p', 'g/p', 'private', now(), now());
                             INSERT INTO gitlab_branches (id, branch_name, is_main, commit, scanned_commit, project_id,
                                 project_path, created_at, updated_at)
                             VALUES (1, 'main', true, 'c1', 'c1', 1, 'g/p', now(), now())"""))
        conn.execute(text(LIFECYCLE_SEED), {"o": o, "a": a, "b": b})
    testing.migrate(pg_url)
    with engine.begin() as conn:
        q = lambda sql, **p: conn.execute(text(sql), p).all()   # noqa: E731
        assert q("SELECT rule_id, version, status, prompt, target, matchers, core_prompt_version, source "
                 "FROM rule_versions WHERE rule_id IN (801, 802) ORDER BY rule_id") == [
            (801, 3, "active", "p1", "field", {"field_re": "mail"}, "classifier3", "backfill"),
            (802, 1, "active", "p2", "object", {"mark_fields": True, "project_re": "g/"}, "rule3", "backfill")]
        assert q("SELECT id, core_prompt_version, llm_model FROM rules WHERE id IN (801, 802) ORDER BY id") == [
            (801, "classifier3", None), (802, "rule3", None)]
        assert q("SELECT field_name, prompt_version, verify_key FROM rule_hits WHERE rule_id IN (801, 802) "
                 "ORDER BY rule_id, field_name NULLS FIRST") == [
            ("email", "classifier3", "3:classifier3:h:match"), (None, "rule3", None), ("x", "rule7", "1:rule7:h2:match")]
        assert q("SELECT prompt_version FROM llm_coverage WHERE rule_id = 801") == [("classifier3",)]
        # history: the current LLM hits, then only real verdict changes
        assert q("SELECT count(*), min(source) FROM hit_verdicts WHERE rule_id IN (801, 802)") == [(3, "backfill")]
        conn.execute(text("UPDATE rule_hits SET note = 'n', category = 'c', severity = 'low' WHERE rule_id = 801"))
        assert q("SELECT count(*) FROM hit_verdicts WHERE rule_id = 801") == [(1,)]
        conn.execute(text("SELECT set_config('discovery.rollout_id', '7', true)"))
        conn.execute(text("UPDATE rule_hits SET status = 'no_match', rule_version = 4 WHERE rule_id = 801"))
        assert q("SELECT status, rule_version, source, rollout_id FROM hit_verdicts WHERE rule_id = 801 ORDER BY id") == [
            ("match", 3, "backfill", None), ("no_match", 4, "service", 7)]
        # rollouts: one open per rule; jobs get a priority; the controller's kind
        conn.execute(text("INSERT INTO llm_rollouts (rule_id, to_version, status) VALUES (801, 4, 'running')"))
        with pytest.raises(Exception):
            with conn.begin_nested():
                conn.execute(text("INSERT INTO llm_rollouts (rule_id, to_version, status) VALUES (801, 5, 'planned')"))
        conn.execute(text("INSERT INTO jobs (kind, payload, dedup_key, priority) VALUES ('llm_rollout', '{}', 'r', -10)"))
        assert q("SELECT answered_stale FROM llm_coverage WHERE rule_id = 801") == [(0,)]
    with engine.begin() as connection:                               # downgrade
        config = alembic_config()
        config.attributes["connection"] = connection
        command.downgrade(config, "0023_match_statuses")
    with engine.connect() as conn:
        q = lambda sql, **p: conn.execute(text(sql), p).all()   # noqa: E731
        assert q("SELECT field_name, prompt_version, verify_key FROM rule_hits WHERE rule_id = 802 "
                 "ORDER BY field_name NULLS FIRST") == [(None, "core3.3", None), ("x", "rule7", "1:rule7:h2:match")]
        assert q("SELECT to_regclass('rule_versions'), to_regclass('hit_verdicts'), to_regclass('llm_rollouts')") == [
            (None, None, None)]
        assert q("SELECT count(*) FROM jobs WHERE kind = 'llm_rollout'") == [(0,)]
    engine.dispose()


def test_0027_drops_the_type_prefix_of_stored_names_and_keeps_the_llm_names_hash(pg_url):
    """Stored object versions get the current parsers' names; an LLM hit whose names_hash was the old name's gets
    the new name's (nothing is asked again), a stale one stays stale; rules are not rewritten."""
    import json as _json
    testing.migrate(pg_url, "0026_llm_rollouts")
    engine = create_engine(pg_url)
    rows = [  # parser, type, legacy name, props, new name
        ("golang", "dto", "Struct dto UserDTO", None, "UserDTO"),
        ("java", "dto", "Javax dto AudioEntity", None, "AudioEntity"),
        ("graphql", "mutation", "Mutation BusinessLoungesMutations.cancelOrder", None,
         "BusinessLoungesMutations.cancelOrder"),
        ("graphql", "query", "Query MgmQueries.offer", None, "MgmQueries.offer"),
        ("javascript", "js-gql-query", "JS GQL Resolver me in query ProfileLoginQuery", None, "ProfileLoginQuery.me"),
        ("migrations", "table", "Table billing.accounts", None, "billing.accounts"),
        ("protobuf", "rpc", "Rpc /com.book.BookService/GetBook", None, "/com.book.BookService/GetBook"),
        ("python", "dto", "Sqlalchemy dto users", None, "users"),
        ("python", "route", "Fastapi route / calls Root handler (GET)", {"func": "root", "path": "/", "method": "get"},
         "GET / (root)"),
        ("python", "route", "Django route admin/ calls Admin.Site.Urls handler", None, "admin/ (admin.site.urls)"),
        ("swagger", "route", "Route /users (GET)", None, "GET /users"),
        ("terraform", "vm", "Virtual machine keycloak01", None, "keycloak01"),
        ("terraform", "resource", "Resource aws_iam_group.ops", None, "aws_iam_group.ops"),
        ("golang", "dto", "AlreadyNew", None, "AlreadyNew"),
    ]
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO gitlab_projects (id, project_name, full_path, visibility, created_at, updated_at) "
                          "VALUES (1, 'p', 'g/p', 'private', now(), now())"))
        rule = conn.execute(text("INSERT INTO rules (kind, name, category, target, mode, scope, version) VALUES "
                                 "('llm', 'o', 'pii', 'object', 'review', '{\"object_re\": \"^Struct dto\"}', 1) "
                                 "RETURNING id")).scalar()
        for i, (parser, type_, name, props, _) in enumerate(rows):
            h, k = f"00000000-0000-0000-0001-{i:012d}", f"00000000-0000-0000-0002-{i:012d}"
            conn.execute(text("INSERT INTO objects (content_hash, object_key, project_id, parser, type, name, props) "
                              "VALUES (:h, :k, 1, :p, :t, :n, CAST(:props AS jsonb))"),
                         {"h": h, "k": k, "p": parser, "t": type_, "n": name, "props": _json.dumps(props)})
            conn.execute(text("INSERT INTO object_fields (content_hash, field_name, field_type, field_key, project_id) "
                              "VALUES (:h, 'f', 'string', :k, 1)"), {"h": h, "k": k})
        # the golang object: a current object hit and a stale one (other names), a field hit of the java object
        conn.execute(text("""
            INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version, prompt_version,
                                   status, names_hash) VALUES
            (:r, '00000000-0000-0000-0002-000000000000', 1, '00000000-0000-0000-0002-000000000000', NULL, 1, 'rule3',
             'match', llm_names_hash('Struct dto UserDTO', ARRAY['f'])),
            (:r, '00000000-0000-0000-0003-000000000000', 1, '00000000-0000-0000-0002-000000000001', 'f', 1, 'rule3',
             'match', llm_names_hash('Javax dto AudioEntity', ARRAY['f'])),
            (:r, '00000000-0000-0000-0002-000000000002', 1, '00000000-0000-0000-0002-000000000002', NULL, 1, 'rule3',
             'match', 'stale-hash')"""), {"r": rule})
    testing.migrate(pg_url)
    with engine.connect() as conn:
        names = [r[0] for r in conn.execute(text("SELECT name FROM objects ORDER BY content_hash"))]
        assert names == [r[4] for r in rows]
        assert conn.execute(text("SELECT names_hash FROM rule_hits ORDER BY subject_key")).all() == [
            (keys.names_hash("UserDTO", ["f"]),), ("stale-hash",), (keys.names_hash("AudioEntity", ["f"]),)]
        assert conn.execute(text("SELECT scope FROM rules WHERE id = :r"), {"r": rule}).scalar() == {
            "object_re": "^Struct dto"}                                    # listed in the log, not rewritten
    engine.dispose()


SCALE_SEED = """
    INSERT INTO gitlab_projects (id, project_name, full_path, visibility, created_at, updated_at)
        VALUES (1, 'p', 'g/p', 'private', now(), now());
    INSERT INTO gitlab_branches (id, branch_name, is_main, commit, scanned_commit, project_id, project_path, created_at,
                                 updated_at) VALUES
        (1, 'main', true, 'c1', 'c1', 1, 'g/p', now(), now()), (2, 'feature', false, 'c2', 'c2', 1, 'g/p', now(), now());
    INSERT INTO gitlab_mrs (id, project_id, project_path, source_branch_id, source_branch, source_branch_commit,
                            target_branch_id, target_branch, target_branch_commit, mr_id, title, state, created_at, updated_at)
        VALUES (1, 1, 'g/p', 2, 'feature', 'c2', 1, 'main', 'c1', 1, 'mr', 'opened', now(), now());
    INSERT INTO objects (content_hash, object_key, project_id, parser, type, name, file) VALUES
        (:user_main, :user, 1, 'go', 'dto', 'User', '/u.go'), (:user_mr, :user, 1, 'go', 'dto', 'User', '/u.go'),
        (:only_mr, :new, 1, 'go', 'dto', 'New', '/n.go'), (:gone_v, :gone, 1, 'go', 'dto', 'Gone', '/g.go');
    INSERT INTO object_fields (content_hash, field_name, field_type, field_key, project_id, comment, samples) VALUES
        (:user_main, 'email', 'string', :email, 1, 'work address', '["a@example.com"]'),
        (:user_main, 'id', 'int', :id, 1, NULL, NULL),
        (:user_mr, 'email', 'text', :email, 1, NULL, NULL), (:user_mr, 'id', 'int', :id, 1, NULL, NULL),
        (:user_mr, 'phone', 'string', :phone, 1, NULL, NULL),
        (:only_mr, 'token', 'string', :token, 1, NULL, NULL), (:gone_v, 'x', 'int', :gone_x, 1, NULL, NULL);
    INSERT INTO branch_objects (branch_id, object_key, content_hash, is_main, change) VALUES
        (1, :user, :user_main, true, NULL), (2, :user, :user_mr, false, 'modified'), (2, :new, :only_mr, false, 'added');
    INSERT INTO rules (id, kind, name, target, mode, version, enabled) VALUES
        (901, 'llm', 'obj', 'object', 'review', 1, true), (902, 'llm', 'fld', 'field', 'review', 1, true);
    INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version, prompt_version, status,
                           reviewer, decided_tier) VALUES
        (901, :user, 1, :user, NULL, 1, 'rule3', 'match', 'alice', 'human'),
        (901, :new, 1, :new, NULL, 1, 'rule3', 'pending_review', NULL, 'service'),
        (901, :gone, 1, :gone, NULL, 1, 'rule3', 'no_match', NULL, 'service'),
        (902, :email, 1, :user, 'email', 1, 'rule3', 'no_match', NULL, 'service'),
        (902, :phone, 1, :user, 'phone', 1, 'rule3', 'pending_review', NULL, 'service'),
        (902, :gone_x, 1, :gone, 'x', 1, 'rule3', 'pending_review', NULL, 'service');
    INSERT INTO jobs (id, kind, payload, status, locked_by, locked_at, created_at) VALUES
        (1, 'scan_branch', '{"branch_id": 1}', 'running', 'w1', now() - interval '3 minutes', now() - interval '5 minutes'),
        (2, 'scan_branch', '{"branch_id": 2}', 'done', NULL, NULL, now() - interval '1 hour');
    SELECT setval('jobs_id_seq', 2);
"""


def test_0029_to_0032_scale_upgrade_with_data_and_downgrade_to_0028(pg_url):
    """A database at 0028 with projects, snapshots, an open MR, hits and jobs: 0030 backfills the presence flags
    (main / open MR delta / gone, object and field hits) and the stored LLM hashes, 0031 widens the job kinds and
    fills ``started_at`` of the running jobs, 0032 adds the batches and the ``batch_id`` of the verdict history; the
    downgrade to 0028 reverses all of it and the schema migrates back to the models."""
    import uuid

    testing.migrate(pg_url, "0028_builtin_rules")
    user, new, gone = keys.object_key(1, "go", "user"), keys.object_key(1, "go", "new"), keys.object_key(1, "go", "gone")
    ids = {"user": user, "new": new, "gone": gone, "user_main": uuid.uuid4(), "user_mr": uuid.uuid4(),
           "only_mr": uuid.uuid4(), "gone_v": uuid.uuid4(), "email": keys.field_key(user, "email"),
           "id": keys.field_key(user, "id"), "phone": keys.field_key(user, "phone"),
           "token": keys.field_key(new, "token"), "gone_x": keys.field_key(gone, "x")}
    engine = create_engine(pg_url)
    with engine.begin() as conn:
        conn.execute(text(SCALE_SEED), {k: str(v) for k, v in ids.items()})
    testing.migrate(pg_url)
    with engine.begin() as conn:
        q = lambda sql, **p: conn.execute(text(sql), p).all()   # noqa: E731
        # presence: object hits by the object's versions, field hits by the field's versions
        flags = {(r[0], r[1]): (r[2], r[3]) for r in q("SELECT rule_id, subject_key, in_main, in_open_mr FROM rule_hits")}
        assert flags == {(901, user): (True, True), (901, new): (False, True), (901, gone): (False, False),
                         (902, ids["email"]): (True, True), (902, ids["phone"]): (False, True),
                         (902, ids["gone_x"]): (False, False)}
        # stored LLM hashes = what the scanner computes in Python
        assert q("SELECT count(*) FROM object_fields WHERE llm_hash IS NULL") == [(0,)]
        assert q("SELECT llm_hash FROM object_fields WHERE content_hash = :h AND field_name = 'email'",
                 h=str(ids["user_main"])) == [(keys.field_subject_hash("email", "string", "work address", ["a@example.com"]),)]
        assert q("SELECT names_hash FROM objects WHERE content_hash = :h", h=str(ids["user_main"])) == [
            (keys.names_hash("User", ["email", "id"]),)]
        assert q("SELECT names_hash FROM objects WHERE content_hash = :h", h=str(ids["user_mr"])) == [
            (keys.names_hash("User", ["email", "id", "phone"]),)]
        # 0031: started_at of the running job, the new kinds, the rate bucket table
        assert q("SELECT started_at = locked_at, (SELECT started_at FROM jobs WHERE id = 2) FROM jobs WHERE id = 1") == [
            (True, None)]
        conn.execute(text("INSERT INTO jobs (kind, payload, dedup_key) VALUES ('stats_refresh', '{}', 'stats'), "
                          "('llm_relabel', '{}', 'relabel')"))
        conn.execute(text("INSERT INTO llm_rate_buckets (name, tokens, updated_at) VALUES ('llm', 10, now())"))
        # 0032: a batch, its items, the batch_id in the verdict history written by the trigger
        batch = conn.execute(text("INSERT INTO review_batches (filter, action, target_status, reviewer, expected_total, "
                                  "matched) VALUES ('{}', 'reject', 'no_match', 'alice', 1, 1) RETURNING id")).scalar()
        conn.execute(text("INSERT INTO review_batch_items (batch_id, rule_id, subject_key, prev_status) "
                          "VALUES (:b, 901, :k, 'pending_review')"), {"b": batch, "k": str(new)})
        conn.execute(text("SELECT set_config('discovery.batch_id', CAST(:b AS text), true)"), {"b": batch})
        conn.execute(text("UPDATE rule_hits SET status = 'no_match' WHERE rule_id = 901 AND subject_key = :k"),
                     {"k": str(new)})
        assert q("SELECT status, batch_id FROM hit_verdicts WHERE rule_id = 901 AND subject_key = :k ORDER BY id",
                 k=str(new)) == [("pending_review", None), ("no_match", batch)]
        conn.execute(text("INSERT INTO stats_snapshots (name, data, computed_at) VALUES ('overview', '{}', now())"))
    with engine.begin() as connection:                               # downgrade
        config = alembic_config()
        config.attributes["connection"] = connection
        command.downgrade(config, "0028_builtin_rules")
    with engine.begin() as conn:
        q = lambda sql, **p: conn.execute(text(sql), p).all()   # noqa: E731
        assert q("SELECT version_num FROM alembic_version") == [("0028_builtin_rules",)]
        assert q("SELECT to_regclass('stats_snapshots'), to_regclass('llm_rate_buckets'), to_regclass('review_batches'), "
                 "to_regclass('review_batch_items')") == [(None, None, None, None)]
        assert q("SELECT column_name FROM information_schema.columns WHERE (table_name, column_name) IN "
                 "(('rule_hits', 'in_main'), ('rule_hits', 'in_open_mr'), ('objects', 'names_hash'), "
                 "('object_fields', 'llm_hash'), ('jobs', 'started_at'), ('hit_verdicts', 'batch_id'), "
                 "('gitlab_branches', 'scan_fingerprint'))") == []
        assert q("SELECT count(*) FROM pg_indexes WHERE indexname IN ('hits_object', 'hits_project_rule', 'hits_live_seen', "
                 "'hits_live_queue', 'hits_seen', 'objects_name_key', 'jobs_ready_kind', 'llm_verify_rule_created', "
                 "'hit_verdicts_batch')") == [(0,)]
        assert q("SELECT indexdef FROM pg_indexes WHERE indexname = 'hit_verdicts_subject'") == [
            ("CREATE INDEX hit_verdicts_subject ON public.hit_verdicts USING btree (rule_id, subject_key, id)",)]
        assert q("SELECT reloptions FROM pg_class WHERE relname = 'rule_hits'") == [(None,)]
        assert q("SELECT count(*) FROM jobs") == [(2,)]                                  # the new kinds are gone
        with pytest.raises(Exception):
            with conn.begin_nested():
                conn.execute(text("INSERT INTO jobs (kind, payload) VALUES ('stats_refresh', '{}')"))
        # the data survived and the 0025 trigger still logs verdicts
        assert q("SELECT count(*) FROM rule_hits") == [(6,)]
        assert q("SELECT count(*) FROM hit_verdicts") == [(7,)]
        conn.execute(text("UPDATE rule_hits SET status = 'match' WHERE rule_id = 901 AND subject_key = :k"), {"k": str(new)})
        assert q("SELECT count(*) FROM hit_verdicts") == [(8,)]
    testing.migrate(pg_url)                                          # and up again: the schema is the models'
    with engine.connect() as conn:
        assert compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), SQLModel.metadata) == []
        assert conn.execute(text("SELECT count(*) FROM rule_hits WHERE in_main OR in_open_mr")).scalar() == 4
    engine.dispose()
