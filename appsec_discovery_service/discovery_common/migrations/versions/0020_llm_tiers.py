"""Tiered LLM decisions: the service (weak) model categorises, a strong model in a harness verifies.

* ``rule_hits.decided_tier`` (``weak`` | ``strong`` | ``human``, NOT NULL, default ``weak``): who made the
  current decision. Backfill: ``reviewer`` set -> ``human``, else ``weak`` (the column default, no rewrite).
  ``verifier_model`` / ``verified_at``: the strong model that verified the hit last and when (kept when a weak
  re-ask on changed content replaces a strong decision: such hits are verified again). ``asked_by_model``: the
  strong model could not decide and asked a human (``need_more_info``, the question in ``note``; review queue
  tab "Questions from the model"). ``verify_key``: the weak verdict (rule version, core prompts, subject hash,
  status) a verify item was created for, so a verdict is escalated / sampled once.
* ``llm_work_items.purpose`` (``score`` | ``verify``, default ``score``): verify items are model calls of the
  strong model (the harness) about one hit: ``subject_key`` / ``field_name`` name the hit, ``verify`` (jsonb)
  holds the weak verdict being checked (status, reason, fields, model, subject hash, sample: escalation | qa |
  reverify) and the investigation rounds. The open-items unique index of score items gets ``purpose = 'score'``;
  verify items have their own (one open item per hit).
* ``llm_verifications``: the durable log of strong decisions (work items are deleted after their retention):
  weak vs strong verdict per sample, confidence, needs_human - the QA metrics (agreement per rule) read it.
* ``jobs.kind`` gets ``llm_verify`` (the control worker selects escalations and the QA sample after a weak run
  and records their verify calls; no model is called).

Revision ID: 0020_llm_tiers
Revises: 0019_prompt_trials
Create Date: 2026-11-22
"""
from alembic import op

revision = "0020_llm_tiers"
down_revision = "0019_prompt_trials"
branch_labels = None
depends_on = None

OLD_KINDS = ("'sync_projects', 'sync_branches_mrs', 'scan_branch', 'scan_mr', 'llm_score', 'cleanup', 'ingest', "
             "'llm_apply', 'llm_prepare', 'llm_coverage', 'llm_trial'")
OPEN = "'pending', 'leased', 'answered'"


def upgrade() -> None:
    op.execute("ALTER TABLE rule_hits ADD COLUMN IF NOT EXISTS decided_tier text NOT NULL DEFAULT 'weak'")
    op.execute("ALTER TABLE rule_hits DROP CONSTRAINT IF EXISTS rule_hits_decided_tier_check")
    op.execute("ALTER TABLE rule_hits ADD CONSTRAINT rule_hits_decided_tier_check "
               "CHECK (decided_tier IN ('weak', 'strong', 'human'))")
    op.execute("UPDATE rule_hits SET decided_tier = 'human' WHERE reviewer IS NOT NULL")
    op.execute("ALTER TABLE rule_hits ADD COLUMN IF NOT EXISTS verifier_model text")
    op.execute("ALTER TABLE rule_hits ADD COLUMN IF NOT EXISTS verified_at timestamptz")
    op.execute("ALTER TABLE rule_hits ADD COLUMN IF NOT EXISTS asked_by_model boolean NOT NULL DEFAULT false")
    op.execute("ALTER TABLE rule_hits ADD COLUMN IF NOT EXISTS verify_key text")
    op.execute("CREATE INDEX IF NOT EXISTS hits_model_questions ON rule_hits (project_id) "
               "WHERE asked_by_model AND status = 'need_more_info'")

    op.execute("ALTER TABLE llm_work_items ADD COLUMN IF NOT EXISTS purpose text NOT NULL DEFAULT 'score'")
    op.execute("ALTER TABLE llm_work_items DROP CONSTRAINT IF EXISTS llm_work_items_purpose_check")
    op.execute("ALTER TABLE llm_work_items ADD CONSTRAINT llm_work_items_purpose_check "
               "CHECK (purpose IN ('score', 'verify'))")
    op.execute("ALTER TABLE llm_work_items ADD COLUMN IF NOT EXISTS subject_key uuid")
    op.execute("ALTER TABLE llm_work_items ADD COLUMN IF NOT EXISTS field_name text")
    op.execute("ALTER TABLE llm_work_items ADD COLUMN IF NOT EXISTS verify jsonb")
    op.execute("DROP INDEX IF EXISTS llm_work_open")
    op.execute(f"CREATE UNIQUE INDEX llm_work_open ON llm_work_items (rule_id, rule_version, object_key, call_index) "
               f"WHERE status IN ({OPEN}) AND purpose = 'score'")
    op.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS llm_verify_open ON llm_work_items (rule_id, subject_key) "
               f"WHERE status IN ({OPEN}) AND purpose = 'verify'")
    op.execute("CREATE INDEX IF NOT EXISTS llm_work_purpose ON llm_work_items (purpose, status)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS llm_verifications (
            id bigserial PRIMARY KEY,
            rule_id integer NOT NULL REFERENCES rules(id),
            rule_version integer NOT NULL,
            subject_key uuid NOT NULL,
            object_key uuid NOT NULL,
            field_name text,
            project_id integer NOT NULL,
            sample text NOT NULL,
            weak_status text NOT NULL,
            weak_verdict text NOT NULL,
            weak_model text,
            verdict text,
            confidence text,
            needs_human boolean NOT NULL DEFAULT false,
            outcome text NOT NULL,
            verifier_model text,
            verified_by text,
            reason text,
            question text,
            investigation text,
            work_item_id bigint,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT llm_verifications_sample_check CHECK (sample IN ('escalation', 'qa', 'reverify', 'manual')),
            CONSTRAINT llm_verifications_outcome_check CHECK (outcome IN ('final', 'asked_human', 'stale'))
        )""")
    op.execute("CREATE INDEX IF NOT EXISTS llm_verifications_rule ON llm_verifications (rule_id, created_at)")
    op.execute("CREATE INDEX IF NOT EXISTS llm_verifications_created ON llm_verifications (created_at)")

    op.execute("ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_kind_check")
    op.execute(f"ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ({OLD_KINDS}, 'llm_verify'))")


def downgrade() -> None:
    op.execute("DELETE FROM llm_work_items WHERE purpose = 'verify'")
    op.execute("DELETE FROM jobs WHERE kind = 'llm_verify'")
    op.execute("ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_kind_check")
    op.execute(f"ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ({OLD_KINDS}))")
    op.execute("DROP TABLE IF EXISTS llm_verifications")
    op.execute("DROP INDEX IF EXISTS llm_work_purpose")
    op.execute("DROP INDEX IF EXISTS llm_verify_open")
    op.execute("DROP INDEX IF EXISTS llm_work_open")
    op.execute(f"CREATE UNIQUE INDEX llm_work_open ON llm_work_items (rule_id, rule_version, object_key, call_index) "
               f"WHERE status IN ({OPEN})")
    for column in ("verify", "field_name", "subject_key", "purpose"):
        op.execute(f"ALTER TABLE llm_work_items DROP COLUMN IF EXISTS {column}")
    op.execute("DROP INDEX IF EXISTS hits_model_questions")
    for column in ("verify_key", "asked_by_model", "verified_at", "verifier_model", "decided_tier"):
        op.execute(f"ALTER TABLE rule_hits DROP COLUMN IF EXISTS {column}")
