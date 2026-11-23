"""Rule rollouts: the verdicts of an LLM rule made by an older version of it migrate in budgeted slices.

* ``llm_rollouts``: one row per rollout of a rule version (``to_version``), at most one open per rule
  (planned | canary | awaiting_approval | running | paused); ``budget`` (overrides of the scanner's
  LLM_ROLLOUT_* defaults), ``progress`` (written by the controller: planned / remaining / calls / ETA / branches).
* ``jobs.priority`` (NOT NULL, default 0): ``claim`` takes ``ORDER BY priority DESC, run_after, id`` (index
  ``jobs_ready`` rebuilt on that order), so the slices of a rollout (priority -10) never starve fresh work and
  prompt trials (+5) are not stuck behind it.
* ``jobs.kind`` gets ``llm_rollout`` (the controller, control worker; no model is called).
* ``llm_coverage.answered_stale``: remaining subjects whose verdict is from an older version of the rule (kept and
  scoring until the rollout asks them again).

Downgrade: the llm_rollout jobs and the table are dropped, so are the columns; ``jobs_ready`` gets its old order.

Revision ID: 0026_llm_rollouts
Revises: 0025_hit_verdicts
Create Date: 2026-11-22
"""
from alembic import op

revision = "0026_llm_rollouts"
down_revision = "0025_hit_verdicts"
branch_labels = None
depends_on = None

OLD_KINDS = ("'sync_projects', 'sync_branches_mrs', 'scan_branch', 'scan_mr', 'llm_score', 'cleanup', 'ingest', "
             "'llm_apply', 'llm_prepare', 'llm_coverage', 'llm_trial', 'llm_verify'")
OPEN = "'planned', 'canary', 'awaiting_approval', 'running', 'paused'"


def upgrade() -> None:
    op.execute(f"""
        CREATE TABLE IF NOT EXISTS llm_rollouts (
            id bigserial PRIMARY KEY,
            rule_id integer NOT NULL REFERENCES rules(id),
            from_version integer,
            to_version integer NOT NULL,
            status text NOT NULL CONSTRAINT llm_rollouts_status_check CHECK (status IN ({OPEN}, 'done', 'cancelled',
                                                                                         'rolled_back', 'failed')),
            mode text NOT NULL DEFAULT 'staged' CONSTRAINT llm_rollouts_mode_check
                CHECK (mode IN ('immediate', 'canary', 'staged')),
            source text NOT NULL DEFAULT 'manual',
            budget jsonb NOT NULL DEFAULT '{{}}'::jsonb,
            progress jsonb NOT NULL DEFAULT '{{}}'::jsonb,
            created_by text,
            started_by text,
            created_at timestamptz NOT NULL DEFAULT now(),
            started_at timestamptz,
            finished_at timestamptz,
            paused_reason text,
            note text
        )""")
    op.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS llm_rollouts_one_open ON llm_rollouts (rule_id) "
               f"WHERE status IN ({OPEN})")
    op.execute("CREATE INDEX IF NOT EXISTS llm_rollouts_rule ON llm_rollouts (rule_id, id)")
    op.execute("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS priority integer NOT NULL DEFAULT 0")
    op.execute("DROP INDEX IF EXISTS jobs_ready")
    op.execute("CREATE INDEX jobs_ready ON jobs (priority DESC, run_after, id) WHERE status = 'pending'")
    op.execute("ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_kind_check")
    op.execute(f"ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ({OLD_KINDS}, 'llm_rollout'))")
    op.execute("ALTER TABLE llm_coverage ADD COLUMN IF NOT EXISTS answered_stale integer NOT NULL DEFAULT 0")


def downgrade() -> None:
    op.execute("ALTER TABLE llm_coverage DROP COLUMN IF EXISTS answered_stale")
    op.execute("DELETE FROM jobs WHERE kind = 'llm_rollout'")
    op.execute("ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_kind_check")
    op.execute(f"ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ({OLD_KINDS}))")
    op.execute("DROP INDEX IF EXISTS jobs_ready")
    op.execute("ALTER TABLE jobs DROP COLUMN IF EXISTS priority")
    op.execute("CREATE INDEX jobs_ready ON jobs (run_after, id) WHERE status = 'pending'")
    op.execute("DROP TABLE IF EXISTS llm_rollouts")
