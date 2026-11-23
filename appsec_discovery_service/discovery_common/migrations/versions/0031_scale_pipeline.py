"""Pipeline at scale (worker pools, LLM throughput, statistics snapshots): new job kinds, ``jobs.started_at``, the
shared LLM rate limit bucket, an index for the day's verify counts.

* Job kinds ``stats_refresh`` (writes ``stats_snapshots`` every STATS_REFRESH_S) and ``llm_relabel`` (the relabel /
  adopt of a rule version's verdicts in slices, instead of one UPDATE over every hit of the rule inside the API
  transaction) in the ``jobs_kind_check`` constraint.
* ``jobs.started_at``: when the last attempt was claimed. ``locked_at`` is the lease and is cleared when the job
  ends, so the typical run / wait times of ``GET /jobs/health`` were always null; ``started_at`` stays on the row.
  Running jobs get their current ``locked_at``.
* ``llm_rate_buckets (name, tokens, updated_at)``: the token bucket of LLM_RATE_PER_MIN shared by every worker and
  replica (``discovery_common.llm_rate``).
* ``llm_verify_rule_created (rule_id, created_at) WHERE purpose = 'verify'``: the per-rule escalation cap
  (LLM_ESCALATION_DAILY_MAX) and the QA cap count the day's items by rule instead of scanning the jsonb of every
  verify item.

Revision ID: 0031_scale_pipeline
Revises: 0030_scale_storage
Create Date: 2026-11-23
"""
from alembic import op

revision = "0031_scale_pipeline"
down_revision = "0030_scale_storage"
branch_labels = None
depends_on = None

# the kinds as of this revision (hard-coded like the earlier job migrations: the list of the models may grow later)
OLD_KINDS = ("sync_projects", "sync_branches_mrs", "scan_branch", "scan_mr", "llm_score", "cleanup", "ingest",
             "llm_apply", "llm_prepare", "llm_coverage", "llm_trial", "llm_verify", "llm_rollout")
NEW_KINDS = ("stats_refresh", "llm_relabel")
JOB_KINDS = OLD_KINDS + NEW_KINDS


def _kinds_sql(kinds) -> str:
    return ", ".join(f"'{k}'" for k in kinds)


def upgrade() -> None:
    op.execute("ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_kind_check")
    op.execute(f"ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ({_kinds_sql(JOB_KINDS)}))")

    op.execute("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS started_at timestamptz")
    op.execute("UPDATE jobs SET started_at = locked_at WHERE status = 'running' AND started_at IS NULL")

    op.execute("""
        CREATE TABLE IF NOT EXISTS llm_rate_buckets (
            name text PRIMARY KEY,
            tokens double precision NOT NULL,
            updated_at timestamptz NOT NULL
        )""")

    op.execute("CREATE INDEX IF NOT EXISTS llm_verify_rule_created ON llm_work_items (rule_id, created_at) "
               "WHERE purpose = 'verify'")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS llm_verify_rule_created")
    op.execute("DROP TABLE IF EXISTS llm_rate_buckets")
    op.execute("ALTER TABLE jobs DROP COLUMN IF EXISTS started_at")
    # jobs of the new kinds cannot satisfy the old constraint
    op.execute(f"DELETE FROM jobs WHERE kind IN ({_kinds_sql(NEW_KINDS)})")
    op.execute("ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_kind_check")
    op.execute(f"ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ({_kinds_sql(OLD_KINDS)}))")
