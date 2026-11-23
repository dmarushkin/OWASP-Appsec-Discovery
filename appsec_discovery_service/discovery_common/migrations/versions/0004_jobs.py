"""Job queue of the scanner (stage 6, P2-4).

``jobs`` replaces the scanner's multiprocessing Manager dicts / queue: the scheduler and
the handlers enqueue work (``INSERT ... ON CONFLICT DO NOTHING`` on the partial unique
index ``jobs_dedup_active``: one active job per ``dedup_key``), workers claim it with
``SELECT ... FOR UPDATE SKIP LOCKED`` and hold a lease (``locked_by`` / ``locked_at``,
renewed by a heartbeat). See ``discovery_common/jobs.py``.

Revision ID: 0004_jobs
Revises: 0003_rules_review
Create Date: 2026-11-20
"""
from alembic import op

revision = "0004_jobs"
down_revision = "0003_rules_review"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE jobs (
            id bigserial PRIMARY KEY,
            kind text NOT NULL,
            payload jsonb NOT NULL DEFAULT '{}'::jsonb,
            dedup_key text,
            status text NOT NULL DEFAULT 'pending',
            attempts integer NOT NULL DEFAULT 0,
            max_attempts integer NOT NULL DEFAULT 5,
            run_after timestamptz NOT NULL DEFAULT now(),
            locked_by text,
            locked_at timestamptz,
            last_error text,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            finished_at timestamptz,
            CONSTRAINT jobs_kind_check CHECK (kind IN ('sync_projects', 'sync_branches_mrs', 'scan_branch',
                                                      'scan_mr', 'llm_score', 'cleanup')),
            CONSTRAINT jobs_status_check CHECK (status IN ('pending', 'running', 'done', 'failed'))
        )""")
    op.execute("CREATE UNIQUE INDEX jobs_dedup_active ON jobs (dedup_key) WHERE status IN ('pending', 'running')")
    op.execute("CREATE INDEX jobs_ready ON jobs (run_after, id) WHERE status = 'pending'")
    op.execute("CREATE INDEX jobs_lease ON jobs (locked_at) WHERE status = 'running'")
    op.execute("CREATE INDEX jobs_kind_created ON jobs (kind, created_at)")


def downgrade() -> None:
    op.execute("DROP TABLE jobs")
