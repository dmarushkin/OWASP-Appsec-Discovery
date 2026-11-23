"""Progress of LLM rule runs and LLM work done by an external executor.

* ``jobs.progress`` (jsonb): progress of ``llm_score`` jobs, e.g. ``{"executor": "service",
  "total_objects": 120, "done_objects": 40, "failed_objects": 1, "rule_ids": [6],
  "phase": "running", "started_at": ..., "finished_at": ...}`` (written by the scanner in
  batches, read by the UI / REST / MCP).
* ``llm_work_items``: one model call of an LLM rule run with ``executor = external``: the
  scanner records the exact prompts a service run would send (prepare), a model running in
  a local harness claims them over MCP / REST and submits the answers, the scanner applies
  them with the same parser and hit code as a service run (``llm_apply`` job).
* ``jobs.kind`` gets ``llm_apply``.

Revision ID: 0012_llm_work
Revises: 0011_ingest_superseded
Create Date: 2026-11-21
"""
from alembic import op

revision = "0012_llm_work"
down_revision = "0011_ingest_superseded"
branch_labels = None
depends_on = None

OLD_KINDS = "'sync_projects', 'sync_branches_mrs', 'scan_branch', 'scan_mr', 'llm_score', 'cleanup', 'ingest'"


def upgrade() -> None:
    op.execute("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS progress jsonb")
    op.execute("ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_kind_check")
    op.execute(f"ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ({OLD_KINDS}, 'llm_apply'))")
    op.execute("""
        CREATE TABLE IF NOT EXISTS llm_work_items (
            id bigserial PRIMARY KEY,
            job_id bigint NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
            rule_id integer NOT NULL REFERENCES rules (id),
            rule_version integer NOT NULL,
            project_id integer NOT NULL,
            branch_id integer NOT NULL,
            mr_id integer,
            object_key uuid NOT NULL,
            content_hash uuid NOT NULL,
            call_index integer NOT NULL DEFAULT 0,
            prompt_hash text NOT NULL,
            system_prompt text,
            user_prompt text NOT NULL,
            json_schema jsonb,
            status text NOT NULL DEFAULT 'pending'
                CONSTRAINT llm_work_items_status_check
                CHECK (status IN ('pending', 'leased', 'answered', 'applied', 'failed', 'expired')),
            lease_owner text,
            lease_token text,
            lease_until timestamptz,
            answer text,
            answer_model text,
            answered_by text,
            answered_at timestamptz,
            error text,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now()
        )""")
    op.execute("CREATE INDEX IF NOT EXISTS llm_work_claim ON llm_work_items (status, job_id, id)")
    op.execute("CREATE INDEX IF NOT EXISTS llm_work_job ON llm_work_items (job_id)")
    # one open item per (rule version, object, call): a second external run does not ask twice
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS llm_work_open ON llm_work_items "
               "(rule_id, rule_version, object_key, call_index) WHERE status IN ('pending', 'leased', 'answered')")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS llm_work_items")
    op.execute("DELETE FROM jobs WHERE kind = 'llm_apply'")
    op.execute("ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_kind_check")
    op.execute(f"ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ({OLD_KINDS}))")
    op.execute("ALTER TABLE jobs DROP COLUMN IF EXISTS progress")
