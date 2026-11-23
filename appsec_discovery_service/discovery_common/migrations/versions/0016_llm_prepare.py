"""``llm_prepare`` job kind: the prepare phase of an external LLM run (``executor = external``)
gets a kind of its own, run by the scanner's control worker together with ``llm_apply``.
Neither calls a model (they read the candidates, build the prompts and write work items /
hits), so they no longer wait behind long service ``llm_score`` runs on the LLM workers.

* ``jobs_kind_check`` gets ``llm_prepare``.
* Existing ``llm_score`` jobs with ``payload.executor = 'external'`` become ``llm_prepare``
  (pending ones are then claimed by the control worker; a running one finishes where it runs,
  a retry of it goes to the control worker; done ones keep their work items and progress).

Revision ID: 0016_llm_prepare
Revises: 0015_jobs_subject
Create Date: 2026-11-22
"""
from alembic import op

revision = "0016_llm_prepare"
down_revision = "0015_jobs_subject"
branch_labels = None
depends_on = None

OLD_KINDS = ("'sync_projects', 'sync_branches_mrs', 'scan_branch', 'scan_mr', 'llm_score', 'cleanup', 'ingest', "
             "'llm_apply'")


def upgrade() -> None:
    op.execute("ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_kind_check")
    op.execute(f"ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ({OLD_KINDS}, 'llm_prepare'))")
    op.execute("UPDATE jobs SET kind = 'llm_prepare', updated_at = now() "
               "WHERE kind = 'llm_score' AND payload ->> 'executor' = 'external'")


def downgrade() -> None:
    op.execute("UPDATE jobs SET kind = 'llm_score', updated_at = now() WHERE kind = 'llm_prepare'")
    op.execute("ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_kind_check")
    op.execute(f"ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ({OLD_KINDS}))")
