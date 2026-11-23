"""Indexes of the jobs of one subject: ``scan_branch`` jobs by ``payload->>'branch_id'`` and
``scan_mr`` jobs by ``payload->>'mr_id'`` (newest last). The parse scan progress
(``GET /scan_progress``, the Projects page) looks up the latest finished and the active scan
job of each main branch / open MR with them instead of reading every job of the kind.

Revision ID: 0015_jobs_subject
Revises: 0014_hit_prompt_version
Create Date: 2026-11-22
"""
from alembic import op

revision = "0015_jobs_subject"
down_revision = "0014_hit_prompt_version"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE INDEX IF NOT EXISTS jobs_scan_branch_subject ON jobs ((payload ->> 'branch_id'), id) "
               "WHERE kind = 'scan_branch'")
    op.execute("CREATE INDEX IF NOT EXISTS jobs_scan_mr_subject ON jobs ((payload ->> 'mr_id'), id) "
               "WHERE kind = 'scan_mr'")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS jobs_scan_mr_subject")
    op.execute("DROP INDEX IF EXISTS jobs_scan_branch_subject")
