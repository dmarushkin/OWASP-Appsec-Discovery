"""``ingest_batches.status = 'superseded'``: a state replaced by a newer processed one.

Older states of a (project, parser) were deleted when a newer one was processed, together
with their Idempotency-Key: a late retry of such a request was then accepted as a new push
and rolled the snapshot back. They are now kept (without their chunks) as ``superseded``,
so the key is still known and the retry is replayed; the cleanup deletes them after the
idempotency retention.

Revision ID: 0011_ingest_superseded
Revises: 0010_comments_samples
Create Date: 2026-11-21
"""
from alembic import op

revision = "0011_ingest_superseded"
down_revision = "0010_comments_samples"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE ingest_batches DROP CONSTRAINT IF EXISTS ingest_batches_status_check")
    op.execute("ALTER TABLE ingest_batches ADD CONSTRAINT ingest_batches_status_check "
               "CHECK (status IN ('open', 'committed', 'processed', 'failed', 'superseded'))")


def downgrade() -> None:
    op.execute("DELETE FROM ingest_batches WHERE status = 'superseded'")
    op.execute("ALTER TABLE ingest_batches DROP CONSTRAINT IF EXISTS ingest_batches_status_check")
    op.execute("ALTER TABLE ingest_batches ADD CONSTRAINT ingest_batches_status_check "
               "CHECK (status IN ('open', 'committed', 'processed', 'failed'))")
