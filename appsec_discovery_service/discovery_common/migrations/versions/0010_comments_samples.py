"""Documentation of objects and fields taken from the code.

* ``objects.comment``: the code comment / description of the object (a message, a type, a
  table, an rpc...).
* ``object_fields.comment``: the comment / description of the field; ``object_fields.samples``:
  example values (examples, enum values, defaults, or values sent by an external parser).

They are part of the content hash only when present, so objects without them keep their hash.

Revision ID: 0010_comments_samples
Revises: 0009_external_ingest
Create Date: 2026-11-21
"""
from alembic import op

revision = "0010_comments_samples"
down_revision = "0009_external_ingest"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE objects ADD COLUMN IF NOT EXISTS comment text")
    op.execute("ALTER TABLE object_fields ADD COLUMN IF NOT EXISTS comment text")
    op.execute("ALTER TABLE object_fields ADD COLUMN IF NOT EXISTS samples jsonb")


def downgrade() -> None:
    op.execute("ALTER TABLE object_fields DROP COLUMN IF EXISTS samples")
    op.execute("ALTER TABLE object_fields DROP COLUMN IF EXISTS comment")
    op.execute("ALTER TABLE objects DROP COLUMN IF EXISTS comment")
