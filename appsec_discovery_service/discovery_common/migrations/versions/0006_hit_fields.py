"""Fields of object hits.

``rule_hits.fields``: on an object hit of a field-combination keyword rule (``fields_all``)
or of an LLM object rule, the names of the fields that made the object match (e.g. last
name + phone). One hit and one review decision per combination.

Revision ID: 0006_hit_fields
Revises: 0005_inventory_mode
Create Date: 2026-11-20
"""
from alembic import op

revision = "0006_hit_fields"
down_revision = "0005_inventory_mode"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE rule_hits ADD COLUMN fields text[]")


def downgrade() -> None:
    op.execute("ALTER TABLE rule_hits DROP COLUMN fields")
