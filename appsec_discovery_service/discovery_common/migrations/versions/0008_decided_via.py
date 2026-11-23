"""Where a human decision on a hit was made.

``rule_hits.decided_via``: ``rest`` (UI / REST API) or ``mcp`` (MCP tools, typically an AI
agent acting for the token's user) for reviewed hits and manual labels; NULL for machine
statuses. Rule statistics report precision for all human decisions and for the non-MCP ones.

Revision ID: 0008_decided_via
Revises: 0007_rule_tags
Create Date: 2026-11-20
"""
from alembic import op

revision = "0008_decided_via"
down_revision = "0007_rule_tags"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE rule_hits ADD COLUMN decided_via text "
               "CONSTRAINT rule_hits_decided_via_check CHECK (decided_via IN ('rest', 'mcp'))")


def downgrade() -> None:
    op.execute("ALTER TABLE rule_hits DROP COLUMN decided_via")
