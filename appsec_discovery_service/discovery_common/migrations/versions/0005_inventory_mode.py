"""Inventory scan mode and manual labels.

* ``gitlab_projects.scan_mode``: ``rules`` (default, keyword + LLM rules categorise objects)
  or ``inventory`` (objects and fields are stored, nothing is categorised).
* ``rules.kind`` gets ``manual``; the built-in rule ``manual:labels`` owns the hits people
  set by hand (REST ``POST /objects/{key}/labels``, MCP ``label``): confirmed hits with a
  reviewer, so scans never overwrite them.

Revision ID: 0005_inventory_mode
Revises: 0004_jobs
Create Date: 2026-11-20
"""
from alembic import op

revision = "0005_inventory_mode"
down_revision = "0004_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE gitlab_projects ADD COLUMN scan_mode text NOT NULL DEFAULT 'rules' "
               "CONSTRAINT gitlab_projects_scan_mode_check CHECK (scan_mode IN ('rules', 'inventory'))")
    op.execute("ALTER TABLE rules DROP CONSTRAINT rules_kind_check")
    op.execute("ALTER TABLE rules ADD CONSTRAINT rules_kind_check CHECK (kind IN ('keyword', 'llm', 'manual'))")
    op.execute("""
        INSERT INTO rules (kind, name, mode, enabled, version, scope, created_at, updated_by)
        SELECT 'manual', 'manual:labels', 'review', true, 1, '{"builtin": "manual"}'::jsonb, now(), 'migration'
        WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'manual:labels' AND deleted_at IS NULL)""")


def downgrade() -> None:
    op.execute("DELETE FROM rule_hits WHERE rule_id IN (SELECT id FROM rules WHERE kind = 'manual')")
    op.execute("DELETE FROM rules WHERE kind = 'manual'")
    op.execute("ALTER TABLE rules DROP CONSTRAINT rules_kind_check")
    op.execute("ALTER TABLE rules ADD CONSTRAINT rules_kind_check CHECK (kind IN ('keyword', 'llm'))")
    op.execute("ALTER TABLE gitlab_projects DROP COLUMN scan_mode")
