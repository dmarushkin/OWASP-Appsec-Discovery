"""Rule tags set on objects.

* ``rules.tags``: tags a rule sets on the object of every confirmed hit (e.g. a
  combination rule "last name + phone" -> ``personal-data``, ``gdpr``). Read at query
  time, so editing a rule's tags re-tags its objects at once (no version bump, no rescan).
* ``rule_hits.tags``: extra tags of one hit, set by hand (manual labels).

An object's tags are the union of these over its confirmed hits.

Revision ID: 0007_rule_tags
Revises: 0006_hit_fields
Create Date: 2026-11-20
"""
from alembic import op

revision = "0007_rule_tags"
down_revision = "0006_hit_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE rules ADD COLUMN tags text[]")
    op.execute("ALTER TABLE rule_hits ADD COLUMN tags text[]")
    op.execute("CREATE INDEX rules_tags ON rules USING gin (tags) WHERE tags IS NOT NULL")


def downgrade() -> None:
    op.execute("DROP INDEX rules_tags")
    op.execute("ALTER TABLE rule_hits DROP COLUMN tags")
    op.execute("ALTER TABLE rules DROP COLUMN tags")
