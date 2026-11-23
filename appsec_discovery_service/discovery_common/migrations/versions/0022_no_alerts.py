"""Alerting is removed (MR notes, Telegram; the ``alert`` action of keyword rules).

* ``rules.scope.action``: ``alert`` -> ``score`` (an alert rule scored like a score rule and also flagged its
  hits for the MR alerts; the scoring is unchanged). The rule's ``version`` is not bumped: its hits stay as they
  are.
* ``rule_hits.alerted_at`` (when a hit was alerted on an MR) and the legacy ``gitlab_mrs.alerted_at`` (never written
  since the storage v2) are dropped. No index or constraint uses them (a dependent index would go with the column).
  ``rules`` has no CHECK on ``scope.action``.

Downgrade re-adds both columns, NULL everywhere. The ``alert`` actions cannot be restored (which ``score`` rules
were ``alert`` rules is not recorded): set them again by hand if the previous release is run. Note that a previous
scanner treats confirmed hits with ``alerted_at`` NULL as not alerted yet: it alerts the ones new in an open MR on
the MR's next scan.

Revision ID: 0022_no_alerts
Revises: 0021_service_tier
Create Date: 2026-11-22
"""
from alembic import op

revision = "0022_no_alerts"
down_revision = "0021_service_tier"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""UPDATE rules SET scope = jsonb_set(scope, '{action}', '"score"')
                  WHERE scope ->> 'action' = 'alert'""")
    op.execute("ALTER TABLE rule_hits DROP COLUMN IF EXISTS alerted_at")
    op.execute("ALTER TABLE gitlab_mrs DROP COLUMN IF EXISTS alerted_at")


def downgrade() -> None:
    op.execute("ALTER TABLE rule_hits ADD COLUMN IF NOT EXISTS alerted_at timestamptz")
    op.execute("ALTER TABLE gitlab_mrs ADD COLUMN IF NOT EXISTS alerted_at timestamp without time zone")
