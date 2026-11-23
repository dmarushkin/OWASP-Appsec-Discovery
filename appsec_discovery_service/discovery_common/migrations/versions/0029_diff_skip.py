"""Diff-based scan skip: what a branch snapshot was made with.

Before cloning a main branch (or an MR) the scanner asks the GitLab compare API which files changed since the commit
the snapshot reflects (``scanned_commit``); when no parser of the scan reads any of them, the snapshot is moved to the
new commit without a clone or a parse (README "Service mode", SCAN_DIFF_SKIP). Three columns of ``gitlab_branches``
say when that is safe:

* ``scan_fingerprint``: the scan configuration of the snapshot (core package version, parsers, keyword rules; the
  scanner's ``services.diff_service.scan_fingerprint``) - a different one forces a full scan;
* ``full_scanned_at``: when the branch was last cloned and parsed (a skip keeps it) - older than
  SCAN_FULL_RESCAN_DAYS forces a full scan;
* ``delta_target_commit`` (MR source branches): the target commit the stored delta was computed against - an MR is
  skipped only when neither its source nor its target moved in parser files since.

Existing rows have none of them: every branch is fully scanned once at its next commit, then the skip applies.

Revision ID: 0029_diff_skip
Revises: 0028_builtin_rules
Create Date: 2026-11-23
"""
import sqlalchemy as sa
from alembic import op

revision = "0029_diff_skip"
down_revision = "0028_builtin_rules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("gitlab_branches", sa.Column("scan_fingerprint", sa.Text(), nullable=True))
    op.add_column("gitlab_branches", sa.Column("full_scanned_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("gitlab_branches", sa.Column("delta_target_commit", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("gitlab_branches", "delta_target_commit")
    op.drop_column("gitlab_branches", "full_scanned_at")
    op.drop_column("gitlab_branches", "scan_fingerprint")
