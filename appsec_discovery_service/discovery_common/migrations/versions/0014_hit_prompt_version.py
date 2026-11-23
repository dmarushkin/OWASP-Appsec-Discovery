"""``rule_hits.prompt_version``: the core LLM prompts version (``LLM_PROMPTS_VERSION``) an LLM
verdict was made with. A machine verdict (no reviewer: pending, confirmed in mode auto,
rejected, need_more_info) with another version is asked again by the scanner, so new core
prompts re-classify everything a human has not decided. Existing LLM hits get NULL: they are
re-asked once with the current prompts. Human decisions are never touched.

Revision ID: 0014_hit_prompt_version
Revises: 0013_example_rules
Create Date: 2026-11-22
"""
import sqlalchemy as sa
from alembic import op

revision = "0014_hit_prompt_version"
down_revision = "0013_example_rules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("rule_hits", sa.Column("prompt_version", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("rule_hits", "prompt_version")
