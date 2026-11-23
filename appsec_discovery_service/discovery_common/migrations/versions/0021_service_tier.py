"""Tiered LLM workflow: the tiers are called "service model" and "harness model" (were "weak" and "strong",
migration 0020).

* ``rule_hits.decided_tier``: ``weak`` -> ``service``, ``strong`` -> ``harness`` (rows, the column default and the
  CHECK constraint): tiers ``service`` | ``harness`` | ``human``. No index predicate uses the tier.
* ``llm_verifications``: ``weak_status`` / ``weak_verdict`` / ``weak_model`` are renamed to ``service_status`` /
  ``service_verdict`` / ``service_model`` (plain column renames, no index uses them; ``verifier_model`` stays).
* ``llm_work_items.verify`` (verify items, jsonb): the keys ``weak_status`` / ``weak_reason`` / ``weak_fields`` /
  ``weak_model`` become ``service_*``, so open verify items stay answerable after the upgrade. Their stored
  prompts (the previous wording of the verify prompt) are kept: they are answered as they are, or expire after
  the retention (``verify_key`` reset) and are prepared again with the current prompt (VERIFY_PROMPT_VERSION 2).

The downgrade reverses all three.

Revision ID: 0021_service_tier
Revises: 0020_llm_tiers
Create Date: 2026-11-22
"""
from alembic import op

revision = "0021_service_tier"
down_revision = "0020_llm_tiers"
branch_labels = None
depends_on = None

NEW_TIERS = {"weak": "service", "strong": "harness"}
COLUMNS = ("status", "verdict", "model")
VERIFY_KEYS = ("status", "reason", "fields", "model")


def _tiers(mapping: dict, default: str) -> None:
    op.execute("ALTER TABLE rule_hits DROP CONSTRAINT IF EXISTS rule_hits_decided_tier_check")
    cases = " ".join(f"WHEN '{old}' THEN '{new}'" for old, new in mapping.items())
    olds = ", ".join(f"'{old}'" for old in mapping)
    op.execute(f"UPDATE rule_hits SET decided_tier = CASE decided_tier {cases} END WHERE decided_tier IN ({olds})")
    op.execute(f"ALTER TABLE rule_hits ALTER COLUMN decided_tier SET DEFAULT '{default}'")
    tiers = ", ".join(f"'{new}'" for new in mapping.values())
    op.execute(f"ALTER TABLE rule_hits ADD CONSTRAINT rule_hits_decided_tier_check "
               f"CHECK (decided_tier IN ({tiers}, 'human'))")


def _columns(old: str, new: str) -> None:
    for column in COLUMNS:
        op.execute(f"""
            DO $$ BEGIN
                IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema()
                           AND table_name = 'llm_verifications' AND column_name = '{old}_{column}') THEN
                    ALTER TABLE llm_verifications RENAME COLUMN {old}_{column} TO {new}_{column};
                END IF;
            END $$""")


def _verify_keys(old: str, new: str) -> None:
    for key in VERIFY_KEYS:
        op.execute(f"UPDATE llm_work_items SET verify = (verify - '{old}_{key}') "
                   f"|| jsonb_build_object('{new}_{key}', verify -> '{old}_{key}') "
                   f"WHERE purpose = 'verify' AND verify ? '{old}_{key}'")


def upgrade() -> None:
    _tiers(NEW_TIERS, "service")
    _columns("weak", "service")
    _verify_keys("weak", "service")


def downgrade() -> None:
    _verify_keys("service", "weak")
    _columns("service", "weak")
    _tiers({new: old for old, new in NEW_TIERS.items()}, "weak")
