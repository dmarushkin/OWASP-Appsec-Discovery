"""Built-in rules: short names, the keyword scoring opt-in, no env-managed LLM rule.

* The core keyword scoring rules get short names: ``core:score_tags:field`` -> ``kw-fields`` (field names),
  ``core:score_tags:object`` -> ``kw-props`` (the object's properties). A live rule that already has the new name
  is left alone (logged). ``manual:labels`` keeps its name.
* New installs (no project, no hit of these rules yet): both are disabled - the built-in keyword scoring is opt-in
  (enable kw-fields / kw-props in the UI); a disabled one records no score_tags hit. Existing installs keep their
  ``enabled`` state.
* The env-managed LLM rule (``scope.source = 'env'``, synced from LLM_PROMPT / LLM_PROMPT_VER, both removed): without
  human decisions it is soft-deleted, else only disabled (its decided hits stay, logged); its open rollouts are
  cancelled. An LLM rule without category made in the UI / REST / MCP is the built-in classifier, as before.

Downgrade: the old names come back; the env rule this migration deleted / disabled is live and enabled again
(``updated_by`` marks it); the keyword rules keep their ``enabled`` state.

Revision ID: 0028_builtin_rules
Revises: 0027_object_names
Create Date: 2026-11-22
"""
import logging

import sqlalchemy as sa
from alembic import context, op

revision = "0028_builtin_rules"
down_revision = "0027_object_names"
branch_labels = None
depends_on = None

logger = logging.getLogger("alembic.runtime.migration")

RENAMES = {"core:score_tags:field": "kw-fields", "core:score_tags:object": "kw-props"}
MARK = "migration:0028_builtin_rules"


def _rename(mapping) -> None:
    for old, new in mapping.items():
        if not context.is_offline_mode():
            taken = op.get_bind().execute(sa.text(
                "SELECT id FROM rules WHERE name = :n AND deleted_at IS NULL"), {"n": new}).scalar()
            if taken is not None:
                logger.warning(f"0028_builtin_rules: a live rule {new!r} (id {taken}) exists: {old!r} is not renamed")
                continue
        op.execute(sa.text("UPDATE rules SET name = :new WHERE name = :old AND deleted_at IS NULL AND NOT EXISTS "
                           "(SELECT 1 FROM rules x WHERE x.name = :new AND x.deleted_at IS NULL)")
                   .bindparams(old=old, new=new))


def upgrade() -> None:
    _rename(RENAMES)
    names = ", ".join(f"'{n}'" for n in RENAMES.values())
    op.execute(f"""UPDATE rules SET enabled = false
                   WHERE name IN ({names}) AND deleted_at IS NULL
                     AND NOT EXISTS (SELECT 1 FROM gitlab_projects)
                     AND NOT EXISTS (SELECT 1 FROM rule_hits h JOIN rules r ON r.id = h.rule_id WHERE r.name IN ({names}))""")
    if not context.is_offline_mode():
        for row in op.get_bind().execute(sa.text("""
                SELECT r.id, r.name, (SELECT count(*) FROM rule_hits h WHERE h.rule_id = r.id AND h.reviewer IS NOT NULL)
                       AS decided
                FROM rules r WHERE r.kind = 'llm' AND r.deleted_at IS NULL AND r.scope ->> 'source' = 'env'""")):
            if row.decided:
                logger.warning(f"0028_builtin_rules: the env-managed LLM rule {row.name!r} (id {row.id}) has "
                               f"{row.decided} human decisions: disabled, not deleted (delete it in the UI when done)")
    op.execute(f"""UPDATE llm_rollouts SET status = 'cancelled', finished_at = now(),
                          note = COALESCE(note || E'\\n', '') || 'the env-managed rule was removed'
                   WHERE status IN ('planned', 'canary', 'awaiting_approval', 'running', 'paused')
                     AND rule_id IN (SELECT id FROM rules WHERE kind = 'llm' AND deleted_at IS NULL
                                     AND scope ->> 'source' = 'env')""")
    op.execute(f"""UPDATE rules r SET enabled = false, updated_by = '{MARK}', updated_at = now(),
                          deleted_at = CASE WHEN EXISTS (SELECT 1 FROM rule_hits h WHERE h.rule_id = r.id
                                                         AND h.reviewer IS NOT NULL) THEN NULL ELSE now() END
                   WHERE r.kind = 'llm' AND r.deleted_at IS NULL AND r.scope ->> 'source' = 'env'""")


def downgrade() -> None:
    op.execute(f"""UPDATE rules SET enabled = true, deleted_at = NULL, updated_by = NULL
                   WHERE updated_by = '{MARK}' AND kind = 'llm' AND scope ->> 'source' = 'env'
                     AND NOT EXISTS (SELECT 1 FROM rules x WHERE x.name = rules.name AND x.deleted_at IS NULL
                                     AND x.id <> rules.id)""")
    _rename({new: old for old, new in RENAMES.items()})
