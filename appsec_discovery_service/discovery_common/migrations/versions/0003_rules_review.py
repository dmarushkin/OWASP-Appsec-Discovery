"""Rules and human review (stage 5b, P1-6 / P3-2).

Schema:
  * rules: ``created_at``, ``deleted_at`` (soft delete: a deleted rule is also disabled; its
    hits keep a valid FK), ``updated_by``; one live rule per name
    (``rules_name_live``, partial unique index). Existing duplicate names get a ``#<id>``
    suffix first.
  * rule_hits: ``reason`` (the LLM's explanation, shown to the reviewer).

Data:
  * the API's legacy ``scorerule`` table -> ``rules`` (kind keyword, mode auto):
    ``service_re`` -> ``scope.project_re``, ``object_re``/``object_type_re``/``field_re``/
    ``field_type_re`` -> the same scope keys, ``status = skip`` -> ``scope.action = exclude``,
    ``risk_score`` -> severity buckets (>= 9 critical, >= 7 high, >= 4 medium, >= 1 low,
    else info; the raw value is kept in ``scope.legacy_risk_score``). Then ``scorerule`` and
    its enum type are dropped: rules are now edited through ``/keyword_rules``.
  * the LLM rule created from LLM_PROMPT / LLM_PROMPT_VER by 0002 is marked
    ``scope.source = 'env'``: the scanner keeps it in sync with the env until it is edited
    through the API (which removes the marker).

Revision ID: 0003_rules_review
Revises: 0002_storage_v2
Create Date: 2026-11-20
"""
from alembic import op

revision = "0003_rules_review"
down_revision = "0002_storage_v2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE rules ADD COLUMN created_at timestamptz DEFAULT now(), "
               "ADD COLUMN deleted_at timestamptz, ADD COLUMN updated_by text")
    op.execute("UPDATE rules SET created_at = COALESCE(updated_at, now())")
    op.execute("ALTER TABLE rule_hits ADD COLUMN reason text")

    # ---- legacy API rules (scorerule) -> keyword rules ----------------------------------------
    op.execute("""
        INSERT INTO rules (kind, name, category, severity, target, mode, scope, version, enabled,
                           created_at, updated_at, updated_by)
        SELECT 'keyword', 'scorerule:' || id, NULL,
               CASE WHEN risk_score >= 9 THEN 'critical' WHEN risk_score >= 7 THEN 'high'
                    WHEN risk_score >= 4 THEN 'medium' WHEN risk_score >= 1 THEN 'low' ELSE 'info' END,
               CASE WHEN COALESCE(field_re, '') <> '' OR COALESCE(field_type_re, '') <> '' THEN 'field' ELSE 'object' END,
               'auto',
               jsonb_strip_nulls(jsonb_build_object(
                   'project_re', NULLIF(service_re, ''), 'object_re', NULLIF(object_re, ''),
                   'object_type_re', NULLIF(object_type_re, ''), 'field_re', NULLIF(field_re, ''),
                   'field_type_re', NULLIF(field_type_re, ''),
                   'action', CASE WHEN status::text = 'skip' THEN 'exclude' ELSE 'score' END,
                   'legacy_risk_score', risk_score)),
               1, true, now(), now(), 'migrated'
        FROM scorerule ORDER BY id""")
    op.execute("DROP TABLE scorerule")
    op.execute("DROP TYPE IF EXISTS scorerulestatus")

    # ---- the env-managed LLM rule ------------------------------------------------------------
    op.execute("""
        UPDATE rules SET scope = COALESCE(scope, '{}'::jsonb) || '{"source": "env"}'::jsonb
        WHERE kind = 'llm' AND name = 'llm'""")

    # ---- one live rule per name ----------------------------------------------------------------
    op.execute("""
        UPDATE rules r SET name = COALESCE(r.name, r.kind) || ' #' || r.id
        FROM (SELECT id, row_number() OVER (PARTITION BY name ORDER BY id) AS rn FROM rules) d
        WHERE d.id = r.id AND (d.rn > 1 OR r.name IS NULL)""")
    op.execute("CREATE UNIQUE INDEX rules_name_live ON rules (name) WHERE deleted_at IS NULL")


def downgrade() -> None:
    raise NotImplementedError("0003_rules_review is a one-way data migration; restore a backup to go back")
