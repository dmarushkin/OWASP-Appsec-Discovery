"""API at scale: decisions by filter (``review_batches``) and their trace in the verdict history.

* ``review_batches``: one row per applied ``POST /hits/decide`` - the filter (as sent), the action and target
  status, note / category / severity, the reviewer and channel (``via``), ``expected_total`` (what the dry run
  showed) and ``matched`` (what the server counted at apply time; equal or the apply was refused), the hits
  ``applied`` and ``cascaded`` (field marks of decided object hits), ``applied_at``; undo fills ``undone_at`` /
  ``undone_by`` / ``restored``.
* ``review_batch_items``: the hits of a batch with the state the decision replaced (``prev_*``), so an undo can put
  it back for the hits nobody touched since; ``cascaded`` marks the field hits decided through their object.
* ``hit_verdicts.batch_id``: the history rows written while a batch applies (or is undone) name it; the trigger
  function ``log_hit_verdict`` (migration 0025) reads it from the transaction setting ``discovery.batch_id``, as it
  reads ``discovery.hit_source`` and ``discovery.rollout_id``.

Revision ID: 0032_scale_api
Revises: 0031_scale_pipeline
Create Date: 2026-11-23
"""
from alembic import op

revision = "0032_scale_api"
down_revision = "0031_scale_pipeline"
branch_labels = None
depends_on = None

# the columns the trigger copies (as migration 0025)
COLUMNS = ("rule_id, subject_key, object_key, field_name, project_id, rule_version, prompt_version, model, status, "
           "category, severity, reason, fields, names_hash, subject_hash, decided_tier, reviewer, verifier_model")


def _trigger_function(with_batch: bool) -> str:
    new = ", ".join(f"NEW.{c.strip()}" for c in COLUMNS.split(","))
    batch_col = ", batch_id" if with_batch else ""
    batch_val = ", CAST(NULLIF(current_setting('discovery.batch_id', true), '') AS bigint)" if with_batch else ""
    return f"""
        CREATE OR REPLACE FUNCTION log_hit_verdict() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            INSERT INTO hit_verdicts ({COLUMNS}, source, rollout_id{batch_col})
            VALUES ({new},
                    COALESCE(NULLIF(current_setting('discovery.hit_source', true), ''), NEW.decided_tier),
                    CAST(NULLIF(current_setting('discovery.rollout_id', true), '') AS bigint){batch_val});
            RETURN NULL;
        END $$"""


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS review_batches (
            id bigserial PRIMARY KEY,
            filter jsonb NOT NULL,
            action text NOT NULL,
            target_status text NOT NULL,
            note text,
            category text,
            severity text,
            reviewer text NOT NULL,
            via text NOT NULL DEFAULT 'rest',
            expected_total integer NOT NULL,
            matched integer NOT NULL,
            applied integer NOT NULL DEFAULT 0,
            cascaded integer NOT NULL DEFAULT 0,
            applied_at timestamptz NOT NULL DEFAULT now(),
            undone_at timestamptz,
            undone_by text,
            restored integer
        )""")
    op.execute("CREATE INDEX IF NOT EXISTS review_batches_reviewer ON review_batches (reviewer, id)")
    op.execute("""
        CREATE TABLE IF NOT EXISTS review_batch_items (
            batch_id bigint NOT NULL REFERENCES review_batches (id) ON DELETE CASCADE,
            rule_id integer NOT NULL,
            subject_key uuid NOT NULL,
            cascaded boolean NOT NULL DEFAULT false,
            prev_status text NOT NULL,
            prev_reviewer text,
            prev_reviewed_at timestamptz,
            prev_decided_via text,
            prev_decided_tier text,
            prev_asked_by_model boolean,
            prev_category text,
            prev_severity text,
            prev_note text,
            prev_machine_status text,
            PRIMARY KEY (batch_id, rule_id, subject_key)
        )""")
    op.execute("CREATE INDEX IF NOT EXISTS review_batch_items_hit ON review_batch_items (rule_id, subject_key)")
    op.execute("ALTER TABLE hit_verdicts ADD COLUMN IF NOT EXISTS batch_id bigint")
    op.execute("CREATE INDEX IF NOT EXISTS hit_verdicts_batch ON hit_verdicts (batch_id) WHERE batch_id IS NOT NULL")
    op.execute(_trigger_function(with_batch=True))


def downgrade() -> None:
    op.execute(_trigger_function(with_batch=False))
    op.execute("DROP INDEX IF EXISTS hit_verdicts_batch")
    op.execute("ALTER TABLE hit_verdicts DROP COLUMN IF EXISTS batch_id")
    op.execute("DROP TABLE IF EXISTS review_batch_items")
    op.execute("DROP TABLE IF EXISTS review_batches")
