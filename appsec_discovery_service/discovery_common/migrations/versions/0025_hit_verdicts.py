"""Verdict history of the LLM hits: ``hit_verdicts``.

A ``rule_hits`` row is one current verdict per (rule, subject), updated in place by every writer (service runs,
external answers, the harness model, reviewers, carry-over / re-review, rollouts). Two triggers append the new state
of an LLM hit (``prompt_version`` set) to ``hit_verdicts``: on INSERT, and on UPDATE only when something of the
verdict changed - status, rule version, core prompts version, model, reason, fields, tier, reviewer, verifier model,
the hashes of what the model saw. Category / severity / note / seen / verify-key updates alone are not logged
(``category`` / ``severity`` edits of a rule are propagated to its machine hits without a history row per hit).

``source``: the session setting ``discovery.hit_source`` (``adopt``, ``relabel``, ...) when a writer sets one, else
the hit's ``decided_tier`` (service | harness | human); ``rollout_id``: the setting ``discovery.rollout_id`` (the
slices of a rule rollout set it). Retention (the scanner's cleanup): rows older than HIT_HISTORY_DAYS (180) except the
last row of every rule version of a subject that still has a hit. Backfill: the current LLM hits (``source``
backfill), so every hit has its history from now on.

Revision ID: 0025_hit_verdicts
Revises: 0024_rule_versions
Create Date: 2026-11-22
"""
from alembic import op

revision = "0025_hit_verdicts"
down_revision = "0024_rule_versions"
branch_labels = None
depends_on = None

COLUMNS = ("rule_id, subject_key, object_key, field_name, project_id, rule_version, prompt_version, model, status, "
           "category, severity, reason, fields, names_hash, subject_hash, decided_tier, reviewer, verifier_model")
CHANGED = ("status", "rule_version", "prompt_version", "model", "reason", "fields", "decided_tier", "reviewer",
           "verifier_model", "names_hash", "subject_hash")


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS hit_verdicts (
            id bigserial PRIMARY KEY,
            rule_id integer NOT NULL,
            subject_key uuid NOT NULL,
            object_key uuid NOT NULL,
            field_name text,
            project_id integer NOT NULL,
            rule_version integer NOT NULL,
            prompt_version text,
            model text,
            status text NOT NULL,
            category text,
            severity text,
            reason text,
            fields text[],
            names_hash text,
            subject_hash text,
            decided_tier text NOT NULL,
            reviewer text,
            verifier_model text,
            source text NOT NULL,
            rollout_id bigint,
            created_at timestamptz NOT NULL DEFAULT now()
        )""")
    op.execute("CREATE INDEX IF NOT EXISTS hit_verdicts_subject ON hit_verdicts (rule_id, subject_key, id)")
    op.execute("CREATE INDEX IF NOT EXISTS hit_verdicts_created ON hit_verdicts (created_at)")
    op.execute("CREATE INDEX IF NOT EXISTS hit_verdicts_rollout ON hit_verdicts (rollout_id) "
               "WHERE rollout_id IS NOT NULL")
    new = ", ".join(f"NEW.{c.strip()}" for c in COLUMNS.split(","))
    op.execute(f"""
        CREATE OR REPLACE FUNCTION log_hit_verdict() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            INSERT INTO hit_verdicts ({COLUMNS}, source, rollout_id)
            VALUES ({new},
                    COALESCE(NULLIF(current_setting('discovery.hit_source', true), ''), NEW.decided_tier),
                    CAST(NULLIF(current_setting('discovery.rollout_id', true), '') AS bigint));
            RETURN NULL;
        END $$""")
    op.execute("DROP TRIGGER IF EXISTS hit_verdicts_insert ON rule_hits")
    op.execute("DROP TRIGGER IF EXISTS hit_verdicts_update ON rule_hits")
    op.execute("""CREATE TRIGGER hit_verdicts_insert AFTER INSERT ON rule_hits FOR EACH ROW
                  WHEN (NEW.prompt_version IS NOT NULL) EXECUTE FUNCTION log_hit_verdict()""")
    old = ", ".join(f"OLD.{c}" for c in CHANGED)
    cur = ", ".join(f"NEW.{c}" for c in CHANGED)
    op.execute(f"""CREATE TRIGGER hit_verdicts_update AFTER UPDATE ON rule_hits FOR EACH ROW
                   WHEN (NEW.prompt_version IS NOT NULL AND ({old}) IS DISTINCT FROM ({cur}))
                   EXECUTE FUNCTION log_hit_verdict()""")
    op.execute(f"""INSERT INTO hit_verdicts ({COLUMNS}, source, created_at)
                   SELECT {COLUMNS}, 'backfill', COALESCE(reviewed_at, verified_at, last_seen_at, now())
                   FROM rule_hits WHERE prompt_version IS NOT NULL""")


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS hit_verdicts_update ON rule_hits")
    op.execute("DROP TRIGGER IF EXISTS hit_verdicts_insert ON rule_hits")
    op.execute("DROP FUNCTION IF EXISTS log_hit_verdict()")
    op.execute("DROP TABLE IF EXISTS hit_verdicts")
