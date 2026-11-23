"""Prompt trials and proposals: try a candidate prompt of an LLM rule with the SERVICE model on a few subjects
(mislabelled ones plus controls) before a human is asked to adopt it.

* ``prompt_trials``: one trial of a candidate system prompt of an LLM rule (version ``rule_version``,
  ``base_prompt`` = the rule's prompt when the trial was made); run by an ``llm_trial`` job on the scanner's LLM
  workers with the service backend (LLM_API_URL). ``planned_calls`` is what the API budgeted
  (LLM_TRIAL_DAILY_CALLS), ``calls`` / ``failed_calls`` what the scanner made. A trial never writes ``rule_hits``,
  ``llm_coverage`` or the rule.
* ``prompt_trial_items``: one subject (object or field) of a trial: ``role`` target (expected verdict from a human
  or the harness) or control (a currently agreed verdict, to catch regressions); ``current_*`` = the stored
  verdict of the current prompt, ``rerun_*`` = the current prompt asked again in the same job (fair A/B),
  ``new_*`` = the candidate prompt.
* ``prompt_proposals``: a candidate prompt proposed to a human (MCP ``propose_prompt_change``) with the finished
  trial of the same text; only a human accepts it (UI / REST), which updates the rule through the normal path
  (version bump, re-ask).
* ``rule_hits.machine_status``: the status the scanner (model) had set, recorded when a human first decides the
  hit (``review_service``), so a disagreement between the model and the human can be found later. NULL for
  hits decided before this migration (unknown).
* ``jobs.kind`` gets ``llm_trial``.

Revision ID: 0019_prompt_trials
Revises: 0018_llm_reask
Create Date: 2026-11-22
"""
from alembic import op

revision = "0019_prompt_trials"
down_revision = "0018_llm_reask"
branch_labels = None
depends_on = None

OLD_KINDS = ("'sync_projects', 'sync_branches_mrs', 'scan_branch', 'scan_mr', 'llm_score', 'cleanup', 'ingest', "
             "'llm_apply', 'llm_prepare', 'llm_coverage'")
VERDICTS = "'match', 'no_match', 'need_more_info'"


def upgrade() -> None:
    op.execute("ALTER TABLE rule_hits ADD COLUMN IF NOT EXISTS machine_status text")
    op.execute(f"""
        CREATE TABLE IF NOT EXISTS prompt_trials (
            id bigserial PRIMARY KEY,
            rule_id integer NOT NULL REFERENCES rules(id),
            rule_version integer NOT NULL,
            prompt_version text NOT NULL,
            base_prompt text,
            candidate_prompt text NOT NULL,
            prompt_hash text NOT NULL,
            rerun_current boolean NOT NULL DEFAULT true,
            status text NOT NULL DEFAULT 'queued',
            job_id bigint REFERENCES jobs(id) ON DELETE SET NULL,
            planned_calls integer NOT NULL DEFAULT 0,
            calls integer NOT NULL DEFAULT 0,
            failed_calls integer NOT NULL DEFAULT 0,
            model text,
            created_by text,
            note text,
            error text,
            totals jsonb,
            created_at timestamptz NOT NULL DEFAULT now(),
            started_at timestamptz,
            finished_at timestamptz,
            CONSTRAINT prompt_trials_status_check CHECK (status IN ('queued', 'running', 'done', 'failed'))
        )""")
    op.execute("CREATE INDEX IF NOT EXISTS prompt_trials_rule ON prompt_trials (rule_id, id)")
    op.execute("CREATE INDEX IF NOT EXISTS prompt_trials_created ON prompt_trials (created_at)")
    op.execute(f"""
        CREATE TABLE IF NOT EXISTS prompt_trial_items (
            id bigserial PRIMARY KEY,
            trial_id bigint NOT NULL REFERENCES prompt_trials(id) ON DELETE CASCADE,
            subject_key uuid NOT NULL,
            object_key uuid NOT NULL,
            content_hash uuid NOT NULL,
            project_id integer NOT NULL,
            field_name text,
            role text NOT NULL,
            expected text NOT NULL,
            current_verdict text,
            current_reason text,
            current_status text,
            rerun_verdict text,
            rerun_reason text,
            rerun_fields text[],
            new_verdict text,
            new_reason text,
            new_fields text[],
            error text,
            asked_at timestamptz,
            CONSTRAINT prompt_trial_items_role_check CHECK (role IN ('target', 'control')),
            CONSTRAINT prompt_trial_items_expected_check CHECK (expected IN ({VERDICTS})),
            CONSTRAINT prompt_trial_items_subject_key UNIQUE (trial_id, subject_key)
        )""")
    op.execute(f"""
        CREATE TABLE IF NOT EXISTS prompt_proposals (
            id bigserial PRIMARY KEY,
            rule_id integer NOT NULL REFERENCES rules(id),
            base_version integer NOT NULL,
            prompt text NOT NULL,
            prompt_hash text NOT NULL,
            trial_id bigint NOT NULL REFERENCES prompt_trials(id),
            rationale text NOT NULL,
            status text NOT NULL DEFAULT 'open',
            created_by text,
            decided_by text,
            decided_at timestamptz,
            decision_note text,
            accepted_version integer,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT prompt_proposals_status_check CHECK (status IN ('open', 'accepted', 'rejected', 'superseded'))
        )""")
    op.execute("CREATE INDEX IF NOT EXISTS prompt_proposals_rule ON prompt_proposals (rule_id, status)")
    op.execute("ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_kind_check")
    op.execute(f"ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ({OLD_KINDS}, 'llm_trial'))")


def downgrade() -> None:
    op.execute("DELETE FROM jobs WHERE kind = 'llm_trial'")
    op.execute("ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_kind_check")
    op.execute(f"ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ({OLD_KINDS}))")
    op.execute("DROP TABLE IF EXISTS prompt_proposals")
    op.execute("DROP TABLE IF EXISTS prompt_trial_items")
    op.execute("DROP TABLE IF EXISTS prompt_trials")
    op.execute("ALTER TABLE rule_hits DROP COLUMN IF EXISTS machine_status")
