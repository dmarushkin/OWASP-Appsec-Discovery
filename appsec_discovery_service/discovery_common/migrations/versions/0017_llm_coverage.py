"""LLM rule coverage (``GET /llm_progress``, MCP ``llm_progress``, the Dashboard "LLM coverage").

* ``llm_coverage``: one row per (branch, LLM rule), written by the scanner (never by the API):
  of the subjects the rule would ask about on the branch's snapshot if nothing were answered
  (``candidates_total``: fields in the rule's scope - for the classifier rule only the fields
  it sends to the model - or objects for object rules), how many have a verdict of the rule's
  current version and the current core prompts or a human decision (``answered``); of the
  rest, how many objects an external run holds (``pending_external``) and how many failed
  (``failed``). ``commit`` / ``rule_version`` / ``prompt_version`` say what the counts were
  computed for, so a reader can tell a row went stale (new snapshot, rule edit, new prompts).
  Rows go with their branch (``ON DELETE CASCADE``).
* ``jobs.kind`` gets ``llm_coverage`` (the scanner's control worker recomputes stale rows in
  bounded slices; no model call).
* ``jobs_llm_branch_subject``: the ``llm_score`` / ``llm_prepare`` jobs of one branch (the
  active and the latest finished LLM run of each main branch / open MR in the progress).

Revision ID: 0017_llm_coverage
Revises: 0016_llm_prepare
Create Date: 2026-11-22
"""
from alembic import op

revision = "0017_llm_coverage"
down_revision = "0016_llm_prepare"
branch_labels = None
depends_on = None

OLD_KINDS = ("'sync_projects', 'sync_branches_mrs', 'scan_branch', 'scan_mr', 'llm_score', 'cleanup', 'ingest', "
             "'llm_apply', 'llm_prepare'")


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS llm_coverage (
            branch_id integer NOT NULL REFERENCES gitlab_branches (id) ON DELETE CASCADE,
            rule_id integer NOT NULL REFERENCES rules (id) ON DELETE CASCADE,
            rule_version integer NOT NULL,
            prompt_version text NOT NULL,
            commit text,
            candidates_total integer NOT NULL DEFAULT 0,
            answered integer NOT NULL DEFAULT 0,
            pending_external integer NOT NULL DEFAULT 0,
            failed integer NOT NULL DEFAULT 0,
            computed_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT llm_coverage_pkey PRIMARY KEY (branch_id, rule_id)
        )""")
    op.execute("ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_kind_check")
    op.execute(f"ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ({OLD_KINDS}, 'llm_coverage'))")
    op.execute("CREATE INDEX IF NOT EXISTS jobs_llm_branch_subject ON jobs ((payload ->> 'branch_id'), id) "
               "WHERE kind IN ('llm_score', 'llm_prepare')")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS jobs_llm_branch_subject")
    op.execute("DELETE FROM jobs WHERE kind = 'llm_coverage'")
    op.execute("ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_kind_check")
    op.execute(f"ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ({OLD_KINDS}))")
    op.execute("DROP TABLE IF EXISTS llm_coverage")
