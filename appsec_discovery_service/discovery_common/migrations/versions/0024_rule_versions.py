"""Versions of LLM rules and per-family core prompt versions (LLM rule lifecycle, ``discovery_common.lifecycle``).

* ``rule_versions``: one row per version of an LLM rule (draft -> candidate -> active -> retired | rolled_back; at
  most one active per rule). ``rules.prompt`` / ``scope`` / ``target`` / ``version`` stay and are the projection of
  the active version (``rules.version`` = its number); new: ``rules.core_prompt_version`` (the core prompts family
  version the active version's verdicts are pinned to) and ``rules.llm_model`` (the service model they belong to;
  NULL: not known yet - the scanner records LLM_API_MODEL at its next start). Backfill: one ``active`` version per
  live LLM rule (``source`` backfill) with the rule's prompt, target and matchers.
* Core prompts families: a hit stores the version of the prompts that made it per family - ``classifier{N}`` for
  the built-in classifier (a field rule without category), ``rule{N}`` for the other rules - instead of the
  combined ``core{classifier}.{rule}`` (``core3.3`` -> ``classifier3`` / ``rule3``), so a new classifier prompt does
  not make the other rules' verdicts stale. Rewritten in ``rule_hits.prompt_version`` and its ``verify_key``
  (``<rule version>:<prompts>:<subject hash>:<status>``: a verdict sent to the harness model is not sent again),
  ``llm_coverage.prompt_version``, ``prompt_trials.prompt_version`` and the verify items' context. Nothing is asked
  again by the migration.
* ``llm_verifications.verify_prompt_version`` (the core's VERIFY_PROMPT_VERSION of the item, NULL before),
  ``prompt_proposals.version_id`` (the candidate version an accepted proposal became), ``llm_runtime`` (key/value:
  what the scanner runs with, read by the API: ``service_model``).

Downgrade: the tables and columns are dropped; the current families (``classifier3`` / ``rule3``) go back to
``core3.3`` (other family versions are left as they are: the previous release asks those hits again).

Revision ID: 0024_rule_versions
Revises: 0023_match_statuses
Create Date: 2026-11-22
"""
from alembic import op

revision = "0024_rule_versions"
down_revision = "0023_match_statuses"
branch_labels = None
depends_on = None

CLASSIFIER = "r.target <> 'object' AND COALESCE(r.category, '') = ''"
MATCHER_KEYS = "'project_re', 'object_re', 'object_type_re', 'field_re', 'field_type_re', 'mark_fields'"
CURRENT = {"classifier": "classifier3", "rule": "rule3"}
COMBINED = "core3.3"


def _family(column: str) -> str:
    """``core{c}.{r}`` in ``column`` -> the family version of rule ``r``."""
    return (f"CASE WHEN {CLASSIFIER} THEN 'classifier' || substring({column} from '^core([^.]+)[.]') "
            f"ELSE 'rule' || substring({column} from '^core[^.]+[.](.+)$') END")


COMBINED_RE = "'^core[^.]+[.].+$'"
# chr(58) = ':' (a literal colon would be read as a bind parameter)
SEG = "split_part(h.verify_key, chr(58), {n})"


def upgrade() -> None:
    op.execute("ALTER TABLE rules ADD COLUMN IF NOT EXISTS core_prompt_version text")
    op.execute("ALTER TABLE rules ADD COLUMN IF NOT EXISTS llm_model text")
    op.execute("""
        CREATE TABLE IF NOT EXISTS rule_versions (
            id bigserial PRIMARY KEY,
            rule_id integer NOT NULL REFERENCES rules(id),
            version integer NOT NULL,
            status text NOT NULL CONSTRAINT rule_versions_status_check
                CHECK (status IN ('draft', 'candidate', 'active', 'retired', 'rolled_back')),
            prompt text,
            target text NOT NULL,
            matchers jsonb NOT NULL DEFAULT '{}'::jsonb,
            core_prompt_version text,
            model text,
            source text NOT NULL DEFAULT 'manual',
            parent_version integer,
            proposal_id bigint,
            created_by text,
            created_at timestamptz NOT NULL DEFAULT now(),
            activated_at timestamptz,
            retired_at timestamptz,
            note text,
            CONSTRAINT rule_versions_rule_version_key UNIQUE (rule_id, version)
        )""")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS rule_versions_one_active ON rule_versions (rule_id) "
               "WHERE status = 'active'")
    op.execute("""
        CREATE TABLE IF NOT EXISTS llm_runtime (
            key text PRIMARY KEY,
            value text,
            updated_at timestamptz NOT NULL DEFAULT now()
        )""")
    op.execute("ALTER TABLE llm_verifications ADD COLUMN IF NOT EXISTS verify_prompt_version text")
    op.execute("ALTER TABLE prompt_proposals ADD COLUMN IF NOT EXISTS version_id bigint")

    # per-family core prompt versions
    op.execute(f"""UPDATE rule_hits h SET prompt_version = {_family('h.prompt_version')}
                   FROM rules r WHERE r.id = h.rule_id AND r.kind = 'llm' AND h.prompt_version ~ {COMBINED_RE}""")
    seg2 = SEG.format(n=2)
    rest = f"substr(h.verify_key, length({SEG.format(n=1)}) + length({seg2}) + 3)"
    op.execute(f"""UPDATE rule_hits h SET verify_key = {SEG.format(n=1)} || chr(58) || {_family(seg2)} || chr(58) || {rest}
                   FROM rules r WHERE r.id = h.rule_id AND r.kind = 'llm' AND h.verify_key IS NOT NULL
                     AND {seg2} ~ {COMBINED_RE}""")
    op.execute(f"""UPDATE llm_coverage c SET prompt_version = {_family('c.prompt_version')}
                   FROM rules r WHERE r.id = c.rule_id AND c.prompt_version ~ {COMBINED_RE}""")
    op.execute(f"""UPDATE prompt_trials t SET prompt_version = {_family('t.prompt_version')}
                   FROM rules r WHERE r.id = t.rule_id AND t.prompt_version ~ {COMBINED_RE}""")
    op.execute(f"""UPDATE llm_work_items w SET verify = jsonb_set(w.verify, '{{prompt_version}}',
                       to_jsonb({_family("(w.verify ->> 'prompt_version')")}))
                   FROM rules r WHERE r.id = w.rule_id AND w.purpose = 'verify'
                     AND (w.verify ->> 'prompt_version') ~ {COMBINED_RE}""")

    # the active version of every live LLM rule: the rule as it is
    op.execute(f"""UPDATE rules r SET core_prompt_version = CASE WHEN {CLASSIFIER} THEN '{CURRENT["classifier"]}'
                                                                ELSE '{CURRENT["rule"]}' END
                   WHERE r.kind = 'llm' AND r.core_prompt_version IS NULL""")
    op.execute(f"""
        INSERT INTO rule_versions (rule_id, version, status, prompt, target, matchers, core_prompt_version, source,
                                   created_by, created_at, activated_at, note)
        SELECT r.id, r.version, 'active', r.prompt, COALESCE(r.target, 'field'),
               (SELECT COALESCE(jsonb_object_agg(e.key, e.value), '{{}}'::jsonb) FROM jsonb_each(COALESCE(r.scope, '{{}}'))
                e WHERE e.key IN ({MATCHER_KEYS}) AND e.value NOT IN ('null'::jsonb, '""'::jsonb, 'false'::jsonb)),
               r.core_prompt_version, 'backfill', 'migration:0024_rule_versions', COALESCE(r.updated_at, now()), now(),
               'the rule as it was when versions were introduced'
        FROM rules r
        WHERE r.kind = 'llm' AND r.deleted_at IS NULL
        ON CONFLICT (rule_id, version) DO NOTHING""")


def downgrade() -> None:
    families = ", ".join(f"'{v}'" for v in CURRENT.values())
    op.execute(f"UPDATE rule_hits SET prompt_version = '{COMBINED}' WHERE prompt_version IN ({families})")
    seg2 = SEG.format(n=2)
    rest = f"substr(h.verify_key, length({SEG.format(n=1)}) + length({seg2}) + 3)"
    op.execute(f"""UPDATE rule_hits h SET verify_key = {SEG.format(n=1)} || chr(58) || '{COMBINED}' || chr(58) || {rest}
                   WHERE h.verify_key IS NOT NULL AND {seg2} IN ({families})""")
    op.execute(f"UPDATE llm_coverage SET prompt_version = '{COMBINED}' WHERE prompt_version IN ({families})")
    op.execute(f"UPDATE prompt_trials SET prompt_version = '{COMBINED}' WHERE prompt_version IN ({families})")
    op.execute(f"""UPDATE llm_work_items SET verify = jsonb_set(verify, '{{prompt_version}}', '"{COMBINED}"')
                   WHERE purpose = 'verify' AND verify ->> 'prompt_version' IN ({families})""")
    op.execute("ALTER TABLE prompt_proposals DROP COLUMN IF EXISTS version_id")
    op.execute("ALTER TABLE llm_verifications DROP COLUMN IF EXISTS verify_prompt_version")
    op.execute("DROP TABLE IF EXISTS llm_runtime")
    op.execute("DROP TABLE IF EXISTS rule_versions")
    op.execute("ALTER TABLE rules DROP COLUMN IF EXISTS llm_model")
    op.execute("ALTER TABLE rules DROP COLUMN IF EXISTS core_prompt_version")
