"""LLM rules ask again when what the model saw changed (``rule_hits.names_hash`` / ``subject_hash``).

* ``rule_hits.names_hash`` / ``subject_hash`` (text, nullable): set by the scanner on every LLM
  hit (``discovery_common.keys``): names_hash = object name + sorted field names (field hits:
  the one field), subject_hash = the object's content hash (object rules) or the field's name,
  type, comment and samples (field rules). Keyword and manual hits keep NULL.
* SQL twins of the Python hashes, used by the scanner's candidate queries, the coverage counts
  and the backfill below: ``llm_names_hash(object_name, field_names[])`` and
  ``llm_field_hash(field_name, field_type, comment, samples)`` (immutable SQL functions;
  ``test_common_keys`` checks them against the Python ones).
* Backfill: the existing LLM hits get the hashes of the CURRENT stored version of their subject
  (the main snapshot's version of the object / of an object having the field, else one of an MR
  delta), so the migration itself
  asks nothing again - only later changes do. Hits whose subject is in no branch any more keep
  NULL (NULL never triggers a re-ask).

Revision ID: 0018_llm_reask
Revises: 0017_llm_coverage
Create Date: 2026-11-22
"""
from alembic import op

revision = "0018_llm_reask"
down_revision = "0017_llm_coverage"
branch_labels = None
depends_on = None

# Must match discovery_common.keys.names_hash / field_subject_hash (PART_SEP '#', ITEM_SEP chr(31),
# PAIR_SEP chr(30); names sorted by code point = COLLATE "C").
NAMES_HASH_FN = """
    CREATE OR REPLACE FUNCTION llm_names_hash(object_name text, field_names text[]) RETURNS text
    LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
        SELECT md5(COALESCE(object_name, '') || '#' || COALESCE(
            (SELECT string_agg(n, chr(31) ORDER BY n COLLATE "C") FROM unnest(field_names) AS n), ''))
    $$"""

FIELD_HASH_FN = """
    CREATE OR REPLACE FUNCTION llm_field_hash(field_name text, field_type text, comment text, samples jsonb)
    RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
        SELECT md5(COALESCE(field_name, '') || chr(30) || COALESCE(field_type, '') || chr(30) || COALESCE(comment, '')
                   || chr(30) || COALESCE(
            (SELECT string_agg(e, chr(31) ORDER BY i)
             FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(samples) = 'array' THEN samples END)
                  WITH ORDINALITY AS t(e, i)), ''))
    $$"""

# objects: the current version of every object with an LLM object hit (its main snapshot row, else an
# MR delta row)
CURRENT = """
    WITH cur AS (
        SELECT DISTINCT ON (b.object_key) b.object_key, b.content_hash
        FROM branch_objects b
        WHERE b.content_hash IS NOT NULL
          AND b.object_key IN (SELECT h.object_key FROM rule_hits h JOIN rules r ON r.id = h.rule_id
                               WHERE r.kind = 'llm')
        ORDER BY b.object_key, b.is_main DESC, b.branch_id DESC)"""

BACKFILL_OBJECTS = CURRENT + """
    UPDATE rule_hits h SET
        subject_hash = c.content_hash::text,
        names_hash = llm_names_hash(o.name, ARRAY(SELECT f.field_name FROM object_fields f
                                                  WHERE f.content_hash = c.content_hash))
    FROM rules r, cur c, objects o
    WHERE r.id = h.rule_id AND r.kind = 'llm' AND h.field_name IS NULL AND h.subject_key = h.object_key
      AND c.object_key = h.object_key AND o.content_hash = c.content_hash"""

# fields: the stored version of the object that has the field (the main snapshot's first)
BACKFILL_FIELDS = """
    WITH cur AS (
        SELECT DISTINCT ON (f.field_key) f.field_key, f.content_hash, f.field_name, f.field_type, f.comment, f.samples
        FROM branch_objects b JOIN object_fields f ON f.content_hash = b.content_hash
        WHERE b.content_hash IS NOT NULL
          AND f.field_key IN (SELECT h.subject_key FROM rule_hits h JOIN rules r ON r.id = h.rule_id
                              WHERE r.kind = 'llm' AND h.field_name IS NOT NULL)
        ORDER BY f.field_key, b.is_main DESC, b.branch_id DESC)
    UPDATE rule_hits h SET
        subject_hash = llm_field_hash(c.field_name, c.field_type, c.comment, c.samples),
        names_hash = llm_names_hash(o.name, ARRAY[c.field_name])
    FROM rules r, cur c, objects o
    WHERE r.id = h.rule_id AND r.kind = 'llm' AND h.field_name IS NOT NULL
      AND c.field_key = h.subject_key AND o.content_hash = c.content_hash"""


def upgrade() -> None:
    op.execute("ALTER TABLE rule_hits ADD COLUMN IF NOT EXISTS names_hash text")
    op.execute("ALTER TABLE rule_hits ADD COLUMN IF NOT EXISTS subject_hash text")
    op.execute(NAMES_HASH_FN)
    op.execute(FIELD_HASH_FN)
    op.execute(BACKFILL_OBJECTS)
    op.execute(BACKFILL_FIELDS)


def downgrade() -> None:
    op.execute("ALTER TABLE rule_hits DROP COLUMN IF EXISTS subject_hash")
    op.execute("ALTER TABLE rule_hits DROP COLUMN IF EXISTS names_hash")
    op.execute("DROP FUNCTION IF EXISTS llm_field_hash(text, text, text, jsonb)")
    op.execute("DROP FUNCTION IF EXISTS llm_names_hash(text, text[])")
