"""Storage v2: content-addressed objects, relational fields, branch deltas, rules/rule_hits.

Schema (storage design, AGREED REVISIONS):
  * gitlab_projects.gitlab_id (unique; NULL only for rows that predate this revision, the
    GitLab sync fills it in by full_path), gitlab_branches unique (project_id, branch_name)
    + one main per project + scanned_commit, gitlab_mrs unique (project_id, mr_id) +
    closed_at + partial "open" indexes, FKs with ON DELETE CASCADE / SET NULL (P0-3),
    discovery_scans unique key (P0-3).
  * objects, object_fields, branch_objects, rules, rule_hits with exactly the indexes of
    the design (incl. pg_trgm for field-name search).

Data (one-way):
  * main branches only: discovery_objects + discovery_object_fields -> objects,
    object_fields, branch_objects. Keys are computed in SQL exactly like
    ``discovery_common.keys`` (tested against it). MR branch objects are not migrated.
  * discovery_score_rules -> rules (kind=keyword, mode=auto; ``skip`` rules keep their
    meaning as core exclusions via scope.action = 'exclude').
  * one synthetic llm rule from LLM_PROMPT / LLM_PROMPT_VER (env at migration time) and the
    two synthetic rules for the core keyword scoring (field names / props).
  * discovery_llm_scores -> rule_hits: tp -> confirmed, fp -> rejected (reviewer
    'migrated': human decisions), new -> pending_review; alerted_at = now() so old
    findings never alert.
  * main branches get processed_at = NULL and scanned_commit = NULL: every main is
    rescanned once with the new object identity (the scanner carries the decisions over).
  * duplicate branches / MRs / scans are removed before the unique keys are added;
    non-main branches that are not used by an open MR are no longer tracked and removed.
  * the old object / field / score tables and their enum types are dropped.

Revision ID: 0002_storage_v2
Revises: 0001_baseline
Create Date: 2026-11-20
"""
import os

import sqlalchemy as sa
from alembic import op

revision = "0002_storage_v2"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None

# Must match discovery_common.keys (PART_SEP '#', ITEM_SEP chr(31), PAIR_SEP chr(30)).
SQL_OBJECT_KEY = "md5({project_id}::text || '#' || {parser} || '#' || {hash})::uuid"
SQL_FIELD_KEY = "md5({object_key}::text || '#' || {field_name})::uuid"


def _env(name):
    value = os.environ.get(name)
    return value if value and value.strip() else None


NEW_TABLES = [
    """
    CREATE TABLE objects (
        content_hash uuid PRIMARY KEY,
        object_key   uuid NOT NULL,
        project_id   integer NOT NULL REFERENCES gitlab_projects(id) ON DELETE CASCADE,
        parser text, type text, name text, file text,
        props jsonb
    )""",
    """
    CREATE TABLE object_fields (
        content_hash uuid NOT NULL REFERENCES objects(content_hash) ON DELETE CASCADE,
        field_name   text NOT NULL,
        field_type   text,
        field_key    uuid NOT NULL,
        project_id   integer NOT NULL,
        CONSTRAINT object_fields_pkey PRIMARY KEY (content_hash, field_name)
    )""",
    """
    CREATE TABLE branch_objects (
        branch_id    integer NOT NULL REFERENCES gitlab_branches(id) ON DELETE CASCADE,
        object_key   uuid NOT NULL,
        content_hash uuid REFERENCES objects(content_hash),
        is_main      boolean NOT NULL,
        change       text CONSTRAINT branch_objects_change_check CHECK (change IN ('added','modified','removed')),
        line         integer,
        field_lines  jsonb,
        CONSTRAINT branch_objects_pkey PRIMARY KEY (branch_id, object_key),
        CONSTRAINT branch_objects_check CHECK (is_main = (change IS NULL))
    ) WITH (fillfactor = 80)""",
    """
    CREATE TABLE rules (
        id serial PRIMARY KEY,
        kind text CONSTRAINT rules_kind_check CHECK (kind IN ('keyword','llm')),
        name text, category text, severity text,
        target text CONSTRAINT rules_target_check CHECK (target IN ('object','field')),
        mode text CONSTRAINT rules_mode_check CHECK (mode IN ('auto','review')),
        scope jsonb,
        prompt text,
        version integer NOT NULL DEFAULT 1,
        enabled boolean DEFAULT true,
        updated_at timestamptz
    )""",
    """
    CREATE TABLE rule_hits (
        rule_id      integer NOT NULL REFERENCES rules(id),
        subject_key  uuid NOT NULL,
        project_id   integer NOT NULL,
        object_key   uuid NOT NULL,
        field_name   text,
        rule_version integer NOT NULL,
        model text, category text, severity text,
        status text NOT NULL CONSTRAINT rule_hits_status_check
            CHECK (status IN ('pending_review','need_more_info','confirmed','rejected')),
        reviewer text, reviewed_at timestamptz, note text,
        first_seen_at timestamptz, last_seen_at timestamptz, alerted_at timestamptz,
        CONSTRAINT rule_hits_pkey PRIMARY KEY (rule_id, subject_key)
    )""",
]

# Created after the data is loaded.
NEW_INDEXES = [
    "CREATE INDEX objects_key ON objects (object_key)",
    "CREATE INDEX objects_proj_name ON objects (project_id, name)",
    "CREATE INDEX fields_proj_name ON object_fields (project_id, field_name)",
    "CREATE INDEX fields_key ON object_fields (field_key)",
    "CREATE INDEX fields_name_trgm ON object_fields USING gin (field_name gin_trgm_ops)",
    "CREATE INDEX bo_content ON branch_objects (content_hash, is_main)",
    "CREATE INDEX bo_mr_rows ON branch_objects (content_hash) INCLUDE (branch_id, change) WHERE NOT is_main",
    "CREATE INDEX hits_subject ON rule_hits (subject_key)",
    "CREATE INDEX hits_queue ON rule_hits (project_id, status) WHERE status IN ('pending_review','need_more_info')",
]


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    # ---- projects ---------------------------------------------------------------------
    op.execute("ALTER TABLE gitlab_projects ADD COLUMN gitlab_id integer")
    op.execute("ALTER TABLE gitlab_projects ADD CONSTRAINT gitlab_projects_gitlab_id_key UNIQUE (gitlab_id)")

    # ---- branches: one main per project (latest), keeper per (project_id, branch_name) ---
    op.execute("""
        UPDATE gitlab_branches b SET is_main = false
        FROM (SELECT id, row_number() OVER (PARTITION BY project_id ORDER BY updated_at DESC, id DESC) AS rn
              FROM gitlab_branches WHERE is_main) r
        WHERE r.id = b.id AND r.rn > 1""")
    op.execute("""
        CREATE TEMP TABLE mig_branch_keep ON COMMIT DROP AS
        SELECT id, first_value(id) OVER (PARTITION BY project_id, branch_name
                                         ORDER BY is_main DESC, updated_at DESC, id DESC) AS keep_id
        FROM gitlab_branches""")

    # ---- new tables ----------------------------------------------------------------------
    for ddl in NEW_TABLES:
        op.execute(ddl)

    # ---- objects of main branches ------------------------------------------------------------
    object_key = SQL_OBJECT_KEY.format(project_id="b.project_id", parser="o.parser", hash="o.hash")
    op.execute(f"""
        CREATE TEMP TABLE mig_objects ON COMMIT DROP AS
        SELECT o.id AS old_id, b.id AS branch_id, b.project_id, o.parser, o.type, o.name, o.file, o.line,
               CASE WHEN json_typeof(o.props) = 'object' THEN o.props END AS props,
               {object_key} AS object_key,
               NULL::uuid AS content_hash
        FROM discovery_objects o
        JOIN gitlab_branches b ON b.id = o.branch_id AND b.is_main
        WHERE b.project_id IS NOT NULL""")
    op.execute("""
        UPDATE mig_objects m SET content_hash = md5(
            m.object_key::text || '#' ||
            COALESCE((SELECT string_agg(f.name || chr(30) || COALESCE(f.type, ''), chr(31) ORDER BY f.name COLLATE "C")
                      FROM discovery_object_fields f WHERE f.object_id = m.old_id), '') || '#' ||
            COALESCE((SELECT string_agg(p.key || chr(30) || COALESCE(p.value, ''), chr(31) ORDER BY p.key COLLATE "C")
                      FROM json_each_text(COALESCE(m.props, '{}'::json)) p), '')
        )::uuid""")
    op.execute("""
        INSERT INTO objects (content_hash, object_key, project_id, parser, type, name, file, props)
        SELECT DISTINCT ON (content_hash) content_hash, object_key, project_id, parser, type, name, file, props::jsonb
        FROM mig_objects ORDER BY content_hash, old_id""")
    field_key = SQL_FIELD_KEY.format(object_key="m.object_key", field_name="f.name")
    op.execute(f"""
        INSERT INTO object_fields (content_hash, field_name, field_type, field_key, project_id)
        SELECT DISTINCT ON (m.content_hash, f.name) m.content_hash, f.name, f.type, {field_key}, m.project_id
        FROM mig_objects m JOIN discovery_object_fields f ON f.object_id = m.old_id
        ORDER BY m.content_hash, f.name, m.old_id""")
    op.execute("""
        INSERT INTO branch_objects (branch_id, object_key, content_hash, is_main, change, line, field_lines)
        SELECT DISTINCT ON (m.branch_id, m.object_key) m.branch_id, m.object_key, m.content_hash, true, NULL, m.line,
               (SELECT jsonb_object_agg(f.name, f.line) FROM discovery_object_fields f
                WHERE f.object_id = m.old_id AND f.line IS NOT NULL)
        FROM mig_objects m ORDER BY m.branch_id, m.object_key, m.old_id""")

    # ---- rules -------------------------------------------------------------------------------
    op.execute("""
        INSERT INTO rules (kind, name, category, severity, target, mode, scope, version, enabled, updated_at)
        SELECT 'keyword', 'score_rule:' || id, NULLIF(tag, ''), severity::text,
               CASE WHEN COALESCE(field, '') <> '' OR COALESCE(field_type, '') <> '' THEN 'field' ELSE 'object' END,
               'auto',
               jsonb_strip_nulls(jsonb_build_object(
                   'project_re', NULLIF(project, ''), 'object_re', NULLIF(object, ''),
                   'object_type_re', NULLIF(object_type, ''), 'field_re', NULLIF(field, ''),
                   'field_type_re', NULLIF(field_type, ''),
                   'action', CASE WHEN status = 'skip' THEN 'exclude' END,
                   'legacy_status', status::text)),
               1, true, now()
        FROM discovery_score_rules ORDER BY id""")
    op.execute("""
        INSERT INTO rules (kind, name, target, mode, scope, version, enabled, updated_at) VALUES
            ('keyword', 'core:score_tags:field', 'field', 'auto', '{"source": "core"}', 1, true, now()),
            ('keyword', 'core:score_tags:object', 'object', 'auto', '{"source": "core"}', 1, true, now())""")
    op.execute(sa.text("""
        INSERT INTO rules (kind, name, target, mode, scope, prompt, version, enabled, updated_at)
        VALUES ('llm', 'llm', 'field', 'review', jsonb_build_object('prompt_ver', CAST(:prompt_ver AS text)),
                :prompt, 1, true, now())""").bindparams(
        sa.bindparam("prompt", _env("LLM_PROMPT"), type_=sa.Text),
        sa.bindparam("prompt_ver", _env("LLM_PROMPT_VER"), type_=sa.Text),
    ))

    # ---- LLM scores -> rule_hits (one per field subject; decided rows win) ------------------
    op.execute(f"""
        INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version, model,
                               category, severity, status, reviewer, reviewed_at, note,
                               first_seen_at, last_seen_at, alerted_at)
        SELECT DISTINCT ON (subject_key)
               (SELECT id FROM rules WHERE kind = 'llm' AND name = 'llm'), subject_key, project_id, object_key,
               field_name, 1, model, category, severity, status, reviewer, reviewed_at, note,
               first_seen_at, last_seen_at, now()
        FROM (
            SELECT {field_key} AS subject_key, m.project_id, m.object_key, f.name AS field_name,
                   s.model, s.tag AS category, s.severity,
                   CASE s.status WHEN 'tp' THEN 'confirmed' WHEN 'fp' THEN 'rejected' ELSE 'pending_review' END AS status,
                   CASE WHEN s.status IN ('tp', 'fp') THEN 'migrated' END AS reviewer,
                   CASE WHEN s.status IN ('tp', 'fp') THEN s.updated_at END AS reviewed_at,
                   'migrated from discovery_llm_scores, prompt_ver ' || s.prompt_ver AS note,
                   s.created_at AS first_seen_at, COALESCE(s.updated_at, now()) AS last_seen_at,
                   (s.status <> 'new') AS decided, s.updated_at, s.id
            FROM discovery_llm_scores s
            JOIN discovery_object_fields f ON f.id = s.field_id
            JOIN mig_objects m ON m.old_id = f.object_id
        ) x
        ORDER BY subject_key, decided DESC, updated_at DESC NULLS LAST, id DESC""")

    # ---- drop the old object / field / score tables ---------------------------------------------
    op.execute("DROP TABLE discovery_llm_scores, discovery_object_fields, discovery_objects, discovery_score_rules")
    op.execute("DROP TYPE IF EXISTS dbllmscorestatus, dbscoreruleseverity, dbscorerulestatus")

    # ---- FKs with cascades (P0-3) ---------------------------------------------------------------
    op.execute("DELETE FROM gitlab_mrs WHERE project_id IS NULL")
    op.execute("DELETE FROM discovery_scans WHERE branch_id IN (SELECT id FROM gitlab_branches WHERE project_id IS NULL)")
    op.execute("DELETE FROM gitlab_branches WHERE project_id IS NULL")
    for table, column, target, ondelete in (
        ("gitlab_branches", "project_id", "gitlab_projects", "CASCADE"),
        ("gitlab_mrs", "project_id", "gitlab_projects", "CASCADE"),
        ("discovery_scans", "project_id", "gitlab_projects", "CASCADE"),
        ("discovery_scans", "branch_id", "gitlab_branches", "CASCADE"),
    ):
        op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {table}_{column}_fkey")
        op.execute(f"ALTER TABLE {table} ADD CONSTRAINT {table}_{column}_fkey FOREIGN KEY ({column}) "
                   f"REFERENCES {target}(id) ON DELETE {ondelete}")
    op.execute("ALTER TABLE gitlab_branches ALTER COLUMN project_id SET NOT NULL")
    op.execute("ALTER TABLE gitlab_mrs ALTER COLUMN project_id SET NOT NULL")

    # ---- MRs: keeper branches, dedupe, nullable branch refs with FKs, closed_at ------------------
    for column in ("source_branch_id", "target_branch_id"):
        op.execute(f"""
            UPDATE gitlab_mrs m SET {column} = k.keep_id
            FROM mig_branch_keep k WHERE m.{column} = k.id AND k.id <> k.keep_id""")
    op.execute("DELETE FROM gitlab_branches b USING mig_branch_keep k WHERE b.id = k.id AND k.id <> k.keep_id")
    op.execute("""
        DELETE FROM gitlab_mrs m
        USING (SELECT id, row_number() OVER (PARTITION BY project_id, mr_id ORDER BY updated_at DESC, id DESC) AS rn
               FROM gitlab_mrs) d
        WHERE m.id = d.id AND d.rn > 1""")
    op.execute("ALTER TABLE gitlab_mrs ALTER COLUMN source_branch_id DROP NOT NULL, "
               "ALTER COLUMN target_branch_id DROP NOT NULL, ADD COLUMN closed_at timestamptz")
    for column in ("source_branch_id", "target_branch_id"):
        op.execute(f"""
            UPDATE gitlab_mrs m SET {column} = NULL
            WHERE {column} IS NOT NULL AND NOT EXISTS (SELECT 1 FROM gitlab_branches b WHERE b.id = m.{column})""")
        op.execute(f"ALTER TABLE gitlab_mrs ADD CONSTRAINT gitlab_mrs_{column}_fkey FOREIGN KEY ({column}) "
                   f"REFERENCES gitlab_branches(id) ON DELETE SET NULL")
    op.execute("UPDATE gitlab_mrs SET closed_at = now() WHERE state <> 'opened'")

    # Only main branches and branches of open MRs are tracked (retention).
    op.execute("""
        DELETE FROM gitlab_branches b
        WHERE NOT b.is_main AND NOT EXISTS (
            SELECT 1 FROM gitlab_mrs m
            WHERE m.state = 'opened' AND (m.source_branch_id = b.id OR m.target_branch_id = b.id))""")

    op.execute("ALTER TABLE gitlab_branches ADD COLUMN scanned_commit text")
    op.execute("UPDATE gitlab_branches SET processed_at = NULL WHERE is_main")
    op.execute("ALTER TABLE gitlab_branches ADD CONSTRAINT gitlab_branches_project_id_branch_name_key "
               "UNIQUE (project_id, branch_name)")
    op.execute("CREATE UNIQUE INDEX branches_one_main ON gitlab_branches (project_id) WHERE is_main")

    op.execute("ALTER TABLE gitlab_mrs ADD CONSTRAINT gitlab_mrs_project_id_mr_id_key UNIQUE (project_id, mr_id)")
    op.execute("CREATE INDEX mrs_open ON gitlab_mrs (project_id) WHERE state = 'opened'")
    op.execute("CREATE INDEX mrs_source ON gitlab_mrs (source_branch_id)")
    op.execute("CREATE INDEX mrs_target_open ON gitlab_mrs (target_branch_id) WHERE state = 'opened'")

    # ---- discovery_scans unique key (P0-3) ----------------------------------------------------------
    op.execute("""
        DELETE FROM discovery_scans s
        USING (SELECT id, row_number() OVER (PARTITION BY branch_id, branch_commit, scanner, rules_version, parsers
                                             ORDER BY id) AS rn
               FROM discovery_scans) d
        WHERE s.id = d.id AND d.rn > 1""")
    op.execute("ALTER TABLE discovery_scans ADD CONSTRAINT uq_scan "
               "UNIQUE (branch_id, branch_commit, scanner, rules_version, parsers)")

    for ddl in NEW_INDEXES:
        op.execute(ddl)
    op.execute("ANALYZE objects, object_fields, branch_objects, rule_hits")


def downgrade() -> None:
    raise NotImplementedError("0002_storage_v2 is a one-way data migration; restore a backup to go back")
