"""Baseline: the schema the services created with ``SQLModel.metadata.create_all`` before
Alembic (scanner tables + the API's ``scorerule``), as dumped from a fresh create_all.

Idempotent on purpose (``IF NOT EXISTS`` / ``duplicate_object``): an existing database
created by ``create_all`` has no ``alembic_version`` table, so ``upgrade head`` runs this
revision against it; tables that already exist are left as they are, missing ones (for
example ``scorerule`` when the API never started) are created. Rows of ``discovery_scans``
with ``parsers IS NULL`` are tolerated (nothing here depends on them).

Revision ID: 0001_baseline
Revises:
Create Date: 2026-11-20
"""
from alembic import op

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


ENUMS = {
    "dbllmscorestatus": ("new", "fp", "tp"),
    "dbscoreruleseverity": ("critical", "high", "medium", "low", "info"),
    "dbscorerulestatus": ("mark", "skip", "alert"),
    "scorerulestatus": ("active", "skip"),
}

TABLES = [
    """
    CREATE TABLE IF NOT EXISTS gitlab_projects (
        id serial PRIMARY KEY,
        project_name varchar NOT NULL,
        full_path varchar NOT NULL,
        description varchar,
        default_branch varchar,
        visibility varchar NOT NULL,
        severity varchar,
        tags varchar[],
        created_at timestamp without time zone NOT NULL,
        updated_at timestamp without time zone NOT NULL,
        processed_at timestamp without time zone
    )""",
    """
    CREATE TABLE IF NOT EXISTS gitlab_branches (
        id serial PRIMARY KEY,
        branch_name varchar NOT NULL,
        is_main boolean NOT NULL,
        commit varchar NOT NULL,
        processed_at timestamp without time zone,
        project_id integer REFERENCES gitlab_projects(id),
        project_path varchar NOT NULL,
        created_at timestamp without time zone NOT NULL,
        updated_at timestamp without time zone NOT NULL
    )""",
    """
    CREATE TABLE IF NOT EXISTS gitlab_mrs (
        id serial PRIMARY KEY,
        project_id integer REFERENCES gitlab_projects(id),
        project_path varchar NOT NULL,
        source_branch_id integer NOT NULL,
        source_branch varchar NOT NULL,
        source_branch_commit varchar NOT NULL,
        target_branch_id integer NOT NULL,
        target_branch varchar NOT NULL,
        target_branch_commit varchar NOT NULL,
        mr_id integer NOT NULL,
        title varchar NOT NULL,
        description varchar,
        state varchar NOT NULL,
        diff varchar,
        created_at timestamp without time zone NOT NULL,
        updated_at timestamp without time zone NOT NULL,
        alerted_at timestamp without time zone,
        processed_at timestamp without time zone
    )""",
    """
    CREATE TABLE IF NOT EXISTS discovery_scans (
        id serial PRIMARY KEY,
        project_id integer REFERENCES gitlab_projects(id),
        branch_id integer REFERENCES gitlab_branches(id),
        project_path varchar NOT NULL,
        branch_name varchar NOT NULL,
        branch_commit varchar NOT NULL,
        scanner varchar NOT NULL,
        rules_version varchar NOT NULL,
        parsers varchar[],
        scanned_at timestamp without time zone NOT NULL
    )""",
    """
    CREATE TABLE IF NOT EXISTS discovery_objects (
        id serial PRIMARY KEY,
        project_id integer REFERENCES gitlab_projects(id),
        branch_id integer REFERENCES gitlab_branches(id),
        hash varchar NOT NULL,
        name varchar NOT NULL,
        type varchar NOT NULL,
        parser varchar NOT NULL,
        props json,
        file varchar NOT NULL,
        line integer NOT NULL,
        severity varchar,
        tags varchar[],
        created_at timestamp without time zone,
        updated_at timestamp without time zone,
        alerted_at timestamp without time zone,
        CONSTRAINT discovery_objects_project_id_branch_id_name_type_key UNIQUE (project_id, branch_id, name, type)
    )""",
    """
    CREATE TABLE IF NOT EXISTS discovery_object_fields (
        id serial PRIMARY KEY,
        object_id integer REFERENCES discovery_objects(id),
        name varchar NOT NULL,
        type varchar NOT NULL,
        file varchar,
        line integer,
        severity varchar,
        tags varchar[],
        CONSTRAINT uq_object_field UNIQUE (object_id, name)
    )""",
    """
    CREATE TABLE IF NOT EXISTS discovery_llm_scores (
        id serial PRIMARY KEY,
        field_id integer NOT NULL REFERENCES discovery_object_fields(id),
        model varchar NOT NULL,
        prompt_ver varchar NOT NULL,
        severity varchar,
        tag varchar,
        status dbllmscorestatus NOT NULL,
        created_at timestamp without time zone,
        updated_at timestamp without time zone,
        CONSTRAINT discovery_llm_scores_field_id_model_prompt_ver_key UNIQUE (field_id, model, prompt_ver)
    )""",
    """
    CREATE TABLE IF NOT EXISTS discovery_score_rules (
        id serial PRIMARY KEY,
        project varchar,
        object varchar,
        object_type varchar,
        field varchar,
        field_type varchar,
        severity dbscoreruleseverity,
        tag varchar,
        status dbscorerulestatus NOT NULL
    )""",
    """
    CREATE TABLE IF NOT EXISTS scorerule (
        id serial PRIMARY KEY,
        service_re varchar,
        object_type_re varchar,
        object_re varchar,
        field_re varchar,
        field_type_re varchar,
        risk_score integer NOT NULL,
        status scorerulestatus NOT NULL
    )""",
]


def upgrade() -> None:
    for name, values in ENUMS.items():
        labels = ", ".join(f"'{value}'" for value in values)
        op.execute(f"""
            DO $$ BEGIN
                CREATE TYPE {name} AS ENUM ({labels});
            EXCEPTION WHEN duplicate_object THEN NULL;
            END $$""")
    for ddl in TABLES:
        op.execute(ddl)


def downgrade() -> None:
    for table in ("scorerule", "discovery_score_rules", "discovery_llm_scores", "discovery_object_fields",
                  "discovery_objects", "discovery_scans", "gitlab_mrs", "gitlab_branches", "gitlab_projects"):
        op.execute(f"DROP TABLE IF EXISTS {table}")
    for name in ENUMS:
        op.execute(f"DROP TYPE IF EXISTS {name}")
