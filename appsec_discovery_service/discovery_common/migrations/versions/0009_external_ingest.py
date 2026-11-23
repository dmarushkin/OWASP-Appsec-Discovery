"""Objects of external parsers (e.g. databases, tables and columns collected from SQL servers).

* ``gitlab_projects.source``: ``gitlab`` (synced, cloned and parsed by the scanner) or
  ``external`` (objects pushed through ``POST /ingest``, paths under ``external/``; never
  cloned); ``created_by``: who created an external project. ``full_path`` becomes unique
  (two first pushes of the same path, or a GitLab project with an external's path, cannot
  make duplicates).
* ``ingest_batches``: one full state of one parser for one external project (status ``open``
  while its chunks are uploaded, ``committed``, ``processed``, ``failed``); the objects are in
  ``ingest_chunks`` (one chunk for a single ``POST /ingest``). ``content_hash`` makes a push of
  an unchanged state a no-op. The ``ingest`` job processes the latest committed batch of the
  (project, parser); the latest processed one is kept so a parse re-applies edited rules.
* ``api_tokens``: service tokens (only a sha256 is stored) for collectors: scope ``ingest``,
  limited to project path prefixes.
* ``jobs.kind`` gets ``ingest``.

Revision ID: 0009_external_ingest
Revises: 0008_decided_via
Create Date: 2026-11-20
"""
from alembic import context, op
from sqlalchemy import text

revision = "0009_external_ingest"
down_revision = "0008_decided_via"
branch_labels = None
depends_on = None

OLD_KINDS = "'sync_projects', 'sync_branches_mrs', 'scan_branch', 'scan_mr', 'llm_score', 'cleanup'"


def upgrade() -> None:
    if not context.is_offline_mode():            # offline (--sql): the unique index fails on duplicates anyway
        duplicates = op.get_bind().execute(text(
            "SELECT full_path FROM gitlab_projects GROUP BY full_path HAVING count(*) > 1 LIMIT 5")).scalars().all()
        if duplicates:
            raise RuntimeError(f"gitlab_projects has duplicate full_path values {duplicates}: merge or delete them first")
    op.execute("CREATE UNIQUE INDEX gitlab_projects_full_path_key ON gitlab_projects (full_path)")
    op.execute("ALTER TABLE gitlab_projects ADD COLUMN source text NOT NULL DEFAULT 'gitlab' "
               "CONSTRAINT gitlab_projects_source_check CHECK (source IN ('gitlab', 'external'))")
    op.execute("ALTER TABLE gitlab_projects ADD COLUMN created_by text")
    op.execute("""
        CREATE TABLE ingest_batches (
            id bigserial PRIMARY KEY,
            project_id integer NOT NULL REFERENCES gitlab_projects (id) ON DELETE CASCADE,
            parser text NOT NULL,
            snapshot text NOT NULL,
            status text NOT NULL DEFAULT 'open'
                CONSTRAINT ingest_batches_status_check CHECK (status IN ('open', 'committed', 'processed', 'failed')),
            llm boolean NOT NULL DEFAULT false,
            objects integer NOT NULL DEFAULT 0,
            fields integer NOT NULL DEFAULT 0,
            content_hash text,
            idempotency_key text,
            created_by text,
            created_at timestamptz NOT NULL DEFAULT now(),
            committed_at timestamptz,
            processed_at timestamptz,
            stats jsonb,
            error text
        )""")
    op.execute("CREATE INDEX ingest_batches_latest ON ingest_batches (project_id, parser, id DESC)")
    op.execute("CREATE UNIQUE INDEX ingest_batches_idempotency ON ingest_batches (project_id, parser, idempotency_key) "
               "WHERE idempotency_key IS NOT NULL")
    op.execute("""
        CREATE TABLE ingest_chunks (
            batch_id bigint NOT NULL REFERENCES ingest_batches (id) ON DELETE CASCADE,
            seq integer NOT NULL,
            payload jsonb NOT NULL,
            objects integer NOT NULL,
            fields integer NOT NULL,
            content_hash text NOT NULL,
            PRIMARY KEY (batch_id, seq)
        )""")
    op.execute("""
        CREATE TABLE api_tokens (
            id serial PRIMARY KEY,
            name text NOT NULL,
            token_hash text NOT NULL UNIQUE,
            scopes text[] NOT NULL,
            project_prefixes text[] NOT NULL,
            created_by text,
            created_at timestamptz NOT NULL DEFAULT now(),
            last_used_at timestamptz,
            revoked_at timestamptz
        )""")
    op.execute("ALTER TABLE jobs DROP CONSTRAINT jobs_kind_check")
    op.execute(f"ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ({OLD_KINDS}, 'ingest'))")


def downgrade() -> None:
    op.execute("DELETE FROM jobs WHERE kind = 'ingest'")
    op.execute("ALTER TABLE jobs DROP CONSTRAINT jobs_kind_check")
    op.execute(f"ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ({OLD_KINDS}))")
    op.execute("DROP TABLE api_tokens")
    op.execute("DROP TABLE ingest_chunks")
    op.execute("DROP TABLE ingest_batches")
    op.execute("ALTER TABLE gitlab_projects DROP COLUMN created_by")
    op.execute("ALTER TABLE gitlab_projects DROP COLUMN source")
    op.execute("DROP INDEX gitlab_projects_full_path_key")
