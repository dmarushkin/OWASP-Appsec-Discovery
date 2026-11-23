"""Storage at scale (thousands of projects, millions of objects and hits): stored presence flags, stored LLM
hashes, the missing indexes, a statistics table, storage parameters of ``rule_hits``.

* ``rule_hits.in_main`` / ``in_open_mr`` (boolean NOT NULL DEFAULT false): the subject is in some main snapshot /
  in the delta of an open MR (``discovery_common.presence``). The API computed them per row with ``CASE ... EXISTS``
  over every main row (minutes at millions of hits); now the scanner maintains them on every snapshot, MR and
  branch change and the API reads the columns. Backfilled here, project by project. Partial indexes
  ``hits_live_seen`` (live hits in list order), ``hits_live_queue`` (the open review queue per project) and
  ``hits_seen`` (retention: hits in no branch, by COALESCE(last_seen_at, first_seen_at) and status).
* ``object_fields.llm_hash`` = ``llm_field_hash(name, type, comment, samples)`` and ``objects.names_hash`` =
  ``llm_names_hash(name, field names)``: what an LLM rule sees of the immutable, content-addressed row, written
  once by the scanner (``discovery_common.keys``) instead of hashed for every row by every candidate / coverage
  query (minutes per rule run on a big branch). Backfilled here, project by project.
* Indexes: ``hits_object (object_key)`` - the hits of one object (siblings, labels / tags of /objects, cascades,
  field marks) were a sequential scan of ``rule_hits``; ``hits_project_rule (project_id, rule_id)`` - the scan
  cleanups, relabel, stale counts; ``jobs_ready_kind`` - a claim restricted to some kinds; ``objects_name_key
  (name, object_key)`` - name-ordered pages of /objects; ``hit_verdicts_subject`` gets ``rule_version`` before
  ``id`` (the retention's "a newer row of the same version" probe, ``ADOPT_SQL``).
* ``rule_hits`` storage: fillfactor 85 and an autovacuum that keeps up with the daily ``last_seen_at`` updates of
  every hit of a main scan (``autovacuum_vacuum_scale_factor`` 0.02, ``autovacuum_analyze_scale_factor`` 0.01).
* ``stats_snapshots (name, data jsonb, computed_at)``: statistics precomputed by the scanner's ``stats_refresh``
  job (``overview``, ``job_health``, ``scan_progress``, ``llm_progress``, ``llm_quality``, ``hits_aggregate``),
  served by the API while fresh.

Online the backfills run per project (one UPDATE per project and table, in the migration's transaction), so a
statement never touches more than one project's rows; offline SQL emits the global statements. Measured on a
throwaway database: see docs/service/data-model.md.

Revision ID: 0030_scale_storage
Revises: 0029_diff_skip
Create Date: 2026-11-23
"""
import logging
import time

import sqlalchemy as sa
from alembic import context, op

from discovery_common.presence import BACKFILL_IN_MAIN, BACKFILL_IN_OPEN_MR

revision = "0030_scale_storage"
down_revision = "0029_diff_skip"
branch_labels = None
depends_on = None

logger = logging.getLogger("alembic.runtime.migration")

FIELD_HASH_BACKFILL = """
    UPDATE object_fields SET llm_hash = llm_field_hash(field_name, field_type, comment, samples)
    WHERE llm_hash IS NULL{scope}"""
NAMES_HASH_BACKFILL = """
    UPDATE objects o SET names_hash = llm_names_hash(o.name, ARRAY(SELECT f.field_name FROM object_fields f
                                                                   WHERE f.content_hash = o.content_hash))
    WHERE o.names_hash IS NULL{scope}"""

RULE_HITS_STORAGE = ("ALTER TABLE rule_hits SET (fillfactor = 85, autovacuum_vacuum_scale_factor = 0.02, "
                     "autovacuum_analyze_scale_factor = 0.01)")


def _backfill_online(conn) -> None:
    projects = [r[0] for r in conn.execute(sa.text("SELECT id FROM gitlab_projects ORDER BY id"))]
    started = time.monotonic()
    totals = {"fields": 0, "objects": 0, "hits": 0}
    for n, project_id in enumerate(projects, 1):
        p = {"p": project_id}
        totals["fields"] += conn.execute(sa.text(FIELD_HASH_BACKFILL.format(scope=" AND project_id = :p")), p).rowcount
        totals["objects"] += conn.execute(sa.text(NAMES_HASH_BACKFILL.format(scope=" AND o.project_id = :p")), p).rowcount
        for statement in (BACKFILL_IN_MAIN, BACKFILL_IN_OPEN_MR):
            totals["hits"] += conn.execute(sa.text(statement.format(scope=" AND h.project_id = :p")), p).rowcount
        if n % 100 == 0:
            logger.info(f"0030_scale_storage: {n}/{len(projects)} projects backfilled ({time.monotonic() - started:.0f}s)")
    # rows of projects that are gone (hits have no FK to the project): hashes for completeness, flags stay false
    totals["fields"] += conn.execute(sa.text(FIELD_HASH_BACKFILL.format(scope=""))).rowcount
    totals["objects"] += conn.execute(sa.text(NAMES_HASH_BACKFILL.format(scope=""))).rowcount
    logger.info(f"0030_scale_storage: backfilled {totals['fields']} field hashes, {totals['objects']} object name "
                f"hashes and the presence flags of {totals['hits']} hits of {len(projects)} projects in "
                f"{time.monotonic() - started:.1f}s")


def upgrade() -> None:
    op.execute("ALTER TABLE rule_hits ADD COLUMN IF NOT EXISTS in_main boolean NOT NULL DEFAULT false")
    op.execute("ALTER TABLE rule_hits ADD COLUMN IF NOT EXISTS in_open_mr boolean NOT NULL DEFAULT false")
    op.execute("ALTER TABLE objects ADD COLUMN IF NOT EXISTS names_hash text")
    op.execute("ALTER TABLE object_fields ADD COLUMN IF NOT EXISTS llm_hash text")

    # the backfill reads the hits per project and the objects' fields per version
    op.execute("CREATE INDEX IF NOT EXISTS hits_object ON rule_hits (object_key)")
    op.execute("CREATE INDEX IF NOT EXISTS hits_project_rule ON rule_hits (project_id, rule_id)")

    if context.is_offline_mode():
        op.execute(FIELD_HASH_BACKFILL.format(scope=""))
        op.execute(NAMES_HASH_BACKFILL.format(scope=""))
        op.execute(BACKFILL_IN_MAIN.format(scope=""))
        op.execute(BACKFILL_IN_OPEN_MR.format(scope=""))
    else:
        _backfill_online(op.get_bind())

    op.execute("CREATE INDEX IF NOT EXISTS hits_live_seen ON rule_hits (first_seen_at DESC NULLS LAST, rule_id, "
               "subject_key) WHERE in_main OR in_open_mr")
    op.execute("CREATE INDEX IF NOT EXISTS hits_live_queue ON rule_hits (project_id, first_seen_at DESC NULLS LAST) "
               "WHERE (in_main OR in_open_mr) AND status IN ('pending_review', 'need_more_info')")
    op.execute("CREATE INDEX IF NOT EXISTS hits_seen ON rule_hits ((COALESCE(last_seen_at, first_seen_at, "
               "'-infinity')), status) WHERE NOT in_main AND NOT in_open_mr")
    op.execute(RULE_HITS_STORAGE)

    op.execute("CREATE INDEX IF NOT EXISTS objects_name_key ON objects (name, object_key)")
    op.execute("CREATE INDEX IF NOT EXISTS jobs_ready_kind ON jobs (kind, priority DESC, run_after, id) "
               "WHERE status = 'pending'")
    op.execute("DROP INDEX IF EXISTS hit_verdicts_subject")
    op.execute("CREATE INDEX hit_verdicts_subject ON hit_verdicts (rule_id, subject_key, rule_version, id)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS stats_snapshots (
            name text PRIMARY KEY,
            data jsonb NOT NULL,
            computed_at timestamptz NOT NULL
        )""")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS stats_snapshots")
    op.execute("DROP INDEX IF EXISTS hit_verdicts_subject")
    op.execute("CREATE INDEX hit_verdicts_subject ON hit_verdicts (rule_id, subject_key, id)")
    op.execute("DROP INDEX IF EXISTS jobs_ready_kind")
    op.execute("DROP INDEX IF EXISTS objects_name_key")
    op.execute("ALTER TABLE rule_hits RESET (fillfactor, autovacuum_vacuum_scale_factor, autovacuum_analyze_scale_factor)")
    for index in ("hits_seen", "hits_live_queue", "hits_live_seen", "hits_project_rule", "hits_object"):
        op.execute(f"DROP INDEX IF EXISTS {index}")
    op.execute("ALTER TABLE object_fields DROP COLUMN IF EXISTS llm_hash")
    op.execute("ALTER TABLE objects DROP COLUMN IF EXISTS names_hash")
    op.execute("ALTER TABLE rule_hits DROP COLUMN IF EXISTS in_open_mr")
    op.execute("ALTER TABLE rule_hits DROP COLUMN IF EXISTS in_main")
