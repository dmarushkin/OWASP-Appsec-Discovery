"""Presence of a hit's subject: ``rule_hits.in_main`` / ``in_open_mr`` (migration 0030).

A hit is branch-agnostic (one row per rule and subject); whether its subject is in some main snapshot or in the
delta of an open MR used to be computed per row by the API (``CASE ... EXISTS`` over ``branch_objects``), which
the planner turns into a hashed sub-plan over every main row: minutes at millions of hits. The two flags are
stored on the hit instead and kept current by the scanner at every write that changes a snapshot:

* ``in_main``: the object (object hits) or the field (field hits) is in a version held by a main branch;
* ``in_open_mr``: it is in a version held by the source branch of an MR in state ``opened`` (MR rows are the
  delta vs the target, so this means "new or changed in an open MR").

Who refreshes them: ``save_main_scan`` / ``save_mr_delta`` for the objects the snapshot diff touched (and new
hits are inserted with the flag of the branch they come from), ``_prune_mr_deltas``, a demoted main branch,
``upsert_mr`` (an MR reopened), ``close_missing_mrs`` / ``release_stale_mr_branches`` / the cleanup's untracked
branches (the keys of the released branch are collected before its rows go), LLM verdicts (the objects a run
asked about), harness field marks. The API filters and ``HitOut.in_main`` / ``in_open_mr`` read the columns; the
retention of the cleanup deletes only hits with both flags false. Anything else that inserts hits (manual
labels, ...) calls ``refresh(session, object_keys=...)`` afterwards or sets the flags itself.

``refresh`` works in batches of object keys (every hit of the object, object hits and field hits, through
``hits_object``) or for a whole project (``hits_project_rule``); only rows whose flags change are written.
"""

import uuid
from typing import Iterable, List, Optional, Sequence

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID

UUIDS = ARRAY(UUID(as_uuid=True))
BATCH = 5000

# The subject (field of the object, or the object itself) is in some main snapshot.
IN_MAIN = """CASE WHEN h.field_name IS NULL
    THEN EXISTS (SELECT 1 FROM objects o2 JOIN branch_objects b2 ON b2.content_hash = o2.content_hash AND b2.is_main
                 WHERE o2.object_key = h.object_key)
    ELSE EXISTS (SELECT 1 FROM object_fields f2 JOIN branch_objects b2 ON b2.content_hash = f2.content_hash AND b2.is_main
                 WHERE f2.field_key = h.subject_key) END"""

# The subject is in a new/changed object of an open MR (MR rows hold only the delta).
IN_OPEN_MR = """CASE WHEN h.field_name IS NULL
    THEN EXISTS (SELECT 1 FROM objects o3 JOIN branch_objects b3 ON b3.content_hash = o3.content_hash AND NOT b3.is_main
                 JOIN gitlab_mrs m3 ON m3.source_branch_id = b3.branch_id AND m3.state = 'opened'
                 WHERE o3.object_key = h.object_key)
    ELSE EXISTS (SELECT 1 FROM object_fields f3 JOIN branch_objects b3 ON b3.content_hash = f3.content_hash AND NOT b3.is_main
                 JOIN gitlab_mrs m3 ON m3.source_branch_id = b3.branch_id AND m3.state = 'opened'
                 WHERE f3.field_key = h.subject_key) END"""

# The hits of a set of objects (object hits and field hits: every hit carries object_key): the hits are found
# through ``hits_object`` and joined back by primary key, the two EXISTS are evaluated once per hit.
REFRESH_BY_OBJECTS_SQL = text(f"""
    UPDATE rule_hits h SET in_main = x.in_main, in_open_mr = x.in_open_mr
    FROM (SELECT h.rule_id, h.subject_key, {IN_MAIN} AS in_main, {IN_OPEN_MR} AS in_open_mr
          FROM rule_hits h JOIN unnest(CAST(:keys AS uuid[])) k(object_key) ON k.object_key = h.object_key) x
    WHERE h.rule_id = x.rule_id AND h.subject_key = x.subject_key
      AND (h.in_main <> x.in_main OR h.in_open_mr <> x.in_open_mr)""").bindparams(bindparam("keys", type_=UUIDS))

# Every hit of a project (a demoted main branch): one direct UPDATE per flag, no self-join (which the planner turns
# into a hash join over a sequential scan of rule_hits); a flag is rewritten only where it changes.
REFRESH_PROJECT_IN_MAIN_SQL = text(f"""
    UPDATE rule_hits h SET in_main = NOT h.in_main WHERE h.project_id = :p AND h.in_main <> ({IN_MAIN})""")
REFRESH_PROJECT_IN_OPEN_MR_SQL = text(f"""
    UPDATE rule_hits h SET in_open_mr = NOT h.in_open_mr WHERE h.project_id = :p AND h.in_open_mr <> ({IN_OPEN_MR})""")

# The backfill of migration 0030 (every flag starts false, so only the hits that are live are written), plain SQL;
# ``{scope}``: "" or " AND h.project_id = :p".
BACKFILL_IN_MAIN = f"UPDATE rule_hits h SET in_main = true WHERE NOT h.in_main{{scope}} AND ({IN_MAIN})"
BACKFILL_IN_OPEN_MR = f"UPDATE rule_hits h SET in_open_mr = true WHERE NOT h.in_open_mr{{scope}} AND ({IN_OPEN_MR})"

BRANCH_KEYS_SQL = text("SELECT DISTINCT object_key FROM branch_objects WHERE branch_id = :b")


def branch_object_keys(conn, branch_id: int) -> List[uuid.UUID]:
    """The objects a branch holds rows of - to be read BEFORE the rows (or the branch) are deleted, and passed
    to ``refresh`` afterwards."""
    return [r[0] for r in conn.execute(BRANCH_KEYS_SQL, {"b": int(branch_id)})]


def refresh(conn, object_keys: Optional[Iterable[uuid.UUID]] = None, project_id: Optional[int] = None,
            batch: int = BATCH) -> int:
    """Recompute ``in_main`` / ``in_open_mr`` of the hits of ``object_keys`` (in batches) and / or of every hit of
    ``project_id``, in the caller's transaction (``conn``: a Session or a Connection). Returns the rows changed."""
    changed = 0
    if object_keys is not None:
        keys: Sequence[uuid.UUID] = list(dict.fromkeys(object_keys))
        for i in range(0, len(keys), batch):
            changed += conn.execute(REFRESH_BY_OBJECTS_SQL, {"keys": list(keys[i:i + batch])}).rowcount or 0
    if project_id is not None:
        for statement in (REFRESH_PROJECT_IN_MAIN_SQL, REFRESH_PROJECT_IN_OPEN_MR_SQL):
            changed += conn.execute(statement, {"p": int(project_id)}).rowcount or 0
    return changed
