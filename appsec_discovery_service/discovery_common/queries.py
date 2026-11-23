"""SQL shared by the API and the scanner: the owner of an MR delta.

The storage is read through dedicated (partial) indexes, by scope:

* **main only** - ``branch_objects.is_main`` rows (full snapshots): ``bo_content
  (content_hash, is_main)`` answers the "is this object version in some main" semi-join;
  ``gitlab_branches.branches_one_main`` finds a project's main branch.
* **open (unmerged) MRs only** - MR source rows hold only the delta vs the target:
  ``bo_mr_rows (content_hash) INCLUDE (branch_id, change) WHERE NOT is_main`` plus
  ``gitlab_mrs.mrs_open`` / ``mrs_source`` / ``mrs_target_open`` (``WHERE state='opened'``).

Field lookups go through ``object_fields`` (``fields_proj_name`` for exact names per
project, ``fields_name_trgm`` for ``ILIKE '%...%'``). ``tests/test_common_query_plans``
checks the plans with EXPLAIN (with the reference readers of ``discovery_common.testing``).
"""

from sqlalchemy import text

# The delta of an MR is stored on its source branch, so one source branch holds one delta.
# When several open MRs share a source branch (e.g. a backport into another target), the
# delta belongs to the oldest one (lowest gitlab_mrs.id, see DELTA_OWNER_SQL): the scanner
# scans only that MR, and the readers show the delta under that MR only.
DELTA_OWNER_COND = """NOT EXISTS (SELECT 1 FROM gitlab_mrs m2
                                  WHERE m2.source_branch_id = m.source_branch_id AND m2.state = 'opened'
                                    AND m2.id < m.id)"""

DELTA_OWNER_SQL = text("""
    SELECT min(id) FROM gitlab_mrs WHERE source_branch_id = :source AND state = 'opened'
""")
