"""Retention and garbage collection (storage design, AGREED REVISIONS #3).

* In the GitLab sync loop (``update_branches_mrs``): ``close_missing_mrs`` marks MRs that
  are no longer open (merged/closed) and ``release_mr_branches`` deletes the tracked
  source branch of closed/merged/stale MRs (CASCADE removes its ``branch_objects``).
* ``cleanup()``: the ``cleanup`` job (P2-4), enqueued by the scheduler every
  ``GC_INTERVAL_HOURS``; still guarded by ``pg_try_advisory_lock`` so only one process
  collects at a time: closed MR rows after ``MR_ROW_RETENTION_DAYS``, untracked branches,
  scan markers beyond ``SCANS_KEEP_PER_BRANCH``, orphan object versions (collected in one
  anti-join pass, deleted by key in batches), rule_hits retention (hits in no branch:
  ``in_main`` / ``in_open_mr`` both false, by the ``hits_seen`` index), finished jobs after
  ``JOBS_RETENTION_DAYS``, verdict history after ``HIT_HISTORY_DAYS``, harness verifications
  after ``LLM_VERIFICATIONS_RETENTION_DAYS``, finished prompt trials after
  ``PROMPT_TRIALS_RETENTION_DAYS``, then table statistics are logged (the API exposes them on
  ``/health/db``).

Whenever a tracked branch loses its rows here (an MR closed / stale / untracked), the presence
flags of the hits of its objects are refreshed (``discovery_common.presence``): the keys are
read before the rows go.
"""

import time
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, Iterable, Optional, Sequence

from sqlalchemy import bindparam, text
from sqlalchemy.exc import IntegrityError

from discovery_common import db, jobs, llm_work, presence
from config import get_settings
from logger import get_logger

logger = get_logger(__name__)

GC_LOCK_KEY = 0x0D15C0_6C  # pg advisory lock id for cleanup()


# ---------------------------------------------------------------------------------------------
# GitLab sync loop helpers
# ---------------------------------------------------------------------------------------------

# Non-main source branch of the MR, unless another non-stale open MR still uses the branch.
RELEASE_BRANCH_SQL = text("""
    DELETE FROM gitlab_branches b
    WHERE b.id = :branch_id AND NOT b.is_main
      AND NOT EXISTS (
          SELECT 1 FROM gitlab_mrs m
          WHERE m.id <> :mr_id AND m.state = 'opened' AND m.updated_at >= :stale_before
            AND (m.source_branch_id = b.id OR m.target_branch_id = b.id))
""")


def close_missing_mrs(project_id: int, open_iids: Iterable[int], fetch_state: Optional[Callable[[int], Optional[str]]] = None,
                      fetch_states: Optional[Callable[[Sequence[int]], Dict[int, str]]] = None) -> int:
    """MRs stored as opened that GitLab no longer lists as opened: store their real state ('closed' when unknown)
    and ``closed_at``, then release their source branch. The states come from ``fetch_states(iids)`` (one batched
    GitLab call per 100 MRs, ``gl_service.get_gitlab_mr_states``) or, when only ``fetch_state(iid)`` is given,
    one call per MR. Returns the number of MRs closed."""
    settings = get_settings()
    open_iids = set(open_iids)

    with db.unit_of_work() as s:
        stored = s.execute(text(
            "SELECT id, mr_id, source_branch_id FROM gitlab_mrs WHERE project_id = :p AND state = 'opened'"),
            {"p": project_id}).all()

    missing = [row for row in stored if row.mr_id not in open_iids]
    states: Dict[int, str] = {}
    if missing and fetch_states is not None:
        try:
            states = {int(k): v for k, v in (fetch_states([row.mr_id for row in missing]) or {}).items()}
        except Exception as e:  # GitLab error: do not keep vanished MRs open forever
            logger.warning(f"Cannot fetch the states of {len(missing)} MRs of project {project_id}: {e}")
            states = {row.mr_id: 'closed' for row in missing}

    closed = 0
    for row in missing:
        if fetch_states is not None:
            state = states.get(row.mr_id) or 'closed'
        else:
            try:
                state = (fetch_state(row.mr_id) if fetch_state is not None else None) or 'closed'
            except Exception as e:  # GitLab error: do not keep a vanished MR open forever
                logger.warning(f"Cannot fetch state of MR {row.mr_id} of project {project_id}: {e}")
                state = 'closed'
        if state == 'opened':
            continue
        with db.unit_of_work() as s:
            keys = presence.branch_object_keys(s, row.source_branch_id) if row.source_branch_id is not None else []
            s.execute(text("UPDATE gitlab_mrs SET state = :state, closed_at = now() WHERE id = :id"),
                      {"state": state, "id": row.id})
            if row.source_branch_id is not None:
                _hand_over_delta(s, row.id, row.source_branch_id)
                s.execute(RELEASE_BRANCH_SQL, {"branch_id": row.source_branch_id, "mr_id": row.id,
                                               "stale_before": _stale_before(settings)})
            presence.refresh(s, object_keys=keys)       # the delta is not "in an open MR" any more
        logger.info(f"MR {row.mr_id} of project {project_id} is {state}: source branch released")
        closed += 1
    return closed


def _hand_over_delta(session, mr_row_id: int, source_branch_id: int) -> None:
    """A closed MR owned the delta of its source branch (the oldest open MR of the branch, see
    ``queries.DELTA_OWNER_COND``) and another open MR uses the same source branch: that delta
    is vs the closed MR's target, so it is dropped and the new owner is scanned again."""
    others = session.execute(text("""
        SELECT id FROM gitlab_mrs WHERE source_branch_id = :s AND state = 'opened' AND id <> :id"""),
        {"s": source_branch_id, "id": mr_row_id}).scalars().all()
    if not others or min(others) < mr_row_id:
        return              # not shared, or the closed MR did not own the delta
    session.execute(text("DELETE FROM branch_objects WHERE branch_id = :s AND NOT is_main"), {"s": source_branch_id})
    session.execute(text("UPDATE gitlab_branches SET scanned_commit = NULL WHERE id = :s AND NOT is_main"),
                    {"s": source_branch_id})
    session.execute(text("UPDATE gitlab_mrs SET processed_at = NULL WHERE id = :id"), {"id": min(others)})
    logger.info(f"Delta of source branch {source_branch_id} handed over to the open MR row {min(others)}")


def release_stale_mr_branches(project_id: int) -> int:
    """Open MRs not updated for ``MR_STALE_DAYS``: stop tracking their source branch."""
    settings = get_settings()
    stale_before = _stale_before(settings)
    released = 0
    with db.unit_of_work() as s:
        stale = s.execute(text("""
            SELECT id, source_branch_id FROM gitlab_mrs
            WHERE project_id = :p AND state = 'opened' AND updated_at < :stale_before
              AND source_branch_id IS NOT NULL"""), {"p": project_id, "stale_before": stale_before}).all()
        for row in stale:
            keys = presence.branch_object_keys(s, row.source_branch_id)
            gone = s.execute(RELEASE_BRANCH_SQL, {"branch_id": row.source_branch_id, "mr_id": row.id,
                                                  "stale_before": stale_before}).rowcount
            released += gone
            if gone:
                presence.refresh(s, object_keys=keys)
    if released:
        logger.info(f"Released {released} source branches of stale MRs of project {project_id}")
    return released


def is_stale(updated_at: datetime) -> bool:
    return updated_at < _stale_before(get_settings())


def _stale_before(settings) -> datetime:
    return datetime.now() - timedelta(days=settings.mr_stale_days)


# ---------------------------------------------------------------------------------------------
# Scheduled GC
# ---------------------------------------------------------------------------------------------

# Orphan object versions (no branch has them): one anti-join pass collects them into a temp table of the GC
# connection, then they are deleted by primary key in batches (the old form re-ran the whole anti-join for every
# batch of 1000). A version a scan references again meanwhile is skipped (NOT EXISTS; the FK is the final guard:
# a batch that still collides is rolled back and left for the next pass).
ORPHAN_COLLECT_SQL = text("""
    CREATE TEMP TABLE _gc_orphans AS
    SELECT o.content_hash FROM objects o
    WHERE NOT EXISTS (SELECT 1 FROM branch_objects b WHERE b.content_hash = o.content_hash)
""")
ORPHAN_PICK_SQL = text("""
    DELETE FROM _gc_orphans WHERE content_hash IN (SELECT content_hash FROM _gc_orphans LIMIT :batch)
    RETURNING content_hash""")
ORPHAN_DELETE_SQL = text("""
    DELETE FROM objects o WHERE o.content_hash = ANY(:hashes)
      AND NOT EXISTS (SELECT 1 FROM branch_objects b WHERE b.content_hash = o.content_hash)
""").bindparams(bindparam("hashes", type_=presence.UUIDS))

# Hits whose subject is in no branch any more (``in_main`` / ``in_open_mr`` both false, maintained by the scanner,
# ``discovery_common.presence``) past their retention: served by the partial index ``hits_seen``.
HITS_RETENTION_SQL = text("""
    DELETE FROM rule_hits WHERE (rule_id, subject_key) IN (
        SELECT h.rule_id, h.subject_key FROM rule_hits h
        WHERE h.status = ANY(:statuses)
          AND COALESCE(h.last_seen_at, h.first_seen_at, '-infinity') < :before
          AND NOT h.in_main AND NOT h.in_open_mr
        LIMIT :batch)
""")

# Only main branches and branches of open MRs are tracked.
_UNTRACKED_BRANCHES = """
    SELECT b.id FROM gitlab_branches b
    WHERE NOT b.is_main AND NOT EXISTS (
        SELECT 1 FROM gitlab_mrs m
        WHERE m.state = 'opened' AND m.updated_at >= :stale_before
          AND (m.source_branch_id = b.id OR m.target_branch_id = b.id))"""
UNTRACKED_BRANCH_KEYS_SQL = text(f"""
    SELECT DISTINCT bo.object_key FROM branch_objects bo WHERE bo.branch_id IN ({_UNTRACKED_BRANCHES})""")
UNTRACKED_BRANCHES_SQL = text(f"DELETE FROM gitlab_branches WHERE id IN ({_UNTRACKED_BRANCHES})")

STEPS_SQL = {
    "closed_mrs_without_closed_at": text(
        "UPDATE gitlab_mrs SET closed_at = now() WHERE state <> 'opened' AND closed_at IS NULL"),
    "old_closed_mrs": text(
        "DELETE FROM gitlab_mrs WHERE state <> 'opened' AND closed_at < :mr_rows_before"),
    "old_scans": text("""
        DELETE FROM discovery_scans WHERE id IN (
            SELECT id FROM (
                SELECT id, row_number() OVER (PARTITION BY branch_id ORDER BY scanned_at DESC, id DESC) AS rn
                FROM discovery_scans) x
            WHERE x.rn > :keep)"""),
    # external parsers: upload sessions never committed (24 h), failed states (7 days)
    "stale_ingest_sessions": text(
        "DELETE FROM ingest_batches WHERE status = 'open' AND created_at < now() - interval '24 hours'"),
    "failed_ingest_states": text(
        "DELETE FROM ingest_batches WHERE status = 'failed' AND created_at < now() - interval '7 days'"),
    # replaced states (no chunks) are kept for their Idempotency-Key: a late retry is replayed
    "superseded_ingest_states": text(
        "DELETE FROM ingest_batches WHERE status = 'superseded' AND created_at < now() - interval '7 days'"),
    # external LLM runs: finished work items (applied / failed / expired) after the retention
    "llm_work_finished": text(
        f"DELETE FROM llm_work_items WHERE status IN ('applied', 'failed', 'expired') "
        f"AND updated_at < now() - interval '{llm_work.RETENTION_DAYS} days'"),
}

# work items nobody answered within the retention expire (the run's progress is recounted)
LLM_WORK_EXPIRE_SQL = text(f"""
    UPDATE llm_work_items SET status = 'expired', error = 'not answered within {llm_work.RETENTION_DAYS} days',
           lease_owner = NULL, lease_token = NULL, lease_until = NULL, updated_at = now()
    WHERE status IN ('pending', 'leased') AND created_at < now() - interval '{llm_work.RETENTION_DAYS} days'
    RETURNING job_id, purpose, rule_id, subject_key
""")

# an unanswered verify item expired: its service verdict becomes eligible again (escalation / QA, llm_verify job)
VERIFY_KEY_RESET_SQL = text("""
    UPDATE rule_hits SET verify_key = NULL WHERE rule_id = :r AND subject_key = :s AND decided_tier = 'service'
""")


# verdict history (hit_verdicts, migration 0025): rows older than HIT_HISTORY_DAYS, except the last row of every rule
# version of a subject whose hit still exists (diffs between versions, rollback / adopt); a gone hit loses all of them.
# Candidates by ``hit_verdicts_created``, the "newer row of the same version" probe by ``hit_verdicts_subject``
# (rule_id, subject_key, rule_version, id) since migration 0030.
HIT_HISTORY_SQL = text("""
    DELETE FROM hit_verdicts WHERE id IN (
        SELECT v.id FROM hit_verdicts v
        WHERE v.created_at < :before
          AND (EXISTS (SELECT 1 FROM hit_verdicts n WHERE n.rule_id = v.rule_id AND n.subject_key = v.subject_key
                                                     AND n.rule_version = v.rule_version AND n.id > v.id)
               OR NOT EXISTS (SELECT 1 FROM rule_hits h WHERE h.rule_id = v.rule_id AND h.subject_key = v.subject_key))
        LIMIT :batch)""")

# harness verifications (QA metrics read the last 30 days; ``llm_mislabeled`` the rest): LLM_VERIFICATIONS_RETENTION_DAYS
VERIFICATIONS_RETENTION_SQL = text("""
    DELETE FROM llm_verifications WHERE id IN (
        SELECT id FROM llm_verifications WHERE created_at < :before LIMIT :batch)""")

# finished prompt trials (with their items, CASCADE) after PROMPT_TRIALS_RETENTION_DAYS, unless a proposal refers to
# the trial (the proposal keeps its evidence)
TRIALS_RETENTION_SQL = text("""
    DELETE FROM prompt_trials WHERE id IN (
        SELECT t.id FROM prompt_trials t
        WHERE t.created_at < :before AND t.status IN ('done', 'failed')
          AND NOT EXISTS (SELECT 1 FROM prompt_proposals p WHERE p.trial_id = t.id)
        LIMIT :batch)""")


def _batched(conn, statement, params, batch: int, max_batches: int = 10_000) -> int:
    total = 0
    for _ in range(max_batches):
        with conn.begin():
            deleted = conn.execute(statement, {**params, "batch": batch}).rowcount
        total += deleted
        if deleted < batch:
            break
    return total


def _collect_orphans(conn, batch: int, max_batches: int = 10_000) -> int:
    """Delete the object versions no branch has: one anti-join pass into a temp table, then batches by key."""
    with conn.begin():
        conn.execute(text("DROP TABLE IF EXISTS _gc_orphans"))
        found = conn.execute(ORPHAN_COLLECT_SQL).rowcount
    deleted = 0
    try:
        for _ in range(max_batches):
            with conn.begin():
                picked = conn.execute(ORPHAN_PICK_SQL, {"batch": batch}).scalars().all()
                if not picked:
                    break
                try:
                    with conn.begin_nested():
                        deleted += conn.execute(ORPHAN_DELETE_SQL, {"hashes": list(picked)}).rowcount
                except IntegrityError as e:        # a scan referenced a version again: this batch waits for the next pass
                    logger.info(f"Orphan GC batch skipped (a version was referenced again meanwhile): {e.orig}")
    finally:
        with conn.begin():
            conn.execute(text("DROP TABLE IF EXISTS _gc_orphans"))
    if found != deleted:
        logger.info(f"Orphan GC: {found} versions collected, {deleted} deleted")
    return deleted


def _untracked_branches(conn, stale_before: datetime) -> int:
    """Drop the branches no open MR uses any more (CASCADE takes their rows) and refresh the presence of the hits of
    the objects they held."""
    with conn.begin():
        keys = [r[0] for r in conn.execute(UNTRACKED_BRANCH_KEYS_SQL, {"stale_before": stale_before})]
        deleted = conn.execute(UNTRACKED_BRANCHES_SQL, {"stale_before": stale_before}).rowcount
        if keys:
            presence.refresh(conn, object_keys=keys)
    return deleted


def cleanup(now: Optional[datetime] = None) -> Optional[Dict[str, int]]:
    """Run one GC pass. Returns per-step counts, or None when another process holds the lock."""
    settings = get_settings()
    now = now or datetime.now()
    now_tz = now.astimezone(timezone.utc) if now.tzinfo else now.replace(tzinfo=timezone.utc)
    batch = settings.gc_batch_size
    stats: Dict[str, int] = {}

    with db.get_engine().connect() as conn:
        locked = conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": GC_LOCK_KEY}).scalar()
        conn.commit()
        if not locked:
            logger.info("Cleanup skipped: another process holds the GC lock")
            return None
        try:
            started = time.monotonic()
            params = {
                "mr_rows_before": now_tz - timedelta(days=settings.mr_row_retention_days),
                "stale_before": now - timedelta(days=settings.mr_stale_days),
                "keep": settings.scans_keep_per_branch,
            }
            for name, statement in STEPS_SQL.items():
                with conn.begin():
                    stats[name] = conn.execute(statement, params).rowcount
            stats["untracked_branches"] = _untracked_branches(conn, params["stale_before"])

            with conn.begin():
                expired = conn.execute(LLM_WORK_EXPIRE_SQL).all()
                expired_jobs = {r[0] for r in expired}
                verify = [{"r": r.rule_id, "s": r.subject_key} for r in expired if r.purpose == "verify"]
                if verify:
                    conn.execute(VERIFY_KEY_RESET_SQL, verify)
                llm_work.refresh_progress(expired_jobs, conn)
            stats["llm_work_expired_runs"] = len(expired_jobs)

            stats["orphan_objects"] = _collect_orphans(conn, batch)

            for name, statuses, days in (
                ("hits_pending_orphan", ["pending_review"], settings.hits_pending_orphan_days),
                ("hits_decided_unseen", ["match", "need_more_info"], settings.hits_decided_unseen_days),
                # the setting keeps its name (HITS_REJECTED_UNSEEN_DAYS) since migration 0023: no_match hits
                ("hits_rejected_unseen", ["no_match"], settings.hits_rejected_unseen_days),
            ):
                stats[name] = _batched(conn, HITS_RETENTION_SQL,
                                       {"statuses": statuses, "before": now_tz - timedelta(days=days)}, batch)

            stats["old_jobs"] = _batched(conn, jobs.PURGE_SQL, {"days": settings.jobs_retention_days}, batch)
            stats["hit_history"] = _batched(conn, HIT_HISTORY_SQL, {
                "before": now_tz - timedelta(days=settings.hit_history_days)}, batch)
            for name, statement, days in (
                ("llm_verifications", VERIFICATIONS_RETENTION_SQL, settings.llm_verifications_retention_days),
                ("prompt_trials", TRIALS_RETENTION_SQL, settings.prompt_trials_retention_days),
            ):
                stats[name] = _batched(conn, statement, {"before": now_tz - timedelta(days=days)}, batch) if days else 0

            table_stats = db.table_stats(conn)
            conn.commit()
            logger.info(f"Cleanup done in {time.monotonic() - started:.1f}s: {stats}")
            logger.info("Table stats: " + ", ".join(
                f"{name}={value['rows']} rows/{value['dead']} dead" for name, value in table_stats.items()))
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": GC_LOCK_KEY})
            conn.commit()

    return stats
