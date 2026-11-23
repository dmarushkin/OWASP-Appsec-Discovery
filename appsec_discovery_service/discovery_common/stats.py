"""Statistics the API used to aggregate per request, computed by the scanner's ``stats_refresh`` job every
STATS_REFRESH_S into ``stats_snapshots (name, data, computed_at)`` (migration 0030) and served by the API while
fresh (``read_snapshot``; stale or filtered requests compute live).

The functions here return exactly what the API services return today (``insights_service.overview`` without a
project / filters, ``jobs_service.job_health``, ``scan_progress_service.totals``, ``llm_progress_service.totals``,
``quality_service.llm_quality`` for every rule), so a snapshot can replace the live computation unchanged; the API
imports them from here (one copy of the SQL). They take a SQLAlchemy connection or session (anything with
``execute``) and only depend on ``discovery_common``, so the scanner (pydantic 1) and the API (pydantic 2) share them.
Values are plain JSON when written: datetimes as ISO 8601 strings (``isoformat()``, as FastAPI encodes them).

Snapshot names: ``overview``, ``job_health``, ``scan_progress``, ``llm_progress``, ``llm_quality``,
``hits_aggregate`` (counts of hits by status x decided_tier x asked_by_model x in_main x in_open_mr x rule_id x
category x severity x field_mark: ``{"by": [...], "rows": [{<dims>, "n"}]}``; a field mark is a field hit of an
object rule).

``job_health`` fixes the typical run / wait times: ``jobs.started_at`` (migration 0031) stays on the finished row,
``locked_at`` (the lease) does not.
"""

import datetime as _dt
import decimal
import json
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from discovery_common import lifecycle
from discovery_common.models import LLM_PROMPTS_VERSION, SCAN_MODES
from discovery_common.queries import DELTA_OWNER_COND

SNAPSHOT_NAMES = ("overview", "job_health", "scan_progress", "llm_progress", "llm_quality", "hits_aggregate")


# ---------------------------------------------------------------------------------------------
# snapshot table
# ---------------------------------------------------------------------------------------------

def jsonable(value: Any) -> Any:
    """Plain JSON: datetimes / dates -> ISO 8601 strings, Decimal -> int / float, UUID -> str, mappings / sequences
    recursively (tuple keys are not allowed: the API functions drop them before returning)."""
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [jsonable(v) for v in value]
    if isinstance(value, (_dt.datetime, _dt.date)):
        return value.isoformat()
    if isinstance(value, decimal.Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, uuid.UUID):
        return str(value)
    return value


WRITE_SQL = text("""
    INSERT INTO stats_snapshots (name, data, computed_at) VALUES (:name, CAST(:data AS jsonb), now())
    ON CONFLICT (name) DO UPDATE SET data = EXCLUDED.data, computed_at = EXCLUDED.computed_at""")

READ_SQL = text("SELECT data, computed_at FROM stats_snapshots WHERE name = :name")


def write_snapshot(conn, name: str, data: Any) -> None:
    conn.execute(WRITE_SQL, {"name": name, "data": json.dumps(jsonable(data))})


def read_snapshot(conn, name: str, max_age_s: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """``{"data", "computed_at"}`` of a snapshot, None when missing or older than ``max_age_s``."""
    row = conn.execute(READ_SQL, {"name": name}).first()
    if row is None:
        return None
    if max_age_s is not None:
        age = conn.execute(text("SELECT extract(epoch FROM now() - CAST(:t AS timestamptz))"),
                           {"t": row.computed_at}).scalar()
        if age is None or float(age) > max_age_s:
            return None
    return {"data": row.data, "computed_at": row.computed_at}


def _rows(conn, sql: str, binds: Optional[dict] = None) -> List[dict]:
    return [dict(r) for r in conn.execute(text(sql), binds or {}).mappings()]


def _age_s(now, then) -> Optional[int]:
    return int((now - then).total_seconds()) if then is not None else None


def _seconds(value) -> Optional[int]:
    return int(round(float(value))) if value is not None else None


def _share(part: int, whole: int) -> Optional[float]:
    return round(part / whole, 4) if whole else None


# ---------------------------------------------------------------------------------------------
# overview (insights_service.overview, project_id None, no filters)
# ---------------------------------------------------------------------------------------------

MATCHES_BY_PROJECT_MAX = 200
LANDSCAPE_TYPES = ("table", "rpc", "query", "mutation")


def overview(conn) -> Dict[str, Any]:
    """= ``insights_service.overview(session)`` without a project or filters."""
    by_type = ", ".join(f"count(*) FILTER (WHERE h.status = 'match' AND obj.type = '{t}') AS type_{t}"
                        for t in LANDSCAPE_TYPES)
    matches_by_project = [{
        "project_id": r["project_id"], "project_path": r["project_path"], "matches": int(r["matches"]),
        "open": int(r["open"]), "by_type": {t: int(r[f"type_{t}"]) for t in LANDSCAPE_TYPES},
    } for r in _rows(conn, f"""
        SELECT p.id AS project_id, p.full_path AS project_path,
               count(*) FILTER (WHERE h.status = 'match') AS matches,
               count(*) FILTER (WHERE h.status IN ('pending_review', 'need_more_info')) AS "open", {by_type}
        FROM rule_hits h JOIN rules r ON r.id = h.rule_id JOIN gitlab_projects p ON p.id = h.project_id
        LEFT JOIN LATERAL (SELECT o.type FROM objects o WHERE o.object_key = h.object_key LIMIT 1) obj ON true
        WHERE true GROUP BY 1, 2
        HAVING count(*) FILTER (WHERE h.status IN ('match', 'pending_review', 'need_more_info')) > 0
        ORDER BY matches DESC, "open" DESC, p.full_path LIMIT {MATCHES_BY_PROJECT_MAX}""")]
    return {
        "project_id": None,
        "projects": _rows(conn, "SELECT scan_mode, count(*) n FROM gitlab_projects GROUP BY 1"),
        "objects_by_type": _rows(conn, """SELECT o.type, count(DISTINCT o.object_key) n FROM branch_objects b
            JOIN gitlab_branches g ON g.id = b.branch_id JOIN objects o ON o.content_hash = b.content_hash
            WHERE b.is_main GROUP BY 1 ORDER BY 2 DESC"""),
        "hits_by_status": _rows(conn, "SELECT h.status, count(*) n FROM rule_hits h WHERE true GROUP BY 1 ORDER BY 2 DESC"),
        "confirmed_by_category": _rows(conn, """SELECT h.category, h.severity, count(*) n FROM rule_hits h
            JOIN rules r ON r.id = h.rule_id
            WHERE h.status = 'match' GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 30"""),
        "matches_by_project": matches_by_project,
        "filters": None,
        "pending_by_rule": _rows(conn, """SELECT r.id AS rule_id, r.name, count(*) n FROM rule_hits h JOIN rules r ON r.id = h.rule_id
            WHERE h.status IN ('pending_review', 'need_more_info') GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 30"""),
        "open_mrs": conn.execute(text("SELECT count(*) FROM gitlab_mrs WHERE state = 'opened'")).scalar(),
        "stale_main_branches": _rows(conn, """SELECT g.id AS branch_id, g.project_path, g.commit, g.scanned_commit
            FROM gitlab_branches g WHERE g.is_main AND g.commit IS DISTINCT FROM g.scanned_commit
            ORDER BY g.project_path LIMIT 50"""),
        "failed_jobs": _rows(conn, "SELECT id, kind, left(last_error, 200) AS last_error, finished_at FROM jobs "
                                   "WHERE status = 'failed' ORDER BY id DESC LIMIT 20"),
    }


# ---------------------------------------------------------------------------------------------
# job_health (jobs_service.job_health)
# ---------------------------------------------------------------------------------------------

# kinds the scanner schedules for later (run_after in the future, periodic): their pending age says nothing about
# the queue keeping up, so the totals' oldest pending job is taken over the other kinds only
SCHEDULED_KINDS = ("cleanup", "llm_rollout")

_DUE = "GREATEST(created_at, run_after)"
# run / wait times from ``started_at`` (the claim of the last attempt, kept on the finished row; migration 0031), or
# the lease start for the running rows claimed before the column existed
_STARTED = "COALESCE(started_at, locked_at)"
HEALTH_SQL = text(f"""
    SELECT kind,
           count(*) FILTER (WHERE status = 'pending') AS pending,
           count(*) FILTER (WHERE status = 'pending' AND attempts > 0) AS retrying,
           count(*) FILTER (WHERE status = 'running') AS running,
           count(*) FILTER (WHERE status = 'failed') AS failed,
           count(*) FILTER (WHERE status = 'done' AND finished_at > now() - interval '1 hour') AS done_1h,
           count(*) FILTER (WHERE status = 'done' AND finished_at > now() - interval '24 hours') AS done_24h,
           count(*) FILTER (WHERE status = 'failed' AND finished_at > now() - interval '24 hours') AS failed_24h,
           count(*) FILTER (WHERE status = 'done' AND finished_at > now() - interval '24 hours'
                            AND progress ? 'skipped') AS skipped_24h,
           min({_DUE}) FILTER (WHERE status = 'pending' AND run_after <= now()) AS oldest_pending_at,
           (array_agg(id ORDER BY {_DUE}) FILTER (WHERE status = 'pending' AND run_after <= now()))[1]
               AS oldest_pending_job,
           count(*) FILTER (WHERE status = 'pending' AND run_after > now()) AS scheduled,
           min(run_after) FILTER (WHERE status = 'pending' AND run_after > now()) AS next_run_at,
           min(locked_at) FILTER (WHERE status = 'running') AS longest_running_at,
           (array_agg(id ORDER BY locked_at) FILTER (WHERE status = 'running'))[1] AS longest_running_job,
           max(finished_at) FILTER (WHERE status = 'done') AS last_done_at,
           percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM finished_at - {_STARTED}))
               FILTER (WHERE status = 'done' AND {_STARTED} IS NOT NULL AND finished_at > now() - interval '24 hours')
               AS typical_run_s,
           percentile_cont(0.5) WITHIN GROUP (ORDER BY GREATEST(0, extract(epoch FROM {_STARTED} - {_DUE})))
               FILTER (WHERE {_STARTED} > now() - interval '24 hours') AS typical_wait_s
    FROM jobs GROUP BY kind ORDER BY kind
""")

WORKERS_SQL = text("""
    SELECT id, kind, locked_by, locked_at, progress FROM jobs WHERE status = 'running' ORDER BY locked_at, id
""")

LLM_RATE_SQL = text("""
    SELECT coalesce(sum((progress->>'done_objects')::int) FILTER (
               WHERE status = 'done' AND finished_at > now() - interval '1 hour'), 0) AS objects_done_1h,
           coalesce(sum((progress->>'done_objects')::int) FILTER (
               WHERE status = 'done' AND finished_at > now() - interval '24 hours'), 0) AS objects_done_24h,
           coalesce(sum((progress->>'done_objects')::int) FILTER (
               WHERE status = 'running' AND (progress->>'started_at')::timestamptz > now() - interval '1 hour'), 0)
               AS running_objects_1h,
           avg((progress->>'total_objects')::int) FILTER (
               WHERE status = 'done' AND finished_at > now() - interval '24 hours') AS avg_objects_per_run_24h,
           count(*) FILTER (WHERE status = 'pending') AS pending_runs,
           count(*) FILTER (WHERE status = 'running') AS running_runs
    FROM jobs WHERE kind = 'llm_score' AND payload->>'executor' IS DISTINCT FROM 'external'
""")


def _eta(pending: int, done_1h: int, typical_run_s: Optional[int], running: int) -> Optional[int]:
    """Seconds until the pending jobs of a kind are done: at the rate of the last hour; without finished jobs in
    the last hour, the typical run time times the backlog over the workers busy with the kind (at least one)."""
    if not pending:
        return None
    if done_1h:
        return int(pending / done_1h * 3600)
    if typical_run_s is not None:
        return int(pending * typical_run_s / max(1, running))
    return None


def job_health(conn) -> Dict[str, Any]:
    """``GET /jobs/health`` (the API serves the snapshot or calls this): per kind the pending (``retrying``: after a
    failed attempt), running and failed jobs, done / failed in the last hour and 24 hours, the oldest pending age (from
    the moment it was due; jobs due later are ``scheduled``), the longest running, ``last_done_at``, the typical run
    and wait time of the last 24 hours (p50, from ``started_at``) and ``eta_s``; the busy ``workers``; the throughput of
    the service LLM runs (``llm``); the diff-skipped vs full ``scans`` of the last 24 hours."""
    now = conn.execute(text("SELECT now()")).scalar()
    kinds: Dict[str, Dict[str, Any]] = {}
    totals = {"pending": 0, "retrying": 0, "running": 0, "failed": 0, "failed_24h": 0, "done_1h": 0, "done_24h": 0,
              "oldest_pending_s": None, "oldest_pending_kind": None, "oldest_pending_job": None}
    for r in conn.execute(HEALTH_SQL).mappings():
        item = {k: int(r[k] or 0) for k in ("pending", "retrying", "running", "failed", "done_1h", "done_24h", "failed_24h",
                                            "skipped_24h")}
        next_run = r["next_run_at"]
        item.update({"oldest_pending_s": _age_s(now, r["oldest_pending_at"]), "oldest_pending_job": r["oldest_pending_job"],
                     "longest_running_s": _age_s(now, r["longest_running_at"]),
                     "longest_running_job": r["longest_running_job"],
                     "scheduled": {"count": int(r["scheduled"] or 0),
                                   "next_run_in_s": max(0, _age_s(next_run, now)) if next_run is not None else None},
                     "last_done_at": r["last_done_at"],
                     "typical_run_s": _seconds(r["typical_run_s"]), "typical_wait_s": _seconds(r["typical_wait_s"]),
                     "eta_s": _eta(item["pending"], item["done_1h"], _seconds(r["typical_run_s"]), item["running"])})
        kinds[r["kind"]] = item
        for k in ("pending", "retrying", "running", "failed", "failed_24h", "done_1h", "done_24h"):
            totals[k] += item[k]
        age = item["oldest_pending_s"]
        if r["kind"] not in SCHEDULED_KINDS and age is not None and (
                totals["oldest_pending_s"] is None or age > totals["oldest_pending_s"]):
            totals.update({"oldest_pending_s": age, "oldest_pending_kind": r["kind"],
                           "oldest_pending_job": r["oldest_pending_job"]})
    workers = []
    for r in conn.execute(WORKERS_SQL).mappings():
        progress = r["progress"] or {}
        workers.append({"job_id": r["id"], "kind": r["kind"], "locked_by": r["locked_by"],
                        "since_s": _age_s(now, r["locked_at"]),
                        "progress": {k: progress.get(k) for k in ("phase", "done_objects", "total_objects", "objects")
                                     if progress.get(k) is not None} or None})
    rate = conn.execute(LLM_RATE_SQL).mappings().one()
    per_hour = int(rate["objects_done_1h"] or 0) + int(rate["running_objects_1h"] or 0)
    avg_run = float(rate["avg_objects_per_run_24h"]) if rate["avg_objects_per_run_24h"] is not None else None
    pending_runs = int(rate["pending_runs"] or 0)
    estimated = int(round(pending_runs * avg_run)) if avg_run is not None else None
    llm = {
        "objects_done_1h": int(rate["objects_done_1h"] or 0), "objects_done_24h": int(rate["objects_done_24h"] or 0),
        "objects_per_hour": per_hour, "avg_objects_per_run_24h": round(avg_run, 1) if avg_run is not None else None,
        "pending_runs": pending_runs, "running_runs": int(rate["running_runs"] or 0),
        "estimated_pending_objects": estimated,
        "eta_s": int(estimated / per_hour * 3600) if estimated is not None and per_hour > 0 else None,
        "note": "service llm_score runs only; objects from jobs.progress; the ETA assumes the current hourly rate and "
                "the average run size of the last 24 hours",
    }
    scans = {kind: {"full": kinds.get(kind, {}).get("done_24h", 0) - kinds.get(kind, {}).get("skipped_24h", 0),
                    "skipped": kinds.get(kind, {}).get("skipped_24h", 0)}
             for kind in ("scan_branch", "scan_mr")}
    scans["note"] = "done jobs of the last 24 hours: skipped = ended by the diff-based skip (no parser file changed " \
                    "since the snapshot, nothing cloned or parsed), full = cloned and parsed"
    return {"now": now, "kinds": kinds, "totals": totals, "workers": workers, "llm": llm, "scans": scans}


# the day's escalations (tiered workflow, LLM_ESCALATION_DAILY_MAX): items recorded and the overflow the verify jobs
# counted (``progress.escalation_overflow``), per rule; added by the stats_refresh job to the job_health snapshot
ESCALATIONS_SQL = text("""
    WITH today AS (SELECT (date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC') AS start),
    items AS (
        SELECT w.rule_id, count(*) AS n FROM llm_work_items w, today
        WHERE w.purpose = 'verify' AND w.created_at >= today.start AND w.verify ->> 'sample' = 'escalation'
        GROUP BY w.rule_id),
    overflow AS (
        SELECT (j.payload ->> 'rule_ids') AS rule_ids, sum((j.progress ->> 'escalation_overflow')::int) AS n
        FROM jobs j, today
        WHERE j.kind = 'llm_verify' AND j.created_at >= today.start AND j.progress ? 'escalation_overflow'
        GROUP BY 1)
    SELECT (SELECT coalesce(json_object_agg(rule_id, n), '{}'::json) FROM items) AS items,
           (SELECT coalesce(sum(n), 0) FROM overflow) AS overflow
""")


def escalations_today(conn, daily_max: int) -> Dict[str, Any]:
    """``{daily_max, items_today, overflow_today, by_rule: {rule_id: items}}`` for the job health snapshot."""
    row = conn.execute(ESCALATIONS_SQL).mappings().one()
    by_rule = {int(k): int(v) for k, v in (row["items"] or {}).items()}
    return {"daily_max": int(daily_max), "items_today": sum(by_rule.values()),
            "overflow_today": int(row["overflow"] or 0), "by_rule": by_rule}


# ---------------------------------------------------------------------------------------------
# scan_progress (scan_progress_service.totals)
# ---------------------------------------------------------------------------------------------

MAIN_STATES = ("current", "outdated", "never_scanned", "partial", "failed", "skipped", "no_main")
MR_STATES = ("current", "outdated", "never_scanned", "partial", "failed", "not_tracked")

MAINS_SQL = """
WITH mains AS (
    SELECT p.id AS project_id, p.full_path AS project_path, p.scan_mode,
           p.updated_at AS activity_at, p.processed_at AS synced_at,
           (p.processed_at IS NOT NULL AND p.processed_at >= p.updated_at) AS synced,
           g.id AS branch_id, g.branch_name, g.commit, g.scanned_commit, g.updated_at AS commit_at
    FROM gitlab_projects p
    LEFT JOIN gitlab_branches g ON g.project_id = p.id AND g.is_main
    WHERE p.source = 'gitlab'{scope}
), st AS (
    SELECT m.*,
           CASE WHEN m.branch_id IS NULL THEN 'no_main'
                WHEN m.scanned_commit = m.commit THEN 'current'
                WHEN lj.status = 'failed' THEN 'failed'
                WHEN EXISTS (SELECT 1 FROM discovery_scans s WHERE s.branch_id = m.branch_id
                             AND s.branch_commit = m.commit AND s.rules_version LIKE '%+partial') THEN 'partial'
                WHEN lj.status = 'done' AND lj.commit = m.commit AND NOT lj.subset THEN 'skipped'
                WHEN m.scanned_commit IS NULL THEN 'never_scanned'
                ELSE 'outdated' END AS state,
           CASE WHEN a.running THEN 'running' WHEN a.n > 0 THEN 'queued' END AS job,
           COALESCE(a.retrying, false) AS retrying, a.job_id,
           CASE WHEN sj.status = 'running' THEN 'running' WHEN sj.status = 'pending' THEN 'queued' END AS sync_job,
           lj.id AS last_job_id, lj.status AS last_job_status, lj.finished_at AS last_job_at,
           COALESCE(a.last_error, CASE WHEN lj.status = 'failed' THEN lj.last_error END) AS last_error
    FROM mains m
    LEFT JOIN LATERAL (
        SELECT count(*) AS n, bool_or(j.status = 'running') AS running,
               bool_or(j.status = 'pending' AND j.attempts > 0) AS retrying, min(j.id) AS job_id,
               (array_agg(j.last_error ORDER BY j.id DESC))[1] AS last_error
        FROM jobs j WHERE j.kind = 'scan_branch' AND j.payload ->> 'branch_id' = m.branch_id::text
          AND j.status IN ('pending', 'running')) a ON true
    LEFT JOIN LATERAL (
        SELECT j.id, j.status, j.finished_at, j.last_error, j.payload ->> 'commit' AS commit,
               j.payload ? 'parsers' AS subset
        FROM jobs j WHERE j.kind = 'scan_branch' AND j.payload ->> 'branch_id' = m.branch_id::text
          AND j.status IN ('done', 'failed')
        ORDER BY j.id DESC LIMIT 1) lj ON true
    LEFT JOIN LATERAL (
        SELECT j.status FROM jobs j WHERE j.dedup_key = 'sync_branches_mrs:' || m.project_id
          AND j.status IN ('pending', 'running') LIMIT 1) sj ON true
)
"""

MR_ACTIVE_COND = "m.updated_at > now() - interval '1 day'"

MRS_SQL = f"""
WITH mrs AS (
    SELECT m.id, m.project_id, m.source_branch_commit, sb.scanned_commit,
           (m.source_branch_id IS NULL OR m.target_branch_id IS NULL OR sb.id IS NULL OR sb.is_main
            OR NOT {DELTA_OWNER_COND}) AS not_tracked,
           ({MR_ACTIVE_COND}) AS active
    FROM gitlab_mrs m
    JOIN gitlab_projects p ON p.id = m.project_id AND p.source = 'gitlab'
    LEFT JOIN gitlab_branches sb ON sb.id = m.source_branch_id
    WHERE m.state = 'opened'{{scope}}
)
SELECT m.project_id,
       CASE WHEN m.not_tracked THEN 'not_tracked'
            WHEN m.scanned_commit = m.source_branch_commit THEN 'current'
            WHEN lj.status = 'failed' THEN 'failed'
            WHEN lj.status = 'done' AND lj.commit = m.source_branch_commit AND NOT lj.subset THEN 'partial'
            WHEN m.scanned_commit IS NULL THEN 'never_scanned'
            ELSE 'outdated' END AS state,
       CASE WHEN a.running THEN 'running' WHEN a.n > 0 THEN 'queued' END AS job,
       (m.active AND NOT m.not_tracked) AS active,
       min(a.waiting_since) AS waiting_since,
       count(*) AS n
FROM mrs m
LEFT JOIN LATERAL (
    SELECT count(*) AS n, bool_or(j.status = 'running') AS running,
           min(GREATEST(j.created_at, j.run_after)) AS waiting_since
    FROM jobs j WHERE j.kind = 'scan_mr' AND j.payload ->> 'mr_id' = m.id::text
      AND j.status IN ('pending', 'running')) a ON true
LEFT JOIN LATERAL (
    SELECT j.status, j.payload ->> 'source_commit' AS commit, j.payload ? 'parsers' AS subset
    FROM jobs j WHERE j.kind = 'scan_mr' AND j.payload ->> 'mr_id' = m.id::text AND j.status IN ('done', 'failed')
    ORDER BY j.id DESC LIMIT 1) lj ON true
GROUP BY 1, 2, 3, 4
"""


def _main_totals() -> Dict[str, int]:
    return {"projects": 0, "synced": 0, "sync_queued": 0, "sync_running": 0, "scanned_current": 0,
            **{s: 0 for s in MAIN_STATES if s != "current"}, "queued": 0, "running": 0, "retrying": 0}


def _mr_totals() -> Dict[str, Any]:
    return {"open": 0, "scanned_current": 0, **{s: 0 for s in MR_STATES if s != "current"}, "queued": 0, "running": 0,
            "active_24h": 0, "active_scanned": 0, "active_waiting": 0, "oldest_waiting_s": None}


def _add_active(totals: Dict[str, Any], row, now) -> None:
    if not row["active"]:
        return
    totals["active_24h"] += row["n"]
    if row["state"] == "current":
        totals["active_scanned"] += row["n"]
    if row["job"]:
        totals["active_waiting"] += row["n"]
        age = int((now - row["waiting_since"]).total_seconds()) if row["waiting_since"] is not None else None
        if age is not None and (totals["oldest_waiting_s"] is None or age > totals["oldest_waiting_s"]):
            totals["oldest_waiting_s"] = age


def _add_scan(totals: Dict[str, int], state: str, job: Optional[str], n: int) -> None:
    totals["scanned_current" if state == "current" else state] += n
    if job:
        totals[job] += n


def scan_progress(conn) -> Dict[str, Any]:
    """= ``scan_progress_service.totals(session)``."""
    main, by_mode = _main_totals(), {mode: _main_totals() for mode in SCAN_MODES}
    for r in conn.execute(text(MAINS_SQL.format(scope="") + """
            SELECT scan_mode, state, job, synced, sync_job, retrying, count(*) AS n FROM st GROUP BY 1, 2, 3, 4, 5, 6
            """)).mappings():
        for t in (main, by_mode.setdefault(r["scan_mode"], _main_totals())):
            t["projects"] += r["n"]
            t["synced"] += r["n"] if r["synced"] else 0
            if r["sync_job"]:
                t[f"sync_{r['sync_job']}"] += r["n"]
            t["retrying"] += r["n"] if r["retrying"] else 0
            _add_scan(t, r["state"], r["job"], r["n"])
    mrs = _mr_totals()
    now = conn.execute(text("SELECT now()")).scalar()
    for r in conn.execute(text(MRS_SQL.format(scope="")), {}).mappings().all():
        mrs["open"] += r["n"]
        _add_scan(mrs, r["state"], r["job"], r["n"])
        _add_active(mrs, r, now)
    external = dict(conn.execute(text("""
        SELECT count(*) AS projects, count(g.scanned_commit) AS with_state FROM gitlab_projects p
        LEFT JOIN gitlab_branches g ON g.project_id = p.id AND g.is_main WHERE p.source = 'external'
    """)).mappings().one())
    queue: Dict[str, Dict[str, int]] = {}
    for r in conn.execute(text("SELECT kind, status, count(*) AS n FROM jobs "
                               "WHERE status IN ('pending', 'running') GROUP BY 1, 2")).mappings():
        queue.setdefault(r["kind"], {"pending": 0, "running": 0})[r["status"]] = r["n"]
    external.update({s: (queue.get("ingest") or {}).get(s, 0) for s in ("pending", "running")})
    last_sync = conn.execute(text(
        "SELECT status, created_at, finished_at FROM jobs WHERE kind = 'sync_projects' "
        "ORDER BY created_at DESC LIMIT 1")).mappings().first()
    return {"main": main, "by_scan_mode": by_mode, "mrs": mrs, "external": external, "queue": queue,
            "last_projects_sync": dict(last_sync) if last_sync else None}


# ---------------------------------------------------------------------------------------------
# llm_progress (llm_progress_service.totals)
# ---------------------------------------------------------------------------------------------

LLM_STATES = ("current", "outdated", "never", "not_scanned", "failed")
LLM_JOB_STATES = ("queued", "running", "awaiting_answers")

LLM_RULES_SQL = text("""
    SELECT id, name, target, category, version FROM rules
    WHERE kind = 'llm' AND deleted_at IS NULL AND enabled IS NOT FALSE ORDER BY id
""")

LLM_KINDS = "j.kind IN ('llm_score', 'llm_prepare')"

LLM_STATE_SQL = """
WITH lr AS (SELECT id, version, """ + lifecycle.pinned_core_sql("rules") + """ AS pv FROM rules
            WHERE kind = 'llm' AND deleted_at IS NULL AND enabled IS NOT FALSE),
n AS (SELECT count(*) AS rules FROM lr),
br AS ({branches}),
cov AS (
    SELECT br.*, cv.*
    FROM br LEFT JOIN LATERAL (
        SELECT count(c.rule_id) AS n_rows,
               count(*) FILTER (WHERE c.commit = br.scanned_commit AND c.rule_version = lr.version
                                AND c.prompt_version = lr.pv AND c.answered >= c.candidates_total) AS rules_current,
               COALESCE(sum(c.answered), 0) AS answered, COALESCE(sum(c.candidates_total), 0) AS total,
               COALESCE(sum(c.answered_stale), 0) AS answered_stale,
               COALESCE(sum(c.pending_external), 0) AS pending_external, COALESCE(sum(c.failed), 0) AS failed_subjects,
               max(c.computed_at) AS computed_at
        FROM lr LEFT JOIN llm_coverage c ON c.branch_id = br.branch_id AND c.rule_id = lr.id) cv ON true
), st AS (
    SELECT cov.*,
           CASE WHEN cov.branch_id IS NULL OR cov.scanned_commit IS NULL THEN 'not_scanned'
                WHEN cov.rules_current = n.rules THEN 'current'
                WHEN lj.status = 'failed' THEN 'failed'
                WHEN cov.n_rows < n.rules THEN 'never'
                ELSE 'outdated' END AS state,
           CASE WHEN a.running THEN 'running' WHEN a.pending THEN 'queued'
                WHEN a.awaiting THEN 'awaiting_answers' END AS job,
           a.job_id, lj.id AS last_job_id, lj.status AS last_job_status, lj.finished_at AS last_job_at,
           CASE WHEN lj.status = 'failed' THEN lj.last_error END AS last_error
    FROM cov CROSS JOIN n
    LEFT JOIN LATERAL (
        SELECT bool_or(j.status = 'running') AS running, bool_or(j.status = 'pending') AS pending,
               bool_or(j.status = 'done') AS awaiting, min(j.id) AS job_id
        FROM jobs j WHERE """ + LLM_KINDS + """ AND j.payload ->> 'branch_id' = cov.branch_id::text
          AND (j.status IN ('pending', 'running')
               OR (j.status = 'done' AND j.progress ->> 'phase' = 'awaiting_answers'))) a ON true
    LEFT JOIN LATERAL (
        SELECT j.id, j.status, j.finished_at, j.last_error
        FROM jobs j WHERE """ + LLM_KINDS + """ AND j.payload ->> 'branch_id' = cov.branch_id::text
          AND j.status IN ('done', 'failed')
        ORDER BY j.id DESC LIMIT 1) lj ON true
)
"""

LLM_MAIN_BRANCHES = """
    SELECT p.id AS project_id, p.full_path AS project_path, p.source, g.id AS branch_id, g.branch_name, g.commit,
           g.scanned_commit
    FROM gitlab_projects p
    LEFT JOIN gitlab_branches g ON g.project_id = p.id AND g.is_main
    WHERE p.scan_mode = 'rules'{scope}
"""

LLM_MR_BRANCHES = f"""
    SELECT m.project_id, m.project_path, p.source, sb.id AS branch_id, sb.branch_name, m.source_branch_commit AS commit,
           sb.scanned_commit
    FROM gitlab_mrs m
    JOIN gitlab_projects p ON p.id = m.project_id AND p.scan_mode = 'rules'
    JOIN gitlab_branches sb ON sb.id = m.source_branch_id AND NOT sb.is_main
    WHERE m.state = 'opened' AND m.target_branch_id IS NOT NULL AND {DELTA_OWNER_COND}{{scope}}
"""


def _llm_totals() -> Dict[str, int]:
    return {**{s: 0 for s in LLM_STATES}, **{j: 0 for j in LLM_JOB_STATES}}


def _add_llm(totals: Dict[str, int], state: str, job: Optional[str], n: int) -> None:
    totals[state] += n
    if job:
        totals[job] += n


def _llm_rule_totals(conn, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = {r["rule_id"]: r for r in conn.execute(text("""
        SELECT c.rule_id, count(*) AS projects,
               count(*) FILTER (WHERE c.commit = g.scanned_commit AND c.rule_version = r.version
                                AND c.prompt_version = """ + lifecycle.pinned_core_sql("r") + """) AS fresh,
               count(*) FILTER (WHERE c.commit = g.scanned_commit AND c.rule_version = r.version
                                AND c.prompt_version = """ + lifecycle.pinned_core_sql("r") + """
                                AND c.answered >= c.candidates_total) AS current,
               sum(c.answered) AS answered, sum(c.candidates_total) AS total, sum(c.answered_stale) AS answered_stale,
               sum(c.pending_external) AS pending_external, sum(c.failed) AS failed, max(c.computed_at) AS computed_at
        FROM llm_coverage c
        JOIN rules r ON r.id = c.rule_id
        JOIN gitlab_branches g ON g.id = c.branch_id AND g.is_main AND g.scanned_commit IS NOT NULL
        JOIN gitlab_projects p ON p.id = g.project_id AND p.scan_mode = 'rules'
        WHERE c.rule_id = ANY(:ids)
        GROUP BY c.rule_id
    """), {"pv": LLM_PROMPTS_VERSION, "ids": [r["id"] for r in rules]}).mappings()} if rules else {}
    scanned = conn.execute(text("""
        SELECT count(*) FROM gitlab_projects p JOIN gitlab_branches g ON g.project_id = p.id AND g.is_main
        WHERE p.scan_mode = 'rules' AND g.scanned_commit IS NOT NULL""")).scalar()
    out = []
    for rule in rules:
        r = rows.get(rule["id"]) or {}
        answered, total = int(r.get("answered") or 0), int(r.get("total") or 0)
        out.append({
            "id": rule["id"], "name": rule["name"], "target": rule["target"], "version": rule["version"],
            "answered": answered, "total": total, "remaining": total - answered,
            "answered_stale": int(r.get("answered_stale") or 0),
            "pending_external": int(r.get("pending_external") or 0), "failed": int(r.get("failed") or 0),
            "projects": scanned, "projects_counted": int(r.get("projects") or 0),
            "projects_fresh": int(r.get("fresh") or 0), "projects_current": int(r.get("current") or 0),
            "computed_at": r.get("computed_at"),
        })
    return out


def llm_progress(conn) -> Dict[str, Any]:
    """= ``llm_progress_service.totals(session)``."""
    rules = [dict(r) for r in conn.execute(LLM_RULES_SQL).mappings()]
    main = {"projects": 0, **_llm_totals(), "answered": 0, "total": 0, "pending_external": 0, "failed_subjects": 0,
            "answered_stale": 0}
    for r in conn.execute(text(LLM_STATE_SQL.format(branches=LLM_MAIN_BRANCHES.format(scope="")) + """
            SELECT state, job, count(*) AS n, sum(answered) AS answered, sum(total) AS total,
                   sum(pending_external) AS pending_external, sum(failed_subjects) AS failed_subjects,
                   sum(answered_stale) AS answered_stale
            FROM st GROUP BY 1, 2"""), {"pv": LLM_PROMPTS_VERSION}).mappings():
        main["projects"] += r["n"]
        _add_llm(main, r["state"], r["job"], r["n"])
        for k in ("answered", "total", "pending_external", "failed_subjects", "answered_stale"):
            main[k] += int(r[k] or 0)
    mrs = {"open": 0, **_llm_totals()}
    sql = LLM_STATE_SQL.format(branches=LLM_MR_BRANCHES.format(scope=""))
    for r in conn.execute(text(sql + "SELECT project_id, state, job, count(*) AS n FROM st GROUP BY 1, 2, 3"),
                          {"pv": LLM_PROMPTS_VERSION}).mappings().all():
        mrs["open"] += r["n"]
        _add_llm(mrs, r["state"], r["job"], r["n"])
    queue: Dict[str, Dict[str, int]] = {}
    for r in conn.execute(text("SELECT kind, status, count(*) AS n FROM jobs WHERE kind IN "
                               "('llm_score', 'llm_prepare', 'llm_apply', 'llm_coverage') "
                               "AND status IN ('pending', 'running') GROUP BY 1, 2")).mappings():
        queue.setdefault(r["kind"], {"pending": 0, "running": 0})[r["status"]] = r["n"]
    last = conn.execute(text("SELECT max(computed_at) FROM llm_coverage")).scalar()
    return {"prompt_version": LLM_PROMPTS_VERSION, "rules": _llm_rule_totals(conn, rules), "main": main, "mrs": mrs,
            "queue": queue, "last_computed_at": last}


# ---------------------------------------------------------------------------------------------
# llm_quality (quality_service.llm_quality, every rule)
# ---------------------------------------------------------------------------------------------

QA_MIN_SAMPLES = 30
_AGREE = "v.verdict = v.service_verdict"
_SURE = "v.confidence = 'high' AND v.verdict IN ('match', 'no_match')"

QUALITY_VERIFY_SQL = text(f"""
    SELECT v.rule_id,
           count(*) FILTER (WHERE v.sample = 'qa' AND {_SURE}) AS samples,
           count(*) FILTER (WHERE v.sample = 'qa' AND {_SURE} AND {_AGREE}) AS agreed,
           count(*) FILTER (WHERE v.sample = 'qa' AND {_SURE} AND v.service_verdict = 'match') AS samples_match,
           count(*) FILTER (WHERE v.sample = 'qa' AND {_SURE} AND v.service_verdict = 'match' AND {_AGREE}) AS agreed_match,
           count(*) FILTER (WHERE v.sample = 'qa' AND {_SURE} AND v.service_verdict = 'no_match') AS samples_no_match,
           count(*) FILTER (WHERE v.sample = 'qa' AND {_SURE} AND v.service_verdict = 'no_match' AND {_AGREE})
               AS agreed_no_match,
           count(*) FILTER (WHERE v.sample = 'qa' AND {_SURE} AND v.created_at > now() - interval '7 days') AS samples_7d,
           count(*) FILTER (WHERE v.sample = 'qa' AND {_SURE} AND {_AGREE} AND v.created_at > now() - interval '7 days')
               AS agreed_7d,
           count(*) FILTER (WHERE v.sample = 'qa' AND {_SURE} AND v.created_at > now() - interval '30 days')
               AS samples_30d,
           count(*) FILTER (WHERE v.sample = 'qa' AND {_SURE} AND {_AGREE} AND v.created_at > now() - interval '30 days')
               AS agreed_30d,
           count(*) FILTER (WHERE v.sample = 'qa' AND NOT ({_SURE})) AS unsure,
           count(*) FILTER (WHERE v.sample = 'escalation' AND v.created_at > now() - interval '30 days')
               AS escalations_30d,
           count(*) FILTER (WHERE v.sample = 'escalation' AND v.outcome = 'final'
                            AND v.created_at > now() - interval '30 days') AS escalations_decided_30d,
           count(*) FILTER (WHERE v.outcome = 'asked_human' AND v.created_at > now() - interval '30 days')
               AS asked_human_30d,
           max(v.created_at) AS last_verified_at
    FROM llm_verifications v WHERE (CAST(:r AS int) IS NULL OR v.rule_id = :r)
    GROUP BY v.rule_id
""")

QUALITY_HITS_SQL = text("""
    SELECT h.rule_id,
           count(*) FILTER (WHERE h.decided_tier = 'service' AND h.reviewer IS NULL AND (h.field_name IS NULL) = (r.target = 'object'))
               AS service,
           count(*) FILTER (WHERE h.decided_tier = 'service' AND h.reviewer IS NULL AND h.status = 'need_more_info'
                            AND (h.field_name IS NULL) = (r.target = 'object')) AS service_unsure,
           count(*) FILTER (WHERE h.decided_tier = 'harness') AS harness_decisions,
           count(*) FILTER (WHERE h.asked_by_model AND h.status = 'need_more_info' AND h.reviewer IS NULL)
               AS questions_open,
           min(COALESCE(h.verified_at, h.reviewed_at, h.first_seen_at))
               FILTER (WHERE h.asked_by_model AND h.status = 'need_more_info' AND h.reviewer IS NULL)
               AS oldest_question_at
    FROM rule_hits h JOIN rules r ON r.id = h.rule_id
    WHERE r.kind = 'llm' AND (CAST(:r AS int) IS NULL OR h.rule_id = :r)
    GROUP BY h.rule_id
""")

QUALITY_BACKLOG_SQL = text("""
    SELECT rule_id, COALESCE(verify ->> 'sample', 'qa') AS sample, status, count(*) AS n
    FROM llm_work_items
    WHERE purpose = 'verify' AND status IN ('pending', 'leased', 'answered') AND (CAST(:r AS int) IS NULL OR rule_id = :r)
    GROUP BY 1, 2, 3
""")

ESCALATION_SAMPLE = "escalation"

QUALITY_RULES_SQL = text("""
    SELECT id, name, category, target, version, enabled FROM rules
    WHERE kind = 'llm' AND deleted_at IS NULL AND (CAST(:r AS int) IS NULL OR id = :r) ORDER BY id
""")


def quality_backlog(conn, rule_id: Optional[int] = None) -> Dict[str, Any]:
    """= ``quality_service.backlog``."""
    out: Dict[str, Any] = {"total": 0, "pending": 0, "leased": 0, "answered": 0, "by_sample": {}, "by_rule": {},
                           "by_rule_sample": {}}
    for r in conn.execute(QUALITY_BACKLOG_SQL, {"r": rule_id}).mappings():
        out["total"] += r["n"]
        out[r["status"]] += r["n"]
        out["by_sample"][r["sample"]] = out["by_sample"].get(r["sample"], 0) + r["n"]
        out["by_rule"][r["rule_id"]] = out["by_rule"].get(r["rule_id"], 0) + r["n"]
        key = (r["rule_id"], r["sample"])
        out["by_rule_sample"][key] = out["by_rule_sample"].get(key, 0) + r["n"]
    return out


def llm_quality(conn, agreement_min: float, rule_id: Optional[int] = None) -> Dict[str, Any]:
    """= ``quality_service.llm_quality(session, rule_id)`` with ``agreement_min`` = LLM_QA_AGREEMENT_MIN. A
    ``rule_id`` nobody has returns an empty ``rules`` list (the API raises 404 itself)."""
    now = conn.execute(text("SELECT now()")).scalar()
    rules = [dict(r) for r in conn.execute(QUALITY_RULES_SQL, {"r": rule_id}).mappings()]
    verified = {r["rule_id"]: dict(r) for r in conn.execute(QUALITY_VERIFY_SQL, {"r": rule_id}).mappings()}
    hits = {r["rule_id"]: dict(r) for r in conn.execute(QUALITY_HITS_SQL, {"r": rule_id}).mappings()}
    queue = quality_backlog(conn, rule_id)
    items, totals = [], {"samples": 0, "agreed": 0, "samples_30d": 0, "agreed_30d": 0, "questions_open": 0,
                         "harness_decisions": 0, "escalations_30d": 0, "needs_improvement": 0,
                         "oldest_question_s": None}
    for rule in rules:
        v, h = verified.get(rule["id"], {}), hits.get(rule["id"], {})
        get = lambda d, k: int(d.get(k) or 0)      # noqa: E731
        samples_30d, agreed_30d = get(v, "samples_30d"), get(v, "agreed_30d")
        agreement_30d = _share(agreed_30d, samples_30d)
        flagged = samples_30d >= QA_MIN_SAMPLES and agreement_30d is not None and agreement_30d < agreement_min
        oldest_question_s = _age_s(now, h.get("oldest_question_at"))
        item = {
            "rule_id": rule["id"], "rule_name": rule["name"], "category": rule["category"], "target": rule["target"],
            "version": rule["version"], "enabled": rule["enabled"] is not False,
            "qa": {
                "samples": get(v, "samples"), "agreement": _share(get(v, "agreed"), get(v, "samples")),
                "by_verdict": {
                    "match": {"samples": get(v, "samples_match"),
                              "agreement": _share(get(v, "agreed_match"), get(v, "samples_match"))},
                    "no_match": {"samples": get(v, "samples_no_match"),
                                 "agreement": _share(get(v, "agreed_no_match"), get(v, "samples_no_match"))},
                },
                "last_7d": {"samples": get(v, "samples_7d"), "agreement": _share(get(v, "agreed_7d"),
                                                                                 get(v, "samples_7d"))},
                "last_30d": {"samples": samples_30d, "agreement": agreement_30d},
                "unsure": get(v, "unsure"),
            },
            "escalation_rate": _share(get(h, "service_unsure"), get(h, "service")),
            "service_verdicts": get(h, "service"), "service_unsure": get(h, "service_unsure"),
            "escalations_30d": get(v, "escalations_30d"), "escalations_decided_30d": get(v, "escalations_decided_30d"),
            "asked_human_30d": get(v, "asked_human_30d"), "questions_open": get(h, "questions_open"),
            "oldest_question_s": oldest_question_s,
            "harness_decisions": get(h, "harness_decisions"), "backlog": queue["by_rule"].get(rule["id"], 0),
            "escalation_pending": queue["by_rule_sample"].get((rule["id"], ESCALATION_SAMPLE), 0),
            "last_verified_at": v.get("last_verified_at"),
            "needs_improvement": flagged,
            "health": "needs_improvement" if flagged else ("ok" if samples_30d >= QA_MIN_SAMPLES else "not_enough_samples"),
        }
        items.append(item)
        totals["samples"] += item["qa"]["samples"]
        totals["agreed"] += get(v, "agreed")
        totals["samples_30d"] += samples_30d
        totals["agreed_30d"] += agreed_30d
        for key in ("questions_open", "harness_decisions", "escalations_30d"):
            totals[key] += item[key]
        totals["needs_improvement"] += int(flagged)
        if oldest_question_s is not None and (totals["oldest_question_s"] is None
                                              or oldest_question_s > totals["oldest_question_s"]):
            totals["oldest_question_s"] = oldest_question_s
    totals["agreement"] = _share(totals.pop("agreed"), totals["samples"])
    totals["agreement_30d"] = _share(totals.pop("agreed_30d"), totals["samples_30d"])
    return {"agreement_min": agreement_min, "min_samples": QA_MIN_SAMPLES, "totals": totals, "backlog": {
        k: v for k, v in queue.items() if k not in ("by_rule", "by_rule_sample")}, "rules": items}


# ---------------------------------------------------------------------------------------------
# hits_aggregate (GET /hits/aggregate without filters)
# ---------------------------------------------------------------------------------------------

HITS_AGGREGATE_BY = ("status", "decided_tier", "asked_by_model", "in_main", "in_open_mr", "rule_id", "category",
                     "severity", "field_mark")

HITS_AGGREGATE_SQL = text("""
    SELECT h.status, h.decided_tier, COALESCE(h.asked_by_model, false) AS asked_by_model, h.in_main, h.in_open_mr,
           h.rule_id, h.category, h.severity,
           (h.field_name IS NOT NULL AND r.target = 'object') AS field_mark,
           count(*) AS n
    FROM rule_hits h JOIN rules r ON r.id = h.rule_id
    GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9
    ORDER BY n DESC
""")


def hits_aggregate(conn) -> Dict[str, Any]:
    """``{"by": HITS_AGGREGATE_BY, "rows": [{<dims>, "n"}]}``: one GROUP BY over the hits; the API sums the rows
    over the dimensions a client did not ask for (``GET /hits/aggregate?by=status,rule_id``)."""
    rows = [{**{k: r[k] for k in HITS_AGGREGATE_BY}, "n": int(r["n"])}
            for r in conn.execute(HITS_AGGREGATE_SQL).mappings()]
    return {"by": list(HITS_AGGREGATE_BY), "rows": rows}


COMPUTE = {
    "overview": overview,
    "job_health": job_health,
    "scan_progress": scan_progress,
    "llm_progress": llm_progress,
    "hits_aggregate": hits_aggregate,
    # llm_quality needs the agreement threshold: stats_service passes it
}
