"""The scanner's job queue (``jobs`` table, P2-4) for the UI / operators.

Same list conventions as the other resources (``services.paging``): whitelisted filters
(``id``, ``kind``, ``status``, ``q`` = substring of the dedup key or the last error) and
sort fields, ``total`` counts the filtered rows, newest first by default. Every job carries
``subject`` (project, branch, MR, rule names resolved from its payload; None for kinds without
one). Operators may ``retry_job`` a failed job and ``cancel_job`` a pending one; ``job_errors``
groups the failures of the last hours by kind and error text.
"""

from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from discovery_common import stats
from discovery_common.models import JOB_KINDS, JOB_STATUSES, LLM_EXECUTORS, PARSER_TYPES
from discovery_common.queries import DELTA_OWNER_COND
from services.errors import Conflict, Invalid, NotFound
from services.paging import ListParams, as_ints, as_list, escape_like

COLUMNS = ("j.id, j.kind, j.payload, j.dedup_key, j.status, j.attempts, j.max_attempts, j.run_after, j.locked_by, "
           "j.locked_at, j.last_error, j.created_at, j.updated_at, j.finished_at, j.progress")

# the subject of a job from its payload (branch_id / mr_id / project_id / rule_ids); payload values come from the
# scanner, the digit guards keep a stray value from breaking the cast
_INT = "CASE WHEN j.payload ->> '{key}' ~ '^[0-9]+$' THEN (j.payload ->> '{key}')::int END"
SUBJECT_SQL = f"""
    LEFT JOIN LATERAL (SELECT g.branch_name, g.project_id FROM gitlab_branches g
                       WHERE g.id = {_INT.format(key='branch_id')}) sb ON true
    LEFT JOIN LATERAL (SELECT m.mr_id AS mr_iid, m.source_branch, m.project_id FROM gitlab_mrs m
                       WHERE m.id = {_INT.format(key='mr_id')}) sm ON true
    LEFT JOIN gitlab_projects sp ON sp.id = COALESCE({_INT.format(key='project_id')}, sb.project_id, sm.project_id)
    LEFT JOIN LATERAL (SELECT array_agg(r.name ORDER BY r.id) AS names FROM rules r
                       WHERE jsonb_typeof(j.payload -> 'rule_ids') = 'array'
                         AND r.id IN (SELECT (e)::int FROM jsonb_array_elements_text(j.payload -> 'rule_ids') e
                                      WHERE e ~ '^[0-9]+$')) sr ON true
"""
SUBJECT_COLUMNS = ("sp.id AS s_project_id, sp.full_path AS s_project_path, "
                   "COALESCE(sb.branch_name, sm.source_branch) AS s_branch_name, sm.mr_iid AS s_mr_iid, "
                   "sr.names AS s_rule_names")
JOB_SQL = f"SELECT {COLUMNS}, {SUBJECT_COLUMNS} FROM jobs j{SUBJECT_SQL}"

SORTABLE = {
    "id": "j.id", "kind": "j.kind", "status": "j.status", "attempts": "j.attempts", "run_after": "j.run_after",
    "created_at": "j.created_at", "updated_at": "j.updated_at", "finished_at": "j.finished_at",
}


def _choices(name: str, values, allowed) -> List[str]:
    values = [str(v) for v in as_list(values)]
    unknown = sorted(set(values) - set(allowed))
    if unknown:
        raise Invalid(f"unknown {name}: {unknown}, expected one of {list(allowed)}")
    return values


def _conditions(filters: Dict[str, Any]) -> Tuple[List[str], Dict[str, Any]]:
    filters = dict(filters)
    where: List[str] = []
    binds: Dict[str, Any] = {}
    try:
        if "id" in filters:
            where.append("j.id = ANY(:ids)")
            binds["ids"] = [int(v) for v in as_list(filters.pop("id"))]
    except (TypeError, ValueError):
        raise Invalid("id must be integers") from None
    if "kind" in filters:
        where.append("j.kind = ANY(:kinds)")
        binds["kinds"] = _choices("kind", filters.pop("kind"), JOB_KINDS)
    if "status" in filters:
        where.append("j.status = ANY(:statuses)")
        binds["statuses"] = _choices("status", filters.pop("status"), JOB_STATUSES)
    if "q" in filters:
        where.append("(j.dedup_key ILIKE :q ESCAPE '\\' OR j.last_error ILIKE :q ESCAPE '\\')")
        binds["q"] = f"%{escape_like(str(filters.pop('q')))}%"
    if "project_id" in filters:
        ids = as_ints(filters.pop("project_id"), "project_id")
        if len(ids) != 1:
            raise Invalid("project_id: one project per jobs list")
        where.append(PROJECT_JOBS_COND)
        binds.update(project_job_binds(ids[0]))
    if filters:
        raise Invalid(f"unknown filters: {sorted(filters)}")
    return where, binds


# the jobs of one project (contract 7, the project page): by the project id in the payload (sync, parse requests),
# by one of its branches (scan_branch, LLM runs: ``jobs_scan_branch_subject`` / ``jobs_llm_branch_subject``) or one
# of its MRs (``jobs_scan_mr_subject``); the ids are matched as text, as the expression indexes store them
PROJECT_JOBS_COND = """(j.payload ->> 'project_id' = :pj_id
    OR (j.kind IN ('scan_branch', 'llm_score', 'llm_prepare') AND j.payload ->> 'branch_id' IN (
        SELECT g.id::text FROM gitlab_branches g WHERE g.project_id = :pj))
    OR (j.kind = 'scan_mr' AND j.payload ->> 'mr_id' IN (SELECT m.id::text FROM gitlab_mrs m WHERE m.project_id = :pj)))"""


def project_job_binds(project_id: int) -> Dict[str, Any]:
    return {"pj": int(project_id), "pj_id": str(int(project_id))}


def project_jobs(session: Session, project_id: int, limit: int = 20) -> List[dict]:
    """The last ``limit`` jobs of a project, newest first (``GET /projects/{id}``)."""
    rows = session.execute(text(f"{JOB_SQL} WHERE {PROJECT_JOBS_COND} ORDER BY j.id DESC LIMIT :limit"),
                           {**project_job_binds(project_id), "limit": max(1, min(int(limit), 200))}).mappings().all()
    return [_job_row(r) for r in rows]


def _job_row(row) -> dict:
    """A job dict with ``subject`` ({project_id, project_path, branch_name, mr_iid, rule_names}; None when the
    payload names nothing resolvable)."""
    data = dict(row)
    subject = {k: data.pop(f"s_{k}") for k in ("project_id", "project_path", "branch_name", "mr_iid", "rule_names")}
    data["subject"] = subject if any(v is not None for v in subject.values()) else None
    return data


def list_jobs(session: Session, params: ListParams) -> Tuple[List[dict], int]:
    where, binds = _conditions(params.filters)
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    if params.sort is not None and params.sort not in SORTABLE:
        raise Invalid(f"cannot sort by {params.sort!r}, allowed: {sorted(SORTABLE)}")
    if params.sort is None:
        order = "j.id DESC"
    else:
        order = f"{SORTABLE[params.sort]} {'DESC' if params.descending else 'ASC'} NULLS LAST, j.id DESC"
    total = session.execute(text(f"SELECT count(*) FROM jobs j{where_sql}"), binds).scalar()
    rows = session.execute(text(f"{JOB_SQL}{where_sql} ORDER BY {order} LIMIT :limit OFFSET :offset"),
                           {**binds, "limit": params.limit, "offset": params.offset}).mappings().all()
    return [_job_row(r) for r in rows], total


def get_job(session: Session, job_id: int) -> dict:
    row = session.execute(text(f"{JOB_SQL} WHERE j.id = :id"), {"id": job_id}).mappings().first()
    if row is None:
        raise NotFound(f"job {job_id} not found")
    return _job_row(row)


# ---- operator actions: retry a failed job, cancel a pending one ------------------------------

PREVIOUS_ERROR_MAX = 2000


def _job_for_update(session: Session, job_id: int):
    row = session.execute(text("SELECT id, kind, status, dedup_key, last_error FROM jobs WHERE id = :id FOR UPDATE"),
                          {"id": job_id}).mappings().first()
    if row is None:
        raise NotFound(f"job {job_id} not found")
    return row


def retry_job(session: Session, job_id: int) -> dict:
    """A failed job pending again (attempts 0, due now); its last error is kept in ``payload.previous_error``.
    409 for any other status, or when a job with the same dedup key is pending / running already."""
    row = _job_for_update(session, job_id)
    if row["status"] != "failed":
        raise Conflict(f"job {job_id} is {row['status']}: only a failed job can be retried")
    if row["dedup_key"] and session.execute(text(
            "SELECT 1 FROM jobs WHERE dedup_key = :k AND status IN ('pending', 'running') AND id <> :id"),
            {"k": row["dedup_key"], "id": job_id}).first():
        raise Conflict(f"job {job_id} cannot be retried: a job with the same dedup key is pending or running")
    session.execute(text("""
        UPDATE jobs SET status = 'pending', attempts = 0, run_after = now(), finished_at = NULL, locked_by = NULL,
               locked_at = NULL, updated_at = now(),
               payload = payload || CASE WHEN last_error IS NULL THEN '{}'::jsonb
                                         ELSE jsonb_build_object('previous_error', left(last_error, :max)) END,
               last_error = NULL
        WHERE id = :id"""), {"id": job_id, "max": PREVIOUS_ERROR_MAX})
    return get_job(session, job_id)


def cancel_job(session: Session, job_id: int, user: str) -> dict:
    """A pending job becomes failed (``last_error`` 'cancelled by <user>'); 409 for any other status."""
    row = _job_for_update(session, job_id)
    if row["status"] != "pending":
        raise Conflict(f"job {job_id} is {row['status']}: only a pending job can be cancelled")
    session.execute(text("""
        UPDATE jobs SET status = 'failed', last_error = :error, finished_at = now(), updated_at = now()
        WHERE id = :id"""), {"id": job_id, "error": f"cancelled by {user}"})
    return get_job(session, job_id)


# ---- top errors: failed jobs of the last hours grouped by kind and error text ----------------

ERROR_PREFIX_LEN = 160
ERROR_GROUP_JOBS = 50
ERRORS_HOURS_MAX = 24 * 30

# ids, uuids and hashes vary between failures of the same cause: normalised to '#' before grouping. The scanner puts
# the subject of a failure in single quotes (``scan of 'grp/proj', MR !25: cannot clone source branch 'x': ...``,
# see discovery_scanner/services/failures.py): quoted parts go first, then uuids, hex runs of 7+ characters (short
# commit ids, sha prefixes) and any digit run. The cause itself (git's line, the parser's / model's error) stays.
ERROR_PREFIX_SQL = f"""left(regexp_replace(regexp_replace(regexp_replace(regexp_replace(j.last_error,
        '''[^'']*''', '''#''', 'g'),
        '[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}', '#', 'gi'),
        '\\m[0-9a-f]{{7,}}\\M', '#', 'gi'),
        '[0-9]+', '#', 'g'), {ERROR_PREFIX_LEN})"""

ERRORS_SQL = text(f"""
    SELECT j.kind, {ERROR_PREFIX_SQL} AS error_prefix, count(*) AS n,
           min(j.finished_at) AS first_seen_at, max(j.finished_at) AS last_seen_at,
           (array_agg(j.id ORDER BY j.finished_at DESC, j.id DESC))[1:{ERROR_GROUP_JOBS}] AS job_ids
    FROM jobs j
    WHERE j.status = 'failed' AND j.last_error IS NOT NULL AND j.finished_at > now() - make_interval(hours => :hours)
    GROUP BY 1, 2 ORDER BY n DESC, last_seen_at DESC
""")


def job_errors(session: Session, hours: int = 24) -> Dict[str, Any]:
    """Failed jobs of the last ``hours`` grouped by kind and the first 160 characters of their error (quoted
    subjects, ids, uuids and hashes replaced by '#', so one cause on many projects / branches is one row):
    ``{hours, items: [{kind, error_prefix, count, first_seen_at, last_seen_at, sample_job_id, job_ids}]}``, the most
    frequent first; ``job_ids`` holds at most 50 (newest) ids."""
    try:
        hours = int(hours)
    except (TypeError, ValueError):
        raise Invalid("hours must be an integer") from None
    if not 1 <= hours <= ERRORS_HOURS_MAX:
        raise Invalid(f"hours must be between 1 and {ERRORS_HOURS_MAX}")
    items = [{"kind": r["kind"], "error_prefix": r["error_prefix"], "count": int(r["n"]),
              "first_seen_at": r["first_seen_at"], "last_seen_at": r["last_seen_at"],
              "sample_job_id": (r["job_ids"] or [None])[0], "job_ids": list(r["job_ids"] or [])}
             for r in session.execute(ERRORS_SQL, {"hours": hours}).mappings()]
    return {"hours": hours, "items": items}


def job_counts(session: Session) -> Dict[str, Dict[str, int]]:
    """``{kind: {status: count}}``."""
    result: Dict[str, Dict[str, int]] = {}
    for row in session.execute(text("SELECT kind, status, count(*) AS n FROM jobs GROUP BY kind, status")):
        result.setdefault(row.kind, {})[row.status] = row.n
    return result


# ---- queue health: is the pipeline keeping up? (UI "Pipeline health", MCP job_health) ----------

# kinds the scanner schedules for later (``run_after`` in the future, periodic): their pending age says nothing
# about the queue keeping up, so the totals' oldest pending job is taken over the other kinds only
SCHEDULED_KINDS = stats.SCHEDULED_KINDS


def _age_s(now, then) -> Optional[int]:
    return int((now - then).total_seconds()) if then is not None else None


def job_health(session: Session) -> Dict[str, Any]:
    """Read-only health of the scanner's job queue (``GET /jobs/health``, MCP ``job_health``): per kind the pending
    (and retrying: pending after a failed attempt), running and failed jobs, jobs finished / failed in the last hour
    and 24 hours, the age of the oldest pending job (from the moment it was due, jobs due in the future are
    ``scheduled`` = {count, next_run_in_s}) and of the longest running one, ``last_done_at``, the typical run and wait
    time of the last 24 hours (p50) and ``eta_s`` for the pending jobs at the rate of the last hour; the busy workers
    (``locked_by`` of the running jobs); and the throughput of the service LLM runs (objects processed in the last
    hour / 24 hours from ``jobs.progress``, the average size of a run) with an ETA for the pending runs at the current
    rate. ``totals.oldest_pending_*`` skips the kinds in SCHEDULED_KINDS (periodic work due later). No trend history
    is stored: the UI shows the current backlog and the oldest pending age instead. ``skipped_24h`` per kind and
    ``scans`` (``scan_branch`` / ``scan_mr``: ``full`` vs ``skipped`` in the last 24 hours): the scans the scanner's
    diff-based skip ended without a clone (``progress.skipped``, no parser file changed; README "Service mode",
    SCAN_DIFF_SKIP)."""
    return stats.job_health(session)


# ---- parse: scan projects again (after rule edits, with a parser subset) ---------------------

def _project_ids(session: Session, project_ids: Optional[List[int]]) -> Optional[List[int]]:
    """Validated project ids (None: every project)."""
    if project_ids is None:
        return None
    ids = sorted({int(p) for p in project_ids})
    if not ids:
        raise Invalid("project_ids is empty: omit it to use every project")
    found = {r[0] for r in session.execute(text("SELECT id FROM gitlab_projects WHERE id = ANY(:ids)"), {"ids": ids})}
    missing = sorted(set(ids) - found)
    if missing:
        raise NotFound(f"projects {missing} not found")
    return ids


def _parsers(session: Session, parsers: Optional[List[str]]) -> Optional[List[str]]:
    """Built-in parser types or external parser names that pushed a batch (POST /ingest)."""
    if parsers is None:
        return None
    names = sorted({str(p) for p in parsers})
    if not names:
        raise Invalid("parsers is empty: omit it to use the scanner's PARSERS")
    external = {r[0] for r in session.execute(text("SELECT DISTINCT parser FROM ingest_batches"))}
    unknown = sorted(set(names) - set(PARSER_TYPES) - external)
    if unknown:
        raise Invalid(f"unknown parsers {unknown}, expected some of {list(PARSER_TYPES) + sorted(external)}")
    return names


def request_parse(session: Session, project_ids: Optional[List[int]] = None, *, parsers: Optional[List[str]] = None,
                  mains: bool = True, mrs: bool = True, llm: bool = False, force: bool = False,
                  requested_by: Optional[str] = None) -> Dict[str, Any]:
    """Queue a parse of projects for the scanner's workers (``POST /projects/parse``): every
    project (``project_ids`` None) or the given ones.

    mains: ``scan_branch`` of each main branch at its known commit (clone + parsers + keyword
      rules). Skipped by the worker when a scan with the same rules and parsers exists
      (keyword rule edits change that marker); ``force`` parses again anyway.
    parsers: only these parsers (default: the scanner's PARSERS); only their objects in the
      snapshots / MR deltas are replaced, the other parsers' objects are kept.
    mrs: ``scan_mr`` of every open MR with tracked branches.
    llm: also the LLM rules (on the main snapshot after its parse, and on MR deltas). Off by
      default: run LLM rules over stored snapshots with ``POST /llm_rules/run``.

    Same dedup keys as the scanner's own jobs (plus the parser subset): a job already pending
    / running for the same subject is not queued twice (listed in ``already_queued``)."""
    from discovery_common import jobs

    if not (mains or mrs):
        raise Invalid("nothing to parse: set mains and / or mrs")
    ids = _project_ids(session, project_ids)
    parsers = _parsers(session, parsers)
    scope = "" if ids is None else " AND project_id = ANY(:ids)"
    binds = {} if ids is None else {"ids": ids}
    code_parsers = [p for p in parsers if p in PARSER_TYPES] if parsers else None    # built-in: GitLab projects
    suffix = (f":p={','.join(code_parsers)}" if code_parsers else "")

    meta = {"requested_by": requested_by} if requested_by else {}
    extra = {"parsers": code_parsers} if code_parsers else {}
    planned = []
    if mains:
        # external projects (POST /ingest): no clone; the latest state of each external parser is
        # applied again (edited keyword rules / inventory mode; skipped when unchanged unless force)
        gscope = "" if ids is None else " AND g.project_id = ANY(:ids)"
        for b in session.execute(text(f"""
                SELECT DISTINCT g.id AS branch_id, g.project_id, ib.parser FROM gitlab_branches g
                JOIN gitlab_projects p ON p.id = g.project_id AND p.source = 'external'
                JOIN ingest_batches ib ON ib.project_id = g.project_id AND ib.status IN ('committed', 'processed')
                WHERE g.is_main{gscope} ORDER BY 2, 3"""), binds).mappings():
            if parsers and b["parser"] not in parsers:
                continue
            planned.append(("ingest", {"project_id": b["project_id"], "branch_id": b["branch_id"], "parser": b["parser"],
                                       "force": force, "llm": llm, **meta},
                            f"ingest:{b['project_id']}:{b['parser']}:parse" + (":force" if force else "")))
        gitlab_mains = [] if parsers and not code_parsers else session.execute(text(
                f"SELECT g.id, g.commit FROM gitlab_branches g JOIN gitlab_projects p ON p.id = g.project_id "
                f"AND p.source = 'gitlab' WHERE g.is_main AND g.commit IS NOT NULL{gscope} "
                f"ORDER BY g.project_id, g.id"),
                binds).mappings()
        for b in gitlab_mains:
            planned.append(("scan_branch", {"branch_id": b["id"], "commit": b["commit"], "force": force, "llm": llm,
                                            **extra, **meta},
                            f"scan_branch:{b['id']}:{b['commit']}{suffix}" + (":force" if force else "")))
    if mrs and not (parsers and not code_parsers):
        for m in session.execute(text(f"""
                SELECT id, source_branch_commit, target_branch_commit FROM gitlab_mrs m
                WHERE state = 'opened' AND source_branch_id IS NOT NULL AND target_branch_id IS NOT NULL{scope}
                  AND {DELTA_OWNER_COND}
                ORDER BY project_id, id"""), binds).mappings():
            planned.append(("scan_mr", {"mr_id": m["id"], "source_commit": m["source_branch_commit"],
                                        "target_commit": m["target_branch_commit"], "llm": llm, **extra, **meta},
                            f"scan_mr:{m['id']}:{m['source_branch_commit']}:{m['target_branch_commit']}{suffix}"))

    queued, already = [], []
    for kind, payload, key in planned:
        job_id = jobs.enqueue(kind, payload, key, conn=session)
        if job_id is None:
            already.append(key)
        else:
            queued.append({"id": job_id, "kind": kind, "dedup_key": key})
    projects = ids if ids is not None else [r[0] for r in session.execute(text("SELECT id FROM gitlab_projects ORDER BY id"))]
    return {"project_ids": projects, "parsers": parsers, "queued": queued, "already_queued": already}


# ---- run LLM rules over projects already parsed ----------------------------------------------

def request_llm_rules_run(session: Session, rule_ids: List[int], *, project_ids: Optional[List[int]] = None,
                          mrs: bool = False, requested_by: Optional[str] = None,
                          executor: str = "service") -> Dict[str, Any]:
    """Queue LLM rules over stored snapshots (``POST /llm_rules/run``): the main branch of
    every project (``project_ids`` None) or of the given ones, and with ``mrs`` the deltas of
    their open MRs; one job per branch runs every given rule. Nothing is cloned or parsed
    again; only subjects without a verdict of a rule's current version go to the model.
    Projects in ``inventory`` mode are skipped (listed in ``skipped_inventory``).

    ``executor``: ``service`` (the scanner calls its LLM API) or ``external`` (the scanner only
    records the model calls as work items; a model outside the service answers them through
    ``llm_work_claim`` / ``llm_work_submit``, see ``discovery_common.llm_work``)."""
    from discovery_common import jobs

    if executor not in LLM_EXECUTORS:
        raise Invalid(f"executor must be one of {list(LLM_EXECUTORS)}")

    wanted = sorted({int(r) for r in rule_ids or []})
    if not wanted:
        raise Invalid("rule_ids is empty")
    rules = session.execute(text(
        "SELECT id, name, kind, version, enabled, deleted_at FROM rules WHERE id = ANY(:ids) ORDER BY id"),
        {"ids": wanted}).mappings().all()
    found = {r["id"]: r for r in rules if r["kind"] == "llm" and r["deleted_at"] is None}
    missing = [r for r in wanted if r not in found]
    if missing:
        raise NotFound(f"llm rules {missing} not found")
    disabled = [found[r]["name"] for r in wanted if found[r]["enabled"] is False]
    if disabled:
        raise Invalid(f"llm rules {disabled} are disabled: enable them first")

    ids = _project_ids(session, project_ids)
    scope = "" if ids is None else " AND p.id = ANY(:ids)"
    binds = {} if ids is None else {"ids": ids}
    skipped = [r[0] for r in session.execute(text(
        f"SELECT p.full_path FROM gitlab_projects p WHERE p.scan_mode = 'inventory'{scope} ORDER BY p.full_path"),
        binds)]

    targets = session.execute(text(f"""
        SELECT g.id AS branch_id, g.scanned_commit AS commit, NULL::int AS mr_id, p.full_path
        FROM gitlab_branches g JOIN gitlab_projects p ON p.id = g.project_id
        WHERE g.is_main AND g.scanned_commit IS NOT NULL AND p.scan_mode = 'rules'{scope}
        UNION ALL
        SELECT m.source_branch_id, m.source_branch_commit, m.id, p.full_path
        FROM gitlab_mrs m JOIN gitlab_projects p ON p.id = m.project_id
        WHERE :mrs AND m.state = 'opened' AND m.source_branch_id IS NOT NULL AND p.scan_mode = 'rules'{scope}
          AND EXISTS (SELECT 1 FROM branch_objects b WHERE b.branch_id = m.source_branch_id AND NOT b.is_main)
          AND {DELTA_OWNER_COND}
        ORDER BY 4, 3 NULLS FIRST
    """), {**binds, "mrs": bool(mrs)}).mappings().all()

    versions = "+".join(f"{r}:v{found[r]['version']}" for r in wanted)
    meta = {"requested_by": requested_by} if requested_by else {}
    if executor != "service":
        meta["executor"] = executor
    prefix = "llm_rule:" if executor == "service" else f"llm_rule:{executor}:"
    # external: the prepare calls no model, the scanner's control worker runs it (llm_prepare)
    kind = "llm_score" if executor == "service" else "llm_prepare"
    queued, already = [], []
    for t in targets:
        payload = {"branch_id": t["branch_id"], "commit": t["commit"], "rule_ids": wanted, **meta}
        if t["mr_id"] is not None:
            payload["mr_id"] = t["mr_id"]
        key = f"{prefix}{versions}:{t['branch_id']}:{t['commit']}"
        job_id = jobs.enqueue(kind, payload, key, conn=session)
        if job_id is None:
            already.append(key)
        else:
            queued.append({"id": job_id, "kind": kind, "project_path": t["full_path"], "branch_id": t["branch_id"],
                           "mr_id": t["mr_id"], "dedup_key": key})
    return {"rules": [{"id": r, "name": found[r]["name"], "version": found[r]["version"]} for r in wanted],
            "executor": executor, "queued": queued, "already_queued": already, "skipped_inventory": skipped}


# ---- progress of LLM rule runs (dashboard, external executor) --------------------------------

ERROR_TEXT_MAX = 1000

RUNS_SQL = """
    SELECT j.id, j.kind, j.status, j.payload, j.progress, j.attempts, j.created_at, j.finished_at, j.last_error,
           g.branch_name, g.is_main, p.id AS project_id, p.full_path AS project_path
    FROM jobs j
    LEFT JOIN gitlab_branches g ON g.id = (j.payload->>'branch_id')::int
    LEFT JOIN gitlab_projects p ON p.id = g.project_id
    WHERE j.kind IN ('llm_score', 'llm_prepare', 'llm_trial', 'llm_verify') AND {where}
    ORDER BY j.id DESC LIMIT :limit
"""

ACTIVE_RUN = "(j.status IN ('pending', 'running') OR j.progress->>'phase' = 'awaiting_answers')"


def _run_row(row, rule_names: Dict[int, str]) -> Dict[str, Any]:
    payload, progress = row["payload"] or {}, row["progress"] or {}
    rule_ids = payload.get("rule_ids") or []
    status = row["status"]
    if status == "done" and progress.get("phase") == "awaiting_answers":
        status = "awaiting_answers"
    counts = {k: progress.get(k) for k in ("total_objects", "done_objects", "failed_objects", "expired_objects",
                                           "pending_objects", "leased_objects", "answered_objects",
                                           "skipped_objects")
              if progress.get(k) is not None}
    return {
        "id": row["id"], "kind": row["kind"], "status": status, "job_status": row["status"],
        "executor": payload.get("executor") or "service", "phase": progress.get("phase"),
        "rules": [{"id": r, "name": rule_names.get(r)} for r in rule_ids] if rule_ids else None,
        "project_id": row["project_id"], "project_path": row["project_path"], "branch_id": payload.get("branch_id"),
        "branch_name": row["branch_name"], "mr_id": payload.get("mr_id"), "requested_by": payload.get("requested_by"),
        "taken_over_by": payload.get("taken_over_by"), "released_from": payload.get("released_from"),
        "trial_id": payload.get("trial_id"), "purpose": "verify" if row["kind"] == "llm_verify" else (
            "trial" if row["kind"] == "llm_trial" else "score"),
        **counts,
        "started_at": progress.get("started_at"), "created_at": row["created_at"],
        "finished_at": progress.get("finished_at") or row["finished_at"],
        "attempts": row["attempts"], "last_error": (row["last_error"] or "")[:ERROR_TEXT_MAX] or None,
        # why objects failed: the summary of an incomplete run and the bounded per-object log (progress.errors:
        # {total, items: [{rule, object, object_key, error}], by_class: [{rule, error_class, count}]})
        "error": (progress.get("error") or "")[:ERROR_TEXT_MAX] or None,
        "errors": progress.get("errors") or None,
    }


def _runs(session: Session, where: str, binds: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = [dict(r) for r in session.execute(text(RUNS_SQL.format(where=where)), binds).mappings()]
    ids = sorted({int(r) for row in rows for r in ((row["payload"] or {}).get("rule_ids") or [])})
    names = dict(session.execute(text("SELECT id, name FROM rules WHERE id = ANY(:ids)"), {"ids": ids}).all()) \
        if ids else {}
    return [_run_row(row, names) for row in rows]


def llm_runs(session: Session, limit: int = 20, recent_hours: int = 24) -> Dict[str, Any]:
    """LLM rule runs for the dashboard: active ones (queued, running, or external runs waiting
    for answers) with their progress, and the ones finished in the last ``recent_hours``. Prompt trials
    (``llm_trial`` jobs, ``trial_id`` set) are listed too: they call the service model; so are the verify jobs of
    the tiered workflow (``llm_verify``, purpose verify: items for the harness model)."""
    limit = max(1, min(int(limit), 100))
    active = _runs(session, ACTIVE_RUN, {"limit": limit})
    recent = _runs(session, f"NOT {ACTIVE_RUN} AND j.finished_at > now() - make_interval(hours => :hours)",
                   {"limit": limit, "hours": int(recent_hours)})
    return {"active": active, "recent": recent}


def llm_work_jobs(session: Session, active_only: bool = True, limit: int = 20) -> List[Dict[str, Any]]:
    """External LLM runs (``executor = external``) with their progress, newest first; verify jobs of the tiered
    workflow (``purpose`` verify) too."""
    limit = max(1, min(int(limit), 100))
    where = "j.kind <> 'llm_trial' AND j.payload->>'executor' = 'external'" + (f" AND {ACTIVE_RUN}" if active_only else "")
    return _runs(session, where, {"limit": limit})


# ---- harness work: work items by purpose / status / sample, leases and answers by owner ------

WORK_STATUS_SQL = text("""
    SELECT purpose, status, count(*) AS n, min(created_at) FILTER (WHERE status = 'pending') AS oldest_pending_at
    FROM llm_work_items GROUP BY purpose, status
""")

WORK_SAMPLE_SQL = text("""
    SELECT COALESCE(verify ->> 'sample', 'qa') AS sample, status, count(*) AS n
    FROM llm_work_items WHERE purpose = 'verify' AND status IN ('pending', 'leased', 'answered') GROUP BY 1, 2
""")

WORK_LEASES_SQL = text("""
    SELECT lease_owner AS owner, purpose, count(*) AS leased,
           count(*) FILTER (WHERE lease_until < now()) AS expired, min(lease_until) AS lease_until_min,
           max(lease_until) AS lease_until_max, array_agg(DISTINCT job_id) AS job_ids
    FROM llm_work_items WHERE status = 'leased' GROUP BY 1, 2 ORDER BY 1, 2
""")

WORK_ANSWERS_SQL = text("""
    SELECT answered_by AS owner, purpose,
           count(*) AS answered_24h,
           count(*) FILTER (WHERE answered_at > now() - interval '1 hour') AS answered_1h,
           count(*) FILTER (WHERE status = 'failed') AS failed_24h,
           max(answered_at) AS last_answer_at,
           array_remove(array_agg(DISTINCT answer_model), NULL) AS models
    FROM llm_work_items WHERE answered_at > now() - interval '24 hours' AND answered_by IS NOT NULL
    GROUP BY 1, 2 ORDER BY 1, 2
""")


def llm_work_stats(session: Session) -> Dict[str, Any]:
    """Read-only view of the harness work (``GET /llm_work/stats``): work items by purpose (``score``: calls of
    external LLM runs, ``verify``: the tiered workflow's checks for the harness model) and status with the age of
    the oldest pending one; the open verify items by sample (escalation / qa / reverify / manual); the leases held
    now by owner (who claimed, how many, until when, how many leases ran out); and the answers of the last 24 hours
    by owner (throughput of each harness, the models it answered with). Finished items are deleted by the cleanup
    after their retention, so the figures cover the recent work only."""
    now = session.execute(text("SELECT now()")).scalar()
    by_purpose: Dict[str, Dict[str, Any]] = {}
    for p in ("score", "verify"):
        by_purpose[p] = {s: 0 for s in ("pending", "leased", "answered", "applied", "failed", "expired")}
        by_purpose[p].update({"open": 0, "oldest_pending_s": None})
    for r in session.execute(WORK_STATUS_SQL).mappings():
        item = by_purpose.setdefault(r["purpose"], {})
        item[r["status"]] = int(r["n"])
        if r["status"] in ("pending", "leased", "answered"):
            item["open"] = item.get("open", 0) + int(r["n"])
        if r["oldest_pending_at"] is not None:
            item["oldest_pending_s"] = _age_s(now, r["oldest_pending_at"])
    by_sample: Dict[str, Dict[str, int]] = {}
    for r in session.execute(WORK_SAMPLE_SQL).mappings():
        entry = by_sample.setdefault(r["sample"], {"pending": 0, "leased": 0, "answered": 0, "total": 0})
        entry[r["status"]] += int(r["n"])
        entry["total"] += int(r["n"])
    leases = [{"owner": r["owner"], "purpose": r["purpose"], "leased": int(r["leased"]), "expired": int(r["expired"]),
               "lease_until_min": r["lease_until_min"], "lease_until_max": r["lease_until_max"],
               "job_ids": sorted(r["job_ids"] or [])} for r in session.execute(WORK_LEASES_SQL).mappings()]
    owners = [{"owner": r["owner"], "purpose": r["purpose"], "answered_24h": int(r["answered_24h"]),
               "answered_1h": int(r["answered_1h"]), "failed_24h": int(r["failed_24h"]),
               "last_answer_at": r["last_answer_at"], "models": sorted(r["models"] or [])}
              for r in session.execute(WORK_ANSWERS_SQL).mappings()]
    return {"now": now, "by_purpose": by_purpose, "verify_by_sample": by_sample, "leases": leases,
            "owners_24h": owners, "awaiting_apply": by_purpose.get("score", {}).get("answered", 0)}



# ---- external executor: work items -----------------------------------------------------------

def _work(fn, *args, **kwargs):
    from discovery_common import llm_work
    try:
        return fn(*args, **kwargs)
    except llm_work.WorkError as e:
        raise Invalid(str(e)) from None


def llm_take_over(session: Session, user: str, *, job_id: Optional[int] = None, limit: int = 1) -> Dict[str, Any]:
    """Take over PENDING service LLM runs (``llm_score`` jobs the scanner's LLM workers have not
    started): they become external runs with the same job ids (``discovery_common.llm_work.take_over``).
    ``job_id``: that job only (a Conflict when it is not a pending service run, e.g. running already)."""
    from discovery_common import llm_work
    taken = _work(llm_work.take_over, session, user, job_id=job_id, limit=limit)
    if job_id is not None and not taken:
        row = session.execute(text("SELECT kind, status, payload->>'executor' AS executor FROM jobs WHERE id = :id"),
                              {"id": job_id}).first()
        if row is None:
            raise NotFound(f"job {job_id} not found")
        raise Conflict(f"job {job_id} cannot be taken over: only a pending service llm_score job can "
                       f"(it is {row.kind}, {row.status}" + (f", executor {row.executor}" if row.executor else "") + ")")
    return {"taken_over": _runs(session, "j.id = ANY(:ids)", {"ids": taken, "limit": len(taken) or 1}) if taken else [],
            "retry_after_s": llm_work.TAKE_OVER_RETRY_S if taken else None,
            "note": "the scanner's control worker prepares the work items of these runs: claim them with "
                    "llm_work_claim(job_id) in a few seconds" if taken else "no pending service LLM run to take over"}


def llm_work_claim(session: Session, owner: str, *, job_id: Optional[int] = None, limit: int = 3,
                   lease_seconds: int = 300, take_over_pending: bool = False, purpose: str = "score") -> Dict[str, Any]:
    """``take_over_pending``: when nothing is claimable (in ``job_id``, else anywhere), take over the
    pending service run ``job_id`` (else the oldest one) and say when to claim again: the prepare is
    asynchronous (``taken_over``: job ids, ``retry_after_s``). ``purpose``: score (default) | verify
    (the tiered workflow's verify items, ``discovery_common.llm_verify``; no take over)."""
    from discovery_common import llm_work
    result = _work(llm_work.claim, session, owner, job_id=job_id, limit=limit, lease_seconds=lease_seconds,
                   purpose=purpose)
    if take_over_pending and purpose == "score" and not result["items"]:
        taken = _work(llm_work.take_over, session, owner, job_id=job_id, limit=1)
        result["taken_over"] = taken
        result["retry_after_s"] = llm_work.TAKE_OVER_RETRY_S if taken else None
    return result


def llm_work_submit(session: Session, owner: str, items: List[Dict[str, Any]], *, lease: Optional[str] = None,
                    via: str = "mcp") -> Dict[str, Any]:
    from discovery_common import llm_work
    return _work(llm_work.submit, session, owner, items, lease=lease, via=via)


def llm_work_release(session: Session, owner: str, ids: Optional[List[int]] = None, lease: Optional[str] = None, *,
                     job_id: Optional[int] = None, all_unanswered: bool = False) -> Dict[str, Any]:
    """Give claimed items back (``ids`` + ``lease``: pending again), or with ``job_id`` and
    ``all_unanswered`` everything unanswered of that external run back to the service
    (``discovery_common.llm_work.release_run``: items expire, a service run is queued)."""
    from discovery_common import llm_work
    if all_unanswered:
        if job_id is None:
            raise Invalid("all_unanswered needs job_id (the external run to give back)")
        if ids:
            raise Invalid("give either ids + lease or job_id + all_unanswered")
        return _work(llm_work.release_run, session, owner, job_id)
    return _work(llm_work.release, session, owner, ids, lease)


# ---- last errors of one LLM rule (rule studio, Runs tab) --------------------------------------

RULE_ERRORS_HOURS = 24 * 7
RULE_ERRORS_LIMIT = 50
LLM_RUN_KINDS = "('llm_score', 'llm_prepare')"
_ERROR_ITEMS = ("CASE WHEN jsonb_typeof(j.progress -> 'errors' -> 'items') = 'array' "
                "THEN j.progress -> 'errors' -> 'items' ELSE '[]'::jsonb END")
_ERROR_CLASSES = ("CASE WHEN jsonb_typeof(j.progress -> 'errors' -> 'by_class') = 'array' "
                  "THEN j.progress -> 'errors' -> 'by_class' ELSE '[]'::jsonb END")

# per-object failures recorded by the scanner in progress.errors.items (service runs, refused harness answers)
RULE_ERROR_ITEMS_SQL = text(f"""
    SELECT j.id AS job_id, j.kind, j.status, j.progress ->> 'phase' AS phase,
           COALESCE(j.finished_at, j.updated_at) AS at, e
    FROM jobs j CROSS JOIN LATERAL jsonb_array_elements({_ERROR_ITEMS}) e
    WHERE j.kind IN {LLM_RUN_KINDS} AND e ->> 'rule_id' = :rid
      AND COALESCE(j.finished_at, j.updated_at) > now() - make_interval(hours => :hours)
    ORDER BY j.id DESC, (e ->> 'object') LIMIT :limit
""")

RULE_ERROR_CLASSES_SQL = text(f"""
    SELECT c ->> 'error_class' AS error_class, sum((c ->> 'count')::int) AS n, count(DISTINCT j.id) AS jobs,
           max(j.id) AS last_job_id
    FROM jobs j CROSS JOIN LATERAL jsonb_array_elements({_ERROR_CLASSES}) c
    WHERE j.kind IN {LLM_RUN_KINDS} AND c ->> 'rule_id' = :rid
      AND COALESCE(j.finished_at, j.updated_at) > now() - make_interval(hours => :hours)
    GROUP BY 1 ORDER BY n DESC, 1
""")

# runs of the rule that ended failed (their last_error carries the per-rule summary) or incomplete
RULE_ERROR_RUNS_SQL = text(f"""
    SELECT j.id, j.kind, j.status, j.attempts, j.finished_at, j.last_error, j.progress ->> 'phase' AS phase,
           j.progress ->> 'error' AS error,
           CASE WHEN j.progress ->> 'failed_objects' ~ '^[0-9]+$' THEN (j.progress ->> 'failed_objects')::int END AS failed_objects,
           CASE WHEN j.progress ->> 'total_objects' ~ '^[0-9]+$' THEN (j.progress ->> 'total_objects')::int END AS total_objects,
           g.branch_name, p.id AS project_id, p.full_path AS project_path, j.payload ->> 'mr_id' AS mr_id
    FROM jobs j
    LEFT JOIN gitlab_branches g ON g.id = CASE WHEN j.payload ->> 'branch_id' ~ '^[0-9]+$'
                                               THEN (j.payload ->> 'branch_id')::int END
    LEFT JOIN gitlab_projects p ON p.id = g.project_id
    WHERE j.kind IN {LLM_RUN_KINDS}
      AND (j.status = 'failed' OR j.progress ->> 'phase' = 'incomplete')
      AND (j.payload -> 'rule_ids' @> CAST(:rid_json AS jsonb)
           OR (j.payload -> 'rule_ids' IS NULL AND (j.last_error LIKE :name_like OR j.progress ->> 'error' LIKE :name_like))
           OR EXISTS (SELECT 1 FROM jsonb_array_elements({_ERROR_ITEMS}) e WHERE e ->> 'rule_id' = :rid))
      AND COALESCE(j.finished_at, j.updated_at) > now() - make_interval(hours => :hours)
    ORDER BY j.id DESC LIMIT :limit
""")

# answers of a harness model the apply refused (llm_work_items.error), newest first
RULE_WORK_FAILURES_SQL = text("""
    SELECT w.id, w.job_id, w.object_key, w.field_name, w.purpose, w.error, w.updated_at, w.answered_by, w.answer_model,
           (SELECT o.name FROM objects o WHERE o.object_key::text = w.object_key::text LIMIT 1) AS object_name
    FROM llm_work_items w
    WHERE w.rule_id = :rid_int AND w.status = 'failed' AND w.updated_at > now() - make_interval(hours => :hours)
    ORDER BY w.updated_at DESC, w.id DESC LIMIT :limit
""")


def rule_errors(session: Session, rule_id: int, hours: int = RULE_ERRORS_HOURS,
                limit: int = RULE_ERRORS_LIMIT) -> Dict[str, Any]:
    """Why evaluations of one LLM rule failed lately (``GET /llm_rules/{id}/errors``): ``items`` (the failed
    objects with their error and the job, from ``jobs.progress.errors`` of service runs and of external runs whose
    answers were refused), ``by_class`` (counts per error class), ``runs`` (jobs of the rule that ended failed or
    incomplete, with ``last_error`` / the progress summary) and ``work_items`` (failed harness work items of the
    rule with their error). 404 for an unknown rule."""
    try:
        hours, limit = int(hours), int(limit)
    except (TypeError, ValueError):
        raise Invalid("hours and limit must be integers") from None
    if not 1 <= hours <= ERRORS_HOURS_MAX:
        raise Invalid(f"hours must be between 1 and {ERRORS_HOURS_MAX}")
    limit = max(1, min(limit, 200))
    rule = session.execute(text("SELECT id, name, kind FROM rules WHERE id = :id"), {"id": rule_id}).mappings().first()
    if rule is None or rule["kind"] != "llm":
        raise NotFound(f"llm rule {rule_id} not found")
    rid = str(int(rule_id))
    binds = {"rid": rid, "rid_int": int(rule_id), "hours": hours, "limit": limit}
    items = []
    for r in session.execute(RULE_ERROR_ITEMS_SQL, binds).mappings():
        e = r["e"] or {}
        items.append({"job_id": r["job_id"], "job_kind": r["kind"], "job_status": r["status"], "phase": r["phase"],
                      "at": r["at"], "object": e.get("object"), "object_key": e.get("object_key"),
                      "field": e.get("field"), "where": e.get("where"), "error": (e.get("error") or "")[:ERROR_TEXT_MAX]})
    by_class = [{"error_class": r["error_class"], "count": int(r["n"]), "jobs": int(r["jobs"]),
                 "last_job_id": r["last_job_id"]} for r in session.execute(RULE_ERROR_CLASSES_SQL, binds).mappings()]
    runs = [{"id": r["id"], "kind": r["kind"], "status": r["status"], "phase": r["phase"], "attempts": r["attempts"],
             "finished_at": r["finished_at"], "last_error": (r["last_error"] or "")[:ERROR_TEXT_MAX] or None,
             "error": (r["error"] or "")[:ERROR_TEXT_MAX] or None, "failed_objects": r["failed_objects"],
             "total_objects": r["total_objects"], "project_id": r["project_id"], "project_path": r["project_path"],
             "branch_name": r["branch_name"], "mr_id": r["mr_id"]}
            for r in session.execute(RULE_ERROR_RUNS_SQL, {
                **binds, "rid_json": f"[{rid}]", "name_like": f"%LLM rule '{rule['name']}'%"}).mappings()]
    work_items = [{"id": r["id"], "job_id": r["job_id"], "object": r["object_name"], "object_key": r["object_key"],
                   "field": r["field_name"], "purpose": r["purpose"], "error": (r["error"] or "")[:ERROR_TEXT_MAX] or None,
                   "at": r["updated_at"], "answered_by": r["answered_by"], "model": r["answer_model"]}
                  for r in session.execute(RULE_WORK_FAILURES_SQL, binds).mappings()]
    return {"rule_id": int(rule_id), "rule_name": rule["name"], "hours": hours,
            "total": sum(c["count"] for c in by_class), "by_class": by_class, "items": items, "runs": runs,
            "work_items": work_items}
