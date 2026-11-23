"""Progress of the parse scans (``GET /scan_progress``, MCP ``scan_progress``): of the projects
the service tracks, how many were re-read from GitLab and scanned at their current commit, how
many wait in the queue. Computed from the database only (no GitLab calls).

Tracked projects: ``gitlab_projects`` with ``source = 'gitlab'`` (the scanner's GitLab sync
keeps them; it cannot tell the API which prefixes are configured now, so projects of a prefix
removed from GITLAB_PROJECTS_PREFIX stay until deleted). External (``POST /ingest``) projects
are never cloned: they are counted apart (``external``).

Main branch of a project, ``state`` (exactly one, in this order):

* ``no_main``        no main branch row yet (never synced, empty repository, no default branch);
* ``current``        ``scanned_commit = commit``: the snapshot is the branch head (complete scan);
* ``failed``         the latest finished ``scan_branch`` job of the branch failed (attempts used up);
* ``partial``        a partial scan marker (``+partial``: a parser failed) at the head commit;
* ``skipped``        the latest finished full ``scan_branch`` job of the head commit is done, but
                     nothing was saved (SCAN_LANGS gate, the branch stopped being main);
* ``never_scanned``  no snapshot yet;
* ``outdated``       a snapshot of an older commit.

``job`` (orthogonal): ``running`` / ``queued`` when a ``scan_branch`` job of the branch is
running / pending (``retrying``: pending again after a failed attempt). ``synced``: the
project's branches and MRs were re-read for its latest known GitLab activity
(``processed_at >= updated_at``, set by ``sync_branches_mrs``); ``sync_job`` likewise.

Open MRs (``state = 'opened'``): ``not_tracked`` (no tracked source / target branch, the
source is a main branch, or another open MR of the same source branch owns its delta),
``current`` (source branch ``scanned_commit`` = the MR's source commit), ``failed``,
``partial`` (the latest finished ``scan_mr`` job of the source commit is done without a
complete delta: a parser failed or SCAN_LANGS), ``never_scanned``, ``outdated``; ``job`` from
``scan_mr`` jobs. The scanner queues MR scans only for MRs with activity in the last day: the
totals count those apart (``active_24h``, ``active_scanned``, ``active_waiting``,
``oldest_waiting_s``; ``MR_ACTIVE_COND``) - the MR figures that say whether the scanner keeps up.

Jobs are matched by ``payload->>'branch_id'`` / ``'mr_id'`` (indexes of migration 0015, one
lookup per branch / MR; finished jobs are purged after JOBS_RETENTION_DAYS), the branch / MR sync
job by its dedup key, the partial markers by the ``uq_scan`` index.
"""

from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from discovery_common import stats
from discovery_common.models import SCAN_MODES
from services.errors import Invalid
from services.paging import as_ints, as_list, escape_like

MAIN_STATES, MR_STATES = stats.MAIN_STATES, stats.MR_STATES
JOB_STATES = ("queued", "running")
# status filter of the project list: a state, a job state, or one of these
EXTRA_FILTERS = ("not_synced", "active", "attention")      # active: queued | running; attention: failed | partial
LIST_MAX = 500
ERROR_MAX = 300

# ``{scope}``: extra conditions on gitlab_projects p (the per-project rows of GET /scan_progress); the statements are
# those of the ``scan_progress`` snapshot (``discovery_common.stats``): see there for the lookups they rely on
MAINS_SQL, MR_ACTIVE_COND, MRS_SQL = stats.MAINS_SQL, stats.MR_ACTIVE_COND, stats.MRS_SQL

STATE_RANK = "CASE state " + " ".join(
    f"WHEN '{s}' THEN {i}" for i, s in enumerate(("failed", "partial", "skipped", "never_scanned", "outdated",
                                                  "no_main", "current"))) + " END"


# the totals helpers of ``discovery_common.stats`` (the per-project rows below reuse them)
_main_totals, _mr_totals, _add_active, _add = stats._main_totals, stats._mr_totals, stats._add_active, stats._add_scan


def _scope(project_ids: Optional[List[int]], alias: str = "p") -> str:
    return "" if project_ids is None else f" AND {alias}.id = ANY(:ids)"


def _mr_rows(session: Session, project_ids: Optional[List[int]]):
    binds = {} if project_ids is None else {"ids": project_ids}
    return session.execute(text(MRS_SQL.format(scope=_scope(project_ids))), binds).mappings().all()


def totals(session: Session) -> Dict[str, Any]:
    """The totals of ``GET /scan_progress`` = the ``scan_progress`` statistics snapshot (``discovery_common.stats``,
    one copy of the SQL for the scanner's ``stats_refresh`` job and the API's live fallback)."""
    return stats.scan_progress(session)


def _list_conditions(status, scan_mode, q, project_ids) -> tuple:
    where, binds = [], {}
    statuses = [str(s) for s in as_list(status)] if status not in (None, "") else []
    allowed = MAIN_STATES + JOB_STATES + EXTRA_FILTERS
    unknown = sorted(set(statuses) - set(allowed))
    if unknown:
        raise Invalid(f"unknown status {unknown}, expected some of {list(allowed)}")
    if statuses:
        parts = []
        states = [s for s in statuses if s in MAIN_STATES] + (["failed", "partial"] if "attention" in statuses else [])
        jobs = [s for s in statuses if s in JOB_STATES] + (list(JOB_STATES) if "active" in statuses else [])
        if states:
            parts.append("state = ANY(:states)")
            binds["states"] = sorted(set(states))
        if jobs:
            parts.append("job = ANY(:jobs)")
            binds["jobs"] = sorted(set(jobs))
        if "not_synced" in statuses:
            parts.append("NOT synced")
        where.append("(" + " OR ".join(parts) + ")")
    if scan_mode not in (None, ""):
        modes = [str(m) for m in as_list(scan_mode)]
        if set(modes) - set(SCAN_MODES):
            raise Invalid(f"scan_mode must be some of {list(SCAN_MODES)}")
        where.append("scan_mode = ANY(:modes)")
        binds["modes"] = modes
    if q:
        where.append("project_path ILIKE :q ESCAPE '\\'")
        binds["q"] = f"%{escape_like(str(q))}%"
    return where, binds


def project_rows(session: Session, *, status=None, scan_mode=None, q: Optional[str] = None,
                 project_ids: Optional[List[int]] = None, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    """Per project: its main branch state (see the module doc), job, sync and its open MRs."""
    ids = as_ints(project_ids, "project_ids") if project_ids not in (None, "", []) else None
    where, binds = _list_conditions(status, scan_mode, q, ids)
    if ids is not None:
        binds["ids"] = ids
    limit, offset = max(1, min(int(limit), LIST_MAX)), max(0, int(offset))
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    rows = session.execute(text(MAINS_SQL.format(scope=_scope(ids)) + f"""
        , page AS (SELECT *, count(*) OVER () AS total FROM st{where_sql}
                   ORDER BY {STATE_RANK}, project_path, project_id LIMIT :limit OFFSET :offset)
        SELECT page.*, ls.scanned_at AS last_scan_at, ls.branch_commit AS last_scan_commit,
               ls.rules_version LIKE '%+partial' AS last_scan_partial
        FROM page LEFT JOIN LATERAL (
            SELECT s.scanned_at, s.branch_commit, s.rules_version FROM discovery_scans s
            WHERE s.branch_id = page.branch_id ORDER BY s.scanned_at DESC, s.id DESC LIMIT 1) ls ON true
        ORDER BY {STATE_RANK.replace('state', 'page.state', 1)}, page.project_path, page.project_id
    """), {**binds, "limit": limit, "offset": offset}).mappings().all()
    total = rows[0]["total"] if rows else (
        0 if offset == 0 else session.execute(text(MAINS_SQL.format(scope=_scope(ids)) +
                                                   f"SELECT count(*) FROM st{where_sql}"), binds).scalar())
    page_ids = [r["project_id"] for r in rows]
    mrs: Dict[int, Dict[str, int]] = {}
    if page_ids:
        for r in _mr_rows(session, page_ids):
            _add(mrs.setdefault(r["project_id"], _mr_totals()), r["state"], r["job"], r["n"])
            mrs[r["project_id"]]["open"] += r["n"]
    items = []
    for r in rows:
        item = {k: r[k] for k in ("project_id", "project_path", "scan_mode", "branch_id", "branch_name", "commit",
                                  "scanned_commit", "commit_at", "activity_at", "synced", "synced_at", "sync_job",
                                  "state", "job", "job_id", "retrying", "last_job_id", "last_job_status",
                                  "last_job_at", "last_scan_at", "last_scan_commit", "last_scan_partial")}
        item["last_error"] = (r["last_error"] or "")[:ERROR_MAX] or None
        m = mrs.get(r["project_id"]) or _mr_totals()
        item["mrs"] = {k: m[k] for k in ("open", "scanned_current", "queued", "running", "failed")}
        items.append(item)
    return {"total": total, "items": items}


def scan_progress(session: Session, *, status=None, scan_mode=None, q: Optional[str] = None,
                  project_ids: Optional[List[int]] = None, limit: int = 50, offset: int = 0,
                  include_projects: bool = True) -> Dict[str, Any]:
    """Totals for main branches (all, and by scan mode), open MRs, external projects and the job
    queue, plus (``include_projects``) the filtered, paged project list (problems first)."""
    result = totals(session)
    if include_projects:
        result["projects"] = project_rows(session, status=status, scan_mode=scan_mode, q=q, project_ids=project_ids,
                                          limit=limit, offset=offset)
    return result


def project_states(session: Session, project_ids: List[int]) -> Dict[int, Dict[str, Any]]:
    """``{project_id: {state, job, synced, mrs...}}`` of some projects (the Projects page)."""
    if not project_ids:
        return {}
    rows = project_rows(session, project_ids=project_ids, limit=LIST_MAX)["items"]
    return {r["project_id"]: {k: r[k] for k in ("state", "job", "synced", "sync_job", "commit", "scanned_commit",
                                                "last_scan_at", "last_error", "mrs")} for r in rows}
