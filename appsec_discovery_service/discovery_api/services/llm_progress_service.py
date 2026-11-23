"""Coverage of the LLM rules (``GET /llm_progress``, MCP ``llm_progress``, the Dashboard "LLM
coverage", the Projects page's LLM column): of the projects in scan mode ``rules``, how many
main branches have current verdicts of every enabled LLM rule, how many wait for a run.

Read from ``llm_coverage`` only (one row per branch and rule, written by the scanner after each
LLM run on the branch, each snapshot save and by its ``llm_coverage`` job for stale rows; see
the scanner's ``services/llm_coverage_service.py``): candidates are never counted here. A row
is *fresh* when it was computed for the branch's current snapshot (``commit`` =
``scanned_commit``), the rule's current version and the current core prompts
(the rule's pinned core prompts family version, ``rules.core_prompt_version``); ``remaining`` =
``candidates_total`` - ``answered``; of it, ``answered_stale`` subjects have a verdict of an older version of
the rule (kept, scoring) that the rule's rollout asks again - the rest the next run sends to the model.

Main branch of a project, ``state`` (exactly one, in this order):

* ``not_scanned``  no main branch or no snapshot yet (nothing to ask about);
* ``current``      every enabled LLM rule has a fresh row with nothing remaining;
* ``failed``       the latest finished LLM run (``llm_score`` / ``llm_prepare`` job) of the branch failed;
* ``never``        some enabled rule has no coverage row yet (the scanner has not counted it);
* ``outdated``     otherwise: subjects remain for some rule, or a row is stale.

``job`` (orthogonal): ``running`` / ``queued`` when an LLM run of the branch is running /
pending, ``awaiting_answers`` for an external run waiting for its model. Open MRs (the source
branch delta of the MRs that own it, see ``scan_progress_service``) get the same states.
"""

from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from discovery_common import lifecycle, stats
from discovery_common.models import LLM_PROMPTS_VERSION
from services.errors import Invalid
from services.paging import as_ints, as_list, escape_like

STATES, JOB_STATES = stats.LLM_STATES, stats.LLM_JOB_STATES
EXTRA_FILTERS = ("active", "incomplete")        # active: a job state; incomplete: failed | never | outdated
LIST_MAX = 500
ERROR_MAX = 300

# the statements of the ``llm_progress`` snapshot (``discovery_common.stats``), reused by the per-project rows:
# ``{scope}`` / ``{branches}`` placeholders as there
RULES_SQL, LLM_KINDS, STATE_SQL = stats.LLM_RULES_SQL, stats.LLM_KINDS, stats.LLM_STATE_SQL
MAIN_BRANCHES, MR_BRANCHES = stats.LLM_MAIN_BRANCHES, stats.LLM_MR_BRANCHES

STATE_RANK = "CASE state " + " ".join(
    f"WHEN '{s}' THEN {i}" for i, s in enumerate(("failed", "never", "outdated", "not_scanned", "current"))) + " END"


def _scope(project_ids: Optional[List[int]], column: str = "p.id") -> str:
    return "" if project_ids is None else f" AND {column} = ANY(:ids)"


_totals, _add = stats._llm_totals, stats._add_llm


def _rules(session: Session) -> List[Dict[str, Any]]:
    return [dict(r) for r in session.execute(RULES_SQL).mappings()]


def _mr_rows(session: Session, project_ids: Optional[List[int]]):
    binds = {"pv": LLM_PROMPTS_VERSION, **({} if project_ids is None else {"ids": project_ids})}
    sql = STATE_SQL.format(branches=MR_BRANCHES.format(scope=_scope(project_ids, "m.project_id")))
    return session.execute(text(sql + "SELECT project_id, state, job, count(*) AS n FROM st GROUP BY 1, 2, 3"),
                           binds).mappings().all()


_rule_totals = stats._llm_rule_totals


def totals(session: Session) -> Dict[str, Any]:
    """The totals of ``GET /llm_progress`` = the ``llm_progress`` statistics snapshot (``discovery_common.stats``)."""
    return stats.llm_progress(session)


def _list_conditions(status, q) -> tuple:
    where, binds = [], {}
    statuses = [str(s) for s in as_list(status)] if status not in (None, "") else []
    allowed = STATES + JOB_STATES + EXTRA_FILTERS
    unknown = sorted(set(statuses) - set(allowed))
    if unknown:
        raise Invalid(f"unknown status {unknown}, expected some of {list(allowed)}")
    if statuses:
        parts = []
        states = [s for s in statuses if s in STATES] + (
            ["failed", "never", "outdated"] if "incomplete" in statuses else [])
        jobs = [s for s in statuses if s in JOB_STATES] + (list(JOB_STATES) if "active" in statuses else [])
        if states:
            parts.append("state = ANY(:states)")
            binds["states"] = sorted(set(states))
        if jobs:
            parts.append("job = ANY(:jobs)")
            binds["jobs"] = sorted(set(jobs))
        where.append("(" + " OR ".join(parts) + ")")
    if q:
        where.append("project_path ILIKE :q ESCAPE '\\'")
        binds["q"] = f"%{escape_like(str(q))}%"
    return where, binds


def _branch_rules(session: Session, branch_ids: List[int], rules: List[Dict[str, Any]]) -> Dict[int, list]:
    """Per branch, every enabled rule: answered / total of its row (None: not counted yet), fresh."""
    found: Dict[tuple, Dict[str, Any]] = {}
    if branch_ids and rules:
        for r in session.execute(text("""
                SELECT c.branch_id, c.rule_id, c.answered, c.candidates_total, c.pending_external, c.failed,
                       c.answered_stale, c.computed_at, (c.commit = g.scanned_commit AND c.rule_version = r.version
                                       AND c.prompt_version = """ + lifecycle.pinned_core_sql("r") + """) AS fresh
                FROM llm_coverage c JOIN gitlab_branches g ON g.id = c.branch_id JOIN rules r ON r.id = c.rule_id
                WHERE c.branch_id = ANY(:b) AND c.rule_id = ANY(:r)"""),
                {"b": branch_ids, "r": [x["id"] for x in rules], "pv": LLM_PROMPTS_VERSION}).mappings():
            found[(r["branch_id"], r["rule_id"])] = dict(r)
    out: Dict[int, list] = {}
    for b in branch_ids:
        items = []
        for rule in rules:
            c = found.get((b, rule["id"]))
            items.append({"rule_id": rule["id"], "name": rule["name"],
                          "answered": c["answered"] if c else None, "total": c["candidates_total"] if c else None,
                          "pending_external": c["pending_external"] if c else None,
                          "failed": c["failed"] if c else None, "fresh": bool(c and c["fresh"]),
                          "answered_stale": c["answered_stale"] if c else None,
                          "computed_at": c["computed_at"] if c else None})
        out[b] = items
    return out


def project_rows(session: Session, *, status=None, q: Optional[str] = None, project_ids: Optional[List[int]] = None,
                 limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    """Per project in scan mode rules: its main branch's LLM state, job, counts per rule, open MRs."""
    ids = as_ints(project_ids, "project_ids") if project_ids not in (None, "", []) else None
    where, binds = _list_conditions(status, q)
    binds["pv"] = LLM_PROMPTS_VERSION
    if ids is not None:
        binds["ids"] = ids
    limit, offset = max(1, min(int(limit), LIST_MAX)), max(0, int(offset))
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    base = STATE_SQL.format(branches=MAIN_BRANCHES.format(scope=_scope(ids)))
    rows = session.execute(text(base + f"""
        SELECT *, count(*) OVER () AS total_rows FROM st{where_sql}
        ORDER BY {STATE_RANK}, project_path, project_id LIMIT :limit OFFSET :offset
    """), {**binds, "limit": limit, "offset": offset}).mappings().all()
    total = rows[0]["total_rows"] if rows else (
        0 if offset == 0 else session.execute(text(base + f"SELECT count(*) FROM st{where_sql}"), binds).scalar())
    rules = _rules(session)
    per_rule = _branch_rules(session, [r["branch_id"] for r in rows if r["branch_id"] is not None], rules)
    page_ids = [r["project_id"] for r in rows]
    mrs: Dict[int, Dict[str, int]] = {}
    if page_ids:
        for r in _mr_rows(session, page_ids):
            m = mrs.setdefault(r["project_id"], {"open": 0, **_totals()})
            m["open"] += r["n"]
            _add(m, r["state"], r["job"], r["n"])
    items = []
    for r in rows:
        item = {k: r[k] for k in ("project_id", "project_path", "source", "branch_id", "branch_name", "commit",
                                  "scanned_commit", "state", "job", "job_id", "last_job_id", "last_job_status",
                                  "last_job_at", "computed_at")}
        item.update(answered=int(r["answered"]), total=int(r["total"]), remaining=int(r["total"]) - int(r["answered"]),
                    pending_external=int(r["pending_external"]), failed_subjects=int(r["failed_subjects"]),
                    answered_stale=int(r["answered_stale"]))
        item["last_error"] = (r["last_error"] or "")[:ERROR_MAX] or None
        item["rules"] = per_rule.get(r["branch_id"], [])
        m = mrs.get(r["project_id"]) or {"open": 0, **_totals()}
        item["mrs"] = {k: m[k] for k in ("open", "current", "queued", "running", "failed")}
        items.append(item)
    return {"total": total, "items": items}


def llm_progress(session: Session, *, status=None, q: Optional[str] = None, project_ids: Optional[List[int]] = None,
                 limit: int = 50, offset: int = 0, include_projects: bool = True) -> Dict[str, Any]:
    """Totals (main branches, open MRs, per rule, active LLM jobs) plus (``include_projects``)
    the filtered, paged project list (problems first)."""
    result = totals(session)
    if include_projects:
        result["projects"] = project_rows(session, status=status, q=q, project_ids=project_ids, limit=limit,
                                          offset=offset)
    return result


def project_states(session: Session, project_ids: List[int]) -> Dict[int, Dict[str, Any]]:
    """``{project_id: {state, job, answered, total, ...}}`` of some projects (the Projects page);
    projects in inventory mode are not in it."""
    if not project_ids:
        return {}
    rows = project_rows(session, project_ids=project_ids, limit=LIST_MAX)["items"]
    return {r["project_id"]: {k: r[k] for k in ("state", "job", "answered", "total", "remaining", "pending_external",
                                                "failed_subjects", "computed_at", "last_job_at", "last_error",
                                                "rules")} for r in rows}
