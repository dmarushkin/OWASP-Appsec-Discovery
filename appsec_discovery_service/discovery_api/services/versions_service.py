"""LLM rule lifecycle in the API (``discovery_common.lifecycle``): rule versions, their cost, activation / rollback,
rule rollouts and the verdict history of a hit. REST and MCP use the same functions; the actions that change what
production asks (activate, rollback, start / resume a rollout) are REST / UI only - MCP agents read and propose.
"""

import difflib
import json
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from discovery_common import lifecycle
from services.errors import Conflict, Invalid, NotFound

HISTORY_MAX = 200
VERDICT_KEYS = ("status", "rule_version", "prompt_version", "model", "reason", "fields", "decided_tier", "reviewer",
                "verifier_model", "category", "severity", "names_hash", "subject_hash")


def _call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except lifecycle.LifecycleError as e:
        raise {"not_found": NotFound, "invalid": Invalid}.get(e.kind, Conflict)(str(e)) from None


def _json(row: Optional[dict]) -> Optional[dict]:
    return json.loads(json.dumps(row, default=str)) if row is not None else None


def _diff(old: Optional[str], new: Optional[str], a: str, b: str) -> str:
    return "".join(difflib.unified_diff((old or "").splitlines(keepends=True), (new or "").splitlines(keepends=True),
                                        fromfile=a, tofile=b, n=2))


def _version_out(version: dict, active: Optional[dict]) -> Dict[str, Any]:
    out = _json(version)
    if active is not None and active["id"] != version["id"]:
        a, b = f"v{active['version']} (active)", f"v{version['version']}"
        matchers_old, matchers_new = lifecycle.matchers_of(active["matchers"]), lifecycle.matchers_of(version["matchers"])
        out["diff"] = {
            "prompt": _diff(active["prompt"], version["prompt"], a, b) or None,
            "matchers": {k: [matchers_old.get(k), matchers_new.get(k)] for k in sorted(set(matchers_old) | set(matchers_new))
                         if matchers_old.get(k) != matchers_new.get(k)},
            "target": [active["target"], version["target"]] if active["target"] != version["target"] else None,
            "core_prompt_version": [active["core_prompt_version"], version["core_prompt_version"]]
            if active["core_prompt_version"] != version["core_prompt_version"] else None,
            "model": [active["model"], version["model"]] if active["model"] != version["model"] else None,
        }
        out["same_content"] = lifecycle.same_content(active, version)
    return out


def list_versions(session: Session, rule_id: int) -> Dict[str, Any]:
    rule = _call(lifecycle.rule_row, session, rule_id)
    active = _call(lifecycle.ensure_active_version, session, rule["id"])
    rollouts = {r["to_version"]: r for r in _rollouts(session, rule_id=rule["id"], limit=50)}
    items = []
    for v in lifecycle.list_versions(session, rule["id"]):
        out = _version_out(v, active)
        out["rollout"] = _rollout_brief(rollouts.get(v["version"]))
        items.append(out)
    return {"rule": {"id": rule["id"], "name": rule["name"], "version": rule["version"],
                     "core_prompt_version": lifecycle.pinned_core_version(rule),
                     "code_core_prompt_version": lifecycle.code_core_version(rule), "llm_model": rule["llm_model"],
                     "service_model": _service_model(session)},
            "items": items}


def get_version(session: Session, version_id: int) -> Dict[str, Any]:
    version = _call(lifecycle.get_version, session, version_id)
    active = _call(lifecycle.ensure_active_version, session, version["rule_id"])
    return _version_out(version, active)


def create_candidate(session: Session, rule_id: int, data: Dict[str, Any], user: str) -> Dict[str, Any]:
    """A candidate version from the active one with ``prompt`` / matchers / ``target`` changed (the rule itself is
    not changed); ``note``."""
    from schemas import LLM_SCOPE_KEYS
    rule = _call(lifecycle.rule_row, session, rule_id, lock=True)
    if rule["deleted_at"] is not None:
        raise NotFound(f"llm rule {rule_id} not found")
    active = _call(lifecycle.ensure_active_version, session, rule["id"], user)
    unknown = sorted(set(data) - set(LLM_SCOPE_KEYS) - {"prompt", "target", "note"})
    if unknown:
        raise Invalid(f"unknown fields {unknown}: a version has prompt, target and the scope {list(LLM_SCOPE_KEYS)}")
    prompt = data.get("prompt", active["prompt"])
    if prompt is not None and len(prompt) > 20000:
        raise Invalid("prompt: at most 20000 characters")
    target = data.get("target") or active["target"]
    if target not in ("field", "object"):
        raise Invalid("target must be field or object")
    matchers = {**(active["matchers"] or {}), **{k: data[k] for k in LLM_SCOPE_KEYS if k in data}}
    candidate = {"prompt": prompt, "target": target, "matchers": matchers}
    if lifecycle.same_content(active, candidate):
        raise Invalid("nothing changed: the candidate would ask the same as the active version")
    version = _call(lifecycle.create_version, session, rule["id"], prompt=prompt, target=target, matchers=matchers,
                    core_prompt_version=lifecycle.code_core_version({"target": target, "category": rule["category"]}),
                    model=active["model"], source="manual", created_by=user, note=data.get("note"))
    return _version_out(version, active)


def _service_model(session: Session) -> Optional[str]:
    return session.execute(text("SELECT value FROM llm_runtime WHERE key = 'service_model'")).scalar()


SAME_CONTENT_SQL = text("""
    SELECT count(*) AS subjects, count(DISTINCT h.object_key) AS objects,
           count(*) FILTER (WHERE h.status = 'need_more_info') AS need_more_info,
           count(*) FILTER (WHERE h.status IN ('match', 'pending_review')) AS positive,
           count(*) FILTER (WHERE h.status = 'no_match') AS negative, count(DISTINCT h.project_id) AS projects
    FROM rule_hits h
    WHERE h.rule_id = :r AND h.prompt_version IS NOT NULL AND h.reviewer IS NULL AND h.decided_tier <> 'harness'
      AND NOT (h.rule_version = :active AND h.prompt_version IS NOT DISTINCT FROM :core
               AND (CAST(:model AS text) IS NULL OR h.model = :model OR COALESCE(h.model, '') LIKE '% via %'))""")


def estimate(session: Session, version_id: int) -> Dict[str, Any]:
    """What activating ``version_id`` (and its rollout) costs, in model calls (one per object; nothing is asked):
    ``fresh`` - subjects the next runs ask anyway (no verdict, new content); ``migration`` - the machine verdicts the
    rollout asks again (a version with the same content - new core prompts / model - only those not already made
    by them: they are relabelled); ``protected_*`` - human / harness decisions kept; ``est_calls``."""
    from services import insights_service
    version = _call(lifecycle.get_version, session, version_id)
    rule = _call(lifecycle.rule_row, session, version["rule_id"])
    active = _call(lifecycle.ensure_active_version, session, rule["id"])
    same = lifecycle.same_content(active, version) and version["id"] != active["id"]
    if version["id"] == active["id"]:
        size = lifecycle.migration_size(session, rule, code_model=_service_model(session))
        migration = {k: size[k] for k in ("subjects", "objects", "need_more_info", "positive", "negative", "projects")}
        protected = size
    elif same:
        migration = dict(session.execute(SAME_CONTENT_SQL, {
            "r": rule["id"], "active": active["version"], "core": version["core_prompt_version"],
            "model": version["model"]}).mappings().one())
        protected = lifecycle.migration_size(session, rule, on_activation=True)
    else:
        protected = lifecycle.migration_size(session, rule, on_activation=True)
        migration = {k: protected[k] for k in ("subjects", "objects", "need_more_info", "positive", "negative",
                                               "projects")}
    patch = {"prompt": version["prompt"], "target": version["target"], **lifecycle.matchers_of(version["matchers"])}
    for key in lifecycle.MATCHER_KEYS:
        patch.setdefault(key, False if key == "mark_fields" else None)
    dry = insights_service.dry_run_rule(session, kind="llm", rule=patch, rule_id=rule["id"])
    fresh = dry.get("fresh") or {"subjects": 0, "model_calls": 0}
    migration = {k: int(v or 0) for k, v in migration.items()}
    return {
        "version_id": version["id"], "version": version["version"], "status": version["status"],
        "rule_id": rule["id"], "active_version": active["version"], "same_content": same,
        "fresh": fresh, "migration": {**migration, "model_calls": migration["objects"]},
        "protected_human": protected["protected_human"], "protected_harness": protected["protected_harness"],
        "est_calls": int(fresh.get("model_calls") or 0) + migration["objects"],
        "truncated": dry.get("truncated", False),
        "note": "model calls are estimated as one per object; the rollout asks the migration part within its budget "
                "(LLM_ROLLOUT_CALLS_PER_HOUR), fresh subjects are asked by the normal runs",
    }


def activate(session: Session, version_id: int, *, user: str, start_rollout: bool = True,
             budget: Optional[dict] = None, note: Optional[str] = None, mode: Optional[str] = None) -> Dict[str, Any]:
    result = _call(lifecycle.activate_version, session, version_id, user=user, start_rollout=start_rollout,
                   budget=budget, note=note, mode=mode or ("staged" if start_rollout else None))
    return _json(result)


def rollback(session: Session, rule_id: int, to_version: int, *, user: str, start_rollout: bool = True,
             budget: Optional[dict] = None, note: Optional[str] = None) -> Dict[str, Any]:
    return _json(_call(lifecycle.rollback, session, rule_id, to_version, user=user, start_rollout=start_rollout,
                       budget=budget, note=note))


def discard(session: Session, version_id: int, *, user: str, note: Optional[str] = None) -> Dict[str, Any]:
    return _json(_call(lifecycle.discard_version, session, version_id, user=user, note=note))


# ---- rollouts ----------------------------------------------------------------------------------------------------

def _rollout_brief(row: Optional[dict]) -> Optional[dict]:
    if row is None:
        return None
    return {k: row.get(k) for k in ("id", "status", "mode", "created_at", "started_at", "finished_at")}


def _rollouts(session: Session, rule_id: Optional[int] = None, status=None, limit: int = 50) -> List[dict]:
    statuses = [status] if isinstance(status, str) else list(status or [])
    from discovery_common.models import ROLLOUT_STATUSES
    unknown = sorted(set(statuses) - set(ROLLOUT_STATUSES) - {"open"})
    if unknown:
        raise Invalid(f"unknown status {unknown}, expected some of {list(ROLLOUT_STATUSES) + ['open']}")
    if "open" in statuses:
        statuses = [s for s in statuses if s != "open"] + list(lifecycle.ROLLOUT_OPEN)
    rows = session.execute(text(f"""
        SELECT {", ".join("o." + c.strip() for c in lifecycle.ROLLOUT_COLUMNS.split(","))}, r.name AS rule_name,
               r.severity AS rule_severity, r.version AS rule_version
        FROM llm_rollouts o JOIN rules r ON r.id = o.rule_id
        WHERE (CAST(:r AS int) IS NULL OR o.rule_id = :r) AND (CAST(:s AS text[]) IS NULL OR o.status = ANY(:s))
        ORDER BY (o.status IN ({lifecycle.OPEN_SQL})) DESC, o.id DESC LIMIT :limit"""),
        {"r": rule_id, "s": statuses or None, "limit": max(1, min(int(limit), 200))}).mappings().all()
    return [dict(r) for r in rows]


def _rollout_out(row: dict) -> Dict[str, Any]:
    out = _json(row)
    p = row.get("progress") or {}
    planned, remaining = p.get("planned_objects"), p.get("remaining_objects")
    out["percent"] = (round(100 * (planned - remaining) / planned) if planned else (100 if row["status"] == "done"
                                                                                       else 0)) \
        if planned is not None and remaining is not None else None
    out["exhausted_branches"] = len(p.get("exhausted") or {})
    return out


def list_rollouts(session: Session, rule_id: Optional[int] = None, status=None, limit: int = 50) -> Dict[str, Any]:
    items = [_rollout_out(r) for r in _rollouts(session, rule_id, status, limit)]
    return {"items": items, "open": sum(1 for r in items if r["status"] in lifecycle.ROLLOUT_OPEN)}


def get_rollout(session: Session, rollout_id: int) -> Dict[str, Any]:
    row = _call(lifecycle.get_rollout, session, rollout_id)
    rule = _call(lifecycle.rule_row, session, row["rule_id"])
    out = _rollout_out({**row, "rule_name": rule["name"], "rule_severity": rule["severity"],
                        "rule_version": rule["version"]})
    out["slices"] = [_json(dict(j)) for j in session.execute(text("""
        SELECT id, status, payload ->> 'branch_id' AS branch_id, payload ->> 'max_objects' AS max_objects,
               progress ->> 'done_objects' AS done_objects, progress ->> 'failed_objects' AS failed_objects,
               created_at, finished_at, last_error
        FROM jobs WHERE kind = 'llm_score' AND payload ->> 'rollout_id' = CAST(:id AS text)
        ORDER BY id DESC LIMIT 20"""), {"id": row["id"]}).mappings()]
    out["flips"] = {f"{r.old} -> {r.new}": r.n for r in session.execute(text("""
        SELECT p.status AS old, v.status AS new, count(*) AS n
        FROM hit_verdicts v
        JOIN LATERAL (SELECT x.status FROM hit_verdicts x WHERE x.rule_id = v.rule_id AND x.subject_key = v.subject_key
                      AND x.id < v.id ORDER BY x.id DESC LIMIT 1) p ON true
        WHERE v.rollout_id = :id GROUP BY 1, 2 ORDER BY 3 DESC"""), {"id": row["id"]})}
    return out


def rollout_action(session: Session, rollout_id: int, action: str, *, user: str, reason: Optional[str] = None,
                   budget: Optional[dict] = None) -> Dict[str, Any]:
    _call(lifecycle.rollout_action, session, rollout_id, action, user=user, reason=reason, budget=budget)
    return get_rollout(session, rollout_id)


# ---- verdict history ---------------------------------------------------------------------------------------------

def hit_history(session: Session, hit_id: str, limit: int = 100) -> Dict[str, Any]:
    """The verdicts of one hit (``hit_verdicts``, newest first), each with what changed vs the one before, and the
    last verdict of every rule version (a diff per version). ``batch_id``: the ``review_batches`` row of a decision
    made by filter (``POST /hits/decide``) or of its undo (``source`` undo)."""
    from services.review_service import hit_id as make_id, parse_hit_id
    rule_id, subject_key = parse_hit_id(hit_id)
    exists = session.execute(text("SELECT 1 FROM rule_hits WHERE rule_id = :r AND subject_key = :s"),
                             {"r": rule_id, "s": subject_key}).first()
    rows = [dict(r) for r in session.execute(text("""
        SELECT id, rule_version, prompt_version, model, status, category, severity, reason, fields, names_hash,
               subject_hash, decided_tier, reviewer, verifier_model, source, rollout_id, batch_id, created_at
        FROM hit_verdicts WHERE rule_id = :r AND subject_key = :s ORDER BY id DESC LIMIT :limit"""),
        {"r": rule_id, "s": subject_key, "limit": max(1, min(int(limit), HISTORY_MAX))}).mappings()]
    if not exists and not rows:
        raise NotFound(f"hit {hit_id} not found")
    items = []
    for i, row in enumerate(rows):
        before = rows[i + 1] if i + 1 < len(rows) else None
        changed = [k for k in VERDICT_KEYS if before is not None and row[k] != before[k]]
        items.append({**_json(row), "changed": changed,
                      "previous": {k: _json({"v": before[k]})["v"] for k in changed} if before else None})
    versions = {}
    for row in reversed(rows):                  # oldest first: the last row of each version wins
        versions[row["rule_version"]] = row
    by_version = []
    previous = None
    for version in sorted(versions):
        row = versions[version]
        diff = {k: [previous[k], row[k]] for k in ("status", "reason", "fields", "prompt_version", "model", "decided_tier")
                if previous is not None and previous[k] != row[k]}
        by_version.append({"rule_version": version, "status": row["status"], "reason": row["reason"],
                           "fields": row["fields"], "prompt_version": row["prompt_version"], "model": row["model"],
                           "decided_tier": row["decided_tier"], "at": _json({"v": row["created_at"]})["v"],
                           "diff_to_previous_version": _json(diff) if previous is not None else None})
        previous = row
    return {"hit_id": make_id(rule_id, subject_key), "items": items, "versions": by_version,
            "truncated": len(rows) >= max(1, min(int(limit), HISTORY_MAX))}
