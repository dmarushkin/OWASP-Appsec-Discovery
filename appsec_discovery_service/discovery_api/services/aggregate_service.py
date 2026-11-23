"""Review at scale (contract 6): counts, clusters and decisions over a filter instead of over a page.

* ``hits_cube``: the counts of every hit by status x tier x asked_by_model x in_main x in_open_mr x rule x category x
  severity x field mark - the ``hits_aggregate`` row of ``stats_snapshots`` (written by the scanner's ``stats_refresh``
  job from the same SQL, served while fresh). ``hits_aggregate`` groups it by any of those dimensions (and derived
  ones: ``presence``, ``queue``, ``kind``) for the tabs, badges and tiles of the UI in one call; a filter the cube
  does not hold (a project, a group, an object type, a text search) or a dimension outside it computes live over
  ``rule_hits`` with the filters of ``GET /hits``.
* ``hits_clusters``: the filtered hits grouped by a cluster key - ``schema`` (object type + sorted field:type pairs,
  "one table in 34 services"), ``field_pattern`` (rule + field name, "the field inn everywhere"), ``object_name``
  (rule + type + object name), ``rule_group`` (rule + GitLab group + type) - with counts, projects, presence share,
  the new ones of the last 7 days, the questions inside and sample hit ids. The filter ``cluster=<by>:<key>`` of
  ``GET /hits`` / ``POST /hits/decide`` addresses one cluster.
* ``decide``: one review action on every hit of a filter. Safety: ``dry_run`` (default) reports what would change
  and what is kept; the apply needs ``expected_total`` equal to the server's current count (else 409: the set
  changed, run the dry run again); human decisions are never overwritten (``include_human`` is an explicit
  re-decision by a human), the harness model's questions are skipped (``skip_questions``), the review transitions
  of ``review_service`` apply (a confirm applies to open hits only, ...). Every apply is a ``review_batches`` row
  with the previous state of each hit (``review_batch_items``); the verdict history rows carry ``batch_id``;
  ``undo_batch`` restores the hits a human did not touch since.
"""

import json
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from discovery_common import stats
from discovery_common.models import REVIEW_TRANSITIONS
from schemas import ACTION_STATUS, ReviewAction
from services import review_service, stats_service
from services.errors import Conflict, Invalid, NotFound
from services.paging import MAX_LIMIT, as_list, decode_cursor, encode_cursor
from services.review_service import (
    CLUSTER_KEY_SQL, CLUSTER_KINDS, FIELD_MARK, GROUP_PATH_SQL, SEVERITY_ORDER, hit_id, hits_from_where,
)

# ---- the cube ----------------------------------------------------------------------------------------------------

CUBE_DIMENSIONS = ("status", "decided_tier", "asked_by_model", "in_main", "in_open_mr", "rule_id", "category",
                   "severity", "field_mark")
# dimensions a caller may group by: the cube's, and the derived / live-only ones
DERIVED = {
    "presence": "CASE WHEN h.in_main THEN 'main' WHEN h.in_open_mr THEN 'mr' ELSE 'gone' END",
    "queue": """CASE WHEN h.status = 'need_more_info' AND h.asked_by_model THEN 'questions'
                     WHEN h.status = 'pending_review' THEN 'pending'
                     WHEN h.status = 'need_more_info' THEN 'unsure'
                     WHEN h.decided_tier = 'human' THEN 'human'
                     WHEN h.decided_tier = 'harness' THEN 'harness'
                     ELSE 'service' END""",
    "kind": "r.kind",
}
LIVE_ONLY = {
    "project_id": "h.project_id",
    "group": GROUP_PATH_SQL.format(path="p.full_path"),
    "object_type": "obj.type",
    "first_seen_day": "date_trunc('day', h.first_seen_at)",
}
DIMENSIONS = CUBE_DIMENSIONS + tuple(DERIVED) + tuple(LIVE_ONLY)
# filters of GET /hits the cube can answer (everything else is live)
CUBE_FILTERS = ("status", "rule_id", "category", "severity", "decided_tier", "asked_by_model", "field_marks",
                "presence", "kind")
AGGREGATE_ROWS_MAX = 2000
QUEUES = ("questions", "pending", "unsure", "human", "harness", "service")


def hits_cube(session: Session) -> Dict[str, Any]:
    """The counts of every hit by the cube dimensions (``rows``; a few thousand at most) - what the ``hits_aggregate``
    snapshot holds, by the one statement of ``discovery_common.stats`` (the scanner writes the snapshot with it), so
    the live cube and the snapshot never differ."""
    data = stats.hits_aggregate(session)
    return {**data, "computed_at": session.execute(text("SELECT now()")).scalar()}


def _rule_info(session: Session, rule_ids) -> Dict[int, dict]:
    ids = sorted({int(r) for r in rule_ids if r is not None})
    if not ids:
        return {}
    return {r["id"]: dict(r) for r in session.execute(text(
        "SELECT id, name, kind, target FROM rules WHERE id = ANY(:ids)"), {"ids": ids}).mappings()}


def _derive(row: dict, rules: Dict[int, dict]) -> dict:
    """The derived dimensions of a cube row."""
    out = dict(row)
    out["presence"] = "main" if row["in_main"] else ("mr" if row["in_open_mr"] else "gone")
    if row["status"] == "need_more_info" and row["asked_by_model"]:
        out["queue"] = "questions"
    elif row["status"] == "pending_review":
        out["queue"] = "pending"
    elif row["status"] == "need_more_info":
        out["queue"] = "unsure"
    else:
        out["queue"] = row["decided_tier"] if row["decided_tier"] in ("human", "harness") else "service"
    out["kind"] = (rules.get(row["rule_id"]) or {}).get("kind")
    return out


def _cube_filter(filters: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The filter as predicates on derived cube rows, or None when the cube cannot answer it."""
    if set(filters) - set(CUBE_FILTERS):
        return None
    pred: Dict[str, Any] = {}
    if "status" in filters:
        statuses = review_service.normalize_statuses(as_list(filters["status"]))
        pred["status"] = set(statuses)
    for name in ("category", "severity", "kind"):
        if name in filters:
            pred[name] = {str(v) for v in as_list(filters[name])}
    if "rule_id" in filters:
        pred["rule_id"] = {int(v) for v in as_list(filters["rule_id"])}
    if "decided_tier" in filters:
        pred["decided_tier"] = {review_service.DECIDED_TIER_ALIASES.get(str(t), str(t))
                                for t in as_list(filters["decided_tier"])}
    for name, key in (("asked_by_model", "asked_by_model"), ("field_marks", "field_mark")):
        if name in filters:
            pred[key] = {str(filters[name]).lower() in ("true", "1")}
    presence = filters.get("presence", "live")
    if presence not in review_service.PRESENCES:
        raise Invalid(f"presence must be one of {list(review_service.PRESENCES)}")
    pred["presence"] = {"main": {"main"}, "mr": {"mr"}, "live": {"main", "mr"}}.get(presence)
    return {k: v for k, v in pred.items() if v is not None}


def _group(rows: List[dict], by: List[str]) -> List[dict]:
    counts: Dict[tuple, int] = {}
    for row in rows:
        key = tuple(row.get(d) for d in by)
        counts[key] = counts.get(key, 0) + int(row["n"])
    out = [{**dict(zip(by, key)), "n": n} for key, n in counts.items()]
    out.sort(key=lambda r: (-r["n"], json.dumps([r[d] for d in by], default=str)))
    return out


def hits_aggregate(session: Session, by: List[str], filters: Optional[Dict[str, Any]] = None, *,
                   live: bool = False) -> Dict[str, Any]:
    """``GET /hits/aggregate``: ``{by, rows: [{<dim>..., n}], total, truncated, computed_at, snapshot}``. ``by``:
    some of DIMENSIONS (``rule_id`` rows carry ``rule_name``, ``project_id`` rows ``project_path``). From the
    ``hits_aggregate`` snapshot when fresh and the filters / dimensions are in the cube, else live."""
    by = [str(b) for b in as_list(by)] or ["queue"]
    unknown = [d for d in by if d not in DIMENSIONS]
    if unknown:
        raise Invalid(f"unknown dimension {unknown}, allowed: {list(DIMENSIONS)}")
    filters = dict(filters or {})
    for key in ("after", "exact"):
        filters.pop(key, None)
    pred = _cube_filter(filters) if not live else None
    snapshot = None
    if pred is not None and not (set(by) & set(LIVE_ONLY)):
        snapshot = stats_service.read_snapshot(session, "hits_aggregate")
    if snapshot is not None:
        data, computed_at = snapshot
        rules = _rule_info(session, [r["rule_id"] for r in data.get("rows", [])])
        rows = [_derive(r, rules) for r in data.get("rows", [])]
        rows = [r for r in rows if all(r.get(k) in v for k, v in pred.items())]
        grouped = _group(rows, by)
        source = {"computed_at": computed_at, "snapshot": True}
    else:
        grouped, rules = _aggregate_live(session, by, filters)
        source = {"computed_at": session.execute(text("SELECT now()")).scalar(), "snapshot": False}
    if "rule_id" in by:
        for row in grouped:
            row["rule_name"] = (rules.get(row["rule_id"]) or {}).get("name")
    truncated = len(grouped) > AGGREGATE_ROWS_MAX
    return {"by": by, "rows": grouped[:AGGREGATE_ROWS_MAX], "total": sum(r["n"] for r in grouped),
            "truncated": truncated, **source}


def _aggregate_live(session: Session, by: List[str], filters: Dict[str, Any]) -> Tuple[List[dict], Dict[int, dict]]:
    exprs = {}
    for d in by:
        if d in CUBE_DIMENSIONS:
            exprs[d] = FIELD_MARK if d == "field_mark" else f"h.{d}"
        else:
            exprs[d] = DERIVED.get(d) or LIVE_ONLY[d]
    from_where, binds = hits_from_where(filters, with_object="object_type" in by)
    select = ", ".join(f"({e}) AS {d}" for d, e in exprs.items())
    extra = ", p.full_path AS project_path" if "project_id" in by else ""
    group_by = ", ".join(str(i + 1) for i in range(len(by)))
    rows = [dict(r) for r in session.execute(text(f"""
        SELECT {select}{extra}, count(*) AS n FROM {from_where}
        GROUP BY {group_by}{", p.full_path" if extra else ""} ORDER BY n DESC, {group_by} LIMIT :cap"""),
        {**binds, "cap": AGGREGATE_ROWS_MAX + 1}).mappings()]
    for row in rows:
        row["n"] = int(row["n"])
    rules = _rule_info(session, [r["rule_id"] for r in rows]) if "rule_id" in by else {}
    return rows, rules


# ---- clusters ----------------------------------------------------------------------------------------------------

CLUSTER_SCAN_MAX = 200_000
CLUSTER_LIMIT_MAX = MAX_LIMIT
SAMPLE_IDS = 5


def hits_clusters(session: Session, by: str, filters: Optional[Dict[str, Any]] = None, *, limit: int = 25,
                  after: Optional[str] = None) -> Dict[str, Any]:
    """``GET /hits/clusters?by=``: the filtered hits (default: the open, live ones) grouped by the cluster key, biggest
    first: ``{by, items: [{key, cluster, label, rule_id, rule_name, object_type, field_name, group, n, n_open,
    questions, projects, groups, severity_max, in_main_share, new_7d, sample_ids, sample}], scanned, truncated,
    next_cursor, computed_at}``. ``cluster`` is the filter value (``<by>:<key>``) for ``GET /hits`` and
    ``POST /hits/decide``. At most CLUSTER_SCAN_MAX hits are clustered per call (``truncated`` when the filter holds
    more: narrow it)."""
    if by not in CLUSTER_KINDS:
        raise Invalid(f"by must be one of {list(CLUSTER_KINDS)}")
    filters = dict(filters or {})
    filters.setdefault("status", list(review_service.OPEN_STATUSES))
    for key in ("after", "exact"):
        filters.pop(key, None)
    limit = max(1, min(int(limit), CLUSTER_LIMIT_MAX))
    offset = int(decode_cursor(after, f"clusters:{by}", 1)[0][0]) if after else 0
    from_where, binds = hits_from_where(filters, with_object=True)
    group_path = GROUP_PATH_SQL.format(path="p.full_path")
    rows = session.execute(text(f"""
        WITH hits AS (
            SELECT h.rule_id, h.subject_key, h.object_key, h.project_id, h.status, h.severity, h.first_seen_at,
                   h.in_main, h.in_open_mr, h.asked_by_model, h.field_name, obj.type AS object_type, obj.name AS object_name,
                   obj.content_hash, {group_path} AS group_path, ({CLUSTER_KEY_SQL[by]}) AS key
            FROM {from_where} LIMIT :scan_cap),
        clusters AS (
            SELECT key, count(*) AS n,
                   count(*) FILTER (WHERE status IN ('pending_review', 'need_more_info')) AS n_open,
                   count(*) FILTER (WHERE status = 'need_more_info' AND asked_by_model) AS questions,
                   count(DISTINCT project_id) AS projects,
                   (array_agg(DISTINCT group_path))[1:3] AS groups,
                   max({SEVERITY_ORDER.replace('h.severity', 'severity')}) AS severity_rank,
                   avg(CASE WHEN in_main THEN 1.0 ELSE 0.0 END) AS in_main_share,
                   count(*) FILTER (WHERE first_seen_at > now() - interval '7 days') AS new_7d,
                   (array_agg(rule_id || ':' || subject_key ORDER BY first_seen_at DESC NULLS LAST))[1:{SAMPLE_IDS}] AS sample_ids,
                   min(rule_id) AS rule_id, min(object_type) AS object_type, min(object_name) AS object_name,
                   min(field_name) AS field_name, min(group_path) AS group_path,
                   (array_agg(content_hash::text ORDER BY first_seen_at DESC NULLS LAST))[1] AS sample_hash
            FROM hits WHERE key IS NOT NULL GROUP BY key)
        SELECT c.*, (SELECT count(*) FROM hits) AS scanned, count(*) OVER () AS total_clusters
        FROM clusters c ORDER BY n DESC, key LIMIT :limit OFFSET :offset"""),
        {**binds, "scan_cap": CLUSTER_SCAN_MAX, "limit": limit + 1, "offset": offset}).mappings().all()
    scanned = int(rows[0]["scanned"]) if rows else 0
    total_clusters = int(rows[0]["total_clusters"]) if rows else 0
    more = len(rows) > limit
    rows = rows[:limit]
    rules = _rule_info(session, [r["rule_id"] for r in rows])
    severities = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}
    schema_fields = _schema_fields(session, [r["sample_hash"] for r in rows]) if by == "schema" else {}
    items = []
    for r in rows:
        rule = rules.get(r["rule_id"]) or {}
        item = {
            "key": r["key"], "cluster": f"{by}:{r['key']}", "rule_id": r["rule_id"], "rule_name": rule.get("name"),
            "object_type": r["object_type"], "field_name": r["field_name"] if by == "field_pattern" else None,
            "group": r["group_path"] if by == "rule_group" else None,
            "n": int(r["n"]), "n_open": int(r["n_open"]), "questions": int(r["questions"]),
            "projects": int(r["projects"]), "groups": list(r["groups"] or []),
            "severity_max": severities.get(int(r["severity_rank"] or 0)),
            "in_main_share": round(float(r["in_main_share"] or 0), 3), "new_7d": int(r["new_7d"]),
            "sample_ids": list(r["sample_ids"] or []),
        }
        item["label"] = _label(by, item, r, schema_fields.get(r["sample_hash"]))
        if by == "schema":
            item["fields"] = schema_fields.get(r["sample_hash"])
            item["sample"] = {"name": r["object_name"], "type": r["object_type"]}
        items.append(item)
    next_cursor = encode_cursor(f"clusters:{by}", [offset + limit]) if more else None
    return {"by": by, "items": items, "scanned": scanned, "truncated": scanned >= CLUSTER_SCAN_MAX,
            "total_clusters": total_clusters, "next_cursor": next_cursor,
            "computed_at": session.execute(text("SELECT now()")).scalar(), "snapshot": False}


def _schema_fields(session: Session, hashes: List[Optional[str]], cap: int = 12) -> Dict[str, List[str]]:
    wanted = [h for h in hashes if h]
    if not wanted:
        return {}
    out: Dict[str, List[str]] = {}
    for r in session.execute(text("""
        SELECT content_hash::text AS h, field_name FROM object_fields WHERE content_hash = ANY(CAST(:h AS uuid[]))
        ORDER BY field_name"""), {"h": wanted}):
        names = out.setdefault(r.h, [])
        if len(names) < cap:
            names.append(r.field_name)
    return out


def _label(by: str, item: dict, row, fields: Optional[List[str]]) -> str:
    if by == "field_pattern":
        return f"field {row['field_name']}"
    if by == "object_name":
        return f"{row['object_type'] or 'object'} {row['object_name']}"
    if by == "rule_group":
        return f"{row['object_type'] or 'object'} in {row['group_path']}"
    shown = ", ".join(fields or [])
    return f"{row['object_type'] or 'object'} {{{shown}}}" if fields else f"{row['object_type'] or 'object'} (no fields)"


# ---- decide by filter --------------------------------------------------------------------------------------------

DECIDE_MAX = 100_000
BY_PROJECT_TOP = 10
# what a decision changes on a hit (as ``review_service.REVIEW_SET``) and what the batch remembers to undo it
PREV_COLUMNS = ("status", "reviewer", "reviewed_at", "decided_via", "decided_tier", "asked_by_model", "category",
                "severity", "note", "machine_status")
QUESTION = "(h.status = 'need_more_info' AND h.asked_by_model)"
HARNESS = "(h.decided_tier = 'harness' AND NOT h.asked_by_model)"


def _action(action) -> ReviewAction:
    try:
        return ReviewAction(getattr(action, "value", action))
    except ValueError:
        raise Invalid(f"unknown action {action!r}, expected one of {[a.value for a in ReviewAction]}") from None


def decide(session: Session, *, filters: Dict[str, Any], action, reviewer: str, note: Optional[str] = None,
           category: Optional[str] = None, severity: Optional[str] = None, expected_total: Optional[int] = None,
           dry_run: bool = True, include_human: bool = False, include_harness: bool = False,
           skip_questions: bool = True, via: str = "rest") -> Dict[str, Any]:
    """``POST /hits/decide``. Returns ``{dry_run, action, matched, applied, cascaded, kept: {human, harness,
    questions, transition}, by_status, by_project, by_project_more, sample, expected_total, batch_id}``; ``matched`` is
    the number of hits the action would change (the figure to pass back as ``expected_total``)."""
    action = _action(action)
    target = ACTION_STATUS[action]
    if not note or not str(note).strip():
        raise Invalid("a decision by filter needs a note (why these hits get the same decision)")
    filters = dict(filters or {})
    for key in ("after", "exact"):
        filters.pop(key, None)
    if not filters or set(filters) <= {"presence"}:
        raise Invalid("the filter must narrow the hits (at least one of status, rule_id, cluster, project_id, group, ...)")
    allowed = sorted(s for s, targets in REVIEW_TRANSITIONS.items() if target in targets)
    from_where, binds = hits_from_where(filters)
    binds = {**binds, "allowed": allowed}
    eligible = [f"h.status = ANY(:allowed)"]
    if skip_questions:
        eligible.append(f"NOT {QUESTION}")
    if not include_human:
        eligible.append("h.reviewer IS NULL")
    if not include_harness:
        eligible.append(f"NOT {HARNESS}")
    elig = " AND ".join(eligible)

    counts = session.execute(text(f"""
        SELECT count(*) AS matched_all, count(*) FILTER (WHERE {elig}) AS matched,
               count(*) FILTER (WHERE h.reviewer IS NOT NULL AND h.status = ANY(:allowed)) AS human,
               count(*) FILTER (WHERE {HARNESS} AND h.reviewer IS NULL AND h.status = ANY(:allowed)) AS harness,
               count(*) FILTER (WHERE {QUESTION}) AS questions,
               count(*) FILTER (WHERE NOT (h.status = ANY(:allowed))) AS transition
        FROM {from_where}"""), binds).mappings().one()
    matched = int(counts["matched"] or 0)
    kept = {"human": int(counts["human"] or 0) if not include_human else 0,
            "harness": int(counts["harness"] or 0) if not include_harness else 0,
            "questions": int(counts["questions"] or 0) if skip_questions else 0,
            "transition": int(counts["transition"] or 0)}
    where_elig = f"{from_where} AND {elig}" if " WHERE " in from_where else f"{from_where} WHERE {elig}"
    by_status = {r["status"]: int(r["n"]) for r in session.execute(text(f"""
        SELECT h.status, count(*) AS n FROM {where_elig} GROUP BY 1"""), binds).mappings()}
    projects = [dict(r) for r in session.execute(text(f"""
        SELECT h.project_id, p.full_path AS project_path, count(*) AS n FROM {where_elig}
        GROUP BY 1, 2 ORDER BY n DESC, p.full_path LIMIT :top"""), {**binds, "top": BY_PROJECT_TOP + 1}).mappings()]
    for row in projects:
        row["n"] = int(row["n"])
    sample = [hit_id(r.rule_id, r.subject_key) for r in session.execute(text(f"""
        SELECT h.rule_id, h.subject_key FROM {where_elig} ORDER BY h.first_seen_at DESC NULLS LAST LIMIT :k"""),
        {**binds, "k": SAMPLE_IDS})]
    distinct_projects = session.execute(text(f"SELECT count(DISTINCT h.project_id) FROM {where_elig}"), binds).scalar()
    result = {
        "dry_run": dry_run, "action": action.value, "target_status": target, "matched": matched, "applied": 0,
        "cascaded": 0, "kept": kept, "by_status": by_status, "by_project": projects[:BY_PROJECT_TOP],
        "by_project_more": max(0, int(distinct_projects or 0) - BY_PROJECT_TOP), "sample": sample,
        "expected_total": expected_total, "batch_id": None,
        "filter": {k: v for k, v in filters.items()},
    }
    if dry_run:
        return result
    if expected_total is None:
        raise Invalid("expected_total is required to apply: pass the matched figure of the dry run")
    if int(expected_total) != matched:
        raise Conflict(f"the set changed: {matched} hits match now, the dry run said {expected_total} - run the "
                       "dry run again")
    if matched == 0:
        raise Invalid("nothing to decide: no hit of the filter can take this action")
    if matched > DECIDE_MAX:
        raise Invalid(f"at most {DECIDE_MAX} hits per decision: narrow the filter")
    if action == ReviewAction.request_info and not note:
        raise Invalid("request_info needs a note (what information is missing)")

    batch_id = session.execute(text("""
        INSERT INTO review_batches (filter, action, target_status, note, category, severity, reviewer, via,
                                    expected_total, matched, applied_at)
        VALUES (CAST(:filter AS jsonb), :action, :target, :note, :category, :severity, :reviewer, :via, :expected,
                :matched, now())
        RETURNING id"""), {
        "filter": json.dumps(filters, default=str), "action": action.value, "target": target, "note": note,
        "category": category, "severity": getattr(severity, "value", severity), "reviewer": reviewer, "via": via,
        "expected": int(expected_total), "matched": matched}).scalar()
    session.execute(text("SELECT set_config('discovery.batch_id', :b, true)"), {"b": str(batch_id)})
    prev = ", ".join(f"h.{c} AS prev_{c}" for c in PREV_COLUMNS)
    prev_cols = ", ".join(f"prev_{c}" for c in PREV_COLUMNS)
    session.execute(text(f"""
        INSERT INTO review_batch_items (batch_id, rule_id, subject_key, cascaded, {prev_cols})
        SELECT :b, h.rule_id, h.subject_key, false, {prev} FROM {where_elig}"""), {**binds, "b": batch_id})
    set_binds = {"target": target, "reviewer": reviewer, "category": category,
                 "severity": getattr(severity, "value", severity), "note": note, "via": via, "b": batch_id}
    applied = session.execute(text(f"""
        UPDATE rule_hits h SET {review_service.REVIEW_SET}
        FROM review_batch_items i
        WHERE i.batch_id = :b AND NOT i.cascaded AND h.rule_id = i.rule_id AND h.subject_key = i.subject_key
          AND h.status = i.prev_status"""), set_binds).rowcount or 0
    # cascade (as review_hit): object hits of LLM object rules with mark_fields decide the rule's service-tier field
    # hits of the same object too
    session.execute(text(f"""
        INSERT INTO review_batch_items (batch_id, rule_id, subject_key, cascaded, {prev_cols})
        SELECT DISTINCT :b, h.rule_id, h.subject_key, true, {prev}
        FROM review_batch_items i
        JOIN rules r ON r.id = i.rule_id AND r.kind = 'llm' AND r.target = 'object'
            AND COALESCE((r.scope ->> 'mark_fields')::boolean, false)
        JOIN rule_hits o ON o.rule_id = i.rule_id AND o.subject_key = i.subject_key AND o.field_name IS NULL
        JOIN rule_hits h ON h.rule_id = o.rule_id AND h.object_key = o.object_key AND h.field_name IS NOT NULL
            AND h.decided_tier = 'service'
        WHERE i.batch_id = :b AND NOT i.cascaded"""), {"b": batch_id})
    cascaded = session.execute(text(f"""
        UPDATE rule_hits h SET {review_service.REVIEW_SET}
        FROM review_batch_items i
        WHERE i.batch_id = :b AND i.cascaded AND h.rule_id = i.rule_id AND h.subject_key = i.subject_key
          AND h.decided_tier = 'service'"""), set_binds).rowcount or 0
    session.execute(text("UPDATE review_batches SET applied = :a, cascaded = :c WHERE id = :b"),
                    {"a": applied, "c": cascaded, "b": batch_id})
    result.update(applied=applied, cascaded=cascaded, batch_id=batch_id)
    return result


def get_batch(session: Session, batch_id: int) -> Dict[str, Any]:
    row = session.execute(text("SELECT * FROM review_batches WHERE id = :b"), {"b": int(batch_id)}).mappings().first()
    if row is None:
        raise NotFound(f"review batch {batch_id} not found")
    return dict(row)


def list_batches(session: Session, limit: int = 50, reviewer: Optional[str] = None) -> Dict[str, Any]:
    where, binds = "", {"limit": max(1, min(int(limit), 500))}
    if reviewer:
        where, binds["reviewer"] = " WHERE reviewer = :reviewer", reviewer
    return {"items": [dict(r) for r in session.execute(text(
        f"SELECT * FROM review_batches{where} ORDER BY id DESC LIMIT :limit"), binds).mappings()]}


def undo_batch(session: Session, batch_id: int, *, user: str, via: str = "rest") -> Dict[str, Any]:
    """``POST /hits/decide/{batch_id}/undo``: the hits of the batch nobody changed since (same status, reviewer and
    ``reviewed_at`` as the batch wrote them) get their previous state back; ``restored`` / ``skipped`` say how many."""
    batch = get_batch(session, batch_id)
    if batch["undone_at"] is not None:
        raise Conflict(f"review batch {batch_id} was already undone at {batch['undone_at'].isoformat()}")
    session.execute(text("SELECT set_config('discovery.batch_id', :b, true)"), {"b": str(batch_id)})
    session.execute(text("SELECT set_config('discovery.hit_source', 'undo', true)"))
    assignments = ", ".join(f"{c} = i.prev_{c}" for c in PREV_COLUMNS)
    restored = session.execute(text(f"""
        UPDATE rule_hits h SET {assignments}
        FROM review_batch_items i, review_batches b
        WHERE b.id = :b AND i.batch_id = b.id AND h.rule_id = i.rule_id AND h.subject_key = i.subject_key
          AND h.status = b.target_status AND h.reviewer = b.reviewer AND h.reviewed_at = b.applied_at"""),
        {"b": batch_id}).rowcount or 0
    total = session.execute(text("SELECT count(*) FROM review_batch_items WHERE batch_id = :b"), {"b": batch_id}).scalar()
    session.execute(text("""UPDATE review_batches SET undone_at = now(), undone_by = :u, restored = :r WHERE id = :b"""),
                    {"u": user, "r": restored, "b": batch_id})
    return {"batch_id": batch_id, "restored": restored, "skipped": int(total or 0) - restored, "undone_by": user,
            "note": "skipped hits were decided again after the batch and keep that later decision"}
