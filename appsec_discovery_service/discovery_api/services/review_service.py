"""Human review of rule hits, used by REST, UI and MCP alike.

A hit is one row of ``rule_hits`` (one per rule and subject, branch-agnostic); its API id
is ``"<rule_id>:<subject_key>"``. Transitions (``discovery_common.models.REVIEW_TRANSITIONS``):

    pending_review -> need_more_info | match | no_match
    need_more_info -> match | no_match
    any decided    -> pending_review (reopen)

The actions keep their reviewer verbs: confirm -> ``match``, reject -> ``no_match``, request_info ->
``need_more_info``, reopen -> ``pending_review``. The status filter also accepts the statuses before migration
0023 (``confirmed`` / ``rejected``) as aliases for one release; the output has the new ones only.

Every review records ``reviewer`` (the authenticated user) and ``reviewed_at`` (the first human decision
also keeps the status the service model had set in ``machine_status``: prompt trials compare the two) and makes the
hit's ``decided_tier`` ``human`` - it then wins over the service and the harness model (tiered workflow); the reviewer
may also change ``category`` / ``severity`` and set a ``note``. Scans never overwrite a
reviewed hit (the scanner only updates ``pending_review`` hits nobody reviewed, or reopened
ones once the rule's version is bumped) - with one exception: an LLM object rule asks again
about an object whose field names changed, and when the model then names a field not confirmed
before, the hit goes back to ``pending_review`` (the old decision in its note; otherwise the
decision is carried over, see the scanner's ``db_service._reasked_human_hits``).

``stale`` (``HitOut``, filter ``stale``): a machine verdict of an older version of its LLM rule (rule version, core
prompts, service model - ``discovery_common.lifecycle``): it is kept and scores until the rule's rollout asks it
again; ``stale_reason`` says what is pending.

Presence filter of the queue (``presence``): ``main`` - the subject is in some main branch;
``mr`` - only in open MRs (new/changed, not in main yet); ``live`` (default) - either;
``all`` - also hits whose subject is gone from every tracked branch. Presence is read from the stored flags
``rule_hits.in_main`` / ``in_open_mr`` (migration 0030, maintained by the scanner, ``discovery_common.presence``):
``main`` -> ``in_main``, ``mr`` -> ``in_open_mr AND NOT in_main``, ``live`` -> ``in_main OR in_open_mr``.

Paging (``services.paging``): the total is an estimate above ``COUNT_CAP`` unless ``exact``; ``after`` continues
after the last row of the previous page (keyset on the sort key + ``rule_id, subject_key``). ``group=<prefix>``
scopes the queue to a GitLab group (``full_path`` prefix); ``cluster=<by>:<key>`` to one cluster of
``GET /hits/clusters`` (``services.aggregate_service``). ``field_marks`` (true / false): only / never
the field hits an LLM object rule with ``mark_fields`` sets on the fields the model named.

Cascade: the review of such an object hit applies the same decision to its field hits of the rule that still carry
the service model's verdict (``decided_tier`` service; human and harness decisions on a field stay), ``cascaded`` in
the response counts them.
"""

import uuid
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from discovery_common import lifecycle
from discovery_common.models import LEGACY_HIT_STATUSES, REVIEW_TRANSITIONS
from schemas import (
    ACTION_STATUS, FieldContext, HitDetail, HitOut, HitStatus, ObjectContext, Presence, ReviewAction, RuleBrief,
    SiblingHit,
)
from services.errors import Conflict, Invalid, NotFound
from services.paging import (
    ListParams, Page, as_ints, as_list, decode_cursor, encode_cursor, escape_like, estimated_total, group_condition,
    keyset_condition, parse_timestamp,
)

PRESENCES = ("main", "mr", "live", "all")

# presence (contract 1): the stored flags instead of per-row EXISTS over branch_objects
PRESENCE_SQL = {"main": "h.in_main", "mr": "(h.in_open_mr AND NOT h.in_main)", "live": "(h.in_main OR h.in_open_mr)"}

# the GitLab group of a project: the first two levels of its path (``grp/payments/ledger`` -> ``grp/payments``)
GROUP_PATH_SQL = ("CASE WHEN position('/' in {path}) > 0 THEN split_part({path}, '/', 1) || '/' || split_part({path}, '/', 2) "
                  "ELSE {path} END")
# the schema signature of an object version: its type and sorted ``field:type`` pairs, without name and project
SCHEMA_SIG_SQL = ("md5(coalesce({o}.type, '') || '|' || coalesce((SELECT string_agg(f.field_name || ':' || "
                  "coalesce(f.field_type, ''), ',' ORDER BY f.field_name) FROM object_fields f "
                  "WHERE f.content_hash = {o}.content_hash), ''))")

SEVERITY_ORDER = ("CASE h.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 "
                  "WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END")

SORTABLE = {
    "first_seen_at": "h.first_seen_at", "last_seen_at": "h.last_seen_at", "reviewed_at": "h.reviewed_at",
    "status": "h.status", "category": "h.category", "severity": SEVERITY_ORDER, "project_id": "h.project_id",
    "rule_id": "h.rule_id", "field_name": "h.field_name", "object_name": "obj.name", "rule_name": "r.name",
    "project_path": "p.full_path", "id": "h.rule_id, h.subject_key",
}

HIT_COLUMNS = f"""h.*, r.name AS rule_name, r.kind AS rule_kind, (r.enabled IS NOT false) AS rule_enabled, r.tags AS rule_tags,
           r.version AS current_rule_version, p.full_path AS project_path,
           r.core_prompt_version AS rule_core_prompt_version, r.llm_model AS rule_llm_model, r.target AS rule_target,
           r.category AS rule_category, ({lifecycle.stale_sql()}) AS stale,
           obj.name AS object_name, obj.type AS object_type, obj.parser, obj.file"""
# one version of the hit's object (name, type, file): any stored one, as before
OBJECT_LATERAL = """LEFT JOIN LATERAL (SELECT o.name, o.type, o.parser, o.file, o.content_hash FROM objects o
                       WHERE o.object_key = h.object_key LIMIT 1) obj ON true"""
HIT_FROM = f"""
    FROM rule_hits h
    JOIN rules r ON r.id = h.rule_id
    LEFT JOIN gitlab_projects p ON p.id = h.project_id
    {OBJECT_LATERAL}
"""
SELECT_HITS = f"SELECT {HIT_COLUMNS}{HIT_FROM}"
# the filters that need the object version (``obj``) - the count skips the LATERAL join without them
OBJECT_FILTERS = ("q", "cluster", "object_type")

DECIDED_TIERS = ("service", "harness", "human")
# the tiers' names before migration 0021 (weak -> service, strong -> harness): accepted on input filters for one
# release, never returned
DECIDED_TIER_ALIASES = {"weak": "service", "strong": "harness"}


def hit_id(rule_id: int, subject_key) -> str:
    return f"{rule_id}:{subject_key}"


def parse_hit_id(value: str) -> Tuple[int, uuid.UUID]:
    try:
        rule_id, _, subject = str(value).partition(":")
        return int(rule_id), uuid.UUID(subject)
    except (ValueError, AttributeError):
        raise NotFound(f"hit {value!r} not found (expected '<rule_id>:<subject_key>')") from None


OPEN_STATUSES = ("pending_review", "need_more_info")


def normalize_statuses(statuses) -> List[str]:
    """Hit status filter values; the statuses before migration 0023 (``confirmed`` / ``rejected``) are accepted as
    aliases of ``match`` / ``no_match`` for one release."""
    return list(dict.fromkeys(LEGACY_HIT_STATUSES.get(str(s), s) for s in statuses))
# SQL of _decided_by, for the ``decided_by`` filter
DECIDED_BY_SQL = {
    "human": "h.reviewer IS NOT NULL",
    "machine": "h.reviewer IS NULL AND h.status IN ('match', 'no_match')",
}


def _decided_by(status, reviewer) -> Optional[str]:
    """'human' when a reviewer set the status, 'machine' for a final status set by a scan
    (auto rule, negative LLM verdict cached as no_match), None while the hit is open."""
    if reviewer:
        return "human"
    if status in OPEN_STATUSES:
        return None
    return "machine"


def _hit_out(row, cls=HitOut, **extra):
    data = dict(row)
    data["id"] = hit_id(data["rule_id"], data["subject_key"])
    data["subject_key"] = str(data["subject_key"])
    data["object_key"] = str(data["object_key"])
    data["decided_by"] = _decided_by(data.get("status"), data.get("reviewer"))
    tags = list(dict.fromkeys((data.pop("rule_tags", None) or []) + (data.get("tags") or [])))
    data["tags"] = tags or None
    data["stale_reason"] = lifecycle.stale_reason(data) if data.get("stale") else None
    data["allowed_actions"] = allowed_actions(data["status"])
    data.update(extra)
    return cls(**{k: v for k, v in data.items() if k in cls.model_fields})


# field hits an LLM object rule with mark_fields sets on the fields the model named (by-products of the object's
# verdict; the review of the object cascades to them)
FIELD_MARK = "(r.target = 'object' AND h.field_name IS NOT NULL)"


def _flag(filters: Dict[str, Any], name: str) -> bool:
    value = str(filters.pop(name)).lower()
    if value not in ("true", "false", "1", "0"):
        raise Invalid(f"{name} must be true or false")
    return value in ("true", "1")


def _conditions(filters: Dict[str, Any]) -> Tuple[List[str], Dict[str, Any]]:
    filters = dict(filters)
    where, params = [], {}

    def in_list(column, name, values, cast=None):
        values = [cast(v) for v in values] if cast else values
        where.append(f"{column} = ANY(:{name})")
        params[name] = values

    try:
        if "id" in filters:            # react-admin getMany
            keys = [parse_hit_id(v) for v in as_list(filters.pop("id"))]
            where.append("(" + " OR ".join(f"(h.rule_id = :idr{i} AND h.subject_key = :ids{i})"
                                           for i in range(len(keys))) + ")" if keys else "false")
            for i, (rule_id, subject) in enumerate(keys):
                params[f"idr{i}"], params[f"ids{i}"] = rule_id, subject
        if "project_id" in filters:
            in_list("h.project_id", "project_id", as_list(filters.pop("project_id")), int)
        if "group" in filters:
            where.append(group_condition("p.full_path", filters.pop("group"), params))
        if "status" in filters:
            statuses = normalize_statuses(as_list(filters.pop("status")))
            unknown = set(statuses) - {s.value for s in HitStatus}
            if unknown:
                raise Invalid(f"unknown status {sorted(unknown)}")
            in_list("h.status", "status", statuses)
        if "rule_id" in filters:
            in_list("h.rule_id", "rule_id", as_list(filters.pop("rule_id")), int)
        if "kind" in filters:
            in_list("r.kind", "kind", as_list(filters.pop("kind")))
        if "category" in filters:
            in_list("h.category", "category", as_list(filters.pop("category")), str)
        if "severity" in filters:
            in_list("h.severity", "severity", as_list(filters.pop("severity")), str)
        if "reviewer" in filters:
            in_list("h.reviewer", "reviewer", as_list(filters.pop("reviewer")), str)
        if "decided_by" in filters:
            values = as_list(filters.pop("decided_by"))
            unknown = set(values) - set(DECIDED_BY_SQL)
            if unknown:
                raise Invalid(f"decided_by must be one of {sorted(DECIDED_BY_SQL)}")
            where.append("(" + " OR ".join(f"({DECIDED_BY_SQL[v]})" for v in values) + ")")
        if "decided_via" in filters:
            in_list("h.decided_via", "decided_via", as_list(filters.pop("decided_via")), str)
        if "decided_tier" in filters:
            tiers = [DECIDED_TIER_ALIASES.get(str(t), t) for t in as_list(filters.pop("decided_tier"))]
            if set(tiers) - set(DECIDED_TIERS):
                raise Invalid("decided_tier must be service, harness or human")
            in_list("h.decided_tier", "decided_tier", tiers, str)
        if "asked_by_model" in filters:
            where.append("h.asked_by_model" if _flag(filters, "asked_by_model") else "NOT h.asked_by_model")
        if "field_marks" in filters:
            where.append(FIELD_MARK if _flag(filters, "field_marks") else f"NOT {FIELD_MARK}")
        if "reviewed_after" in filters:
            where.append("h.reviewed_at >= CAST(:reviewed_after AS timestamptz)")
            params["reviewed_after"] = parse_timestamp(filters.pop("reviewed_after"), "reviewed_after")
        if "first_seen_after" in filters:
            where.append("h.first_seen_at >= CAST(:first_seen_after AS timestamptz)")
            params["first_seen_after"] = parse_timestamp(filters.pop("first_seen_after"), "first_seen_after")
        if "stale" in filters:
            where.append(f"({lifecycle.stale_sql()})" if _flag(filters, "stale")
                         else f"NOT COALESCE(({lifecycle.stale_sql()}), false)")
        if "object_key" in filters:
            in_list("h.object_key", "object_key", as_list(filters.pop("object_key")), uuid.UUID)
        if "object_type" in filters:
            in_list("obj.type", "object_type", as_list(filters.pop("object_type")), str)
        if "q" in filters:
            where.append("(obj.name ILIKE :q ESCAPE '\\' OR h.field_name ILIKE :q ESCAPE '\\')")
            params["q"] = f"%{escape_like(str(filters.pop('q')))}%"
        if "cluster" in filters:
            where.append(cluster_condition(str(filters.pop("cluster")), params))
    except (TypeError, ValueError) as e:
        raise Invalid(f"bad filter value: {e}") from None

    presence = filters.pop("presence", "live")
    if presence not in PRESENCES:
        raise Invalid(f"presence must be one of {list(PRESENCES)}")
    if presence in PRESENCE_SQL:
        where.append(PRESENCE_SQL[presence])

    if filters:
        raise Invalid(f"unknown filters: {sorted(filters)}")
    return where, params


# ---- clusters: the key of a hit in each clustering (``GET /hits/clusters``, filter ``cluster=<by>:<key>``) -----

CLUSTER_KINDS = ("schema", "field_pattern", "object_name", "rule_group")
CLUSTER_SEP = "|"
# the cluster key of a hit ``h`` (object version ``obj``, project ``p``), as text; the condition of a filter compares it
CLUSTER_KEY_SQL = {
    "schema": SCHEMA_SIG_SQL.format(o="obj"),
    "field_pattern": f"CASE WHEN h.field_name IS NOT NULL THEN h.rule_id || '{CLUSTER_SEP}' || lower(h.field_name) END",
    "object_name": f"h.rule_id || '{CLUSTER_SEP}' || coalesce(obj.type, '') || '{CLUSTER_SEP}' || lower(coalesce(obj.name, ''))",
    "rule_group": f"h.rule_id || '{CLUSTER_SEP}' || coalesce({GROUP_PATH_SQL.format(path='p.full_path')}, '') "
                  f"|| '{CLUSTER_SEP}' || coalesce(obj.type, '')",
}


def parse_cluster(value: str) -> Tuple[str, str]:
    by, _, key = str(value).partition(":")
    if by not in CLUSTER_KINDS or not key:
        raise Invalid(f"cluster must be <by>:<key> with by one of {list(CLUSTER_KINDS)}")
    return by, key


def cluster_condition(value: str, params: Dict[str, Any]) -> str:
    by, key = parse_cluster(value)
    params["cluster_key"] = key
    if by == "schema":
        return f"({CLUSTER_KEY_SQL['schema']} = :cluster_key)"
    # the key starts with the rule id: narrow by rule first (index), then compare the key
    rule_id, _, _ = key.partition(CLUSTER_SEP)
    if not rule_id.isdigit():
        raise Invalid(f"cluster key of {by} must start with the rule id")
    params["cluster_rule"] = int(rule_id)
    return f"(h.rule_id = :cluster_rule AND {CLUSTER_KEY_SQL[by]} = :cluster_key)"


def _order(params: ListParams) -> Tuple[str, List[Tuple[str, bool]]]:
    """``(ORDER BY sql, keyset columns)`` of a hits list; every key sorts NULLS LAST."""
    if params.sort is not None and params.sort not in SORTABLE:
        raise Invalid(f"cannot sort by {params.sort!r}, allowed: {sorted(SORTABLE)}")
    sort = params.sort or "first_seen_at"
    desc = params.descending
    if sort == "id":
        columns = [("h.rule_id", desc), ("h.subject_key", desc)]
    else:
        columns = [(SORTABLE[sort], desc), ("h.rule_id", False), ("h.subject_key", False)]
    order_sql = ", ".join(f"{expr} {'DESC' if d else 'ASC'} NULLS LAST" for expr, d in columns)
    return order_sql, columns


def hits_from_where(filters: Dict[str, Any], with_object: bool = False) -> Tuple[str, Dict[str, Any]]:
    """``(FROM ... WHERE ..., binds)`` of a filtered hits set (lists, counts, aggregates, decisions). The object
    version (``obj``) is joined only when a filter needs it or ``with_object`` asks for it."""
    where, binds = _conditions(filters)
    lateral = f" {OBJECT_LATERAL}" if with_object or any(k in filters for k in OBJECT_FILTERS) else ""
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    from_sql = (f"rule_hits h JOIN rules r ON r.id = h.rule_id LEFT JOIN gitlab_projects p ON p.id = h.project_id"
                f"{lateral}{where_sql}")
    return from_sql, binds


def list_hits(session: Session, params: ListParams) -> Page:
    where, binds = _conditions(params.filters)
    order_sql, columns = _order(params)
    from_where, count_binds = hits_from_where(params.filters)
    total, is_estimate = estimated_total(session, from_where, count_binds, exact=params.exact)

    where = list(where)
    if params.after:
        values = decode_cursor(params.after, params.sort or "first_seen_at", len(columns))
        where.append(keyset_condition(columns, values, binds))
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    keys = ", ".join(f"({expr}) AS sort_key_{i}" for i, (expr, _) in enumerate(columns))
    rows = session.execute(
        text(f"SELECT {HIT_COLUMNS}, {keys}{HIT_FROM}{where_sql} ORDER BY {order_sql} LIMIT :limit OFFSET :offset"),
        {**binds, "limit": params.limit + 1, "offset": params.offset},
    ).mappings().all()
    more = len(rows) > params.limit
    rows = rows[:params.limit]
    next_cursor = None
    if more and rows:
        last = rows[-1]
        next_cursor = encode_cursor(params.sort or "first_seen_at", [last[f"sort_key_{i}"] for i in range(len(columns))])
    return Page([_hit_out(row) for row in rows], total, is_estimate, next_cursor)


def _load(session: Session, rule_id: int, subject: uuid.UUID):
    row = session.execute(text(f"{SELECT_HITS} WHERE h.rule_id = :r AND h.subject_key = :s"),
                          {"r": rule_id, "s": subject}).mappings().first()
    if row is None:
        raise NotFound(f"hit {hit_id(rule_id, subject)} not found")
    return row


def get_hit(session: Session, value: str) -> HitOut:
    return _hit_out(_load(session, *parse_hit_id(value)))


def allowed_actions(status: str) -> List[str]:
    targets = REVIEW_TRANSITIONS.get(status, set())
    return [action.value for action, target in ACTION_STATUS.items() if target in targets]


def get_hit_detail(session: Session, value: str) -> HitDetail:
    rule_id, subject = parse_hit_id(value)
    row = _load(session, rule_id, subject)

    rule = session.execute(text("SELECT * FROM rules WHERE id = :r"), {"r": rule_id}).mappings().one()

    versions = session.execute(text("""
        SELECT b.branch_id, g.branch_name, b.is_main, b.change, b.line, b.field_lines, b.content_hash,
               m.mr_id AS mr_iid, m.title AS mr_title
        FROM branch_objects b
        JOIN gitlab_branches g ON g.id = b.branch_id
        LEFT JOIN gitlab_mrs m ON m.source_branch_id = b.branch_id AND m.state = 'opened'
        WHERE b.object_key = :k AND b.branch_id IN (SELECT id FROM gitlab_branches WHERE project_id = :p)
        ORDER BY b.is_main DESC, m.mr_id
    """), {"k": row["object_key"], "p": row["project_id"]}).mappings().all()

    presence = [Presence(branch_id=v["branch_id"], branch_name=v["branch_name"], is_main=v["is_main"],
                         change=v["change"], mr_iid=v["mr_iid"], mr_title=v["mr_title"]) for v in versions]

    live = [v for v in versions if v["content_hash"] is not None]
    chosen = next((v for v in live if v["is_main"]), None) or (live[0] if live else None)
    if chosen is not None:
        version = session.execute(text("SELECT * FROM objects WHERE content_hash = :h"),
                                  {"h": chosen["content_hash"]}).mappings().one()
        source, field_lines, line = ("main" if chosen["is_main"] else "mr"), chosen["field_lines"] or {}, chosen["line"]
    else:
        version = session.execute(text("SELECT * FROM objects WHERE object_key = :k LIMIT 1"),
                                  {"k": row["object_key"]}).mappings().first()
        source, field_lines, line = "orphan", {}, None

    obj = None
    if version is not None:
        fields = session.execute(text(
            "SELECT field_name, field_type FROM object_fields WHERE content_hash = :h ORDER BY field_name"),
            {"h": version["content_hash"]}).all()
        obj = ObjectContext(
            object_key=str(version["object_key"]), content_hash=str(version["content_hash"]), name=version["name"],
            type=version["type"], parser=version["parser"], file=version["file"], line=line,
            props=version["props"], source=source,
            fields=[FieldContext(name=f.field_name, type=f.field_type, line=field_lines.get(f.field_name),
                                 is_subject=(f.field_name == row["field_name"]
                                             or f.field_name in (row.get("fields") or []))) for f in fields],
        )

    siblings = session.execute(text("""
        SELECT h.rule_id, h.subject_key, r.name AS rule_name, h.field_name, h.status, h.category, h.severity
        FROM rule_hits h JOIN rules r ON r.id = h.rule_id
        WHERE h.object_key = :k AND NOT (h.rule_id = :r AND h.subject_key = :s)
        ORDER BY h.field_name NULLS FIRST, r.name
    """), {"k": row["object_key"], "r": rule_id, "s": subject}).mappings().all()

    return _hit_out(
        row, HitDetail,
        rule=RuleBrief(id=rule["id"], name=rule["name"], kind=rule["kind"], target=rule["target"], mode=rule["mode"],
                       version=rule["version"], enabled=rule["enabled"] is not False, prompt=rule["prompt"]),
        object=obj, presence=presence,
        other_hits=[SiblingHit(id=hit_id(s["rule_id"], s["subject_key"]), rule_name=s["rule_name"],
                               field_name=s["field_name"], status=s["status"], category=s["category"],
                               severity=s["severity"]) for s in siblings],
        allowed_actions=allowed_actions(row["status"]),
        service_reason=_service_reason(session, row),
    )


def _service_reason(session: Session, row) -> Optional[str]:
    """The service model's reason for the hit's current rule version: the latest service-tier row of the verdict
    history (kept when a human or the harness model decided since); the hit's own reason while the service verdict is
    the current one (keyword / manual hits have none)."""
    if row["rule_kind"] != "llm":
        return None
    reason = session.execute(text("""
        SELECT reason FROM hit_verdicts
        WHERE rule_id = :r AND subject_key = :s AND decided_tier = 'service' AND rule_version = :v
        ORDER BY id DESC LIMIT 1"""), {"r": row["rule_id"], "s": row["subject_key"], "v": row["rule_version"]}).first()
    if reason is not None:
        return reason[0]
    return row["reason"] if row["decided_tier"] == "service" else None


def review_hit(session: Session, value: str, action, reviewer: str, *, category: Optional[str] = None,
               severity: Optional[str] = None, note: Optional[str] = None, via: str = "rest") -> HitOut:
    """Apply a review action (confirm / reject / request_info / reopen). ``via``: rest | mcp."""
    rule_id, subject = parse_hit_id(value)
    try:
        action = ReviewAction(getattr(action, "value", action))
    except ValueError:
        raise Invalid(f"unknown action {action!r}, expected one of {[a.value for a in ReviewAction]}") from None
    hit = _load(session, rule_id, subject)
    current = hit["status"]
    target = ACTION_STATUS[action]
    if target not in REVIEW_TRANSITIONS.get(current, set()):
        raise Conflict(f"cannot {action.value} a hit in status {current!r} "
                       f"(allowed: {allowed_actions(current) or 'none'})")
    if action == ReviewAction.request_info and not note:
        raise Invalid("request_info needs a note (what information is missing)")

    binds = {"target": target, "reviewer": reviewer, "category": category,
             "severity": getattr(severity, "value", severity), "note": note, "via": via, "r": rule_id, "s": subject}
    updated = session.execute(text(f"""
        UPDATE rule_hits SET {REVIEW_SET}
        WHERE rule_id = :r AND subject_key = :s AND status = :current
    """), {**binds, "current": current}).rowcount
    if not updated:
        raise Conflict("the hit was changed concurrently, reload it and try again")
    cascaded = None
    if _cascades_to_fields(session, hit):
        # the fields the model named carry the object's verdict (mark_fields): the human's decision on the object
        # applies to them too, unless a human or the harness model decided a field on its own
        cascaded = session.execute(text(f"""
            UPDATE rule_hits SET {REVIEW_SET}
            WHERE rule_id = :r AND object_key = :o AND field_name IS NOT NULL AND decided_tier = 'service'
        """), {**binds, "o": hit["object_key"]}).rowcount
    return _hit_out(_load(session, rule_id, subject), cascaded=cascaded)


REVIEW_SET = """status = :target, reviewer = :reviewer, reviewed_at = now(), decided_via = :via,
               machine_status = CASE WHEN reviewer IS NULL AND decided_tier = 'service' THEN status
                                     ELSE machine_status END,
               decided_tier = 'human', asked_by_model = false,
               category = COALESCE(:category, category), severity = COALESCE(:severity, severity),
               note = COALESCE(:note, note)"""


def _cascades_to_fields(session: Session, hit) -> bool:
    """An object hit of an LLM rule with ``mark_fields``: its review cascades to the rule's field hits of the object."""
    if hit["rule_kind"] != "llm" or hit["field_name"] is not None or hit["rule_target"] != "object":
        return False
    scope = session.execute(text("SELECT scope FROM rules WHERE id = :r"), {"r": hit["rule_id"]}).scalar() or {}
    return bool(scope.get("mark_fields"))


def update_hit(session: Session, value: str, reviewer: str, *, category: Optional[str] = None,
               severity: Optional[str] = None, note: Optional[str] = None, via: str = "rest") -> HitOut:
    """Change category / severity / note of a hit without a status transition. The change is
    a human decision: it is recorded (reviewer, reviewed_at) and scans keep it."""
    rule_id, subject = parse_hit_id(value)
    _load(session, rule_id, subject)
    if category is None and severity is None and note is None:
        raise Invalid("nothing to update: set category, severity and/or note")
    session.execute(text("""
        UPDATE rule_hits SET reviewer = :reviewer, reviewed_at = now(), decided_via = :via,
               machine_status = CASE WHEN reviewer IS NULL AND decided_tier = 'service' THEN status
                                     ELSE machine_status END,
               decided_tier = 'human', asked_by_model = false,
               category = COALESCE(:category, category), severity = COALESCE(:severity, severity),
               note = COALESCE(:note, note)
        WHERE rule_id = :r AND subject_key = :s
    """), {"reviewer": reviewer, "category": category, "severity": getattr(severity, "value", severity),
           "note": note, "via": via, "r": rule_id, "s": subject})
    return _hit_out(_load(session, rule_id, subject))


PROJECT_SORTABLE = {"id": "p.id", "full_path": "p.full_path", "pending_hits": "pending_hits", "scan_mode": "p.scan_mode"}
PROJECT_FILTERS = ("q", "id", "scan_mode", "group", "source", "severity", "tag")


def _project_conditions(filters: Dict[str, Any]) -> Tuple[List[str], Dict[str, Any]]:
    filters = dict(filters)
    where, binds = [], {}
    if "q" in filters:
        where.append("p.full_path ILIKE :q ESCAPE '\\'")
        binds["q"] = f"%{escape_like(str(filters.pop('q')))}%"
    if "id" in filters:
        where.append("p.id = ANY(:ids)")
        binds["ids"] = as_ints(filters.pop("id"))
    if "scan_mode" in filters:
        where.append("p.scan_mode = ANY(:modes)")
        binds["modes"] = [str(v) for v in as_list(filters.pop("scan_mode"))]
    if "group" in filters:
        where.append(group_condition("p.full_path", filters.pop("group"), binds))
    if "source" in filters:
        where.append("p.source = ANY(:sources)")
        binds["sources"] = [str(v) for v in as_list(filters.pop("source"))]
    if "severity" in filters:
        where.append("p.severity = ANY(:severities)")
        binds["severities"] = [str(v) for v in as_list(filters.pop("severity"))]
    if "tag" in filters:
        where.append("COALESCE(p.tags, '{}') @> CAST(:ptags AS text[])")
        binds["ptags"] = [str(v) for v in as_list(filters.pop("tag"))]
    if filters:
        raise Invalid(f"unknown filters: {sorted(filters)}")
    return where, binds


PENDING_HITS_SQL = ("(SELECT count(*) FROM rule_hits h WHERE h.project_id = p.id "
                    "AND h.status IN ('pending_review', 'need_more_info') AND (h.in_main OR h.in_open_mr))")


def list_projects(session: Session, params: ListParams) -> Page:
    """``GET /projects``: filters ``q``, ``id``, ``scan_mode``, ``group`` (full_path prefix), ``source``, ``severity``,
    ``tag``; each row with ``pending_hits`` (open, live), the parse state (``scan``) and the LLM coverage (``llm``)."""
    where, binds = _project_conditions(params.filters)
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    total, is_estimate = estimated_total(session, f"gitlab_projects p{where_sql}", binds, exact=params.exact)
    if params.sort is not None and params.sort not in PROJECT_SORTABLE:
        raise Invalid(f"cannot sort by {params.sort!r}, allowed: {sorted(PROJECT_SORTABLE)}")
    sort = params.sort or "full_path"
    columns = [(PROJECT_SORTABLE[sort], params.descending)] + ([("p.id", False)] if sort != "id" else [])
    page_where = list(where)
    if params.after:
        if sort == "pending_hits":
            raise Invalid("after (keyset paging) is not available with sort=pending_hits, use range")
        page_where.append(keyset_condition(columns, decode_cursor(params.after, sort, len(columns)), binds))
    page_where_sql = (" WHERE " + " AND ".join(page_where)) if page_where else ""
    order = ", ".join(f"{expr} {'DESC' if d else 'ASC'} NULLS LAST" for expr, d in columns)
    rows = session.execute(text(f"""
        SELECT p.id, p.full_path, p.project_name, p.scan_mode, p.source, p.severity, p.tags,
               {GROUP_PATH_SQL.format(path='p.full_path')} AS group_path, {PENDING_HITS_SQL} AS pending_hits
        FROM gitlab_projects p{page_where_sql} ORDER BY {order} LIMIT :limit OFFSET :offset
    """), {**binds, "limit": params.limit + 1, "offset": params.offset}).mappings().all()
    more = len(rows) > params.limit
    rows = rows[:params.limit]
    items = [dict(r) for r in rows]
    next_cursor = None
    if more and items and sort != "pending_hits":      # pending_hits is computed per row: offset paging only
        last = items[-1]
        values = [last[sort]] + ([last["id"]] if sort != "id" else [])
        next_cursor = encode_cursor(sort, values)
    # parse scan state of the page's projects (main branch, job, open MRs): GET /scan_progress
    from services.scan_progress_service import project_states
    states = project_states(session, [r["id"] for r in items])
    # LLM rule coverage of the page's projects (scan mode rules only): GET /llm_progress
    from services.llm_progress_service import project_states as llm_states
    llm = llm_states(session, [r["id"] for r in items])
    for item in items:
        item["scan"] = states.get(item["id"])
        item["llm"] = llm.get(item["id"])
    return Page(items, total, is_estimate, next_cursor)


PROJECT_JOBS = 20


def get_project(session: Session, project_id: int, detail: bool = True) -> dict:
    """``GET /projects/{id}`` (react-admin getOne / reference fields; the project page). With ``detail``: the parse
    state and LLM coverage (``scan``, ``llm``, as the list rows), ``hits_by_rule`` (match / no_match / open /
    questions per rule, live hits), ``objects_by_type`` (main snapshot), ``objects_in_open_mrs``, ``open_mrs`` and the
    last ``jobs`` of the project (newest first; ``GET /jobs?filter={"project_id": id}`` pages them)."""
    row = session.execute(text(f"""
        SELECT p.id, p.full_path, p.project_name, p.scan_mode, p.source, p.severity, p.tags, p.description,
               p.default_branch, p.visibility, p.created_at, p.updated_at, p.processed_at,
               {GROUP_PATH_SQL.format(path='p.full_path')} AS group_path, {PENDING_HITS_SQL} AS pending_hits
        FROM gitlab_projects p WHERE p.id = :id
    """), {"id": project_id}).mappings().first()
    if row is None:
        raise NotFound(f"project {project_id} not found")
    out = dict(row)
    if not detail:
        return out
    from services import jobs_service
    from services.llm_progress_service import project_states as llm_states
    from services.scan_progress_service import project_states
    out["scan"] = project_states(session, [project_id]).get(project_id)
    out["llm"] = llm_states(session, [project_id]).get(project_id)
    out["hits_by_rule"] = [dict(r) for r in session.execute(text("""
        SELECT r.id AS rule_id, r.name AS rule_name, r.kind, r.category,
               count(*) FILTER (WHERE h.status = 'match') AS match,
               count(*) FILTER (WHERE h.status = 'no_match') AS no_match,
               count(*) FILTER (WHERE h.status IN ('pending_review', 'need_more_info')) AS open,
               count(*) FILTER (WHERE h.status = 'need_more_info' AND h.asked_by_model) AS questions
        FROM rule_hits h JOIN rules r ON r.id = h.rule_id
        WHERE h.project_id = :p AND (h.in_main OR h.in_open_mr)
        GROUP BY 1, 2, 3, 4 ORDER BY open DESC, match DESC, r.name"""), {"p": project_id}).mappings()]
    out["objects_by_type"] = [dict(r) for r in session.execute(text("""
        SELECT o.type, count(*) AS n FROM branch_objects b
        JOIN gitlab_branches g ON g.id = b.branch_id AND g.project_id = :p AND g.is_main
        JOIN objects o ON o.content_hash = b.content_hash
        WHERE b.is_main GROUP BY 1 ORDER BY 2 DESC"""), {"p": project_id}).mappings()]
    out["objects_in_open_mrs"] = session.execute(text("""
        SELECT count(DISTINCT b.object_key) FROM gitlab_mrs m
        JOIN branch_objects b ON b.branch_id = m.source_branch_id AND NOT b.is_main AND b.content_hash IS NOT NULL
        WHERE m.project_id = :p AND m.state = 'opened'"""), {"p": project_id}).scalar() or 0
    out["open_mrs"] = session.execute(text("SELECT count(*) FROM gitlab_mrs WHERE project_id = :p AND state = 'opened'"),
                                      {"p": project_id}).scalar() or 0
    out["jobs"] = jobs_service.project_jobs(session, project_id, PROJECT_JOBS)
    return out


BULK_MAX = 50


def review_hits_bulk(session: Session, hit_ids: List[str], action, reviewer: str, *, note: Optional[str],
                     category: Optional[str] = None, severity: Optional[str] = None, dry_run: bool = True,
                     via: str = "rest") -> Dict[str, Any]:
    """The same review action on up to ``BULK_MAX`` hits, one transaction, a note required.
    ``dry_run`` (default) only reports what would change. Each item: ``ok`` (with the new
    status), ``conflict`` (transition not allowed / changed concurrently) or ``not_found``."""
    ids = list(dict.fromkeys(str(h) for h in hit_ids or []))
    if not ids:
        raise Invalid("hit_ids is empty")
    if len(ids) > BULK_MAX:
        raise Invalid(f"at most {BULK_MAX} hits per call")
    if not note or not str(note).strip():
        raise Invalid("a bulk review needs a note (why these hits get the same decision)")
    try:
        action = ReviewAction(getattr(action, "value", action))
    except ValueError:
        raise Invalid(f"unknown action {action!r}, expected one of {[a.value for a in ReviewAction]}") from None

    items, changed = [], 0
    for value in ids:
        try:
            rule_id, subject = parse_hit_id(value)
            current = _load(session, rule_id, subject)["status"]
        except NotFound:
            items.append({"id": value, "result": "not_found"})
            continue
        target = ACTION_STATUS[action]
        if target not in REVIEW_TRANSITIONS.get(current, set()):
            items.append({"id": value, "result": "conflict", "status": current,
                          "allowed": allowed_actions(current)})
            continue
        if dry_run:
            items.append({"id": value, "result": "ok", "status": current, "would_be": target})
            continue
        try:
            hit = review_hit(session, value, action, reviewer, category=category, severity=severity, note=note, via=via)
        except Conflict as e:
            items.append({"id": value, "result": "conflict", "error": str(e)})
            continue
        changed += 1
        item = {"id": value, "result": "ok", "status": hit.status}
        if hit.cascaded is not None:
            item["cascaded"] = hit.cascaded
        items.append(item)
    return {"dry_run": dry_run, "action": action.value, "changed": changed, "items": items}


def request_human(session: Session, value: str, question: str, *, user: str, model: Optional[str] = None,
                  via: str = "mcp") -> Dict[str, Any]:
    """The harness model asks a human about a machine hit of an LLM rule: ``need_more_info``, tier
    harness, ``asked_by_model`` (review tab "Questions from the model"), the question in the note; its open verify
    item is closed. Refused for a hit a human decided (``discovery_common.llm_verify.request_human``)."""
    from discovery_common import llm_verify
    from discovery_common.llm_work import model_label
    rule_id, subject = parse_hit_id(value)
    try:
        result = llm_verify.request_human(session, rule_id, subject, question,
                                          model=model_label(model or "harness", via), user=user)
    except LookupError:
        raise NotFound(f"hit {value} not found") from None
    except llm_verify.RequestError as e:
        raise Conflict(str(e)) from None
    result["hit"] = _hit_out(_load(session, rule_id, subject)).model_dump(mode="json", exclude_none=True)
    return result
