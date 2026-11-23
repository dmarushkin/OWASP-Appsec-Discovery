"""Projects' scan mode, the object inventory and manual labels.

``inventory`` projects are scanned without categorisation (no keyword / LLM rules); people
browse the stored objects and label objects or fields by hand. A label is a hit of the
built-in ``manual:labels`` rule (kind ``manual``): status ``match`` with the reviewer
set, so scans never overwrite it, and it shows up in ``/hits`` like any other decision.
Removing a label deletes that hit.
"""

import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from discovery_common import keys, presence
from discovery_common.models import MANUAL_RULE, SCAN_MODES
from services import review_service
from services.errors import Invalid, NotFound
from schemas import PATTERN_MAX
from services.paging import (
    ListParams, Page, as_list, decode_cursor, encode_cursor, escape_like, estimated_total, group_condition,
    keyset_condition,
)

PRESENCES = ("main", "mr", "live")


# ---- scan mode -------------------------------------------------------------------------------

def set_scan_mode(session: Session, project_id: int, scan_mode: str, *, requested_by: Optional[str] = None,
                  parse: bool = True) -> Dict[str, Any]:
    """Switch a project between ``rules`` and ``inventory``.

    To inventory: the open machine hits of keyword / LLM rules (no reviewer) are deleted, so
    the review queue of the project only holds what people label; human decisions and manual
    labels stay. Either way the project is parsed again (the scan marker includes the mode)."""
    from services import jobs_service

    if scan_mode not in SCAN_MODES:
        raise Invalid(f"scan_mode must be one of {list(SCAN_MODES)}")
    current = session.execute(text("SELECT scan_mode FROM gitlab_projects WHERE id = :p"), {"p": project_id}).scalar()
    if current is None:
        raise NotFound(f"project {project_id} not found")

    removed = 0
    if scan_mode != current:
        session.execute(text("UPDATE gitlab_projects SET scan_mode = :m WHERE id = :p"), {"m": scan_mode, "p": project_id})
        if scan_mode == "inventory":
            removed = session.execute(text("""
                DELETE FROM rule_hits h USING rules r
                WHERE r.id = h.rule_id AND h.project_id = :p AND h.reviewer IS NULL AND r.kind IN ('keyword', 'llm')
            """), {"p": project_id}).rowcount

    result = {"project": review_service.get_project(session, project_id), "previous_scan_mode": current,
              "removed_machine_hits": removed}
    if parse and scan_mode != current:
        result["parse"] = jobs_service.request_parse(session, [project_id], llm=(scan_mode == "rules"),
                                                     requested_by=requested_by)
    return result


# ---- objects ---------------------------------------------------------------------------------

# open-MR rows (the delta of an MR in state opened) of an object
MR_ROW_SQL = ("NOT b.is_main AND b.content_hash IS NOT NULL AND EXISTS (SELECT 1 FROM gitlab_mrs m "
              "WHERE m.source_branch_id = b.branch_id AND m.state = 'opened')")

LABELS_SQL = ("(SELECT count(*) FROM rule_hits h JOIN rules r ON r.id = h.rule_id "
              "WHERE r.kind = 'manual' AND h.object_key = {key})")

# an object's tags: the rules' tags (and a manual label's own tags) of its match hits
OBJECT_TAGS_SQL = """(SELECT array_agg(DISTINCT t ORDER BY t)
    FROM rule_hits h JOIN rules r ON r.id = h.rule_id,
         unnest(COALESCE(r.tags, '{{}}'::text[]) || COALESCE(h.tags, '{{}}'::text[])) t
    WHERE h.object_key = {key} AND h.status = 'match')"""
FIELDS_SQL = "(SELECT count(*) FROM object_fields f WHERE f.content_hash = {hash})"

# sort keys of the page; ``labels`` / ``fields`` are counted per row (they sort the whole filtered set: slow at
# scale, kept for the UI's column sort)
SORTABLE = {"name": "x.name", "type": "x.type", "file": "x.file", "parser": "x.parser", "labels": "labels",
            "fields": "fields", "project_path": "x.project_path"}
COMPUTED_SORTS = {"labels": LABELS_SQL.format(key="x.object_key"), "fields": FIELDS_SQL.format(hash="x.content_hash")}

OBJECT_COLUMNS = ("o.object_key, o.content_hash, o.name, o.type, o.parser, o.file, o.comment, g.project_id, "
                  "p.full_path AS project_path, b.is_main, b.line")


def _conditions(filters: Dict[str, Any], session: Session) -> Tuple[List[str], List[str], Dict[str, Any], bool]:
    """``(conditions on the version row, conditions on the object key, binds, include_fields)``. Version conditions
    reference ``o`` (objects), ``b`` (branch_objects), ``g`` (branch), ``p`` (project); key conditions ``x.object_key``
    (hits of the object, any version)."""
    where, by_key, binds = [], [], {}
    try:
        if "project_id" in filters:
            where.append("g.project_id = ANY(:projects)")
            binds["projects"] = [int(v) for v in as_list(filters.pop("project_id"))]
    except (TypeError, ValueError):
        raise Invalid("project_id must be integers") from None
    if "project_glob" in filters:
        from services.insights_service import glob_to_like
        where.append("p.full_path LIKE :pglob ESCAPE '\\'")
        binds["pglob"] = glob_to_like(str(filters.pop("project_glob")))
    if "group" in filters:
        where.append(group_condition("p.full_path", filters.pop("group"), binds))
    fields_all = as_list(filters.pop("fields_all")) if "fields_all" in filters else []
    fields_none = as_list(filters.pop("fields_none")) if "fields_none" in filters else []
    for name, patterns in (("fields_all", fields_all), ("fields_none", fields_none)):
        if len(patterns) > FIELD_PATTERNS_MAX:
            raise Invalid(f"{name}: at most {FIELD_PATTERNS_MAX} patterns")
        for pattern in patterns:
            _check_regex(session, pattern)
    for i, pattern in enumerate(fields_all):
        where.append(f"EXISTS (SELECT 1 FROM object_fields f WHERE f.content_hash = o.content_hash AND f.field_name ~* :fa{i})")
        binds[f"fa{i}"] = str(pattern)
    for i, pattern in enumerate(fields_none):
        where.append(f"NOT EXISTS (SELECT 1 FROM object_fields f WHERE f.content_hash = o.content_hash AND f.field_name ~* :fn{i})")
        binds[f"fn{i}"] = str(pattern)
    if "field_type" in filters:
        where.append("EXISTS (SELECT 1 FROM object_fields f WHERE f.content_hash = o.content_hash "
                     "AND f.field_type ILIKE :ftype ESCAPE '\\')")
        binds["ftype"] = f"%{escape_like(str(filters.pop('field_type')))}%"
    include_fields = _truthy(filters.pop("include_fields", False))
    if "q" in filters:
        where.append("(o.name ILIKE :q ESCAPE '\\' OR o.file ILIKE :q ESCAPE '\\')")
        binds["q"] = f"%{escape_like(str(filters.pop('q')))}%"
    if "field" in filters:
        where.append("EXISTS (SELECT 1 FROM object_fields f WHERE f.content_hash = o.content_hash "
                     "AND f.field_name ILIKE :field ESCAPE '\\')")
        binds["field"] = f"%{escape_like(str(filters.pop('field')))}%"
    if "comment" in filters:
        where.append("(o.comment ILIKE :comment ESCAPE '\\' OR EXISTS (SELECT 1 FROM object_fields f "
                     "WHERE f.content_hash = o.content_hash AND f.comment ILIKE :comment ESCAPE '\\'))")
        binds["comment"] = f"%{escape_like(str(filters.pop('comment')))}%"
    if "type" in filters:
        where.append("o.type = ANY(:types)")
        binds["types"] = [str(v) for v in as_list(filters.pop("type"))]
    if "parser" in filters:
        where.append("o.parser = ANY(:parsers)")
        binds["parsers"] = [str(v) for v in as_list(filters.pop("parser"))]
    if "id" in filters:                 # react-admin getMany
        by_key.append("x.object_key = ANY(CAST(:ids AS uuid[]))")
        binds["ids"] = [str(_parse_key(v)) for v in as_list(filters.pop("id"))]
    labelled = filters.pop("labelled", None)
    if labelled is not None:
        by_key.append(f"{LABELS_SQL.format(key='x.object_key')} {'>' if _truthy(labelled) else '='} 0")
    if "tag" in filters:
        by_key.append(f"COALESCE({OBJECT_TAGS_SQL.format(key='x.object_key')}, '{{}}'::text[]) @> CAST(:tags AS text[])")
        binds["tags"] = [str(t) for t in as_list(filters.pop("tag"))]
    has_open = filters.pop("has_open_hits", None)
    if has_open is not None:
        by_key.append(("" if _truthy(has_open) else "NOT ") + "EXISTS (SELECT 1 FROM rule_hits h WHERE h.object_key = "
                      "x.object_key AND h.status IN ('pending_review', 'need_more_info'))")
    decided = filters.pop("decided", None)
    if decided is not None:
        by_key.append(("" if _truthy(decided) else "NOT ") + "EXISTS (SELECT 1 FROM rule_hits h WHERE h.object_key = "
                      "x.object_key AND h.reviewer IS NOT NULL)")
    if filters:
        raise Invalid(f"unknown filters: {sorted(filters)}")
    return where, by_key, binds, include_fields


def _live_rows(presence: str, where: List[str]) -> str:
    """One row per live object as ``x``. ``main``: the main rows themselves - an object has at most one main row
    (one main branch per project, ``object_key`` holds the project), so no DISTINCT ON and no sort of every live
    object: the page comes from ``objects_name_key`` with a semi-join on the main rows. ``mr`` / ``live``: the
    open-MR rows (a few percent of the objects) de-duplicated, for ``live`` after the main rows (an object in main
    and in an MR is listed once, its main version)."""
    cond = (" AND " + " AND ".join(where)) if where else ""
    base = """FROM objects o
        JOIN branch_objects b ON b.content_hash = o.content_hash
        JOIN gitlab_branches g ON g.id = b.branch_id
        JOIN gitlab_projects p ON p.id = g.project_id"""
    main = f"SELECT {OBJECT_COLUMNS} {base} WHERE b.is_main{cond}"
    mr = f"""SELECT DISTINCT ON (o.object_key) {OBJECT_COLUMNS} {base} WHERE {MR_ROW_SQL}{cond}
             AND NOT EXISTS (SELECT 1 FROM objects o2 JOIN branch_objects b2 ON b2.content_hash = o2.content_hash AND b2.is_main
                             WHERE o2.object_key = o.object_key)
             ORDER BY o.object_key, b.branch_id"""
    if presence == "main":
        return main
    if presence == "mr":
        return mr
    return f"({main}) UNION ALL ({mr})"


def list_objects(session: Session, params: ListParams) -> Page:
    """Live objects (one row per object, the main version first): filters ``project_id``,
    ``group`` (full_path prefix), ``q`` (object name or file), ``field`` (has a field whose name contains it),
    ``type``, ``parser``, ``presence`` (main | mr | live, default main), ``labelled`` (true / false),
    ``tag`` (has every given tag, see ``OBJECT_TAGS_SQL``), ``project_glob`` (``grp/*``),
    ``fields_all`` / ``fields_none`` (field-name regexes, case-insensitive: has a field for each
    / for none), ``field_type`` (has a field of this type, substring), ``comment`` (the code comment
    of the object or of one of its fields contains it), ``has_open_hits`` and
    ``decided`` (true / false: hits waiting for review / decided by a human), ``include_fields``
    (true: the field names of each object in the result). The per-row figures (``fields``, ``labels``, ``tags``)
    are computed for the page only; the total is estimated above COUNT_CAP (``exact`` for an exact count)."""
    filters = dict(params.filters)
    presence = filters.pop("presence", "main")
    if presence not in PRESENCES:
        raise Invalid(f"presence must be one of {list(PRESENCES)}")
    where, by_key, binds, include_fields = _conditions(filters, session)
    if params.sort is not None and params.sort not in SORTABLE:
        raise Invalid(f"cannot sort by {params.sort!r}, allowed: {sorted(SORTABLE)}")
    sort = params.sort or "name"

    rows_sql = _live_rows(presence, where)
    key_where = (" WHERE " + " AND ".join(by_key)) if by_key else ""
    from_where = f"({rows_sql}) x{key_where}"
    total, is_estimate = estimated_total(session, from_where, binds, exact=params.exact)

    if sort in COMPUTED_SORTS:
        # the computed figure sorts the whole filtered set (kept for the UI's column sort; slow at scale)
        page_from = f"(SELECT x.*, {COMPUTED_SORTS[sort]} AS sort_value FROM ({rows_sql}) x) x{key_where}"
        order_expr = "x.sort_value"
    else:
        page_from = from_where
        order_expr = SORTABLE[sort]
    page_where = []
    if params.after:
        page_where.append(keyset_condition([(order_expr, params.descending), ("x.object_key", False)],
                                           decode_cursor(params.after, sort, 2), binds))
    page_where_sql = ((" AND " if key_where else " WHERE ") + " AND ".join(page_where)) if page_where else ""
    order = f"{order_expr} {'DESC' if params.descending else 'ASC'} NULLS LAST, x.object_key"
    columns = ", ".join(f"x.{c.split(' AS ')[-1].split('.')[-1]}" for c in OBJECT_COLUMNS.split(", "))
    sort_col = ", x.sort_value" if sort in COMPUTED_SORTS else ""
    rows = session.execute(text(f"""
        SELECT {columns}{sort_col}, {FIELDS_SQL.format(hash='x.content_hash')} AS fields,
               {LABELS_SQL.format(key='x.object_key')} AS labels, {OBJECT_TAGS_SQL.format(key='x.object_key')} AS tags
        FROM (SELECT x.* FROM {page_from}{page_where_sql} ORDER BY {order} LIMIT :limit OFFSET :offset) x
        ORDER BY {order}
    """), {**binds, "limit": params.limit + 1, "offset": params.offset}).mappings().all()
    more = len(rows) > params.limit
    rows = rows[:params.limit]
    next_cursor = None
    if more and rows:
        last = rows[-1]
        next_cursor = encode_cursor(sort, [last["sort_value" if sort in COMPUTED_SORTS else sort], last["object_key"]])
    items = [_object_row(r) for r in rows]
    if include_fields and items:
        names: Dict[str, List[str]] = {}
        for f in session.execute(text("SELECT content_hash::text AS h, field_name FROM object_fields "
                                      "WHERE content_hash = ANY(CAST(:h AS uuid[])) ORDER BY field_name"),
                                 {"h": [i["content_hash"] for i in items]}):
            names.setdefault(f.h, []).append(f.field_name)
        for item in items:
            item["field_names"] = names.get(item["content_hash"], [])
    return Page(items, total, is_estimate, next_cursor)


def _truthy(value) -> bool:
    return str(value).lower() in ("1", "true", "yes")


FIELD_PATTERNS_MAX = 20
# constructs valid in Python ``re`` (keyword rules, dry runs) that Postgres ARE (``~*`` here)
# rejects or reads differently: \b is a backspace in ARE (word boundary: \y), \B is a
# backslash; named groups do not exist there
_ARE_DIVERGENT = re.compile(r"\\[bB]|\(\?P[<=>]|\(\?<[A-Za-z_]")


def _check_regex(session: Session, pattern) -> None:
    """A field-name pattern of the filters runs in Postgres (``~*``): it must mean the same as
    in Python ``re`` (keyword rules' ``fields_all``) and compile in Postgres, else Invalid
    (422), not an empty result or a 500."""
    pattern = str(pattern)
    if not pattern.strip():
        raise Invalid("empty field pattern")
    if len(pattern) > PATTERN_MAX:
        raise Invalid(f"field pattern longer than {PATTERN_MAX} characters")
    try:
        re.compile(pattern)
    except re.error as e:
        raise Invalid(f"invalid field pattern {pattern!r}: {e}") from None
    divergent = _ARE_DIVERGENT.search(pattern)
    if divergent:
        raise Invalid(f"field pattern {pattern!r}: {divergent.group(0)!r} is not supported here "
                      "(\\b / \\B and named groups mean something else in Postgres; for a word boundary use "
                      "(^|[^a-z0-9]) or _ separators)")
    try:
        with session.begin_nested():
            session.execute(text("SELECT '' ~* :p"), {"p": pattern})
    except DBAPIError as e:
        raise Invalid(f"invalid field pattern {pattern!r} (Postgres): "
                      f"{str(getattr(e, 'orig', e)).splitlines()[0][:200]}") from None


def _object_row(row) -> dict:
    data = dict(row)
    data.pop("sort_value", None)
    data["id"] = str(data.pop("object_key"))
    data["content_hash"] = str(data["content_hash"])
    data["source"] = "main" if data.pop("is_main") else "mr"
    return data


def _parse_key(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except ValueError:
        raise NotFound(f"object {value!r} not found") from None


def get_object(session: Session, value: str) -> Dict[str, Any]:
    """One object with all its fields (main version, else an open MR's, else any stored one)
    and every hit on it or its fields (labels and rule hits)."""
    object_key = _parse_key(value)
    version = session.execute(text("""
        SELECT o.*, b.is_main, b.line, b.field_lines, p.full_path AS project_path
        FROM objects o
        LEFT JOIN branch_objects b ON b.content_hash = o.content_hash
        LEFT JOIN gitlab_projects p ON p.id = o.project_id
        WHERE o.object_key = :k
        ORDER BY b.is_main DESC NULLS LAST, b.branch_id NULLS LAST LIMIT 1
    """), {"k": object_key}).mappings().first()
    if version is None:
        raise NotFound(f"object {value} not found")

    hits = session.execute(text("""
        SELECT h.rule_id, h.subject_key, h.field_name, h.fields, h.status, h.category, h.severity, h.reviewer, h.note,
               r.name AS rule_name, r.kind AS rule_kind,
               (SELECT array_agg(DISTINCT t) FROM unnest(COALESCE(r.tags, '{}'::text[]) || COALESCE(h.tags, '{}'::text[])) t)
                   AS tags
        FROM rule_hits h JOIN rules r ON r.id = h.rule_id WHERE h.object_key = :k ORDER BY r.kind, r.name
    """), {"k": object_key}).mappings().all()

    def brief(h):
        return {"id": review_service.hit_id(h["rule_id"], h["subject_key"]), "rule": h["rule_name"],
                "kind": h["rule_kind"], "status": h["status"], "category": h["category"],
                "severity": h["severity"], "reviewer": h["reviewer"], "note": h["note"], "fields": h["fields"],
                "tags": h["tags"]}

    field_lines = version["field_lines"] or {}
    fields = session.execute(text(
        "SELECT field_name, field_type, comment, samples FROM object_fields WHERE content_hash = :h "
        "ORDER BY field_name"),
        {"h": version["content_hash"]}).all()
    source = "orphan" if version["is_main"] is None else ("main" if version["is_main"] else "mr")
    return {
        "id": str(object_key), "project_id": version["project_id"], "project_path": version["project_path"],
        "name": version["name"], "type": version["type"], "parser": version["parser"], "file": version["file"],
        "line": version["line"], "props": version["props"], "comment": version["comment"], "source": source,
        "tags": session.execute(text(f"SELECT {OBJECT_TAGS_SQL.format(key='CAST(:k AS uuid)')}"), {"k": object_key}).scalar(),
        "object_hits": [brief(h) for h in hits if h["field_name"] is None],
        "fields": [{"name": f.field_name, "type": f.field_type, "line": field_lines.get(f.field_name),
                    "comment": f.comment, "samples": f.samples,
                    "hits": [brief(h) for h in hits if h["field_name"] == f.field_name]} for f in fields],
    }


# ---- manual labels ---------------------------------------------------------------------------

def _manual_rule_id(session: Session) -> int:
    rule_id = session.execute(text(
        "SELECT id FROM rules WHERE name = :n AND kind = 'manual' AND deleted_at IS NULL"), {"n": MANUAL_RULE}).scalar()
    if rule_id is None:
        raise NotFound(f"built-in rule {MANUAL_RULE} is missing (run the migrations)")
    return rule_id


def _object_project(session: Session, object_key: uuid.UUID, field_name: Optional[str]) -> int:
    project_id = session.execute(text("SELECT project_id FROM objects WHERE object_key = :k LIMIT 1"),
                                 {"k": object_key}).scalar()
    if project_id is None:
        raise NotFound(f"object {object_key} not found")
    if field_name is not None:
        exists = session.execute(text("SELECT 1 FROM object_fields WHERE field_key = :f LIMIT 1"),
                                 {"f": keys.field_key(object_key, field_name)}).first()
        if exists is None:
            raise Invalid(f"object {object_key} has no field {field_name!r}")
    return project_id


def set_label(session: Session, value: str, *, category: str, severity: str, reviewer: str,
              field_name: Optional[str] = None, note: Optional[str] = None, tags: Optional[List[str]] = None,
              via: str = "rest"):
    """Label an object (``field_name`` None) or one of its fields: a ``match`` hit of the
    manual rule; labelling again replaces category / severity (and note / tags, when given).
    ``tags`` are set on the object (see ``OBJECT_TAGS_SQL``)."""
    object_key = _parse_key(value)
    if not category or not category.strip():
        raise Invalid("category is required")
    project_id = _object_project(session, object_key, field_name)
    rule_id = _manual_rule_id(session)
    subject = keys.subject_key(object_key, field_name)
    session.execute(text("""
        INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version, category,
                               severity, status, reviewer, reviewed_at, note, tags, decided_via, first_seen_at,
                               last_seen_at, decided_tier)
        VALUES (:r, :s, :p, :k, :f, 1, :c, :sev, 'match', :rev, now(), :note, CAST(:tags AS text[]), :via, now(),
                now(), 'human')
        ON CONFLICT (rule_id, subject_key) DO UPDATE SET
            category = EXCLUDED.category, severity = EXCLUDED.severity, status = 'match',
            reviewer = EXCLUDED.reviewer, reviewed_at = now(), note = COALESCE(EXCLUDED.note, rule_hits.note),
            tags = COALESCE(EXCLUDED.tags, rule_hits.tags), decided_via = EXCLUDED.decided_via, decided_tier = 'human'
    """), {"r": rule_id, "s": subject, "p": project_id, "k": object_key, "f": field_name, "c": category.strip(),
           "sev": getattr(severity, "value", severity), "rev": reviewer, "note": note, "tags": tags or None,
           "via": via})
    # a hit inserted outside the scanner: its presence flags (``in_main`` / ``in_open_mr``) are computed here
    presence.refresh(session, object_keys=[object_key])
    return review_service.get_hit(session, review_service.hit_id(rule_id, subject))


def remove_label(session: Session, value: str, field_name: Optional[str] = None) -> Dict[str, Any]:
    object_key = _parse_key(value)
    rule_id = _manual_rule_id(session)
    subject = keys.subject_key(object_key, field_name)
    deleted = session.execute(text("DELETE FROM rule_hits WHERE rule_id = :r AND subject_key = :s"),
                              {"r": rule_id, "s": subject}).rowcount
    if not deleted:
        raise NotFound(f"no label on {object_key}" + (f" field {field_name!r}" if field_name else ""))
    return {"removed": review_service.hit_id(rule_id, subject)}


def label_bulk(session: Session, items: List[Dict[str, Any]], *, category: str, severity: str, reviewer: str,
               tags: Optional[List[str]] = None, note: Optional[str] = None, dry_run: bool = True,
               via: str = "rest") -> Dict[str, Any]:
    """The same manual label on up to 50 objects / fields (``items``: ``{object_id, field_name?}``),
    one transaction; ``dry_run`` (default) only validates. Each item: ``ok`` (hit id) or an error."""
    from services.review_service import BULK_MAX
    if not items:
        raise Invalid("items is empty")
    if len(items) > BULK_MAX:
        raise Invalid(f"at most {BULK_MAX} items per call")
    if not category or not str(category).strip():
        raise Invalid("category is required")
    results, changed = [], 0
    for item in items:
        object_id, field_name = str(item.get("object_id") or ""), item.get("field_name")
        try:
            object_key = _parse_key(object_id)
            _object_project(session, object_key, field_name)
            if dry_run:
                results.append({"object_id": object_id, "field_name": field_name, "result": "ok"})
                continue
            hit = set_label(session, object_id, category=category, severity=severity, reviewer=reviewer,
                            field_name=field_name, note=note, tags=tags, via=via)
            changed += 1
            results.append({"object_id": object_id, "field_name": field_name, "result": "ok", "hit_id": hit.id})
        except (NotFound, Invalid) as e:
            results.append({"object_id": object_id, "field_name": field_name, "result": "error", "error": str(e)})
    return {"dry_run": dry_run, "changed": changed, "items": results}
