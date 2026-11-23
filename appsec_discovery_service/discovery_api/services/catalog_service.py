"""Autocompletes and the GitLab group tree (contract 7): the UI's dropdowns used to take their choices from
``overview()`` (a full aggregation of every hit per request); these are small, cached queries instead.

* ``rules(q, kind, limit)``: ``GET /rules?q=`` - live rules by name substring;
* ``categories()``: ``GET /categories`` - the categories of rules and of hits (manual labels have free categories),
  with the rules and hits (from the ``hits_aggregate`` snapshot when fresh) per category;
* ``object_types()``: ``GET /object_types`` - object types of the main snapshots with counts (from the ``overview``
  snapshot when fresh, else live);
* ``groups(q, depth)``: ``GET /groups?q=`` - GitLab groups as path prefixes of ``gitlab_projects.full_path`` up to
  ``depth`` levels, with the number of projects under each; ``group=<prefix>`` of the lists takes one of them.

The live variants of ``categories`` / ``object_types`` scan a table once and are cached in the process for
``CACHE_TTL_S``; the snapshot variants are already cheap.
"""

import time
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from services import stats_service
from services.errors import Invalid
from services.paging import escape_like

CACHE_TTL_S = 300
GROUPS_DEPTH_MAX = 4
_cache: Dict[str, Tuple[float, Any]] = {}


def _cached(key: str, compute, ttl: float = CACHE_TTL_S):
    now = time.monotonic()
    hit = _cache.get(key)
    if hit is not None and now - hit[0] < ttl:
        return hit[1]
    value = compute()
    _cache[key] = (now, value)
    return value


def clear_cache() -> None:
    _cache.clear()


def rules(session: Session, q: Optional[str] = None, kind: Optional[str] = None, limit: int = 20,
          include_disabled: bool = True) -> List[Dict[str, Any]]:
    where, binds = ["r.deleted_at IS NULL"], {"limit": max(1, min(int(limit), 200))}
    if q:
        where.append("r.name ILIKE :q ESCAPE '\\'")
        binds["q"] = f"%{escape_like(str(q))}%"
    if kind:
        kinds = [str(k) for k in (kind if isinstance(kind, (list, tuple)) else str(kind).split(","))]
        if set(kinds) - {"keyword", "llm", "manual"}:
            raise Invalid("kind must be some of keyword, llm, manual")
        where.append("r.kind = ANY(:kinds)")
        binds["kinds"] = kinds
    if not include_disabled:
        where.append("r.enabled IS NOT false")
    return [dict(r) for r in session.execute(text(f"""
        SELECT r.id, r.name, r.kind, r.category, r.severity, r.mode, r.target, (r.enabled IS NOT false) AS enabled,
               r.version
        FROM rules r WHERE {" AND ".join(where)}
        ORDER BY (r.name ILIKE :prefix ESCAPE '\\') DESC, r.name, r.id LIMIT :limit"""),
        {**binds, "prefix": f"{escape_like(str(q))}%" if q else "%"}).mappings()]


def categories(session: Session) -> Dict[str, Any]:
    """``{items: [{category, rules, hits, matches}], computed_at, snapshot}``: every category a live rule or a hit has."""
    per_rule: Dict[str, int] = {}
    for r in session.execute(text("SELECT category, count(*) AS n FROM rules WHERE deleted_at IS NULL "
                                  "AND category IS NOT NULL GROUP BY 1")).mappings():
        per_rule[r["category"]] = int(r["n"])
    snapshot = stats_service.read_snapshot(session, "hits_aggregate")
    hits: Dict[str, Dict[str, int]] = {}
    if snapshot is not None:
        data, computed_at = snapshot
        for row in data.get("rows", []):
            if row.get("category") is None:
                continue
            bucket = hits.setdefault(row["category"], {"hits": 0, "matches": 0})
            bucket["hits"] += int(row["n"])
            if row.get("status") == "match":
                bucket["matches"] += int(row["n"])
        source = {"computed_at": computed_at, "snapshot": True}
    else:
        def live():
            out: Dict[str, Dict[str, int]] = {}
            for r in session.execute(text("""
                SELECT category, count(*) AS hits, count(*) FILTER (WHERE status = 'match') AS matches
                FROM rule_hits WHERE category IS NOT NULL GROUP BY 1""")).mappings():
                out[r["category"]] = {"hits": int(r["hits"]), "matches": int(r["matches"])}
            return out, session.execute(text("SELECT now()")).scalar()
        hits, computed_at = _cached("categories", live)
        source = {"computed_at": computed_at, "snapshot": False}
    names = sorted(set(per_rule) | set(hits))
    items = [{"category": c, "rules": per_rule.get(c, 0), **hits.get(c, {"hits": 0, "matches": 0})} for c in names]
    return {"items": items, **source}


def object_types(session: Session) -> Dict[str, Any]:
    """``{items: [{type, n}], computed_at, snapshot}``: object types of the main snapshots."""
    snapshot = stats_service.read_snapshot(session, "overview")
    if snapshot is not None:
        data, computed_at = snapshot
        items = [{"type": r.get("type"), "n": int(r.get("n") or 0)} for r in data.get("objects_by_type", [])]
        return {"items": items, "computed_at": computed_at, "snapshot": True}

    def live():
        rows = [{"type": r["type"], "n": int(r["n"])} for r in session.execute(text("""
            SELECT o.type, count(*) AS n FROM branch_objects b JOIN objects o ON o.content_hash = b.content_hash
            WHERE b.is_main GROUP BY 1 ORDER BY 2 DESC""")).mappings()]
        return rows, session.execute(text("SELECT now()")).scalar()
    items, computed_at = _cached("object_types", live)
    return {"items": items, "computed_at": computed_at, "snapshot": False}


def groups(session: Session, q: Optional[str] = None, depth: int = 2, parent: Optional[str] = None,
           limit: int = 200) -> Dict[str, Any]:
    """``{items: [{path, depth, projects, parent}]}``: the group prefixes of the projects' paths up to ``depth``
    levels (the last path segment is the project itself and is never a group), ``q`` a prefix / substring, ``parent``
    only the groups directly under it."""
    depth = max(1, min(int(depth), GROUPS_DEPTH_MAX))
    parent = str(parent).strip("/") if parent else None
    if parent:
        # the children of a parent are one level below it, however deep the parent is (the cap is for global listings)
        depth = len(parent.split("/")) + 1
    where, binds = ["array_length(string_to_array(p.full_path, '/'), 1) > d.depth"], {"depth": depth,
                                                                                      "limit": max(1, min(int(limit), 2000))}
    if parent:
        binds["parent_like"] = escape_like(parent) + "/%"
        binds["parent_depth"] = depth
        where.append("p.full_path LIKE :parent_like ESCAPE '\\' AND d.depth = :parent_depth")
    rows = session.execute(text(f"""
        SELECT array_to_string((string_to_array(p.full_path, '/'))[1:d.depth], '/') AS path, d.depth, count(*) AS projects
        FROM gitlab_projects p, generate_series(1, :depth) AS d(depth)
        WHERE {" AND ".join(where)}
        GROUP BY 1, 2 HAVING (CAST(:q AS text) IS NULL OR array_to_string((string_to_array(p.full_path, '/'))[1:d.depth], '/')
                              ILIKE :q ESCAPE '\\')
        ORDER BY d.depth, projects DESC, path LIMIT :limit"""),
        {**binds, "q": f"%{escape_like(str(q))}%" if q else None}).mappings().all()
    items = []
    for r in rows:
        path = r["path"]
        items.append({"path": path, "depth": int(r["depth"]), "projects": int(r["projects"]),
                      "parent": path.rsplit("/", 1)[0] if "/" in path else None})
    return {"items": items, "depth": depth}
