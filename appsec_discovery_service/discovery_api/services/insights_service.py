"""Read-mostly helpers for agents and reports: rule dry runs, rule statistics, an overview
of the inventory, merge requests (delta, hits) and a one-MR scan.

Dry run of a keyword rule: the rule is evaluated in Python on the stored main snapshots with
the core's matching semantics (``Pattern``: regex match from the start OR case-insensitive
substring; ``fields_all`` / ``fields_none`` groups: regex searched case-insensitively), so it
predicts what the next parse would hit, without writing anything. An LLM rule cannot be dry
run without calling the model: ``dry_run_rule`` then estimates the cost (subjects that would
be sent) instead.
"""

import re
import time
from collections import Counter, defaultdict
from functools import lru_cache
from typing import Any, Dict, List, Optional

import regex as _rx
from sqlalchemy import text
from sqlalchemy.orm import Session

from discovery_common import keys, lifecycle
from discovery_common.queries import DELTA_OWNER_COND, DELTA_OWNER_SQL
from schemas import KeywordRuleIn, LlmRuleIn
from services.errors import Invalid, NotFound
from services.paging import escape_like, parse_timestamp

DRY_RUN_MAX_OBJECTS = 200_000
SAMPLE_MAX = 50


# ---- core matching semantics (no core import: the API runs pydantic v2) ----------------------
#
# User patterns run on names that come from scanned code / ingest, so a pattern with
# catastrophic backtracking ("(a|aa)+$") must not hold an API thread: validity follows the
# core (``re``; an invalid regex is a literal), but matching runs on the ``regex`` module
# (re-compatible V0 mode) with a per-call timeout, and a dry run has an overall deadline.

MATCH_TIMEOUT_S = 0.25
DRY_RUN_DEADLINE_S = 15.0


class SlowPattern(Invalid):
    def __init__(self, raw: str):
        super().__init__(f"pattern {raw!r} takes too long to match (catastrophic backtracking?): simplify it")


def _compile(raw: str, flags: int):
    try:
        re.compile(raw, flags)
    except re.error:
        raw = re.escape(raw)
    return _rx.compile(raw, flags | _rx.V0)


@lru_cache(maxsize=2048)
def _pattern(raw: str):
    return _compile(raw, 0)


@lru_cache(maxsize=2048)
def _searcher(raw: str):
    return _compile(raw, re.IGNORECASE)


def _timed(raw: str, fn, value: str) -> bool:
    try:
        return bool(fn(value, timeout=MATCH_TIMEOUT_S))
    except TimeoutError:
        raise SlowPattern(raw) from None


def pattern_matches(raw: Optional[str], value: Optional[str]) -> bool:
    """``appsec_discovery.matching.Pattern``: regex from the start OR case-insensitive substring
    (an empty pattern: no constraint, as the scanner's ``_scope_matches``)."""
    if not raw:
        return True
    return value is not None and (raw.lower() in value.lower() or _timed(raw, _pattern(raw).match, value))


def search_matches(raw: str, value: str) -> bool:
    """A ``fields_all`` / ``fields_none`` group: regex searched anywhere, case-insensitive."""
    return _timed(raw, _searcher(raw).search, value)


def keyword_rule_hits(rule: KeywordRuleIn, obj: dict, fields: List[dict]) -> List[Optional[str]]:
    """Subjects a keyword rule hits on one object: field names for a field rule, ``[None]``
    for an object hit (with the matched fields of a combination in ``obj['_matched']``)."""
    if rule.parser and (obj["parser"] or "").lower() != rule.parser.lower():
        return []
    if not (pattern_matches(rule.object_re, obj["name"]) and pattern_matches(rule.object_type_re, obj["type"])):
        return []
    names = [f["field_name"] for f in fields]
    if rule.fields_all:
        if any(search_matches(p, n) for p in rule.fields_none or [] for n in names):
            return []
        groups = [[n for n in names if search_matches(p, n)] for p in rule.fields_all]
        if sum(1 for g in groups if g) < (rule.min_groups or len(rule.fields_all)):
            return []
        matched = {n for g in groups for n in g}
        obj["_matched"] = [n for n in names if n in matched]
        return [None]
    if rule.field_re or rule.field_type_re:
        return [f["field_name"] for f in fields
                if pattern_matches(rule.field_re, f["field_name"]) and pattern_matches(rule.field_type_re, f["field_type"])]
    return [None]


# ---- dry run ---------------------------------------------------------------------------------

def _rule_spec(session: Session, kind: Optional[str], rule: Optional[Dict[str, Any]], rule_id: Optional[int]):
    """(kind, validated rule, existing row id) from a spec, or an existing rule with a patch."""
    base: Dict[str, Any] = {}
    existing = None
    if rule_id is not None:
        row = session.execute(text("SELECT * FROM rules WHERE id = :r AND deleted_at IS NULL"), {"r": rule_id}).mappings().first()
        if row is None or row["kind"] not in ("keyword", "llm"):
            raise NotFound(f"rule {rule_id} not found")
        kind, existing = row["kind"], row["id"]
        base = {"name": row["name"], "category": row["category"], "severity": row["severity"] or "medium",
                "mode": row["mode"] or "review", "enabled": True, **(row["scope"] or {})}
        if kind == "keyword":
            base.pop("source", None)
        else:
            base = {k: v for k, v in base.items() if k in LlmRuleIn.model_fields}
            base.update(target=row["target"] or "field", prompt=row["prompt"])
        base = {k: v for k, v in base.items() if k in (KeywordRuleIn if kind == "keyword" else LlmRuleIn).model_fields}
    if kind not in ("keyword", "llm"):
        raise Invalid("kind must be keyword or llm (or give rule_id)")
    data = {**base, **(rule or {})}
    data.setdefault("name", "dry-run")
    schema = KeywordRuleIn if kind == "keyword" else LlmRuleIn
    try:
        return kind, schema.model_validate(data), existing
    except Exception as e:      # pydantic ValidationError
        raise Invalid(f"invalid rule: {e}") from None


def _scope_projects(session: Session, project_ids: Optional[List[int]], project_re: Optional[str]) -> Dict[int, str]:
    rows = session.execute(text("SELECT id, full_path FROM gitlab_projects WHERE scan_mode = 'rules'"
                                + (" AND id = ANY(:ids)" if project_ids else "") + " ORDER BY id"),
                           {"ids": list(project_ids or [])}).all()
    return {r.id: r.full_path for r in rows if pattern_matches(project_re, r.full_path)}


def dry_run_rule(session: Session, *, kind: Optional[str] = None, rule: Optional[Dict[str, Any]] = None,
                 rule_id: Optional[int] = None, project_ids: Optional[List[int]] = None,
                 sample: int = 20) -> Dict[str, Any]:
    """What a rule (a spec, or ``rule_id`` with ``rule`` as a patch) would hit on the stored
    main snapshots of the projects in ``rules`` mode. Nothing is written.

    keyword: ``hits`` (subjects), per project / object type, a sample, and how many of these
    subjects people already decided for any rule (``human_confirmed`` / ``human_rejected``: status
    ``match`` / ``no_match`` set by a reviewer; a rule that mostly hits rejected subjects is noisy);
    for an existing rule also ``new`` / ``gone`` vs its current hits. llm: ``subjects_to_send`` (the model calls a run would make,
    per project) - an LLM rule cannot be dry run without calling the model."""
    kind, spec, existing = _rule_spec(session, kind, rule, rule_id)
    sample = max(0, min(int(sample), SAMPLE_MAX))
    projects = _scope_projects(session, project_ids, spec.project_re)
    if not projects:
        return {"kind": kind, "projects": 0, "hits": 0, "note": "no project in scope"}

    objects = session.execute(text("""
        SELECT DISTINCT ON (o.object_key) o.object_key, o.content_hash, o.name, o.type, o.parser, o.file,
               g.project_id
        FROM branch_objects b JOIN gitlab_branches g ON g.id = b.branch_id
        JOIN objects o ON o.content_hash = b.content_hash
        WHERE b.is_main AND g.project_id = ANY(:pids)
        ORDER BY o.object_key LIMIT :cap"""), {"pids": list(projects), "cap": DRY_RUN_MAX_OBJECTS + 1}).mappings().all()
    truncated = len(objects) > DRY_RUN_MAX_OBJECTS
    objects = [dict(o) for o in objects[:DRY_RUN_MAX_OBJECTS]]
    fields_by_hash: Dict[Any, List[dict]] = defaultdict(list)
    # an object-target LLM rule never looks at fields: one call per object
    hashes = [] if kind == "llm" and spec.target.value == "object" else list({o["content_hash"] for o in objects})
    for i in range(0, len(hashes), 5000):
        for f in session.execute(text("SELECT content_hash, field_name, field_type, field_key, comment, samples FROM object_fields "
                                      "WHERE content_hash = ANY(:h) ORDER BY field_name"), {"h": hashes[i:i + 5000]}).mappings():
            fields_by_hash[f["content_hash"]].append(dict(f))

    # the deadline bounds the matching (user regexes), not loading the snapshot
    deadline = time.monotonic() + DRY_RUN_DEADLINE_S
    if kind == "llm":
        return _llm_estimate(session, spec, existing, projects, objects, fields_by_hash, truncated, deadline,
                             patched=bool(rule))

    subjects, by_project, by_type, samples = [], Counter(), Counter(), []
    scanned = 0
    for obj in objects:
        if time.monotonic() > deadline:
            truncated = True
            break
        scanned += 1
        fields = fields_by_hash.get(obj["content_hash"], [])
        hit = keyword_rule_hits(spec, obj, fields)
        if not hit:
            continue
        field_keys = {f["field_name"]: f["field_key"] for f in fields}
        for field_name in hit:
            subjects.append(obj["object_key"] if field_name is None else field_keys[field_name])
        by_project[projects[obj["project_id"]]] += len(hit)
        by_type[obj["type"]] += len(hit)
        if len(samples) < sample:
            samples.append({"object_id": str(obj["object_key"]), "project": projects[obj["project_id"]],
                            "object": obj["name"], "type": obj["type"], "file": obj["file"],
                            "fields": obj.get("_matched") if hit == [None] else hit[:10]})

    decided = Counter()
    for i in range(0, len(subjects), 5000):
        for row in session.execute(text("""
                SELECT status, count(DISTINCT subject_key) n FROM rule_hits
                WHERE subject_key = ANY(:s) AND reviewer IS NOT NULL AND status IN ('match', 'no_match')
                GROUP BY status"""), {"s": subjects[i:i + 5000]}):
            decided[row.status] += row.n
    result = {
        "kind": kind, "rule": spec.name, "projects": len(projects), "objects_scanned": scanned,
        "truncated": truncated, "hits": len(subjects), "by_project": dict(by_project.most_common(20)),
        "by_object_type": dict(by_type.most_common()), "sample": samples,
        "human_confirmed": decided["match"], "human_rejected": decided["no_match"],
    }
    if existing is not None:
        current = {r[0] for r in session.execute(text(
            "SELECT subject_key FROM rule_hits WHERE rule_id = :r AND project_id = ANY(:pids)"),
            {"r": existing, "pids": list(projects)})}
        now = set(subjects)
        result.update(rule_id=existing, current_hits=len(current), new=len(now - current), gone=len(current - now))
    return result


def _llm_estimate(session, spec: LlmRuleIn, existing, projects, objects, fields_by_hash, truncated,
                  deadline: float, patched: bool = False) -> Dict[str, Any]:
    """Subjects / model calls the next runs would make. As the scanner (LLM_CANDIDATES_SQL, Python twins
    ``discovery_common.lifecycle.is_fresh`` / ``is_migration``): FRESH - no hit, another content of the subject
    (``subject_hash``), a reopened pending hit of an older version, object rules: another object name / field names
    (``names_hash``, also for human decisions); MIGRATION (a rollout asks them again) - a machine verdict of an older
    rule version (after this edit), other core prompts / service model than the version's. Harness-tier decisions
    are kept on a new version (asked again only on new content)."""
    hits: Dict[Any, Any] = {}
    version = None
    pinned = code = lifecycle.code_core_version({"target": spec.target.value, "category": spec.category})
    pinned_model = code_model = None
    if existing is not None:
        version = _version_after(session, existing, spec if patched else None)
        row = session.execute(text("SELECT target, category, core_prompt_version, llm_model FROM rules WHERE id = :r"),
                              {"r": existing}).mappings().one()
        if not patched or version == _version_after(session, existing, None):
            pinned = lifecycle.pinned_core_version(row)
            pinned_model = row["llm_model"]
            code_model = session.execute(text("SELECT value FROM llm_runtime WHERE key = 'service_model'")).scalar()
        hits = {r.subject_key: r for r in session.execute(text("""
            SELECT subject_key, reviewer, status, rule_version, prompt_version, model, subject_hash, names_hash,
                   decided_tier
            FROM rule_hits WHERE rule_id = :r AND project_id = ANY(:pids)"""),
            {"r": existing, "pids": list(projects)})}
    object_rule = spec.target.value == "object"
    names_of: Dict[Any, List[str]] = {}
    if object_rule and hits:
        # names_hash: the field names of the objects whose hit stores one (others need no fields)
        wanted = list({o["content_hash"] for o in objects
                       if getattr(hits.get(o["object_key"]), "names_hash", None) is not None})
        for i in range(0, len(wanted), 5000):
            for r in session.execute(text("SELECT content_hash, field_name FROM object_fields WHERE content_hash = ANY(:h)"),
                                     {"h": wanted[i:i + 5000]}):
                names_of.setdefault(r.content_hash, []).append(r.field_name)

    def asked(subject_key, subject_hash, names_hash=None) -> Optional[str]:
        """'fresh' (every run asks it), 'migration' (a rollout asks it again) or None (current)."""
        hit = hits.get(subject_key)
        if hit is None or lifecycle.is_fresh(hit, version, subject_hash, names_hash):
            return "fresh"
        if lifecycle.is_migration(hit, version, pinned, code, pinned_model, code_model):
            return "migration"
        return None

    per_project, calls = Counter(), Counter()
    fresh, migration = Counter(), Counter()             # subjects / calls (objects) per class
    scanned = 0
    for obj in objects:
        if time.monotonic() > deadline:
            truncated = True
            break
        scanned += 1
        if not (pattern_matches(spec.object_re, obj["name"]) and pattern_matches(spec.object_type_re, obj["type"])):
            continue
        if object_rule:
            stored = getattr(hits.get(obj["object_key"]), "names_hash", None)
            cls = asked(obj["object_key"], keys.object_subject_hash(obj["content_hash"]),
                        keys.names_hash(obj["name"], names_of.get(obj["content_hash"], [])) if stored else None)
            if cls:
                per_project[projects[obj["project_id"]]] += 1
                calls[projects[obj["project_id"]]] += 1
                (fresh if cls == "fresh" else migration).update(subjects=1, calls=1)
            continue
        todo = []
        for f in fields_by_hash.get(obj["content_hash"], []):
            if not (pattern_matches(spec.field_re, f["field_name"]) and pattern_matches(spec.field_type_re, f["field_type"])
                    and _llm_candidate(f)):
                continue
            cls = asked(f["field_key"], keys.field_subject_hash(f["field_name"], f["field_type"], f.get("comment"),
                                                                f.get("samples")))
            if cls:
                todo.append(cls)
        if todo:
            per_project[projects[obj["project_id"]]] += len(todo)
            calls[projects[obj["project_id"]]] += 1        # one request per object
            fresh.update(subjects=todo.count("fresh"), calls=1 if "fresh" in todo else 0)
            migration.update(subjects=todo.count("migration"), calls=0 if "fresh" in todo else 1)
    return {"kind": "llm", "rule": spec.name, "target": spec.target.value, "projects": len(projects),
            "objects_scanned": scanned, "truncated": truncated,
            "subjects_to_send": sum(per_project.values()), "model_calls": sum(calls.values()),
            "by_project": dict(calls.most_common(20)),
            # the lifecycle classes: fresh subjects every run asks; stale verdicts of an older version of the rule a
            # rollout asks again (an object with both is counted as a fresh call)
            "fresh": {"subjects": fresh["subjects"], "model_calls": fresh["calls"]},
            "migration": {"subjects": migration["subjects"], "model_calls": migration["calls"]},
            "note": "an LLM rule is not run in a dry run: these are the subjects / calls a run would make"}


def _version_after(session: Session, rule_id: int, spec: Optional[LlmRuleIn]) -> int:
    """The rule's version once ``spec`` is saved (``rules_service.update_rule``: an edit of
    what it matches - scope, prompt, target - bumps it); ``None``: no edit, the current one."""
    from services import rules_service
    row = session.execute(text("SELECT scope, prompt, target, version FROM rules WHERE id = :r"),
                          {"r": rule_id}).mappings().one()
    version = row["version"] or 1
    if spec is None:
        return version
    old = (rules_service._matchers(row["scope"] or {}, "llm"), row["prompt"], row["target"])
    new = (rules_service._matchers(spec.scope(), "llm"), spec.prompt, spec.target.value)
    return version + 1 if new != old else version


def _llm_candidate(field: dict) -> bool:
    """``appsec_discovery.ai.is_candidate_field``: ints / strings that are not ids, dates, paging."""
    name, ltype = field["field_name"], (field["field_type"] or "").lower()
    lname = name.lower()
    skip = ('_id', '_ids', '.id', '.ids', '_date', 'page', 'per_page', 'limit', 'total', 'total_items',
            '_filename', '_size', 'id_in', 'ids_in')
    return (('int' in ltype or 'str' in ltype) and 'idempotency' not in lname and not name.endswith('Id')
            and not name.endswith('ID') and not lname.endswith(skip) and lname != 'id')


# ---- rule statistics -------------------------------------------------------------------------

def rule_stats(session: Session, rule_id: Optional[int] = None, since: Optional[str] = None,
               notes: int = 10) -> List[Dict[str, Any]]:
    """Per rule and version: hits by status, who decided (human / machine, rest / mcp) and the
    precision of human decisions: match / (match + no_match), overall and without the
    MCP ones (an agent's decisions are not ground truth). ``since``: hits first seen since."""
    where, binds = ["r.deleted_at IS NULL", "r.kind IN ('keyword', 'llm')"], {}
    if rule_id is not None:
        where.append("r.id = :r")
        binds["r"] = int(rule_id)
    if since:
        where.append("h.first_seen_at >= CAST(:since AS timestamptz)")
        binds["since"] = parse_timestamp(since, "since")
    rows = session.execute(text(f"""
        SELECT r.id, r.name, r.kind, r.mode, r.version AS current_version, h.rule_version, h.status,
               (h.reviewer IS NOT NULL) AS human, h.decided_via, count(*) n, count(DISTINCT h.project_id) projects
        FROM rules r JOIN rule_hits h ON h.rule_id = r.id
        WHERE {" AND ".join(where)}
        GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9 ORDER BY 1, 6"""), binds).mappings().all()
    if rule_id is not None and not rows and session.execute(text("SELECT 1 FROM rules WHERE id = :r"), {"r": rule_id}).first() is None:
        raise NotFound(f"rule {rule_id} not found")

    out: Dict[int, Dict[str, Any]] = {}
    for r in rows:
        rule = out.setdefault(r["id"], {"rule_id": r["id"], "name": r["name"], "kind": r["kind"], "mode": r["mode"],
                                        "current_version": r["current_version"], "versions": {}})
        v = rule["versions"].setdefault(r["rule_version"], {"by_status": Counter(), "human": Counter(),
                                                            "human_rest": Counter(), "machine": Counter()})
        v["by_status"][r["status"]] += r["n"]
        bucket = v["human"] if r["human"] else v["machine"]
        bucket[r["status"]] += r["n"]
        if r["human"] and r["decided_via"] != "mcp":
            v["human_rest"][r["status"]] += r["n"]

    def precision(c: Counter) -> Optional[float]:
        decided = c["match"] + c["no_match"]
        return round(c["match"] / decided, 3) if decided else None

    result = []
    for rule in out.values():
        versions = []
        for version, v in sorted(rule["versions"].items(), key=lambda kv: kv[0] or 0):
            versions.append({"version": version, "by_status": dict(v["by_status"]),
                             "human_decisions": sum(v["human"].values()), "machine": dict(v["machine"]),
                             "precision_human": precision(v["human"]), "precision_human_without_mcp": precision(v["human_rest"])})
        rule["versions"] = versions
        rule["top_reject_notes"] = [dict(n) for n in session.execute(text("""
            SELECT note, count(*) n FROM rule_hits WHERE rule_id = :r AND status = 'no_match' AND note IS NOT NULL
            GROUP BY note ORDER BY n DESC LIMIT :k"""), {"r": rule["rule_id"], "k": max(0, int(notes))}).mappings()]
        result.append(rule)
    return result


# ---- overview --------------------------------------------------------------------------------

MATCHES_BY_PROJECT_MAX = 200
# object types of the landscape: matches of a project by what holds the data
LANDSCAPE_TYPES = ("table", "rpc", "query", "mutation")


def _hit_filters(category, tag, rule_id, severity) -> tuple:
    """Conditions on rule_hits h (joined with rules r) for the landscape filters of ``overview``; a tag matches the
    hit's own tags or its rule's (as ``HitOut.tags`` shows them)."""
    where, binds = [], {}
    for name, values, column in (("category", category, "h.category"), ("severity", severity, "h.severity")):
        if values not in (None, "", []):
            where.append(f"{column} = ANY(:{name})")
            binds[name] = [str(v) for v in (values if isinstance(values, (list, tuple)) else [values])]
    if rule_id not in (None, ""):
        where.append("h.rule_id = :rule_id")
        binds["rule_id"] = int(rule_id)
    if tag not in (None, "", []):
        where.append("(COALESCE(h.tags, '{}') || COALESCE(r.tags, '{}')) && CAST(:tags AS text[])")
        binds["tags"] = [str(v) for v in (tag if isinstance(tag, (list, tuple)) else [tag])]
    return where, binds


def overview(session: Session, project_id: Optional[int] = None, *, category=None, tag=None, rule_id=None,
             severity=None) -> Dict[str, Any]:
    """One call instead of paging: inventory by object type, hits by status, matches (``confirmed_by_category``: status
    match) by category x severity, ``matches_by_project`` (the top 200 projects by matches: matches, open hits,
    matches by object type), pending by rule, open MRs, stale main branches, failed jobs. ``category`` / ``tag`` /
    ``rule_id`` / ``severity`` (lists) narrow ``matches_by_project`` and ``confirmed_by_category``. ``computed_at``:
    when the figures were computed - ``GET /overview`` without arguments serves the ``overview`` row of
    ``stats_snapshots`` while fresh (``services.stats_service``), the filtered variants compute live."""
    p = " AND g.project_id = :p" if project_id else ""
    hp = " AND h.project_id = :p" if project_id else ""
    binds = {"p": project_id} if project_id else {}
    if project_id and session.execute(text("SELECT 1 FROM gitlab_projects WHERE id = :p"), binds).first() is None:
        raise NotFound(f"project {project_id} not found")
    narrow, narrow_binds = _hit_filters(category, tag, rule_id, severity)
    hf = "".join(f" AND {cond}" for cond in narrow)
    binds.update(narrow_binds)

    def rows(sql):
        return [dict(r) for r in session.execute(text(sql), binds).mappings()]

    by_type = ", ".join(f"count(*) FILTER (WHERE h.status = 'match' AND obj.type = '{t}') AS type_{t}"
                        for t in LANDSCAPE_TYPES)
    # the object type per hit by a hash join on one row per object key (any version: the type never changes),
    # not a LATERAL LIMIT 1 probe per hit (5M probes at scale); the projection is scoped to the project when given
    matches_by_project = [{
        "project_id": r["project_id"], "project_path": r["project_path"], "matches": int(r["matches"]),
        "open": int(r["open"]), "by_type": {t: int(r[f"type_{t}"]) for t in LANDSCAPE_TYPES},
    } for r in rows(f"""
        SELECT p.id AS project_id, p.full_path AS project_path,
               count(*) FILTER (WHERE h.status = 'match') AS matches,
               count(*) FILTER (WHERE h.status IN ('pending_review', 'need_more_info')) AS "open", {by_type}
        FROM rule_hits h JOIN rules r ON r.id = h.rule_id JOIN gitlab_projects p ON p.id = h.project_id
        LEFT JOIN (SELECT DISTINCT ON (o.object_key) o.object_key, o.type FROM objects o
                   WHERE true{" AND o.project_id = :p" if project_id else ""}) obj ON obj.object_key = h.object_key
        WHERE true{hp}{hf} GROUP BY 1, 2
        HAVING count(*) FILTER (WHERE h.status IN ('match', 'pending_review', 'need_more_info')) > 0
        ORDER BY matches DESC, "open" DESC, p.full_path LIMIT {MATCHES_BY_PROJECT_MAX}""")]

    return {
        "project_id": project_id,
        "computed_at": session.execute(text("SELECT now()")).scalar(),
        "projects": rows("SELECT scan_mode, count(*) n FROM gitlab_projects"
                         + (" WHERE id = :p" if project_id else "") + " GROUP BY 1"),
        # one main row per object (one main branch per project): count(*), no sort for DISTINCT
        "objects_by_type": rows(f"""SELECT o.type, count(*) n FROM branch_objects b
            JOIN gitlab_branches g ON g.id = b.branch_id JOIN objects o ON o.content_hash = b.content_hash
            WHERE b.is_main{p} GROUP BY 1 ORDER BY 2 DESC"""),
        "hits_by_status": rows(f"SELECT h.status, count(*) n FROM rule_hits h WHERE true{hp} GROUP BY 1 ORDER BY 2 DESC"),
        "confirmed_by_category": rows(f"""SELECT h.category, h.severity, count(*) n FROM rule_hits h
            JOIN rules r ON r.id = h.rule_id
            WHERE h.status = 'match'{hp}{hf} GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 30"""),
        "matches_by_project": matches_by_project,
        "filters": {k: v for k, v in (("category", category), ("tag", tag), ("rule_id", rule_id),
                                      ("severity", severity)) if v not in (None, "", [])} or None,
        "pending_by_rule": rows(f"""SELECT r.id AS rule_id, r.name, count(*) n FROM rule_hits h JOIN rules r ON r.id = h.rule_id
            WHERE h.status IN ('pending_review', 'need_more_info'){hp} GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 30"""),
        "open_mrs": session.execute(text("SELECT count(*) FROM gitlab_mrs WHERE state = 'opened'"
                                         + (" AND project_id = :p" if project_id else "")), binds).scalar(),
        "stale_main_branches": rows(f"""SELECT g.id AS branch_id, g.project_path, g.commit, g.scanned_commit
            FROM gitlab_branches g WHERE g.is_main AND g.commit IS DISTINCT FROM g.scanned_commit{p}
            ORDER BY g.project_path LIMIT 50"""),
        "failed_jobs": rows("SELECT id, kind, left(last_error, 200) AS last_error, finished_at FROM jobs "
                            "WHERE status = 'failed' ORDER BY id DESC LIMIT 20") if not project_id else None,
    }


# ---- merge requests --------------------------------------------------------------------------

def list_mrs(session: Session, project_id: Optional[int] = None, state: str = "opened", q: Optional[str] = None,
             limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    where, binds = ["m.state = :state"], {"state": state, "limit": max(1, min(int(limit), 200)), "offset": max(0, int(offset))}
    if project_id:
        where.append("m.project_id = :p")
        binds["p"] = int(project_id)
    if q:
        where.append("(m.title ILIKE :q ESCAPE '\\' OR m.source_branch ILIKE :q ESCAPE '\\' "
                     "OR m.project_path ILIKE :q ESCAPE '\\')")
        binds["q"] = f"%{escape_like(str(q))}%"
    w = " AND ".join(where)
    total = session.execute(text(f"SELECT count(*) FROM gitlab_mrs m WHERE {w}"), binds).scalar()
    items = [dict(r) for r in session.execute(text(f"""
        SELECT m.id, m.project_id, m.project_path, m.mr_id AS iid, m.title, m.source_branch, m.target_branch, m.state,
               m.updated_at, m.processed_at,
               CASE WHEN {DELTA_OWNER_COND} THEN (SELECT count(*) FROM branch_objects b
                    WHERE b.branch_id = m.source_branch_id AND NOT b.is_main) ELSE 0 END AS delta_objects,
               (SELECT min(m4.id) FROM gitlab_mrs m4 WHERE m4.source_branch_id = m.source_branch_id
                  AND m4.state = 'opened') AS delta_owner_mr_id
        FROM gitlab_mrs m WHERE {w} ORDER BY m.updated_at DESC NULLS LAST, m.id LIMIT :limit OFFSET :offset"""),
        binds).mappings()]
    return {"total": total, "items": items}


def _delta_owner(session: Session, mr_id: int, source_branch_id: Optional[int]) -> Optional[int]:
    """The MR whose delta the source branch holds (several open MRs can share a source branch:
    the oldest open one owns it, ``discovery_common.queries.DELTA_OWNER_SQL``); None: no open
    MR on that branch (the MR itself is shown as is)."""
    if source_branch_id is None:
        return None
    return session.execute(DELTA_OWNER_SQL, {"source": source_branch_id}).scalar()


def get_mr(session: Session, mr_id: int, limit: int = 100) -> Dict[str, Any]:
    """One MR (internal id): its delta vs the target (added / modified / removed objects), the
    hits on the delta's subjects. An MR sharing its source branch with an older open MR has no
    delta of its own: empty delta / hits, ``delta_owner_mr_id`` names the MR that holds it."""
    mr = session.execute(text("""
        SELECT id, project_id, project_path, mr_id AS iid, title, state, source_branch, source_branch_id,
               source_branch_commit, target_branch, target_branch_id, target_branch_commit, updated_at, processed_at
               FROM gitlab_mrs WHERE id = :m"""), {"m": mr_id}).mappings().first()
    if mr is None:
        raise NotFound(f"merge request {mr_id} not found")
    mr = dict(mr)
    owner = _delta_owner(session, mr["id"], mr["source_branch_id"])
    if owner is not None and owner != mr["id"]:
        return {**mr, "delta_owner_mr_id": owner, "delta_counts": {}, "delta": [], "hits": [],
                "note": f"the source branch is shared with the older open MR {owner}: its delta "
                        "belongs to that MR"}
    mr["delta_owner_mr_id"] = owner
    lim = max(1, min(int(limit), 500))
    delta = [dict(r) for r in session.execute(text("""
        SELECT b.change, b.object_key::text AS object_id, o.name, o.type, o.parser, o.file,
               (SELECT count(*) FROM object_fields f WHERE f.content_hash = b.content_hash) AS fields
        FROM branch_objects b
        LEFT JOIN LATERAL (SELECT name, type, parser, file FROM objects WHERE object_key = b.object_key LIMIT 1) o ON true
        WHERE b.branch_id = :s AND NOT b.is_main ORDER BY b.change, o.name LIMIT :lim"""),
        {"s": mr["source_branch_id"], "lim": lim}).mappings()]
    hits = [dict(r) for r in session.execute(text("""
        SELECT h.rule_id || ':' || h.subject_key AS id, r.name AS rule, o.name AS object, h.field_name, h.fields,
               h.status, h.category, h.severity
        FROM branch_objects b
        JOIN rule_hits h ON h.object_key = b.object_key
        JOIN rules r ON r.id = h.rule_id
        LEFT JOIN LATERAL (SELECT name FROM objects WHERE object_key = b.object_key LIMIT 1) o ON true
        WHERE b.branch_id = :s AND NOT b.is_main AND b.content_hash IS NOT NULL
          AND (h.field_name IS NULL OR EXISTS (SELECT 1 FROM object_fields f WHERE f.content_hash = b.content_hash
                                                AND f.field_key = h.subject_key))
        ORDER BY h.status, o.name, h.field_name NULLS FIRST LIMIT :lim"""),
        {"s": mr["source_branch_id"], "lim": lim}).mappings()]
    counts = Counter(d["change"] for d in delta)
    return {**mr, "delta_counts": dict(counts), "delta": delta, "hits": hits}


def request_mr_scan(session: Session, mr_id: int, *, llm: bool = True, requested_by: Optional[str] = None) -> Dict[str, Any]:
    """Queue ``scan_mr`` of one MR (delta, LLM rules on it)."""
    from discovery_common import jobs

    m = session.execute(text("SELECT id, source_branch_commit, target_branch_commit, state, source_branch_id, "
                              "target_branch_id FROM gitlab_mrs WHERE id = :m"), {"m": mr_id}).mappings().first()
    if m is None:
        raise NotFound(f"merge request {mr_id} not found")
    if m["state"] != "opened" or m["source_branch_id"] is None or m["target_branch_id"] is None:
        raise Invalid("only open merge requests with tracked branches can be scanned")
    owner = _delta_owner(session, m["id"], m["source_branch_id"])
    if owner is not None and owner != m["id"]:
        return {"queued": False, "job_id": None, "delta_owner_mr_id": owner,
                "note": f"the source branch is shared with the older open MR {owner}, which owns the delta: scan that one"}
    key = f"scan_mr:{m['id']}:{m['source_branch_commit']}:{m['target_branch_commit']}"
    payload = {"mr_id": m["id"], "source_commit": m["source_branch_commit"], "target_commit": m["target_branch_commit"],
               "llm": llm, **({"requested_by": requested_by} if requested_by else {})}
    job_id = jobs.enqueue("scan_mr", payload, key, conn=session)
    return {"queued": job_id is not None, "job_id": job_id, "dedup_key": key}


def glob_to_like(pattern: str) -> str:
    """``grp/*`` -> ``grp/%`` (SQL LIKE), escaping LIKE metacharacters."""
    out = []
    for ch in pattern:
        out.append({"*": "%", "?": "_", "%": "\\%", "_": "\\_", "\\": "\\\\"}.get(ch, ch))
    return "".join(out)


__all__ = ["dry_run_rule", "rule_stats", "overview", "list_mrs", "get_mr", "request_mr_scan", "glob_to_like",
           "pattern_matches", "keyword_rule_hits"]
