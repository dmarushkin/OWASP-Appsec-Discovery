"""Prompt trials and proposals of LLM rules (migration 0019), used by REST and MCP alike.

A harness (e.g. an expensive model connected to the MCP server) that verified the service model's verdicts and
wants to improve a rule's prompt:

1. ``mislabeled(rule_id, source="human" | "verification")``: subjects where a human decision (``human``) or the
   harness model's final decision of the tiered workflow (``verification``, ``decided_tier = 'harness'``)
   disagrees with the service model's verdict (``rule_hits.machine_status``, recorded at the first human /
   harness decision; human decisions made before migration 0019 have no recorded machine status and are listed
   with ``machine_verdict`` null). A harness with its own expected labels passes them to the trial directly.
2. ``create_trial(rule_id, prompt, subjects | from_mislabeled, include_controls, rerun_current)``: the candidate
   prompt is run by the scanner's LLM workers with the SERVICE model (``llm_trial`` job) on those subjects plus
   ``include_controls`` random subjects whose current verdict is agreed (a human or the harness model confirmed
   the service verdict), to catch regressions. Nothing but the trial is written (no hits, no rule change).
   Guards: the rule is a live LLM rule; the prompt is at most ``PROMPT_MAX`` characters; at most
   ``LLM_TRIAL_MAX_SUBJECTS`` subjects (controls included); every subject is in the rule's scope and in a current
   snapshot (main, else an MR delta); the model calls of all trials of the UTC day stay under
   ``LLM_TRIAL_DAILY_CALLS`` (429 otherwise).
3. ``trial_result(trial_id)``: expected / stored current / re-run current / new verdict per subject and the
   metrics (``metrics``).
4. ``create_proposal(rule_id, prompt, trial_id, rationale)``: a proposal for a human, only with a finished trial of
   the same prompt text (sha256) on the rule's current version; it does not change the rule.
   ``accept_proposal`` (REST / UI only: MCP agents cannot accept) makes it a candidate version of the rule
   (``rule_versions``; a human activates it - with its cost estimate - and its rollout migrates the machine
   verdicts in budgeted slices), ``reject_proposal``.

Candidate prompts come from agents: they are stored and shown as data (a diff against the current prompt), and the
scanner sends them only as the rule's system prompt - the object stays in the core's delimited untrusted block.
"""

import difflib
import hashlib
import json
import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from discovery_common import lifecycle
from discovery_common.models import JOB_PRIORITY_TRIAL, LLM_VERDICTS
from logger import get_logger
from services.errors import Conflict, Invalid, NotFound, TooManyRequests

logger = get_logger(__name__)

PROMPT_MAX = 20000          # = LlmRuleIn.prompt
RATIONALE_MAX = 5000
NOTE_MAX = 2000
MISLABELED_MAX = 200
SOURCES = ("human", "verification")

# status -> the verdict it stands for: the model's (machine) proposal, a human decision (the final statuses are the
# verdict words, migration 0023; pending_review is a service 'match' of a review-mode rule)
MACHINE_VERDICT = {"pending_review": "match", "match": "match", "need_more_info": "need_more_info",
                   "no_match": "no_match"}
HUMAN_VERDICT = {"match": "match", "no_match": "no_match"}
VERDICT_SQL = """(CASE {c} WHEN 'pending_review' THEN 'match' WHEN 'match' THEN 'match'
                  WHEN 'need_more_info' THEN 'need_more_info' WHEN 'no_match' THEN 'no_match' END)"""


def prompt_hash(prompt: str) -> str:
    """sha256 of the exact prompt text (a proposal needs a trial of the same text)."""
    return hashlib.sha256((prompt or "").encode("utf-8")).hexdigest()


def _settings():
    from config import get_settings
    return get_settings()


def _uuid(value, what: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        raise Invalid(f"{what}: {value!r} is not an object key (uuid)") from None


def _text(value, name: str, maximum: int, required: bool = False) -> Optional[str]:
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise Invalid(f"{name} is required")
        return None
    if not isinstance(value, str):
        raise Invalid(f"{name} must be a string")
    if len(value) > maximum:
        raise Invalid(f"{name} is too long ({len(value)} characters, at most {maximum})")
    return value


def _llm_rule(session: Session, rule_id: int, lock: bool = False) -> dict:
    row = session.execute(text(
        "SELECT id, kind, name, category, target, prompt, version, scope, enabled, deleted_at, core_prompt_version, "
        "llm_model FROM rules "
        "WHERE id = :r" + (" FOR UPDATE" if lock else "")), {"r": int(rule_id)}).mappings().first()
    if row is None or row["kind"] != "llm" or row["deleted_at"] is not None:
        raise NotFound(f"llm rule {rule_id} not found")
    return dict(row)


def _field_cond(rule: dict, alias: str = "h") -> str:
    # object rules: the object hits (the field marks of mark_fields are by-products of the object's call)
    return f"{alias}.field_name IS NULL" if rule["target"] == "object" else f"{alias}.field_name IS NOT NULL"


# ---- subjects: the current version of an object, scope -----------------------------------------------

CURRENT_SQL = text("""
    SELECT DISTINCT ON (b.object_key) b.object_key, b.content_hash, b.is_main, o.name, o.type, o.parser,
           o.project_id, p.full_path, p.scan_mode
    FROM branch_objects b JOIN objects o ON o.content_hash = b.content_hash
    JOIN gitlab_projects p ON p.id = o.project_id
    WHERE b.object_key = ANY(CAST(:keys AS uuid[])) AND b.content_hash IS NOT NULL
    ORDER BY b.object_key, b.is_main DESC, b.branch_id DESC""")


def _scope_problem(rule: dict, obj: dict, field: Optional[dict]) -> Optional[str]:
    from services.insights_service import _llm_candidate, pattern_matches
    scope = rule["scope"] or {}
    checks = [("project_re", obj["full_path"]), ("object_re", obj["name"]), ("object_type_re", obj["type"])]
    if field is not None:
        checks += [("field_re", field["field_name"]), ("field_type_re", field["field_type"])]
    for key, value in checks:
        if not pattern_matches(scope.get(key), value):
            return f"outside the rule's scope ({key} {scope.get(key)!r})"
    if field is not None and not rule["category"] and not _llm_candidate(field):
        return "the classifier rule does not send this field to the model (an id / date / paging field)"
    return None


def resolve_subjects(session: Session, rule: dict, wanted: List[Tuple[uuid.UUID, Optional[str]]]
                     ) -> Tuple[List[dict], List[str]]:
    """The current version (main snapshot first, else an MR delta) of each wanted ``(object_key, field_name)``:
    ``(subjects, problems)``; a subject has subject_key (the field key for field rules), content_hash, names."""
    keys = sorted({str(k) for k, _ in wanted})
    objects = {r["object_key"]: dict(r) for r in session.execute(CURRENT_SQL, {"keys": keys}).mappings()} if keys else {}
    hashes = sorted({str(o["content_hash"]) for o in objects.values()})
    fields: Dict[Tuple[Any, str], dict] = {}
    if hashes:
        for r in session.execute(text(
                "SELECT content_hash, field_name, field_type, field_key FROM object_fields "
                "WHERE content_hash = ANY(CAST(:h AS uuid[]))"), {"h": hashes}).mappings():
            fields[(r["content_hash"], r["field_name"])] = dict(r)
    subjects, problems = [], []
    for key, field_name in wanted:
        label = f"{key}" + (f" field {field_name!r}" if field_name else "")
        obj = objects.get(key)
        if obj is None:
            problems.append(f"{label}: not in any current snapshot (main branch or MR delta)")
            continue
        if obj["scan_mode"] != "rules":
            problems.append(f"{label}: project {obj['full_path']} is in inventory mode (no LLM rules)")
            continue
        field = None
        if rule["target"] == "object":
            if field_name:
                problems.append(f"{label}: rule {rule['name']} is an object rule - give the object without field_name")
                continue
        else:
            if not field_name:
                problems.append(f"{label}: rule {rule['name']} is a field rule - field_name is required")
                continue
            field = fields.get((obj["content_hash"], field_name))
            if field is None:
                problems.append(f"{label}: the current version of {obj['name']} has no such field")
                continue
        problem = _scope_problem(rule, obj, field)
        if problem:
            problems.append(f"{label}: {problem}")
            continue
        subjects.append({
            "subject_key": field["field_key"] if field is not None else key, "object_key": key,
            "content_hash": obj["content_hash"], "project_id": obj["project_id"], "project_path": obj["full_path"],
            "object_name": obj["name"], "object_type": obj["type"], "field_name": field_name if field else None,
            "in_main": obj["is_main"],
        })
    return subjects, problems


def _hits(session: Session, rule_id: int, subject_keys: Iterable) -> Dict[Any, dict]:
    keys = sorted({str(k) for k in subject_keys})
    if not keys:
        return {}
    return {r["subject_key"]: dict(r) for r in session.execute(text("""
        SELECT subject_key, status, reviewer, machine_status, reason, note, rule_version, model, decided_via,
               decided_tier
        FROM rule_hits WHERE rule_id = :r AND subject_key = ANY(CAST(:k AS uuid[]))"""),
        {"r": rule_id, "k": keys}).mappings()}


def current_verdict(hit: Optional[dict]) -> Optional[str]:
    """What the current prompt answered (the service model's verdict), as stored: a service hit's status, or the
    recorded ``machine_status`` of a hit a human or the harness model decided (None: no hit, or not recorded)."""
    if hit is None:
        return None
    decided = hit["reviewer"] is not None or hit.get("decided_tier") == "harness"
    return MACHINE_VERDICT.get(hit.get("machine_status") if decided else hit["status"])


# ---- mislabelled subjects --------------------------------------------------------------------------------

def _mislabeled_where(rule: dict, source: str = "human") -> str:
    disagrees = f"{VERDICT_SQL.format(c='h.machine_status')} <> {VERDICT_SQL.format(c='h.status')}"
    if source == "verification":
        return f"""h.rule_id = :r AND h.reviewer IS NULL AND h.decided_tier = 'harness'
            AND h.status IN ('match', 'no_match') AND {_field_cond(rule)} AND h.machine_status IS NOT NULL
            AND {disagrees}"""
    return f"""h.rule_id = :r AND h.reviewer IS NOT NULL AND h.status IN ('match', 'no_match')
        AND {_field_cond(rule)} AND (h.machine_status IS NULL OR {disagrees})"""


def mislabeled(session: Session, rule_id: int, source: str = "human", limit: int = 50,
               offset: int = 0) -> Dict[str, Any]:
    """Subjects of an LLM rule where a human decision (``source="human"``) or a final decision of the harness model
    (``source="verification"``, tiered workflow) disagrees with the service model's verdict (``machine_status``,
    recorded at the first human / harness decision; null for human decisions made before migration 0019: listed
    too, with ``machine_verdict`` null - a trial with ``rerun_current`` measures the current one).
    ``expected_verdict``: the human's / harness model's verdict. ``trial_ready``: the subject is in a current
    snapshot and in the rule's scope (``from_mislabeled`` uses those)."""
    if source == "labels":
        raise Invalid("source='labels': you bring the expected labels yourself - pass them to llm_prompt_trial(rule_id, "
                      "prompt, subjects=[{object_key, field_name?, expected: match|no_match|need_more_info}])")
    if source not in SOURCES:
        raise Invalid(f"source must be one of {list(SOURCES)}")
    rule = _llm_rule(session, rule_id)
    limit = max(1, min(int(limit), MISLABELED_MAX))
    where = _mislabeled_where(rule, source)
    total = session.execute(text(f"SELECT count(*) FROM rule_hits h WHERE {where}"), {"r": rule["id"]}).scalar()
    rows = [dict(r) for r in session.execute(text(f"""
        SELECT h.subject_key, h.object_key, h.field_name, h.status, h.machine_status, h.reason, h.note, h.reviewer,
               h.reviewed_at, h.decided_via, h.rule_version, h.model, h.verifier_model, h.verified_at
        FROM rule_hits h WHERE {where}
        ORDER BY COALESCE(h.reviewed_at, h.verified_at) DESC NULLS LAST, h.subject_key LIMIT :limit OFFSET :offset"""),
        {"r": rule["id"], "limit": limit, "offset": max(int(offset), 0)}).mappings()]
    subjects, problems = resolve_subjects(session, rule, [(r["object_key"], r["field_name"]) for r in rows])
    ready = {(s["object_key"], s["field_name"]): s for s in subjects}
    problem_of = {}
    for p in problems:                      # "<object_key>[ field 'x']: why"
        head, _, why = p.partition(": ")
        problem_of[head] = why
    from services.review_service import hit_id
    items = []
    for r in rows:
        subject = ready.get((r["object_key"], r["field_name"]))
        label = f"{r['object_key']}" + (f" field {r['field_name']!r}" if r["field_name"] else "")
        items.append({
            "hit_id": hit_id(rule["id"], r["subject_key"]), "subject_key": str(r["subject_key"]),
            "object_key": str(r["object_key"]), "field_name": r["field_name"],
            "object_name": subject["object_name"] if subject else None,
            "object_type": subject["object_type"] if subject else None,
            "project_path": subject["project_path"] if subject else None,
            "machine_verdict": MACHINE_VERDICT.get(r["machine_status"]), "machine_status": r["machine_status"],
            "machine_reason": r["reason"], "model": r["model"], "rule_version": r["rule_version"],
            "expected_verdict": HUMAN_VERDICT[r["status"]], "source": source,
            "human_verdict": HUMAN_VERDICT[r["status"]] if source == "human" else None,
            "harness_verdict": HUMAN_VERDICT[r["status"]] if source == "verification" else None,
            "reviewer": r["reviewer"], "decided_via": r["decided_via"], "reviewed_at": r["reviewed_at"],
            "verifier_model": r["verifier_model"], "verified_at": r["verified_at"], "note": r["note"],
            "trial_ready": subject is not None, "problem": None if subject else problem_of.get(label),
        })
    nxt = offset + limit
    return {"rule": {"id": rule["id"], "name": rule["name"], "target": rule["target"], "version": rule["version"]},
            "source": source, "total": total, "next_offset": nxt if nxt < total else None, "items": items}


# ---- trials ------------------------------------------------------------------------------------------------

def _parse_subjects(subjects, maximum: int) -> List[Tuple[uuid.UUID, Optional[str], str]]:
    if not isinstance(subjects, list) or not subjects:
        raise Invalid("subjects must be a non-empty list of {object_key, field_name?, expected}")
    if len(subjects) > maximum:
        raise Invalid(f"too many subjects: {len(subjects)} (at most LLM_TRIAL_MAX_SUBJECTS = {maximum}, controls "
                      f"included)")
    parsed, seen = [], set()
    for i, s in enumerate(subjects):
        if not isinstance(s, dict):
            raise Invalid(f"subjects[{i}] must be an object {{object_key, field_name?, expected}}")
        unknown = set(s) - {"object_key", "object_id", "field_name", "expected"}
        if unknown:
            raise Invalid(f"subjects[{i}]: unknown keys {sorted(unknown)}")
        key = _uuid(s.get("object_key") or s.get("object_id"), f"subjects[{i}].object_key")
        field_name = s.get("field_name") or None
        if field_name is not None and (not isinstance(field_name, str) or len(field_name) > 1000):
            raise Invalid(f"subjects[{i}].field_name must be a field name")
        expected = s.get("expected")
        if expected not in LLM_VERDICTS:
            raise Invalid(f"subjects[{i}].expected must be one of {list(LLM_VERDICTS)}")
        if (key, field_name) in seen:
            raise Invalid(f"subjects[{i}]: duplicate subject {key}" + (f" field {field_name!r}" if field_name else ""))
        seen.add((key, field_name))
        parsed.append((key, field_name, expected))
    return parsed


def _controls(session: Session, rule: dict, exclude: List, n: int) -> List[dict]:
    """``n`` random subjects whose current verdict is agreed, in a current snapshot and the rule's scope: a human
    or the harness model (tiered workflow) decided them and the recorded service verdict (``machine_status``) agrees.
    ``expected`` = the agreed verdict."""
    if n <= 0:
        return []
    rows = [dict(r) for r in session.execute(text(f"""
        SELECT h.subject_key, h.object_key, h.field_name, h.status, h.reviewer, h.machine_status, h.reason
        FROM rule_hits h
        WHERE h.rule_id = :r AND {_field_cond(rule)} AND NOT (h.subject_key = ANY(CAST(:ex AS uuid[])))
          AND (h.reviewer IS NOT NULL OR h.decided_tier = 'harness')
          AND h.status IN ('match', 'no_match') AND h.machine_status IS NOT NULL
          AND {VERDICT_SQL.format(c='h.machine_status')} = {VERDICT_SQL.format(c='h.status')}
        ORDER BY random()
        LIMIT :limit"""), {"r": rule["id"], "ex": [str(k) for k in exclude], "limit": n * 3}).mappings()]
    subjects, _ = resolve_subjects(session, rule, [(r["object_key"], r["field_name"]) for r in rows])
    by_subject = {(s["object_key"], s["field_name"]): s for s in subjects}
    chosen = []
    for r in rows:
        s = by_subject.get((r["object_key"], r["field_name"]))
        if s is None:
            continue
        chosen.append({**s, "expected": HUMAN_VERDICT[r["status"]]})
        if len(chosen) == n:
            break
    return chosen


# ``sample``: random subjects in the rule's scope (a new rule without decisions). The schema of migration 0019 knows
# the roles target / control only and ``expected`` is NOT NULL, so a sample subject WITH a hit is a control (expected
# = the current verdict) and one WITHOUT a hit is stored as a control with this placeholder and no current_status;
# the API shows it as role ``sample`` with expected None and the metrics skip it.
SAMPLE_PLACEHOLDER = "need_more_info"
SAMPLE_CANDIDATES_MAX = 2000

# the dry run's scope: objects of main snapshots of projects in rules mode (``insights_service.dry_run_rule``); the
# patterns of the rule are checked in Python by ``resolve_subjects``
# ``TABLESAMPLE SYSTEM`` (scale): a random share of the pages of branch_objects / object_fields instead of a sort of
# every main field by random() (seconds on the stand, minutes at 50M fields); the share grows with the wanted
# candidates (``sample_percent``) and the query is retried with a bigger share when the sample came back short.
SAMPLE_OBJECTS_SQL = """
    SELECT b.object_key FROM branch_objects b TABLESAMPLE SYSTEM (:pct)
    JOIN gitlab_branches g ON g.id = b.branch_id JOIN gitlab_projects p ON p.id = g.project_id
    WHERE b.is_main AND b.content_hash IS NOT NULL AND p.scan_mode = 'rules'
      AND NOT EXISTS (SELECT 1 FROM unnest(CAST(:ex AS uuid[])) x WHERE x = b.object_key)
    ORDER BY random() LIMIT :limit"""
SAMPLE_FIELDS_SQL = """
    SELECT b.object_key, f.field_name FROM object_fields f TABLESAMPLE SYSTEM (:pct)
    JOIN branch_objects b ON b.content_hash = f.content_hash AND b.is_main
    JOIN gitlab_branches g ON g.id = b.branch_id JOIN gitlab_projects p ON p.id = g.project_id
    WHERE p.scan_mode = 'rules'
      AND NOT EXISTS (SELECT 1 FROM unnest(CAST(:ex AS uuid[])) x WHERE x = f.field_key)
    ORDER BY random() LIMIT :limit"""
SAMPLE_PERCENTS = (0.5, 5, 50, 100)


def sample_rows(session: Session, sql: str, params: dict) -> list:
    """Rows of a TABLESAMPLE query, the sampled share raised until the limit is reached or the whole table was read."""
    rows: list = []
    for pct in SAMPLE_PERCENTS:
        rows = session.execute(text(sql), {**params, "pct": pct}).mappings().all()
        if len(rows) >= params["limit"]:
            break
    return rows


def _is_sample(item: dict) -> bool:
    return item["role"] == "control" and item["current_status"] is None and item["expected"] == SAMPLE_PLACEHOLDER


def _sample(session: Session, rule: dict, exclude: List, n: int) -> List[dict]:
    """``n`` random subjects in the rule's scope (the dry run's scope, the rule's patterns) not in ``exclude``
    (subject keys): role control with the current verdict as expected when a hit exists, else a sample item (see
    SAMPLE_PLACEHOLDER)."""
    if n <= 0:
        return []
    sql = SAMPLE_OBJECTS_SQL if rule["target"] == "object" else SAMPLE_FIELDS_SQL
    rows = sample_rows(session, sql, {"ex": [str(k) for k in exclude],
                                      "limit": min(max(n * 10, 50), SAMPLE_CANDIDATES_MAX)})
    wanted = [(r["object_key"], r["field_name"] if rule["target"] != "object" else None) for r in rows]
    subjects, _ = resolve_subjects(session, rule, wanted)
    chosen = subjects[:n]
    hits = _hits(session, rule["id"], [s["subject_key"] for s in chosen])
    out = []
    for s in chosen:
        verdict = current_verdict(hits.get(s["subject_key"]))
        out.append({**s, "role": "control", "expected": verdict or SAMPLE_PLACEHOLDER, "_sample": verdict is None})
    return out


def planned_calls(items: List[dict], rerun_current: bool) -> int:
    """One model call per object with the candidate, one more with the current prompt for an object with a
    target subject (``rerun_current``)."""
    roles: Dict[Any, set] = {}
    for item in items:
        roles.setdefault(item["object_key"], set()).add(item["role"])
    return sum(1 + (1 if rerun_current and "target" in r else 0) for r in roles.values())


BUDGET_LOCK = 0x7472_6961        # pg_advisory_xact_lock: one budget check at a time
USED_TODAY_SQL = text("""
    SELECT COALESCE(sum(CASE WHEN status IN ('done', 'failed') THEN calls ELSE GREATEST(planned_calls, calls) END), 0)
    FROM prompt_trials WHERE created_at >= (date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')""")


def budget(session: Session) -> Dict[str, int]:
    """Model calls of the prompt trials of the current UTC day (finished: made; queued / running: planned)."""
    cap = _settings().llm_trial_daily_calls
    used = int(session.execute(USED_TODAY_SQL).scalar() or 0)
    return {"daily_calls": cap, "used_today": used, "left_today": max(cap - used, 0)}


def create_trial(session: Session, rule_id: int, prompt: str, *, user: str, subjects=None,
                 from_mislabeled=False, include_controls: int = 20, rerun_current: bool = True,
                 note: Optional[str] = None, sample: int = 0) -> Dict[str, Any]:
    """Queue a prompt trial (see the module doc); returns the trial (status queued), its planned model calls and
    the day's budget. ``sample``: random subjects in the rule's scope (expected = the current verdict when a hit
    exists, else none: a new rule without decisions) - alone or next to ``subjects`` / ``from_mislabeled``."""
    from discovery_common import jobs

    settings = _settings()
    maximum, cap = settings.llm_trial_max_subjects, settings.llm_trial_daily_calls
    if maximum <= 0 or cap <= 0:
        raise Invalid("prompt trials are disabled (LLM_TRIAL_MAX_SUBJECTS / LLM_TRIAL_DAILY_CALLS = 0)")
    rule = _llm_rule(session, rule_id)
    prompt = _text(prompt, "prompt", PROMPT_MAX, required=True)
    note = _text(note, "note", NOTE_MAX)
    try:
        include_controls, sample = int(include_controls), int(sample or 0)
    except (TypeError, ValueError):
        raise Invalid("include_controls and sample must be integers") from None
    if include_controls < 0:
        raise Invalid("include_controls must be >= 0")          # the controls fill what targets leave of the maximum
    if not 0 <= sample <= 200:
        raise Invalid("sample must be between 0 and 200")
    if subjects and from_mislabeled:
        raise Invalid("give either subjects (your own expected labels) or from_mislabeled=true, not both")
    if not (subjects or from_mislabeled or sample > 0):
        raise Invalid("subjects, from_mislabeled=true or sample > 0 is required")

    if from_mislabeled:
        if from_mislabeled is True or from_mislabeled == "any":
            sources = ["human", "verification"]
        elif from_mislabeled in SOURCES:
            sources = [from_mislabeled]
        else:
            raise Invalid(f"from_mislabeled must be true or one of {list(SOURCES)}")
        wanted, seen = [], set()
        for source in sources:                 # a human decision wins over the harness model's
            found = mislabeled(session, rule["id"], source, limit=min(maximum, MISLABELED_MAX))
            for i in found["items"]:
                key = (i["object_key"], i["field_name"])
                if i["trial_ready"] and key not in seen and len(wanted) < maximum:
                    seen.add(key)
                    wanted.append((uuid.UUID(i["object_key"]), i["field_name"], i["expected_verdict"]))
        if not wanted:
            raise Invalid(f"rule {rule['name']} has no mislabelled subject in a current snapshot (human or harness-model "
                          f"decisions that disagree with the service model): pass subjects with your own expected labels")
    elif subjects:
        wanted = _parse_subjects(subjects, maximum)
    else:
        wanted = []
    resolved, problems = resolve_subjects(session, rule, [(k, f) for k, f, _ in wanted])
    if problems:
        raise Invalid(f"{len(problems)} subject(s) cannot be tried with rule {rule['name']}: " + "; ".join(problems[:10])
                      + ("; ..." if len(problems) > 10 else ""))
    expected_of = {(k, f): e for k, f, e in wanted}
    targets = [{**s, "role": "target", "expected": expected_of[(s["object_key"], s["field_name"])]} for s in resolved]
    if len({t["subject_key"] for t in targets}) != len(targets):
        raise Invalid("duplicate subjects")
    controls = [{**c, "role": "control"} for c in _controls(
        session, rule, [t["subject_key"] for t in targets], min(include_controls, maximum - len(targets)))]
    items = targets + controls
    if sample > 0:
        items += _sample(session, rule, [i["subject_key"] for i in items], min(sample, maximum - len(items)))
    if len(items) > maximum:
        raise Invalid(f"too many subjects: {len(items)} (at most LLM_TRIAL_MAX_SUBJECTS = {maximum})")
    if not items:
        raise Invalid(f"rule {rule['name']} has no subject in scope to sample")

    calls = planned_calls(items, rerun_current)
    session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": BUDGET_LOCK})
    spent = budget(session)
    if spent["used_today"] + calls > cap:
        raise TooManyRequests(
            f"the daily budget of prompt trial model calls is used up: {spent['used_today']} of {cap} "
            f"(LLM_TRIAL_DAILY_CALLS, UTC day) and this trial needs {calls} - try fewer subjects or controls, "
            f"rerun_current=false, or tomorrow")

    hits = _hits(session, rule["id"], [i["subject_key"] for i in items])
    trial_id = session.execute(text("""
        INSERT INTO prompt_trials (rule_id, rule_version, prompt_version, base_prompt, candidate_prompt, prompt_hash,
                                   rerun_current, planned_calls, created_by, note)
        VALUES (:r, :v, :pv, :base, :prompt, :hash, :rerun, :calls, :user, :note) RETURNING id"""), {
        "r": rule["id"], "v": rule["version"], "pv": lifecycle.pinned_core_version(rule), "base": rule["prompt"], "prompt": prompt,
        "hash": prompt_hash(prompt), "rerun": bool(rerun_current), "calls": calls, "user": user, "note": note,
    }).scalar()
    session.execute(text("""
        INSERT INTO prompt_trial_items (trial_id, subject_key, object_key, content_hash, project_id, field_name, role,
                                        expected, current_verdict, current_reason, current_status)
        VALUES (:t, :s, :o, :h, :p, :f, :role, :e, :cv, :cr, :cs)"""), [{
        "t": trial_id, "s": i["subject_key"], "o": i["object_key"], "h": i["content_hash"], "p": i["project_id"],
        "f": i["field_name"], "role": i["role"], "e": i["expected"],
        "cv": current_verdict(hits.get(i["subject_key"])),
        "cr": (hits.get(i["subject_key"]) or {}).get("reason"),
        "cs": (hits.get(i["subject_key"]) or {}).get("status"),
    } for i in items])
    job_id = jobs.enqueue("llm_trial", {"trial_id": trial_id, "rule_id": rule["id"], "requested_by": user},
                          f"llm_trial:{trial_id}", conn=session, priority=JOB_PRIORITY_TRIAL)
    session.execute(text("UPDATE prompt_trials SET job_id = :j WHERE id = :t"), {"j": job_id, "t": trial_id})
    sampled = sum(1 for i in items if i.get("_sample"))
    logger.info(f"Prompt trial {trial_id} of LLM rule {rule['name']} v{rule['version']} queued by {user}: "
                f"{len(targets)} targets, {len(items) - len(targets) - sampled} controls, {sampled} samples, "
                f"{calls} planned service model calls ({spent['used_today'] + calls} of {cap} today)")
    result = trial_result(session, trial_id, include_items=False)
    result["budget"] = {**spent, "used_today": spent["used_today"] + calls,
                        "left_today": max(cap - spent["used_today"] - calls, 0)}
    result["next"] = (f"llm_prompt_trial_result(trial_id={trial_id}) once status is done (the scanner's LLM workers "
                      f"run it; llm_runs shows the progress)")
    return result


def metrics(items: List[dict]) -> Dict[str, Any]:
    """Targets: ``before`` = the current prompt's verdict (re-run in the trial, else stored); ``fixed`` = new ==
    expected != before; ``still_wrong`` = new != expected and before != expected; ``newly_wrong`` = new !=
    expected == before; ``kept_right``. Controls: ``regressions`` = new != the agreed verdict. Accuracy = share of
    subjects whose verdict equals the expected one (before: of those with a known current verdict; after: of
    those the candidate answered). ``failed``: no answer of the candidate; ``pending``: not asked yet;
    ``current_drift``: targets whose re-run current verdict differs from the stored one."""
    def acc(pairs):
        pairs = [(v, e) for v, e in pairs if v is not None and e is not None]
        return round(sum(1 for v, e in pairs if v == e) / len(pairs), 4) if pairs else None

    items = [_item_view(i) for i in items]
    targets = [i for i in items if i["role"] == "target"]
    controls = [i for i in items if i["role"] == "control"]
    samples = [i for i in items if i["role"] == "sample"]
    t = dict.fromkeys(("total", "fixed", "still_wrong", "newly_wrong", "kept_right", "failed", "pending",
                       "current_drift"), 0)
    for i in targets:
        t["total"] += 1
        before = i["rerun_verdict"] if i["rerun_verdict"] is not None else i["current_verdict"]
        new, exp = i["new_verdict"], i["expected"]
        if i["rerun_verdict"] is not None and i["current_verdict"] is not None \
                and i["rerun_verdict"] != i["current_verdict"]:
            t["current_drift"] += 1
        if i["asked_at"] is None:
            t["pending"] += 1
        elif new is None:
            t["failed"] += 1
        elif new == exp:
            t["fixed" if before != exp else "kept_right"] += 1
        else:
            t["still_wrong" if before != exp else "newly_wrong"] += 1
    t["accuracy_before"] = acc((i["rerun_verdict"] if i["rerun_verdict"] is not None else i["current_verdict"],
                                i["expected"]) for i in targets)
    t["accuracy_after"] = acc((i["new_verdict"], i["expected"]) for i in targets)
    c = dict.fromkeys(("total", "kept", "regressions", "failed", "pending"), 0)
    for i in controls:
        c["total"] += 1
        if i["asked_at"] is None:
            c["pending"] += 1
        elif i["new_verdict"] is None:
            c["failed"] += 1
        else:
            c["kept" if i["new_verdict"] == i["expected"] else "regressions"] += 1
    c["accuracy_before"] = acc((i["current_verdict"], i["expected"]) for i in controls)
    c["accuracy_after"] = acc((i["new_verdict"], i["expected"]) for i in controls)
    everything = {
        "accuracy_before": acc(((i["rerun_verdict"] if i["rerun_verdict"] is not None else i["current_verdict"]),
                                i["expected"]) for i in items),
        "accuracy_after": acc((i["new_verdict"], i["expected"]) for i in items),
    }
    # samples without an expected verdict: only what the candidate answered
    s = dict.fromkeys(("total", "pending", "failed", "match", "no_match", "need_more_info"), 0)
    for i in samples:
        s["total"] += 1
        if i["asked_at"] is None:
            s["pending"] += 1
        elif i["new_verdict"] is None:
            s["failed"] += 1
        elif i["new_verdict"] in s:
            s[i["new_verdict"]] += 1
    return {"targets": t, "controls": c, "samples": s, "all": everything}


def _item_view(item: dict) -> dict:
    """A trial item as the API shows it: a sample without a hit has role ``sample`` and no expected verdict."""
    if item.get("role") == "sample" or ("current_status" in item and _is_sample(item)):
        return {**item, "role": "sample", "expected": None}
    return item


TRIAL_SQL = """
    SELECT t.*, r.name AS rule_name, r.version AS current_version, r.target, j.status AS job_status,
           j.progress AS job_progress, j.last_error AS job_error
    FROM prompt_trials t JOIN rules r ON r.id = t.rule_id LEFT JOIN jobs j ON j.id = t.job_id"""

ITEMS_SQL = """
    SELECT i.*, o.name AS object_name, o.type AS object_type, p.full_path AS project_path
    FROM prompt_trial_items i LEFT JOIN objects o ON o.content_hash = i.content_hash
    LEFT JOIN gitlab_projects p ON p.id = i.project_id
    WHERE i.trial_id = ANY(:ids) ORDER BY i.trial_id, i.role DESC, i.id"""


def _items(session: Session, trial_ids: List[int]) -> Dict[int, List[dict]]:
    out: Dict[int, List[dict]] = {t: [] for t in trial_ids}
    if trial_ids:
        for r in session.execute(text(ITEMS_SQL), {"ids": trial_ids}).mappings():
            out[r["trial_id"]].append(dict(r))
    return out


def _trial_out(row, items: List[dict], include_items: bool, only: Optional[str] = None) -> Dict[str, Any]:
    progress = row["job_progress"] or {}
    out = {
        "id": row["id"], "rule_id": row["rule_id"], "rule_name": row["rule_name"], "rule_version": row["rule_version"],
        "current_rule_version": row["current_version"], "stale": row["rule_version"] != row["current_version"],
        "status": row["status"], "job_id": row["job_id"], "job_status": row["job_status"],
        "progress": {k: progress.get(k) for k in ("total_objects", "done_objects", "failed_objects", "phase")
                     if progress.get(k) is not None} or None,
        "model": row["model"], "planned_calls": row["planned_calls"], "calls": row["calls"],
        "failed_calls": row["failed_calls"], "rerun_current": row["rerun_current"],
        "prompt_hash": row["prompt_hash"], "prompt_version": row["prompt_version"], "note": row["note"],
        "error": row["error"] or (row["job_error"] if row["status"] == "failed" else None),
        "created_by": row["created_by"], "created_at": row["created_at"], "started_at": row["started_at"],
        "finished_at": row["finished_at"], "metrics": metrics(items),
    }
    if include_items:
        out["candidate_prompt"] = row["candidate_prompt"]
        out["base_prompt"] = row["base_prompt"]
        selected = [_item_view(i) for i in items]
        if only == "changed":
            selected = [i for i in items if i["new_verdict"] != (
                i["rerun_verdict"] if i["rerun_verdict"] is not None else i["current_verdict"])]
        elif only == "wrong":
            selected = [i for i in selected if i["expected"] is not None and i["new_verdict"] != i["expected"]]
        out["items"] = [{
            "subject_key": str(i["subject_key"]), "object_key": str(i["object_key"]), "role": i["role"],
            "project_path": i["project_path"], "object_name": i["object_name"], "object_type": i["object_type"],
            "field_name": i["field_name"], "expected": i["expected"],
            "current": {"verdict": i["current_verdict"], "reason": i["current_reason"], "status": i["current_status"]},
            "rerun": {"verdict": i["rerun_verdict"], "reason": i["rerun_reason"], "fields": i["rerun_fields"]}
            if row["rerun_current"] and i["role"] == "target" else None,
            "new": {"verdict": i["new_verdict"], "reason": i["new_reason"], "fields": i["new_fields"]},
            "error": i["error"], "asked": i["asked_at"] is not None,
        } for i in selected]
    return out


def trial_result(session: Session, trial_id: int, include_items: bool = True, only: Optional[str] = None
                 ) -> Dict[str, Any]:
    if only not in (None, "all", "changed", "wrong"):
        raise Invalid("only must be all, changed or wrong")
    row = session.execute(text(TRIAL_SQL + " WHERE t.id = :id"), {"id": int(trial_id)}).mappings().first()
    if row is None:
        raise NotFound(f"prompt trial {trial_id} not found")
    return _trial_out(row, _items(session, [row["id"]])[row["id"]], include_items, None if only == "all" else only)


def list_trials(session: Session, rule_id: int, limit: int = 20) -> Dict[str, Any]:
    rule = _llm_rule(session, rule_id)
    rows = list(session.execute(text(TRIAL_SQL + " WHERE t.rule_id = :r ORDER BY t.id DESC LIMIT :limit"),
                                {"r": rule["id"], "limit": max(1, min(int(limit), 100))}).mappings())
    items = _items(session, [r["id"] for r in rows])
    return {"rule": {"id": rule["id"], "name": rule["name"], "version": rule["version"]},
            "budget": budget(session), "items": [_trial_out(r, items[r["id"]], False) for r in rows]}


# ---- proposals ---------------------------------------------------------------------------------------------

def _diff(old: Optional[str], new: str) -> str:
    return "".join(difflib.unified_diff((old or "").splitlines(keepends=True), new.splitlines(keepends=True),
                                        fromfile="current", tofile="proposed", n=2))


def _proposal_out(session: Session, row, rule: dict) -> Dict[str, Any]:
    trial = trial_result(session, row["trial_id"], include_items=False)
    return {
        "id": row["id"], "rule_id": row["rule_id"], "rule_name": rule["name"], "base_version": row["base_version"],
        "current_version": rule["version"], "stale": row["status"] == "open" and rule["version"] != row["base_version"],
        "status": row["status"], "prompt": row["prompt"], "prompt_hash": row["prompt_hash"],
        "rationale": row["rationale"], "created_by": row["created_by"], "created_at": row["created_at"],
        "decided_by": row["decided_by"], "decided_at": row["decided_at"], "decision_note": row["decision_note"],
        "accepted_version": row["accepted_version"],
        "diff": _diff(rule["prompt"], row["prompt"]) if row["status"] == "open" else None,
        "trial": {k: trial[k] for k in ("id", "status", "model", "calls", "failed_calls", "rerun_current",
                                        "finished_at", "metrics")},
    }


def create_proposal(session: Session, rule_id: int, prompt: str, trial_id: int, rationale: str, *,
                    user: str) -> Dict[str, Any]:
    """A prompt change proposed to a human: needs a finished trial of the same text on the rule's current
    version; the rule is not changed."""
    rule = _llm_rule(session, rule_id)
    prompt = _text(prompt, "prompt", PROMPT_MAX, required=True)
    rationale = _text(rationale, "rationale", RATIONALE_MAX, required=True)
    trial = session.execute(text("SELECT id, rule_id, rule_version, status, prompt_hash FROM prompt_trials "
                                 "WHERE id = :t"), {"t": int(trial_id)}).mappings().first()
    if trial is None or trial["rule_id"] != rule["id"]:
        raise NotFound(f"prompt trial {trial_id} of rule {rule['name']} not found")
    if trial["status"] != "done":
        raise Conflict(f"prompt trial {trial_id} is {trial['status']}: a proposal needs a finished trial "
                       f"(llm_prompt_trial_result)")
    if trial["prompt_hash"] != prompt_hash(prompt):
        raise Invalid(f"the prompt differs from the one prompt trial {trial_id} ran: try this exact text first "
                      f"(llm_prompt_trial)")
    if trial["rule_version"] != rule["version"]:
        raise Conflict(f"rule {rule['name']} changed since prompt trial {trial_id} (v{trial['rule_version']} -> "
                       f"v{rule['version']}): run the trial again")
    if prompt == (rule["prompt"] or ""):
        raise Invalid("the prompt is the rule's current prompt")
    proposal_id = session.execute(text("""
        INSERT INTO prompt_proposals (rule_id, base_version, prompt, prompt_hash, trial_id, rationale, created_by)
        VALUES (:r, :v, :p, :h, :t, :why, :user) RETURNING id"""), {
        "r": rule["id"], "v": rule["version"], "p": prompt, "h": prompt_hash(prompt), "t": trial["id"],
        "why": rationale, "user": user}).scalar()
    logger.info(f"Prompt proposal {proposal_id} for LLM rule {rule['name']} v{rule['version']} by {user} "
                f"(trial {trial['id']})")
    return get_proposal(session, proposal_id)


def get_proposal(session: Session, proposal_id: int) -> Dict[str, Any]:
    row = session.execute(text("SELECT * FROM prompt_proposals WHERE id = :id"),
                          {"id": int(proposal_id)}).mappings().first()
    if row is None:
        raise NotFound(f"prompt proposal {proposal_id} not found")
    rule = session.execute(text("SELECT id, name, prompt, version FROM rules WHERE id = :r"),
                           {"r": row["rule_id"]}).mappings().one()
    return _proposal_out(session, row, dict(rule))


def reask_estimate(session: Session, proposal_id: int) -> Dict[str, Any]:
    """What accepting (and activating) the proposal costs: the dry run of the rule with the proposed prompt (a new
    version: every service verdict of the rule is asked again by its rollout - human and harness-model decisions
    are kept); ``fresh`` / ``migration``: the subjects / calls of the normal runs and of the rollout."""
    from services import insights_service
    row = session.execute(text("SELECT rule_id, prompt FROM prompt_proposals WHERE id = :id"),
                          {"id": int(proposal_id)}).mappings().first()
    if row is None:
        raise NotFound(f"prompt proposal {proposal_id} not found")
    estimate = insights_service.dry_run_rule(session, kind="llm", rule={"prompt": row["prompt"]},
                                             rule_id=row["rule_id"])
    return {k: estimate.get(k) for k in ("subjects_to_send", "model_calls", "by_project", "projects",
                                         "objects_scanned", "truncated", "note", "fresh", "migration") if k in estimate}


def _proposal_status(status: Optional[str]) -> Optional[str]:
    from discovery_common.models import PROPOSAL_STATUSES
    if status in (None, "", "all"):
        return None
    if status not in PROPOSAL_STATUSES:
        raise Invalid(f"status must be one of {list(PROPOSAL_STATUSES)} or all")
    return status


def list_proposals(session: Session, rule_id: int, status: Optional[str] = None, limit: int = 50) -> Dict[str, Any]:
    rule = _llm_rule(session, rule_id)
    status = _proposal_status(status)
    rows = list(session.execute(text(
        "SELECT * FROM prompt_proposals WHERE rule_id = :r AND (CAST(:s AS text) IS NULL OR status = :s) "
        "ORDER BY (status = 'open') DESC, id DESC LIMIT :limit"),
        {"r": rule["id"], "s": status, "limit": max(1, min(int(limit), 100))}).mappings())
    return {"rule": {"id": rule["id"], "name": rule["name"], "version": rule["version"], "prompt": rule["prompt"]},
            "items": [_proposal_out(session, r, rule) for r in rows]}


def list_all_proposals(session: Session, status: Optional[str] = "open", limit: int = 50) -> Dict[str, Any]:
    """Proposals of every LLM rule (``GET /prompt_proposals``; ``status`` open by default, ``all`` for every status),
    open ones first, each with ``rule_id`` / ``rule_name``: what waits for a human's decision."""
    status = _proposal_status(status)
    rows = list(session.execute(text("""
        SELECT pp.*, r.name AS r_name, r.prompt AS r_prompt, r.version AS r_version
        FROM prompt_proposals pp JOIN rules r ON r.id = pp.rule_id
        WHERE r.deleted_at IS NULL AND (CAST(:s AS text) IS NULL OR pp.status = :s)
        ORDER BY (pp.status = 'open') DESC, pp.id DESC LIMIT :limit"""),
        {"s": status, "limit": max(1, min(int(limit), 200))}).mappings())
    items = [_proposal_out(session, r, {"id": r["rule_id"], "name": r["r_name"], "prompt": r["r_prompt"],
                                        "version": r["r_version"]}) for r in rows]
    return {"status": status or "all", "items": items}


def _open_proposal(session: Session, proposal_id: int) -> dict:
    row = session.execute(text("SELECT * FROM prompt_proposals WHERE id = :id FOR UPDATE"),
                          {"id": int(proposal_id)}).mappings().first()
    if row is None:
        raise NotFound(f"prompt proposal {proposal_id} not found")
    if row["status"] != "open":
        raise Conflict(f"prompt proposal {proposal_id} is {row['status']} already")
    return dict(row)


def accept_proposal(session: Session, proposal_id: int, *, user: str, note: Optional[str] = None,
                    run: bool = False, activate: bool = False, budget: Optional[dict] = None) -> Dict[str, Any]:
    """A human adopts the proposal: it becomes a CANDIDATE version of the rule (``rule_versions``, source
    ``proposal:<id>``; the rule itself is not changed - ``accepted_version`` / ``version_id`` name the candidate);
    the other open proposals of the rule are superseded. ``activate`` (``run``: the same, kept for the clients of the
    previous release): also activate the candidate and start its rollout (the stale verdicts are asked again in
    budgeted slices; human and harness decisions are kept). REST / UI only - MCP agents cannot accept."""
    from services import rules_service, versions_service
    note = _text(note, "note", NOTE_MAX)
    proposal = _open_proposal(session, proposal_id)
    rule = _llm_rule(session, proposal["rule_id"], lock=True)
    if rule["version"] != proposal["base_version"]:
        raise Conflict(f"rule {rule['name']} changed since the proposal (v{proposal['base_version']} -> "
                       f"v{rule['version']}): the proposal is stale - reject it and run a new trial")
    active = lifecycle.ensure_active_version(session, rule["id"], user)
    version = lifecycle.create_version(
        session, rule["id"], prompt=proposal["prompt"], target=active["target"], matchers=active["matchers"],
        core_prompt_version=lifecycle.code_core_version(rule), model=active["model"],
        source=f"proposal:{proposal['id']}", created_by=user, proposal_id=proposal["id"],
        note=(f"prompt proposal #{proposal['id']} by {proposal['created_by']}: {proposal['rationale']}")[:2000])
    session.execute(text("""
        UPDATE prompt_proposals SET status = 'accepted', decided_by = :u, decided_at = now(), decision_note = :n,
               accepted_version = :v, version_id = :vid WHERE id = :id"""),
        {"u": user, "n": note, "v": version["version"], "vid": version["id"], "id": proposal["id"]})
    session.execute(text("""
        UPDATE prompt_proposals SET status = 'superseded', decided_by = :u, decided_at = now(),
               decision_note = :n WHERE rule_id = :r AND status = 'open' AND id <> :id"""),
        {"u": user, "n": f"superseded by proposal {proposal['id']}", "r": rule["id"], "id": proposal["id"]})
    activation = None
    if activate or run:
        activation = versions_service.activate(session, version["id"], user=user, start_rollout=True, budget=budget,
                                               note=note)
    logger.info(f"Prompt proposal {proposal['id']} accepted by {user}: LLM rule {rule['name']} candidate "
                f"v{version['version']}" + (" (activated)" if activation else ""))
    current = rules_service.get_rule(session, "llm", rule["id"])
    session.refresh(current)
    return {"proposal": get_proposal(session, proposal["id"]),
            "rule": json.loads(rules_service.to_out(current).model_dump_json(exclude_none=True)),
            "version": versions_service.get_version(session, version["id"]), "activation": activation,
            "run": activation["rollout"] if activation else None}


def reject_proposal(session: Session, proposal_id: int, *, user: str, note: Optional[str] = None) -> Dict[str, Any]:
    note = _text(note, "note", NOTE_MAX)
    proposal = _open_proposal(session, proposal_id)
    session.execute(text("UPDATE prompt_proposals SET status = 'rejected', decided_by = :u, decided_at = now(), "
                         "decision_note = :n WHERE id = :id"), {"u": user, "n": note, "id": proposal["id"]})
    return get_proposal(session, proposal["id"])
