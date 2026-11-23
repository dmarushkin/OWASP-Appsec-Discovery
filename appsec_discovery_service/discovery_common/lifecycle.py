"""Lifecycle of the LLM rules' verdicts (migrations 0024 - 0026), shared by the scanner and the API.

Version key of a verdict: ``rule_hits.rule_version`` (the rule version number), ``prompt_version`` (the core prompts
FAMILY version that made it: ``classifier{N}`` for the built-in classifier - a field rule without category -, else
``rule{N}``) and ``model`` (the service model). A rule version (``rule_versions``) pins the core prompts version
(``core_prompt_version``) and the service model (``model``) its verdicts belong to; ``rules`` is the projection of
the active version.

Candidates of a rule run come in two classes:

* FRESH (``FRESH_COND``): no verdict, a machine verdict on other content of the subject (``subject_hash``), a pending
  hit a reviewer reopened once the version is newer, object rules: another object name / set of field names
  (``names_hash``, even a human decision). Asked by every run, as before.
* MIGRATION (``MIGRATION_COND``): a machine verdict (no reviewer, not the harness tier) of an older rule version, of
  core prompts that are neither the pinned nor the code's ones, or of a service model that is neither the version's
  nor the scanner's. Such a verdict is kept, shown and scoring - flagged ``stale`` (stale-while-revalidate) - until a
  rule rollout (``llm_rollouts``, scanner ``services.lifecycle_service``) asks it again in budgeted slices;
  LLM_REASK_INLINE=true asks it in every run (the behaviour before the lifecycle).

The SQL conditions here are literal (the scanner's candidate queries, the coverage counts and the query plan tests
contain them verbatim); ``is_fresh`` / ``is_migration`` are their Python twins (the API's estimates).
"""

import json
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from discovery_common.log import get_logger
from discovery_common.models import CORE_PROMPT_FAMILIES, ROLLOUT_MODES, ROLLOUT_OPEN

logger = get_logger(__name__)

META_SCOPE_KEYS = ("source", "legacy_status", "legacy_risk_score", "prompt_ver")
MATCHER_KEYS = ("project_re", "object_re", "object_type_re", "field_re", "field_type_re", "mark_fields")
# rule_versions.source of the versions the scanner makes on its own (no content change)
AUTO_SOURCES = ("core_bump", "model_change", "core_bump+model_change")
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
OPEN_SQL = ", ".join(f"'{s}'" for s in ROLLOUT_OPEN)


class LifecycleError(Exception):
    """A lifecycle action that cannot be done (``kind``: invalid | conflict | not_found)."""

    def __init__(self, message: str, kind: str = "conflict"):
        super().__init__(message)
        self.kind = kind


# ---- version key ------------------------------------------------------------------------------------------------

def _get(rule, key, default=None):
    if isinstance(rule, dict):
        return rule.get(key, default)
    return getattr(rule, key, default)


def core_family(rule) -> str:
    """``classifier`` for the built-in classifier (a field rule without category), else ``rule``."""
    return "classifier" if _get(rule, "target") != "object" and not _get(rule, "category") else "rule"


def code_core_version(rule) -> str:
    """The core prompts family version the code answers ``rule`` with now."""
    return CORE_PROMPT_FAMILIES[core_family(rule)]


def pinned_core_version(rule) -> str:
    """The core prompts version the rule's active version is pinned to (NULL: the code's)."""
    return _get(rule, "core_prompt_version") or code_core_version(rule)


def code_core_sql(r: str = "r") -> str:
    return (f"(CASE WHEN {r}.target <> 'object' AND COALESCE({r}.category, '') = '' "
            f"THEN '{CORE_PROMPT_FAMILIES['classifier']}' ELSE '{CORE_PROMPT_FAMILIES['rule']}' END)")


def pinned_core_sql(r: str = "r") -> str:
    return f"COALESCE({r}.core_prompt_version, {code_core_sql(r)})"


def version_params(rule, code_model: Optional[str], migration: bool) -> Dict[str, Any]:
    """Bind parameters of ``FRESH_COND`` / ``MIGRATION_COND`` / ``CANDIDATE_COND`` for ``rule``."""
    return {"rule_version": _get(rule, "version"), "pinned_pv": pinned_core_version(rule),
            "code_pv": code_core_version(rule), "pinned_model": _get(rule, "llm_model"),
            "code_model": code_model, "migration": bool(migration)}


# ``h``: the rule's hit on the subject (LEFT JOIN); ``s``: the subject's current hashes
FRESH_COND = """(h.subject_key IS NULL
           OR (h.reviewer IS NULL AND h.subject_hash IS NOT NULL AND COALESCE(h.subject_hash <> s.subject_hash, false))
           OR (h.status = 'pending_review' AND h.reviewer IS NOT NULL AND h.rule_version < :rule_version)
           OR (h.names_hash IS NOT NULL AND COALESCE(h.names_hash <> s.names_hash, false)))"""

MIGRATION_COND = """(h.reviewer IS NULL AND h.decided_tier <> 'harness'
           AND (h.rule_version < :rule_version
                OR (h.prompt_version IS DISTINCT FROM :pinned_pv AND h.prompt_version IS DISTINCT FROM :code_pv)
                OR (CAST(:pinned_model AS text) IS NOT NULL AND h.model IS DISTINCT FROM :pinned_model
                    AND h.model IS DISTINCT FROM :code_model AND COALESCE(h.model, '') NOT LIKE '% via %')))"""

CANDIDATE_COND = f"({FRESH_COND} OR (CAST(:migration AS boolean) AND {MIGRATION_COND}))"


def stale_sql(h: str = "h", r: str = "r") -> str:
    """A hit ``h`` of rule ``r`` (``rules`` row) is stale: MIGRATION_COND against the active version, the scanner's
    service model read from ``llm_runtime`` (the API's ``HitOut.stale`` and filter)."""
    code = code_core_sql(r)
    return f"""({r}.kind = 'llm' AND {h}.prompt_version IS NOT NULL AND {h}.reviewer IS NULL
        AND {h}.decided_tier <> 'harness'
        AND ({h}.rule_version < {r}.version
             OR ({h}.prompt_version IS DISTINCT FROM COALESCE({r}.core_prompt_version, {code})
                 AND {h}.prompt_version IS DISTINCT FROM {code})
             OR ({r}.llm_model IS NOT NULL AND {h}.model IS DISTINCT FROM {r}.llm_model
                 AND COALESCE({h}.model, '') NOT LIKE '% via %'
                 AND {h}.model IS DISTINCT FROM (SELECT value FROM llm_runtime WHERE key = 'service_model'))))"""


def is_fresh(hit, rule_version: int, subject_hash: Optional[str], names_hash: Optional[str]) -> bool:
    """Python twin of ``FRESH_COND``."""
    if hit is None:
        return True
    get = hit.get if isinstance(hit, dict) else (lambda k: getattr(hit, k, None))
    stored_subject, stored_names = get("subject_hash"), get("names_hash")
    if get("reviewer") is None and stored_subject is not None and subject_hash is not None \
            and stored_subject != subject_hash:
        return True
    if get("status") == "pending_review" and get("reviewer") is not None and get("rule_version") < rule_version:
        return True
    return stored_names is not None and names_hash is not None and stored_names != names_hash


def is_migration(hit, rule_version: int, pinned_pv: Optional[str], code_pv: Optional[str] = None,
                 pinned_model: Optional[str] = None, code_model: Optional[str] = None) -> bool:
    """Python twin of ``MIGRATION_COND``."""
    if hit is None:
        return False
    get = hit.get if isinstance(hit, dict) else (lambda k: getattr(hit, k, None))
    if get("reviewer") is not None or get("decided_tier") == "harness":
        return False
    code_pv = pinned_pv if code_pv is None else code_pv
    pv = get("prompt_version")
    model = get("model")
    return bool(get("rule_version") < rule_version or (pv != pinned_pv and pv != code_pv)
                or (pinned_model is not None and model != pinned_model and model != code_model
                    and " via " not in (model or "")))


def stale_reason(row) -> Optional[str]:
    """Why a stale hit (``row``: the hit with its rule's ``current_rule_version``, ``rule_core_prompt_version``,
    ``rule_llm_model``, ``rule_target``, ``rule_category``) waits for a rollout, for people."""
    get = row.get
    if get("current_rule_version") is not None and get("rule_version") < get("current_rule_version"):
        return f"rule v{get('rule_version')} -> v{get('current_rule_version')} pending"
    rule = {"target": get("rule_target"), "category": get("rule_category"),
            "core_prompt_version": get("rule_core_prompt_version")}
    if get("prompt_version") not in (pinned_core_version(rule), code_core_version(rule)):
        return f"core prompts {get('prompt_version')} -> {pinned_core_version(rule)} pending"
    if get("rule_llm_model"):
        return f"model {get('model')} -> {get('rule_llm_model')} pending"
    return "a newer rule version is pending"


# ---- versions --------------------------------------------------------------------------------------------------

def matchers_of(scope: Optional[dict]) -> Dict[str, Any]:
    """What an LLM rule matches (``rules_service._matchers``): unset, blank and false values are not part of it."""
    scope = scope or {}
    return {k: scope.get(k) for k in MATCHER_KEYS if scope.get(k) not in (None, "") and scope.get(k) is not False}


VERSION_COLUMNS = ("id, rule_id, version, status, prompt, target, matchers, core_prompt_version, model, source, "
                   "parent_version, proposal_id, created_by, created_at, activated_at, retired_at, note")


def _row(session, sql: str, params: dict) -> Optional[dict]:
    row = session.execute(text(sql), params).mappings().first()
    return dict(row) if row is not None else None


def rule_row(session, rule_id: int, lock: bool = False) -> dict:
    row = _row(session, "SELECT id, kind, name, category, severity, target, mode, scope, prompt, version, enabled, "
                        "deleted_at, core_prompt_version, llm_model FROM rules WHERE id = :r"
                        + (" FOR UPDATE" if lock else ""), {"r": int(rule_id)})
    if row is None or row["kind"] != "llm":
        raise LifecycleError(f"LLM rule {rule_id} not found", "not_found")
    return row


def get_version(session, version_id: int, lock: bool = False) -> dict:
    row = _row(session, f"SELECT {VERSION_COLUMNS} FROM rule_versions WHERE id = :id"
                        + (" FOR UPDATE" if lock else ""), {"id": int(version_id)})
    if row is None:
        raise LifecycleError(f"rule version {version_id} not found", "not_found")
    return row


def list_versions(session, rule_id: int) -> List[dict]:
    return [dict(r) for r in session.execute(text(
        f"SELECT {VERSION_COLUMNS} FROM rule_versions WHERE rule_id = :r ORDER BY version DESC"),
        {"r": int(rule_id)}).mappings()]


def ensure_active_version(session, rule_id: int, user: Optional[str] = None) -> dict:
    """The active version of an LLM rule; one is made from the ``rules`` row when there is none (a rule created
    before migration 0024 left deleted, or inserted directly)."""
    active = _row(session, f"SELECT {VERSION_COLUMNS} FROM rule_versions WHERE rule_id = :r AND status = 'active'",
                  {"r": int(rule_id)})
    if active is not None:
        return active
    rule = rule_row(session, rule_id, lock=True)
    session.execute(text("""
        INSERT INTO rule_versions (rule_id, version, status, prompt, target, matchers, core_prompt_version, model,
                                   source, created_by, activated_at, note)
        VALUES (:r, :v, 'active', :p, :t, CAST(:m AS jsonb), :core, :model, 'backfill', :u, now(),
                'the rule as it was when its versions were first looked at')
        ON CONFLICT (rule_id, version) DO UPDATE SET status = 'active', activated_at = now()"""),
        {"r": rule["id"], "v": rule["version"] or 1, "p": rule["prompt"], "t": rule["target"] or "field",
         "m": json.dumps(matchers_of(rule["scope"])), "core": pinned_core_version(rule), "model": rule["llm_model"],
         "u": user})
    if rule["core_prompt_version"] is None:
        session.execute(text("UPDATE rules SET core_prompt_version = :c WHERE id = :r"),
                        {"c": pinned_core_version(rule), "r": rule["id"]})
    return _row(session, f"SELECT {VERSION_COLUMNS} FROM rule_versions WHERE rule_id = :r AND status = 'active'",
                {"r": int(rule_id)})


def _next_number(session, rule_id: int) -> int:
    return int(session.execute(text(
        "SELECT GREATEST((SELECT COALESCE(max(version), 0) FROM rule_versions WHERE rule_id = :r), "
        "(SELECT COALESCE(version, 0) FROM rules WHERE id = :r)) + 1"), {"r": int(rule_id)}).scalar())


def create_version(session, rule_id: int, *, prompt: Optional[str], target: str, matchers: Dict[str, Any],
                   core_prompt_version: Optional[str], model: Optional[str], source: str = "manual",
                   created_by: Optional[str] = None, note: Optional[str] = None, status: str = "candidate",
                   proposal_id: Optional[int] = None) -> dict:
    """A new version (``candidate`` by default) of an LLM rule; the rule itself is not changed."""
    rule = rule_row(session, rule_id, lock=True)
    active = ensure_active_version(session, rule["id"], created_by)
    number = _next_number(session, rule["id"])
    version_id = session.execute(text("""
        INSERT INTO rule_versions (rule_id, version, status, prompt, target, matchers, core_prompt_version, model,
                                   source, parent_version, proposal_id, created_by, note)
        VALUES (:r, :v, :s, :p, :t, CAST(:m AS jsonb), :core, :model, :src, :parent, :proposal, :u, :note)
        RETURNING id"""), {
        "r": rule["id"], "v": number, "s": status, "p": prompt, "t": target, "m": json.dumps(matchers_of(matchers)),
        "core": core_prompt_version, "model": model, "src": source, "parent": active["version"] if active else None,
        "proposal": proposal_id, "u": created_by, "note": note}).scalar()
    logger.info(f"LLM rule {rule['name']}: version {number} ({status}, {source}) created by {created_by}")
    return get_version(session, version_id)


def same_content(a: dict, b: dict) -> bool:
    """Two versions ask the same (prompt, target, matchers): they differ in core prompts / model at most."""
    return ((a.get("prompt") or None), a.get("target"), matchers_of(a.get("matchers"))) == (
        (b.get("prompt") or None), b.get("target"), matchers_of(b.get("matchers")))


EXPIRE_VERIFY_SQL = text("""
    UPDATE llm_work_items SET status = 'expired', updated_at = now(), lease_until = NULL,
           error = 'superseded by rule v' || CAST(:v AS text)
    WHERE purpose = 'verify' AND rule_id = :r AND rule_version < :v AND status IN ('pending', 'leased')
    RETURNING job_id""")

RELABEL_SQL = text("""
    UPDATE rule_hits SET rule_version = :v
    WHERE rule_id = :r AND rule_version = :prev AND reviewer IS NULL AND decided_tier = 'service'
      AND prompt_version IS NOT DISTINCT FROM :core
      AND (CAST(:model AS text) IS NULL OR model = :model OR COALESCE(model, '') LIKE '% via %')""")


def _set_source(session, source: Optional[str], rollout_id: Optional[int] = None) -> None:
    """``hit_verdicts.source`` / ``rollout_id`` of the hit changes of this transaction (the history triggers)."""
    session.execute(text("SELECT set_config('discovery.hit_source', :s, true), "
                         "set_config('discovery.rollout_id', :r, true)"),
                    {"s": source or "", "r": "" if rollout_id is None else str(int(rollout_id))})


def activate_version(session, version_id: int, *, user: Optional[str], start_rollout: bool = False,
                     mode: Optional[str] = None, budget: Optional[dict] = None, rolled_back: bool = False,
                     keep_env: bool = False, note: Optional[str] = None, rollout_source: Optional[str] = None,
                     batch_jobs: bool = False) -> Dict[str, Any]:
    """Make a draft / candidate version the active one, in the caller's transaction:

    * the rule (``rules``) becomes its projection: prompt, target, the matchers of the scope (meta keys kept; the
      ``env`` marker is dropped unless ``keep_env``), ``version`` (= the version's number), the pinned core prompts
      version and service model;
    * the previous active version is ``retired`` (``rolled_back`` when ``rolled_back``), older open candidates
      ``retired`` (superseded);
    * same content (only the core prompts / the model changed): the machine verdicts of the previous version that
      already have the new key (asked by the new core prompts / model meanwhile) are relabelled, not asked again;
    * open verify items of older versions expire (the harness work is not paid for any more);
    * the open rollout of the rule is cancelled and a new one made: ``running`` when ``start_rollout``, else
      ``planned`` (a human starts it).

    ``batch_jobs``: the relabel is not done here (one UPDATE over every hit of the rule: minutes inside the caller's
    transaction at millions of hits) but by an ``llm_relabel`` job of the scanner in slices (``enqueue_relabel``);
    ``relabelled`` is then None and ``relabel_job_id`` the job (None when nothing was to relabel)."""
    version = get_version(session, version_id, lock=True)
    rule = rule_row(session, version["rule_id"], lock=True)
    if rule["deleted_at"] is not None:
        raise LifecycleError(f"rule {rule['name']} is deleted")
    if version["status"] not in ("draft", "candidate"):
        raise LifecycleError(f"version {version['version']} of rule {rule['name']} is {version['status']}: only a "
                             f"draft or candidate version can be activated (an older one: rollback)")
    if version["version"] <= (rule["version"] or 0):
        raise LifecycleError(f"version {version['version']} of rule {rule['name']} is older than the active "
                             f"v{rule['version']}: make a new candidate from it")
    previous = ensure_active_version(session, rule["id"], user)
    session.execute(text("""UPDATE rule_versions SET status = :s, retired_at = now()
                            WHERE rule_id = :r AND status = 'active'"""),
                    {"s": "rolled_back" if rolled_back else "retired", "r": rule["id"]})
    session.execute(text("""UPDATE rule_versions SET status = 'retired', retired_at = now(),
                                   note = COALESCE(note || E'\\n', '') || 'superseded by v' || CAST(:v AS text)
                            WHERE rule_id = :r AND status IN ('draft', 'candidate') AND version < :v"""),
                    {"r": rule["id"], "v": version["version"]})
    session.execute(text("UPDATE rule_versions SET status = 'active', activated_at = now() WHERE id = :id"),
                    {"id": version["id"]})
    # a version the scanner made (core prompts / model) or the env sync keeps the env-managed rule env-managed
    keep_env = keep_env or version["source"] in AUTO_SOURCES + ("env",)
    scope = {k: v for k, v in (rule["scope"] or {}).items()
             if k in META_SCOPE_KEYS and (keep_env or k != "source")}
    scope.update(matchers_of(version["matchers"]))
    session.execute(text("""
        UPDATE rules SET prompt = :p, target = :t, scope = CAST(:scope AS jsonb), version = :v,
               core_prompt_version = :core, llm_model = :model, updated_at = now(), updated_by = COALESCE(:u, updated_by)
        WHERE id = :r"""), {"p": version["prompt"], "t": version["target"], "scope": json.dumps(scope),
                            "v": version["version"], "core": version["core_prompt_version"],
                            "model": version["model"], "u": user, "r": rule["id"]})
    relabelled: Optional[int] = 0
    relabel_job: Optional[int] = None
    if previous is not None and same_content(previous, version):
        params = {"r": rule["id"], "v": version["version"], "prev": previous["version"],
                  "core": version["core_prompt_version"] or code_core_version(rule), "model": version["model"]}
        if batch_jobs:
            relabelled = None
            relabel_job = enqueue_relabel(session, rule_id=rule["id"], action="relabel", to_version=version["version"],
                                          from_version=previous["version"], core=params["core"], model=params["model"],
                                          user=user)
        else:
            _set_source(session, "relabel")
            relabelled = session.execute(RELABEL_SQL, params).rowcount
            _set_source(session, None)
    expired_jobs = [r[0] for r in session.execute(EXPIRE_VERIFY_SQL, {"r": rule["id"], "v": version["version"]})]
    rollout = create_rollout(session, rule["id"], previous["version"] if previous else None, version["version"],
                             mode=mode, start=start_rollout, budget=budget, user=user,
                             source=rollout_source or version["source"], note=note)
    relabel_note = f"relabel job {relabel_job} queued" if relabel_job else f"{relabelled or 0} verdicts relabelled"
    logger.info(f"LLM rule {rule['name']}: v{version['version']} active (was v{previous and previous['version']}, "
                f"by {user}); {relabel_note}, {len(expired_jobs)} verify items expired, rollout "
                f"{rollout['id']} {rollout['status']}")
    return {"version": get_version(session, version["id"]), "rollout": rollout, "relabelled": relabelled,
            "relabel_job_id": relabel_job,
            "expired_verify_items": len(expired_jobs), "expired_verify_jobs": sorted(set(expired_jobs)),
            "previous_version": previous["version"] if previous else None}


ADOPT_SQL = text("""
    WITH old AS (
        SELECT DISTINCT ON (v.subject_key) v.subject_key, v.status, v.category, v.severity, v.reason, v.fields,
               v.prompt_version, v.model, v.subject_hash, v.names_hash
        FROM hit_verdicts v
        WHERE v.rule_id = :r AND v.rule_version = :m AND v.decided_tier = 'service' AND v.reviewer IS NULL
        ORDER BY v.subject_key, v.id DESC)
    UPDATE rule_hits h SET status = old.status, category = old.category, severity = old.severity,
           reason = old.reason, fields = old.fields, prompt_version = old.prompt_version, model = old.model,
           rule_version = :v, asked_by_model = false
    FROM old
    WHERE h.rule_id = :r AND h.subject_key = old.subject_key AND h.reviewer IS NULL AND h.decided_tier = 'service'
      AND h.subject_hash IS NOT DISTINCT FROM old.subject_hash AND h.names_hash IS NOT DISTINCT FROM old.names_hash
      AND h.rule_version <> :v""")


# ---- relabel / adopt in slices (the ``llm_relabel`` job of the scanner) -----------------------------------------------
#
# RELABEL_SQL / ADOPT_SQL above touch every machine verdict of a rule in one statement: minutes inside the API's
# transaction at millions of hits (and a lock on every row of the rule meanwhile). ``enqueue_relabel`` queues the
# same work as an ``llm_relabel`` job (control pool) that runs ``relabel_slice`` in transactions of ``batch`` rows
# (the hit_verdicts history gets ``source`` relabel / adopt per slice, like the inline form); a slice that changes
# fewer rows than ``batch`` is the last one. The API passes ``batch_jobs=True`` to ``activate_version`` /
# ``rollback`` and shows the job; the rollout controller waits for the job of its rule before queueing slices.

RELABEL_ACTIONS = ("relabel", "adopt")
RELABEL_BATCH = 5000
RELABEL_JOB_PRIORITY = 5           # before the other control jobs: a rollout would ask the model about these verdicts

RELABEL_SLICE_SQL = text("""
    UPDATE rule_hits h SET rule_version = :v
    WHERE (h.rule_id, h.subject_key) IN (
        SELECT rule_id, subject_key FROM rule_hits
        WHERE rule_id = :r AND rule_version = :prev AND reviewer IS NULL AND decided_tier = 'service'
          AND prompt_version IS NOT DISTINCT FROM :core
          AND (CAST(:model AS text) IS NULL OR model = :model OR COALESCE(model, '') LIKE '% via %')
        LIMIT :batch)""")

# the latest history row of version :m per subject, joined like ADOPT_SQL (same hashes, machine verdict, another
# version): :batch hits per slice; the updated hits get version :v and leave the candidate set
ADOPT_SLICE_SQL = text("""
    WITH slice AS (
        SELECT h.subject_key, l.status, l.category, l.severity, l.reason, l.fields, l.prompt_version, l.model
        FROM rule_hits h
        JOIN LATERAL (
            SELECT v.status, v.category, v.severity, v.reason, v.fields, v.prompt_version, v.model, v.subject_hash,
                   v.names_hash
            FROM hit_verdicts v
            WHERE v.rule_id = h.rule_id AND v.subject_key = h.subject_key AND v.rule_version = :m
              AND v.decided_tier = 'service' AND v.reviewer IS NULL
            ORDER BY v.id DESC LIMIT 1) l ON true
        WHERE h.rule_id = :r AND h.reviewer IS NULL AND h.decided_tier = 'service' AND h.rule_version <> :v
          AND h.subject_hash IS NOT DISTINCT FROM l.subject_hash AND h.names_hash IS NOT DISTINCT FROM l.names_hash
        LIMIT :batch)
    UPDATE rule_hits h SET status = s.status, category = s.category, severity = s.severity, reason = s.reason,
           fields = s.fields, prompt_version = s.prompt_version, model = s.model, rule_version = :v,
           asked_by_model = false
    FROM slice s
    WHERE h.rule_id = :r AND h.subject_key = s.subject_key""")


def relabel_dedup_key(rule_id: int, action: str, to_version: int) -> str:
    return f"llm_relabel:{int(rule_id)}:{action}:{int(to_version)}"


def enqueue_relabel(conn, *, rule_id: int, action: str, to_version: int, from_version: Optional[int] = None,
                    core: Optional[str] = None, model: Optional[str] = None, rollout_id: Optional[int] = None,
                    user: Optional[str] = None, batch: int = RELABEL_BATCH, max_attempts: int = 5) -> Optional[int]:
    """Queue the ``llm_relabel`` job that does RELABEL_SQL (``action`` relabel: the machine verdicts of
    ``from_version`` with core prompts ``core`` and model ``model`` get ``to_version``) or ADOPT_SQL (``action``
    adopt: the hits whose latest history row of ``from_version`` is on the same content take that verdict and
    ``to_version``; ``rollout_id`` goes to the history) in slices of ``batch`` rows, in ``conn`` (the caller's
    transaction: the job is visible once it commits). One active job per (rule, action, to_version); returns its id,
    or None when one is queued already. Payload: ``{rule_id, action, to_version, from_version, core, model,
    rollout_id, batch, user}``; progress: ``{phase, rows, slices, batch}``."""
    from discovery_common import jobs
    if action not in RELABEL_ACTIONS:
        raise ValueError(f"unknown relabel action {action!r}: expected one of {RELABEL_ACTIONS}")
    if from_version is None:
        raise ValueError("a relabel / adopt job needs from_version")
    payload = {"rule_id": int(rule_id), "action": action, "to_version": int(to_version),
               "from_version": int(from_version), "core": core, "model": model,
               "rollout_id": int(rollout_id) if rollout_id is not None else None, "batch": int(batch), "user": user}
    return jobs.enqueue("llm_relabel", payload, relabel_dedup_key(rule_id, action, to_version), conn=conn,
                        priority=RELABEL_JOB_PRIORITY, max_attempts=max_attempts)


def relabel_slice(session, payload: Dict[str, Any]) -> int:
    """One slice of an ``llm_relabel`` job in ``session`` (its own transaction): returns the hits changed; fewer
    than ``payload["batch"]`` means the work is done."""
    action = payload["action"]
    batch = max(1, int(payload.get("batch") or RELABEL_BATCH))
    _set_source(session, action, payload.get("rollout_id") if action == "adopt" else None)
    try:
        if action == "relabel":
            return session.execute(RELABEL_SLICE_SQL, {
                "r": int(payload["rule_id"]), "v": int(payload["to_version"]), "prev": int(payload["from_version"]),
                "core": payload.get("core"), "model": payload.get("model"), "batch": batch}).rowcount
        if action == "adopt":
            return session.execute(ADOPT_SLICE_SQL, {
                "r": int(payload["rule_id"]), "v": int(payload["to_version"]), "m": int(payload["from_version"]),
                "batch": batch}).rowcount
        raise ValueError(f"unknown relabel action {action!r}")
    finally:
        _set_source(session, None)


def rollback(session, rule_id: int, to_version: int, *, user: Optional[str], start_rollout: bool = True,
             budget: Optional[dict] = None, note: Optional[str] = None, batch_jobs: bool = False) -> Dict[str, Any]:
    """Go back to an older version ``to_version`` of the rule: a new version with its content (same prompt, target,
    matchers, core prompts pin and model; ``source`` rollback:<to_version>) becomes active and the current one is
    ``rolled_back``; the machine verdicts that version made on the same content (``hit_verdicts``) are adopted
    without asking the model (rules without ``mark_fields``: the field marks of object rules are not in one row);
    the rest is migrated by a rollout. ``batch_jobs``: the adoption (and the relabel of the activation) run as
    ``llm_relabel`` jobs of the scanner in slices (``adopted`` None, ``adopt_job_id`` the job)."""
    rule = rule_row(session, rule_id, lock=True)
    old = _row(session, f"SELECT {VERSION_COLUMNS} FROM rule_versions WHERE rule_id = :r AND version = :v",
               {"r": rule["id"], "v": int(to_version)})
    if old is None:
        raise LifecycleError(f"rule {rule['name']} has no version {to_version}", "not_found")
    if old["status"] not in ("retired", "rolled_back"):
        raise LifecycleError(f"version {to_version} of rule {rule['name']} is {old['status']}: roll back to a retired "
                             f"version (a candidate is activated instead)")
    copy = create_version(session, rule["id"], prompt=old["prompt"], target=old["target"], matchers=old["matchers"],
                          core_prompt_version=old["core_prompt_version"], model=old["model"],
                          source=f"rollback:{old['version']}", created_by=user, note=note)
    result = activate_version(session, copy["id"], user=user, start_rollout=start_rollout, mode="immediate",
                              budget=budget, rolled_back=True, note=note, batch_jobs=batch_jobs)
    adopted: Optional[int] = 0
    adopt_job: Optional[int] = None
    if not (old["target"] == "object" and (old["matchers"] or {}).get("mark_fields")):
        if batch_jobs:
            adopted = None
            adopt_job = enqueue_relabel(session, rule_id=rule["id"], action="adopt", to_version=copy["version"],
                                        from_version=old["version"], rollout_id=result["rollout"]["id"], user=user)
        else:
            _set_source(session, "adopt", result["rollout"]["id"])
            adopted = session.execute(ADOPT_SQL, {"r": rule["id"], "m": old["version"], "v": copy["version"]}).rowcount
            _set_source(session, None)
    result["adopted"] = adopted
    result["adopt_job_id"] = adopt_job
    logger.info(f"LLM rule {rule['name']}: rolled back to the content of v{old['version']} as v{copy['version']} by "
                f"{user}; " + (f"adopt job {adopt_job} queued" if adopt_job else f"{adopted or 0} verdicts adopted from the history"))
    return result


def discard_version(session, version_id: int, *, user: Optional[str], note: Optional[str] = None) -> dict:
    version = get_version(session, version_id, lock=True)
    if version["status"] not in ("draft", "candidate"):
        raise LifecycleError(f"version {version['version']} is {version['status']}: only drafts and candidates are "
                             f"discarded")
    session.execute(text("""UPDATE rule_versions SET status = 'retired', retired_at = now(),
                                   note = COALESCE(note || E'\\n', '') || :n WHERE id = :id"""),
                    {"id": version["id"], "n": f"discarded by {user}" + (f": {note}" if note else "")})
    return get_version(session, version["id"])


# ---- metadata ----------------------------------------------------------------------------------------------------

def propagate_metadata(session, rule_id: int, *, category: Optional[str], severity: Optional[str],
                       old_category: Optional[str], old_severity: Optional[str], classifier: bool) -> int:
    """A category / severity edit of an LLM rule (no new version) goes to its machine hits at once (no model call;
    reviewer and harness decisions are kept). The classifier's categories are the model's (per field): only the
    severity of its positive hits follows the rule."""
    sets, params = [], {"r": int(rule_id)}
    if not classifier and category and category != old_category:
        sets.append("category = :c")
        params["c"] = category
    if severity and severity != old_severity:
        sets.append("severity = CASE WHEN severity IS NULL THEN NULL ELSE :sev END")
        params["sev"] = severity
    if not sets:
        return 0
    return session.execute(text(f"""UPDATE rule_hits SET {', '.join(sets)}
                                    WHERE rule_id = :r AND reviewer IS NULL AND decided_tier = 'service'"""),
                           params).rowcount or 0


# ---- rollouts ----------------------------------------------------------------------------------------------------

ROLLOUT_COLUMNS = ("id, rule_id, from_version, to_version, status, mode, source, budget, progress, created_by, "
                   "started_by, created_at, started_at, finished_at, paused_reason, note")
BUDGET_KEYS = ("calls_per_hour", "max_parallel_jobs", "slice_objects", "fresh_backlog_max", "max_calls")


def clean_budget(budget: Optional[dict]) -> Dict[str, Any]:
    out = {}
    for key, value in (budget or {}).items():
        if value is None:
            continue
        if key not in BUDGET_KEYS:
            raise LifecycleError(f"unknown budget key {key!r}, expected some of {list(BUDGET_KEYS)}", "invalid")
        try:
            value = int(value)
        except (TypeError, ValueError):
            raise LifecycleError(f"budget {key} must be an integer", "invalid") from None
        if value < (0 if key == "fresh_backlog_max" else 1):
            raise LifecycleError(f"budget {key} must be positive", "invalid")
        out[key] = value
    return out


def get_rollout(session, rollout_id: int, lock: bool = False) -> dict:
    row = _row(session, f"SELECT {ROLLOUT_COLUMNS} FROM llm_rollouts WHERE id = :id" + (" FOR UPDATE" if lock else ""),
               {"id": int(rollout_id)})
    if row is None:
        raise LifecycleError(f"rollout {rollout_id} not found", "not_found")
    return row


def create_rollout(session, rule_id: int, from_version: Optional[int], to_version: int, *, mode: Optional[str],
                   start: bool, budget: Optional[dict], user: Optional[str], source: str = "manual",
                   note: Optional[str] = None) -> dict:
    mode = mode or ("immediate" if start else "staged")
    if mode not in ROLLOUT_MODES:
        raise LifecycleError(f"mode must be one of {list(ROLLOUT_MODES)}", "invalid")
    budget = clean_budget(budget)
    session.execute(text(f"""UPDATE llm_rollouts SET status = 'cancelled', finished_at = now(),
                                    note = COALESCE(note || E'\\n', '') || 'superseded by v' || CAST(:v AS text)
                             WHERE rule_id = :r AND status IN ({OPEN_SQL})"""), {"r": int(rule_id), "v": to_version})
    rollout_id = session.execute(text("""
        INSERT INTO llm_rollouts (rule_id, from_version, to_version, status, mode, source, budget, created_by,
                                  started_by, started_at, note)
        VALUES (:r, :f, :t, :s, :mode, :src, CAST(:b AS jsonb), :u, :started_by,
                CASE WHEN :start THEN now() END, :note) RETURNING id"""), {
        "r": int(rule_id), "f": from_version, "t": to_version, "s": "running" if start else "planned", "mode": mode,
        "src": source, "b": json.dumps(budget), "u": user, "started_by": user if start else None, "start": bool(start),
        "note": note}).scalar()
    return get_rollout(session, rollout_id)


ACTIONS = {
    # action: (allowed from, to)
    "start": (("planned", "canary", "awaiting_approval"), "running"),
    "pause": (("running", "planned"), "paused"),
    "resume": (("paused",), "running"),
    "cancel": (tuple(ROLLOUT_OPEN), "cancelled"),
}


def rollout_action(session, rollout_id: int, action: str, *, user: Optional[str], reason: Optional[str] = None,
                   budget: Optional[dict] = None) -> dict:
    """start | pause | resume | cancel (humans: UI / REST). Pending slices of a paused / cancelled rollout are
    dropped from the queue (a running one finishes its slice: no answer is lost)."""
    if action not in ACTIONS:
        raise LifecycleError(f"action must be one of {list(ACTIONS)}", "invalid")
    rollout = get_rollout(session, rollout_id, lock=True)
    allowed, new = ACTIONS[action]
    if rollout["status"] not in allowed:
        raise LifecycleError(f"rollout {rollout_id} is {rollout['status']}: cannot {action} it")
    rule = rule_row(session, rollout["rule_id"])
    if new == "running" and rule["version"] != rollout["to_version"]:
        raise LifecycleError(f"rule {rule['name']} is at v{rule['version']} now, the rollout is for "
                             f"v{rollout['to_version']}")
    merged = {**(rollout["budget"] or {}), **clean_budget(budget)}
    session.execute(text("""
        UPDATE llm_rollouts SET status = :s, budget = CAST(:b AS jsonb),
               started_at = CASE WHEN :s = 'running' THEN COALESCE(started_at, now()) ELSE started_at END,
               started_by = CASE WHEN :s = 'running' THEN COALESCE(started_by, :u) ELSE started_by END,
               paused_reason = CASE WHEN :s = 'paused' THEN :why ELSE NULL END,
               finished_at = CASE WHEN :s = 'cancelled' THEN now() ELSE finished_at END,
               note = CASE WHEN :s IN ('paused', 'cancelled') AND CAST(:why AS text) IS NOT NULL
                           THEN COALESCE(note || E'\\n', '') || :why ELSE note END
        WHERE id = :id"""), {"s": new, "b": json.dumps(merged), "u": user, "id": rollout["id"],
                             "why": (f"{action} by {user}" + (f": {reason}" if reason else "")) if new in (
                                 "paused", "cancelled") else None})
    if new in ("paused", "cancelled"):
        session.execute(text("""UPDATE jobs SET status = 'failed', finished_at = now(), updated_at = now(),
                                       last_error = 'rollout ' || CAST(:id AS text) || ' ' || :s
                                WHERE kind = 'llm_score' AND status = 'pending'
                                  AND payload ->> 'rollout_id' = CAST(:id AS text)"""),
                        {"id": rollout["id"], "s": new})
    return get_rollout(session, rollout["id"])


def slice_payload(rollout: dict, branch_id: int, max_objects: int) -> Dict[str, Any]:
    return {"branch_id": int(branch_id), "rule_ids": [int(rollout["rule_id"])], "rollout_id": int(rollout["id"]),
            "max_objects": int(max_objects), "migration": True}


# ---- migration size (no model call) ------------------------------------------------------------------------------

STALE_HITS_SQL = """
    SELECT h.project_id, count(*) AS subjects, count(DISTINCT h.object_key) AS objects,
           min(CASE h.status WHEN 'need_more_info' THEN 0 WHEN 'pending_review' THEN 1 WHEN 'match' THEN 1
                             ELSE 2 END) AS bucket,
           count(*) FILTER (WHERE h.status = 'need_more_info') AS need_more_info,
           count(*) FILTER (WHERE h.status IN ('match', 'pending_review')) AS positive,
           count(*) FILTER (WHERE h.status = 'no_match') AS negative,
           max(h.last_seen_at) AS last_seen_at
    FROM rule_hits h
    WHERE h.rule_id = :rule_id AND h.prompt_version IS NOT NULL AND {cond}
    GROUP BY h.project_id"""

# for an estimate before a version is active: verdicts of the active version count as stale too
MIGRATION_ON_ACTIVATION = """(h.reviewer IS NULL AND h.decided_tier <> 'harness')"""

PROTECTED_SQL = text("""
    SELECT count(*) FILTER (WHERE reviewer IS NOT NULL) AS human,
           count(*) FILTER (WHERE reviewer IS NULL AND decided_tier = 'harness') AS harness
    FROM rule_hits WHERE rule_id = :r AND prompt_version IS NOT NULL""")


def migration_size(session, rule, *, code_model: Optional[str] = None, on_activation: bool = False
                   ) -> Dict[str, Any]:
    """Stale machine verdicts of ``rule`` per project (the migration a rollout makes, one model call per object):
    ``on_activation``: of a new version with other content (every machine verdict of the rule)."""
    if on_activation:
        cond, params = MIGRATION_ON_ACTIVATION, {"rule_id": _get(rule, "id")}
    else:
        cond = MIGRATION_COND
        params = {"rule_id": _get(rule, "id"), **version_params(rule, code_model, True)}
        params.pop("migration")
    rows = [dict(r) for r in session.execute(text(STALE_HITS_SQL.format(cond=cond)), params).mappings()]
    protected = dict(session.execute(PROTECTED_SQL, {"r": _get(rule, "id")}).mappings().one())
    return {"subjects": sum(r["subjects"] for r in rows), "objects": sum(r["objects"] for r in rows),
            "need_more_info": sum(r["need_more_info"] for r in rows), "positive": sum(r["positive"] for r in rows),
            "negative": sum(r["negative"] for r in rows), "projects": len(rows),
            "protected_human": int(protected["human"] or 0), "protected_harness": int(protected["harness"] or 0),
            "by_project": rows}
