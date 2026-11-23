"""Prompt trials (``llm_trial`` jobs, migration 0019): a candidate system prompt of an LLM rule is asked with the
SERVICE model (LLM_API_URL, ``score_service.get_llm_backend``) about the few subjects of a trial
(``prompt_trial_items``, chosen by the API: mislabelled targets and agreed controls), before a human is asked to
adopt it (``prompt_proposals``).

* The same code path as a run of the rule: ``scan_service.llm_rule_object_verdicts`` with a copy of the rule whose
  prompt is the candidate (everything else - target, category, severity, scope, version - unchanged), so the core
  prompt builders send the object as delimited untrusted data exactly as in a run. One call per object: field
  rules get only the trial's fields of that object as candidates; object rules judge the whole object.
* ``rerun_current`` (default on): objects with a target subject are also asked with the CURRENT prompt in the
  same job (same model, same moment: a fair A/B); controls are compared with their stored, agreed verdict.
* Nothing else is written: no ``rule_hits``, no ``llm_coverage``, no rule change; only the trial's items, its call
  counters and status.
* One object at a time, its answers stored at once (``asked_at``): a graceful stop (``jobs.stop_requested``)
  requeues the job after the object being asked, a retry asks only the objects left.
"""

import hashlib
import json
from types import SimpleNamespace
from typing import Dict, List, Optional

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.types import Text

from discovery_common import db, jobs
from discovery_common.llm_work import JobProgress
from logger import get_logger
from services import scan_service
from services.db_service import get_object_docs, get_object_fields
from services.score_service import LlmObject

logger = get_logger(__name__)

ERROR_MAX = 1000
RULE_COLUMNS = "id, kind, name, category, severity, target, mode, scope, prompt, version, enabled, deleted_at"


def prompt_hash(prompt: str) -> str:
    """The API's ``trials_service.prompt_hash`` (a proposal needs a trial of the same text)."""
    return hashlib.sha256((prompt or "").encode("utf-8")).hexdigest()


class CountingBackend:
    """The service backend, counting the model calls of a trial (the budget is in calls)."""

    def __init__(self, backend):
        self.backend = backend
        self.model = getattr(backend, "model", None)
        self.calls = 0

    def complete(self, system, user, *, json_schema=None):
        self.calls += 1
        return self.backend.complete(system, user, json_schema=json_schema)


def _verdict(v) -> str:
    if v.positive:
        return "match"
    if getattr(v, "need_more_info", False):
        return "need_more_info"
    return "no_match"


def _rule_copy(rule, prompt: Optional[str] = None):
    """The rule as the scanner's LLM code reads it, with another system prompt (a candidate)."""
    values = dict(rule)
    if prompt is not None:
        values["prompt"] = prompt
    return SimpleNamespace(**values)


def _one(session, sql: str, **params):
    return session.execute(text(sql), params).mappings().first()


def _set_trial(trial_id: int, sql_set: str, **params) -> None:
    with db.unit_of_work() as s:
        s.execute(text(f"UPDATE prompt_trials SET {sql_set} WHERE id = :id"), {"id": trial_id, **params})


def _fail(trial_id: int, progress: JobProgress, error: str) -> None:
    _set_trial(trial_id, "status = 'failed', error = :e, finished_at = now()", e=error[:ERROR_MAX])
    progress.finish("failed", error=error[:300])
    logger.warning(f"Prompt trial {trial_id} failed: {error}")


def _objects(rows: List[dict], items_by_object: Dict, target: str) -> Dict[object, Optional[LlmObject]]:
    """``LlmObject`` of each object of the trial, the version the API chose (``content_hash``); None when that
    version is gone (garbage collected since the trial was made)."""
    hashes = [row["content_hash"] for row in rows]
    fields_by_hash = get_object_fields(hashes)
    docs_by_hash = get_object_docs(hashes)
    result = {}
    for row in rows:
        if row["name"] is None:
            result[row["object_key"]] = None
            continue
        docs = docs_by_hash.get(row["content_hash"], (None, {}))
        candidates = set() if target == "object" else {
            i["field_name"] for i in items_by_object[row["object_key"]] if i["field_name"] is not None}
        result[row["object_key"]] = LlmObject(
            object_key=row["object_key"], name=row["name"], fields=fields_by_hash.get(row["content_hash"], []),
            candidates=candidates, type=row["type"], parser=row["parser"], file=row["file"], props=row["props"],
            comment=docs[0], docs=docs[1])
    return result


def _ask(rule, obj: LlmObject, backend: CountingBackend):
    """``({field_name | None: verdict}, error)`` of one object (one model call)."""
    result = scan_service.llm_rule_object_verdicts(rule, [obj], backend)
    if result is None:
        return {}, "LLM is not configured"
    error = None
    if getattr(result, "failed", 0):
        error = (getattr(result, "errors", {}) or {}).get(obj.object_key) or "the model call or its answer failed"
    return {v.field_name: v for v in result}, error


def _record(trial_id: int, items: List[dict], new, rerun, calls: int, failed: int) -> None:
    """Answers of one object: every item of the object, the trial's call counters (one transaction)."""
    (new_verdicts, new_error), (rerun_verdicts, rerun_error) = new, rerun
    with db.unit_of_work() as s:
        for item in items:
            key = item["field_name"]
            v, r = new_verdicts.get(key), rerun_verdicts.get(key)
            error = new_error
            if error is None and v is None:
                error = "no verdict: the rule does not send this field to the model (e.g. an id or date field)"
            if rerun_error:
                error = "; ".join(e for e in (error, f"current prompt: {rerun_error}") if e)
            s.execute(text("""
                UPDATE prompt_trial_items SET new_verdict = :nv, new_reason = :nr, new_fields = :nf,
                       rerun_verdict = :rv, rerun_reason = :rr, rerun_fields = :rf, error = :e, asked_at = now()
                WHERE id = :id""").bindparams(bindparam("nf", type_=ARRAY(Text)), bindparam("rf", type_=ARRAY(Text))), {
                "id": item["id"], "nv": _verdict(v) if v is not None else None,
                "nr": getattr(v, "reason", None) if v is not None else None,
                "nf": (getattr(v, "fields", None) or None) if v is not None else None,
                "rv": _verdict(r) if r is not None else None, "rr": getattr(r, "reason", None) if r is not None else None,
                "rf": (getattr(r, "fields", None) or None) if r is not None else None,
                "e": error[:ERROR_MAX] if error else None})
        s.execute(text("UPDATE prompt_trials SET calls = calls + :c, failed_calls = failed_calls + :f WHERE id = :id"),
                  {"id": trial_id, "c": calls, "f": failed})


def run_trial(job) -> None:
    """The ``llm_trial`` job of trial ``payload.trial_id``."""
    trial_id = int(job.payload["trial_id"])
    with db.unit_of_work() as s:
        trial = _one(s, "SELECT * FROM prompt_trials WHERE id = :id", id=trial_id)
        rule = _one(s, f"SELECT {RULE_COLUMNS} FROM rules WHERE id = :r", r=trial["rule_id"]) if trial else None
    if trial is None:
        logger.info(f"Prompt trial {trial_id} is gone, skipped")
        return
    progress = JobProgress(job.id, executor="service", rule_ids=[trial["rule_id"]], every_n=5)
    progress.base["trial_id"] = trial_id
    if trial["status"] in ("done", "failed"):
        logger.info(f"Prompt trial {trial_id} is {trial['status']} already, skipped")
        return
    try:
        _run(job, trial, rule, progress)
    except jobs.RequeueJob:
        raise
    except jobs.PermanentJobError:
        raise
    except Exception as e:
        if job.last_attempt:
            _fail(trial_id, progress, f"{type(e).__name__}: {e}")
        raise


def _run(job, trial, rule, progress: JobProgress) -> None:
    trial_id = trial["id"]
    if rule is None or rule["kind"] != "llm" or rule["deleted_at"] is not None:
        _fail(trial_id, progress, "the rule is gone")
        raise jobs.PermanentJobError(f"prompt trial {trial_id}: the rule is gone")
    if rule["version"] != trial["rule_version"]:
        error = (f"the rule changed since the trial was created (v{trial['rule_version']} -> v{rule['version']}): "
                 f"create a new trial")
        _fail(trial_id, progress, error)
        raise jobs.PermanentJobError(f"prompt trial {trial_id}: {error}")
    if not scan_service.llm_configured():
        _fail(trial_id, progress, "the service LLM is not configured (LLM_API_URL)")
        raise jobs.PermanentJobError(f"prompt trial {trial_id}: no service LLM")
    backend = CountingBackend(scan_service.get_llm_backend())
    _set_trial(trial_id, "status = 'running', started_at = COALESCE(started_at, now()), model = :m", m=backend.model)

    with db.unit_of_work() as s:
        items = [dict(r) for r in s.execute(text(
            "SELECT id, object_key, content_hash, field_name, role, asked_at FROM prompt_trial_items "
            "WHERE trial_id = :t ORDER BY id"), {"t": trial_id}).mappings()]
        by_object: Dict = {}
        for item in items:
            by_object.setdefault(item["object_key"], []).append(item)
        pending = [key for key, its in by_object.items() if any(i["asked_at"] is None for i in its)]
        hashes = {key: by_object[key][0]["content_hash"] for key in pending}
        rows = [dict(r) for r in s.execute(text("""
            SELECT h.object_key, h.content_hash, o.name, o.type, o.parser, o.file, o.props
            FROM unnest(CAST(:keys AS uuid[]), CAST(:hashes AS uuid[])) AS h(object_key, content_hash)
            LEFT JOIN objects o ON o.content_hash = h.content_hash"""),
            {"keys": [str(k) for k in pending], "hashes": [str(hashes[k]) for k in pending]}).mappings()]

    progress.start(len(by_object))
    progress.done = len(by_object) - len(pending)
    progress.flush(force=True)

    candidate = _rule_copy(rule, prompt=trial["candidate_prompt"])
    current = _rule_copy(rule)
    objects = _objects(rows, by_object, rule["target"])
    asked = 0
    for key in pending:
        if jobs.stop_requested():
            progress.flush(force=True)
            raise jobs.stopping(f"prompt trial {trial_id}: {asked} objects asked, {len(pending) - asked} left")
        obj, its = objects.get(key), by_object[key]
        if obj is None:
            _record(trial_id, its, ({}, "the object version of the trial is gone"), ({}, None), 0, 0)
            progress.step(False)
            asked += 1
            continue
        before = backend.calls
        new = _ask(candidate, obj, backend)
        rerun = ({}, None)
        if trial["rerun_current"] and any(i["role"] == "target" for i in its):
            rerun = _ask(current, obj, backend)
        failed = int(new[1] is not None) + int(rerun[1] is not None)
        _record(trial_id, its, new, rerun, backend.calls - before, failed)
        progress.step(new[1] is None)
        asked += 1

    with db.unit_of_work() as s:
        counts = _one(s, "SELECT calls, failed_calls FROM prompt_trials WHERE id = :id", id=trial_id)
    totals = {"model": backend.model, "objects": len(by_object), "items": len(items), "calls": counts["calls"],
              "failed_calls": counts["failed_calls"]}
    _set_trial(trial_id, "status = 'done', finished_at = now(), error = NULL, totals = CAST(:t AS jsonb)",
               t=json.dumps(totals))
    progress.finish("done")
    logger.info(f"Prompt trial {trial_id} of rule {rule['name']} v{rule['version']}: {len(items)} subjects, "
                f"{counts['calls']} model calls ({counts['failed_calls']} failed), model {backend.model}")
