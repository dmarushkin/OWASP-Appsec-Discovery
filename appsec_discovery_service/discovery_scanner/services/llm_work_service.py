"""External executor of LLM rules (``executor = external``, see ``discovery_common.llm_work``).

Both phases run the service's own per-object code (``scan_service.llm_rule_batch`` for the
candidates, ``llm_rule_object_verdicts`` for the prompts and the parsing,
``store_llm_verdicts`` for the hits) with a different ``LlmBackend``:

* prepare (``llm_prepare`` job; before migration 0016 an ``llm_score`` job with ``executor:
  external``): ``RecordingBackend`` records the calls a service run would make, one
  ``llm_work_items`` row per call; the job ends as soon as they are recorded (no worker waits
  for the external model), its progress says ``awaiting_answers``. A large run is recorded in
  slices (progress ``preparing``, the job is requeued between them).
* apply (``llm_apply`` job, queued by the submit and by the scheduler): ``ReplayBackend``
  answers each rebuilt call with the stored answer when the rebuilt prompt has the stored
  hash. Items end ``applied`` (hits stored exactly as a service run stores them, ``model`` =
  ``answer_model``), ``failed`` (the core parser refused the answer: the object stays a
  candidate) or ``expired`` (rule / object changed, the object is no candidate any more).
"""

import json
import time
from typing import Dict, List, Optional, Sequence

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.types import BigInteger

from discovery_common import db, jobs
from discovery_common.llm_work import (
    ERROR_MAX, PREPARING, JobProgress, add_progress_errors, prompt_hash, refresh_progress, set_progress,
)
from logger import get_logger
from services.db_service import get_branch_by_id
from services.scan_service import (
    _rule_batches, is_inventory, llm_rule_batch, llm_rule_object_verdicts, llm_rules, record_llm_coverage,
    selected_llm_rules, store_llm_verdicts,
)
from services.score_service import LlmVerdicts, RecordingBackend, ReplayBackend

logger = get_logger(__name__)

APPLY_CHUNK = 200
IDS = ARRAY(BigInteger)

# The control worker runs llm_prepare / llm_apply between GitLab syncs and cleanups, so one
# call does a bounded slice and the handler requeues the job behind the jobs that are ready
# (``jobs.RequeueJob``): a prepare slice records at most PREPARE_SLICE_OBJECTS objects or runs
# PREPARE_SLICE_S seconds (at least one object), an apply slice at most APPLY_SLICE_CHUNKS
# chunks of APPLY_CHUNK answers or APPLY_SLICE_S seconds (at least one chunk). A stopping worker
# (``jobs.stop_requested``) ends the slice early: the job is requeued as after a full slice.
PREPARE_SLICE_OBJECTS = 500
PREPARE_SLICE_S = 20.0
APPLY_SLICE_CHUNKS = 5
APPLY_SLICE_S = 20.0

INSERT_SQL = text("""
    INSERT INTO llm_work_items (job_id, rule_id, rule_version, project_id, branch_id, mr_id, object_key, content_hash,
                                call_index, prompt_hash, system_prompt, user_prompt, json_schema)
    VALUES (:job_id, :rule_id, :rule_version, :project_id, :branch_id, :mr_id, CAST(:object_key AS uuid),
            CAST(:content_hash AS uuid),
            :call_index, :prompt_hash, :system_prompt, :user_prompt, CAST(:json_schema AS jsonb))
    ON CONFLICT (rule_id, rule_version, object_key, call_index)
        WHERE status IN ('pending', 'leased', 'answered') AND purpose = 'score'
    DO NOTHING
""")

OPEN_SQL = text("""
    SELECT rule_id, rule_version, object_key, bool_or(job_id = :job) AS own FROM llm_work_items
    WHERE rule_id = ANY(:rules) AND purpose = 'score' AND (status IN ('pending', 'leased', 'answered') OR job_id = :job)
    GROUP BY 1, 2, 3
""")


def _job_phase(job_id: int) -> Optional[str]:
    with db.unit_of_work() as s:
        return s.execute(text("SELECT progress->>'phase' FROM jobs WHERE id = :id"), {"id": job_id}).scalar()


def _has_items(job_id: int) -> bool:
    with db.unit_of_work() as s:
        return bool(s.execute(text("SELECT EXISTS (SELECT 1 FROM llm_work_items WHERE job_id = :id)"),
                              {"id": job_id}).scalar())


def _insert(rows: List[dict]) -> int:
    inserted = 0
    with db.unit_of_work() as s:
        for start in range(0, len(rows), 500):
            inserted += s.execute(INSERT_SQL, rows[start:start + 500]).rowcount or 0
    return inserted


def prepare_external_run(job_id: int, branch, rule_ids: Sequence[int], mr_id: Optional[int] = None,
                         max_objects: Optional[int] = None, max_seconds: Optional[float] = None,
                         clock=time.monotonic) -> Dict:
    """Record the model calls of the rules ``rule_ids`` on ``branch`` as work items of job
    ``job_id``. Objects that already have open items (an earlier external run not answered
    yet) are not asked twice.

    One call records at most ``max_objects`` objects / runs about ``max_seconds``; when more
    are left, ``stats["more"]`` is True and progress.phase stays ``preparing`` (the handler
    requeues the job, the next call goes on: objects this job recorded already are passed
    over, items of the first slices can be claimed meanwhile). The final call counts the
    skipped / failed objects over the whole run and sets ``awaiting_answers`` (or ``done``)."""
    max_objects = PREPARE_SLICE_OBJECTS if max_objects is None else max_objects
    max_seconds = PREPARE_SLICE_S if max_seconds is None else max_seconds
    progress = JobProgress(job_id, executor="external", rule_ids=rule_ids)
    resumed = _job_phase(job_id) == PREPARING
    if not resumed:
        progress.start(0)
    project_path = getattr(branch, "project_path", None)
    rules = selected_llm_rules(branch, rule_ids)

    rows: List[dict] = []
    objects = skipped = failed = 0
    more = False
    deadline = clock() + max_seconds
    if rules:
        with db.unit_of_work() as s:
            open_keys = {(r.rule_id, r.rule_version, str(r.object_key)): r.own
                         for r in s.execute(OPEN_SQL, {"rules": [rule.id for rule in rules], "job": job_id})}
        # reserved objects are counted (skipped_open_objects) below, not dropped by the selection
        for rule, batch in _rule_batches(rules, branch.id, project_path, skip_reserved=False):
            if isinstance(batch, Exception):
                raise batch                  # candidates not selected: the job is retried
            if batch is None:
                continue
            for obj in batch.llm_objects:
                own = open_keys.get((rule.id, rule.version, str(obj.object_key)))
                if own:
                    continue                 # recorded by an earlier slice of this run
                if own is not None:
                    skipped += 1             # open items of another run
                    continue
                if objects >= max_objects or (objects and (clock() >= deadline or jobs.stop_requested())):
                    more = True
                    break
                recorder = RecordingBackend()
                verdicts = llm_rule_object_verdicts(rule, [obj], recorder)
                if getattr(verdicts, "failed", 0):
                    failed += 1              # the prompt could not be built: a service run fails it too
                    continue
                if not recorder.calls:
                    continue                 # nothing to ask (as in a service run)
                row = batch.objects[obj.object_key]["row"]
                objects += 1
                for index, (system, user, schema) in enumerate(recorder.calls):
                    rows.append({
                        "job_id": job_id, "rule_id": rule.id, "rule_version": rule.version,
                        "project_id": row["project_id"], "branch_id": branch.id, "mr_id": mr_id,
                        "object_key": str(obj.object_key), "content_hash": str(row["content_hash"]),
                        "call_index": index, "prompt_hash": prompt_hash(system, user, schema),
                        "system_prompt": system, "user_prompt": user,
                        "json_schema": json.dumps(schema) if schema is not None else None,
                    })
            if more:
                break

    inserted = _insert(rows)
    stats = {"items": inserted, "objects": objects, "more": more}
    if more:
        logger.info(f"External LLM run (job {job_id}) on {project_path}, branch {branch.branch_name}: "
                    f"{objects} objects recorded in this slice, more to go")
        set_progress(job_id, {"phase": PREPARING})
        refresh_progress([job_id])
        return stats
    stats.update(skipped_open_objects=skipped, failed_prompts=failed)
    if rules:
        record_llm_coverage(branch.id, rules)      # the recorded objects are held by this run now
    logger.info(f"External LLM run (job {job_id}) on {project_path}, branch {branch.branch_name}: {stats}")
    if inserted or (resumed and _has_items(job_id)):
        set_progress(job_id, {"phase": "awaiting_answers", "skipped_open_objects": skipped,
                              "failed_prompts": failed})
        refresh_progress([job_id])
    else:
        progress.finish("done", items=0, skipped_open_objects=skipped, failed_prompts=failed)
    return stats


ANSWERED_SQL = text("""
    SELECT id, rule_id, rule_version, branch_id, object_key, content_hash, call_index, prompt_hash, answer,
           answer_model
    FROM llm_work_items WHERE job_id = :job AND status = 'answered' AND purpose = 'score'
    ORDER BY id LIMIT :limit
""")

MARK_SQL = text("""
    UPDATE llm_work_items SET status = :status, error = :error, updated_at = now()
    WHERE id = ANY(:ids) AND status = 'answered'
""").bindparams(bindparam("ids", type_=IDS))


class _Outcome:
    def __init__(self):
        self.by_status: Dict[tuple, List[int]] = {}
        self.failures: List[Dict] = []       # refused answers, for the run's progress.errors

    def add(self, items, status: str, error: Optional[str] = None, rule=None, obj=None):
        self.by_status.setdefault((status, (error or "")[:ERROR_MAX] or None), []).extend(i.id for i in items)
        if status == "failed" and items:
            first = items[0]
            self.failures.append({
                "error": error or "the answer could not be used",
                "rule_id": getattr(rule, "id", None) or first.rule_id, "rule_name": getattr(rule, "name", None),
                "object_name": getattr(obj, "name", None), "object_key": str(first.object_key),
                "where": "harness answer"})

    def save(self):
        with db.unit_of_work() as s:
            for (status, error), ids in self.by_status.items():
                s.execute(MARK_SQL, {"status": status, "error": error, "ids": ids})

    def count(self, status: str) -> int:
        return sum(len(ids) for (s, _), ids in self.by_status.items() if s == status)


def _apply_group(rule, branch, items, outcome: _Outcome) -> None:
    """Answers of one rule on one branch: rebuild every object's calls from the current
    candidates and replay the answers through the service's verdict and hit code."""
    by_object: Dict = {}
    for item in sorted(items, key=lambda i: (str(i.object_key), i.call_index)):
        by_object.setdefault(str(item.object_key), []).append(item)

    # the stale verdicts too: what was prepared (fresh, or a stale verdict in LLM_REASK_INLINE) is still asked
    batch = llm_rule_batch(rule, branch.id, branch.project_path, skip_reserved=False, migration=True)
    llm_objects = {str(o.object_key): o for o in (batch.llm_objects if batch is not None else [])}
    verdicts, ok_keys, ok_items = LlmVerdicts(), [], []
    for key, its in by_object.items():
        obj = llm_objects.get(key)
        if obj is None:
            outcome.add(its, "expired", "no longer a candidate (decided, answered by another run, or removed)")
            continue
        if str(batch.objects[obj.object_key]["row"]["content_hash"]) != str(its[0].content_hash):
            outcome.add(its, "expired", "the object changed since the prompt was recorded")
            continue
        replay = ReplayBackend([(i.prompt_hash, i.answer) for i in its], model=its[0].answer_model or "external")
        result = llm_rule_object_verdicts(rule, [obj], replay)
        if replay.mismatch is not None or replay.calls != len(its):
            outcome.add(its, "expired", "the prompt changed since it was recorded")
        elif getattr(result, "failed", 0):
            outcome.add(its, "failed", result.errors.get(obj.object_key, "the answer could not be used"),
                        rule=rule, obj=obj)
        else:
            verdicts.extend(result)
            ok_keys.append(obj.object_key)
            ok_items.extend(its)
    if verdicts:
        store_llm_verdicts(rule, verdicts, batch.only(ok_keys), is_main=branch.is_main)
    outcome.add(ok_items, "applied")


def apply_answers(job_id: int, max_chunks: Optional[int] = None, max_seconds: Optional[float] = None,
                  clock=time.monotonic) -> Dict[str, int]:
    """Apply the answered items of the external run ``job_id``, ``APPLY_CHUNK`` at a time; at
    most ``max_chunks`` chunks / about ``max_seconds`` per call (``more``: answers may be left,
    the handler requeues the job)."""
    max_chunks = APPLY_SLICE_CHUNKS if max_chunks is None else max_chunks
    max_seconds = APPLY_SLICE_S if max_seconds is None else max_seconds
    totals = {"applied": 0, "failed": 0, "expired": 0}
    rules = None
    seen = set()
    touched: Dict[int, Dict[int, object]] = {}      # branch -> rules whose answers were applied
    chunks, more = 0, False
    deadline = clock() + max_seconds
    while True:
        if chunks and (chunks >= max_chunks or clock() >= deadline or jobs.stop_requested()):
            more = True
            break
        with db.unit_of_work() as s:
            items = s.execute(ANSWERED_SQL, {"job": job_id, "limit": APPLY_CHUNK}).all()
        if not items or seen & {i.id for i in items}:
            break                            # nothing left (or not marked: never loop on the same items)
        chunks += 1
        seen |= {i.id for i in items}
        if rules is None:
            rules = {rule.id: rule for rule in llm_rules()}
        outcome = _Outcome()
        groups: Dict[tuple, list] = {}
        for item in items:
            groups.setdefault((item.branch_id, item.rule_id), []).append(item)
        for (branch_id, rule_id), its in groups.items():
            branch = get_branch_by_id(branch_id)
            rule = rules.get(rule_id)
            if branch is None:
                outcome.add(its, "expired", "the branch is not tracked any more")
            elif rule is None:
                outcome.add(its, "expired", "the rule was deleted or disabled")
            elif is_inventory(branch.project_id):
                outcome.add(its, "expired", "the project is in inventory mode")
            else:
                stale = [i for i in its if i.rule_version != rule.version]
                if stale:
                    outcome.add(stale, "expired", f"the rule changed (now version {rule.version})")
                current = [i for i in its if i.rule_version == rule.version]
                if current:
                    _apply_group(rule, branch, current, outcome)
                    touched.setdefault(branch.id, {})[rule.id] = rule
        outcome.save()
        if outcome.failures:
            add_progress_errors(job_id, outcome.failures)      # why answers were refused: the run's progress
        refresh_progress([job_id])
        for status in totals:
            totals[status] += outcome.count(status)
        if len(items) < APPLY_CHUNK:
            break                            # that was the last chunk
    for branch_id, applied_rules in touched.items():
        record_llm_coverage(branch_id, list(applied_rules.values()))
    logger.info(f"External LLM run (job {job_id}): answers applied {totals}" + (", more to go" if more else ""))
    return {**totals, "more": more}
