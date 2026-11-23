"""Verify items of the tiered workflow (``llm_verify`` job, control worker; ``discovery_common.llm_verify``).

After a service LLM run on a branch, the service verdicts of the branch's current snapshot go to the
harness model as verify items (``llm_work_items.purpose = 'verify'``, one per hit, claimed with
``llm_work_claim(purpose="verify")``):

* escalation - every service ``need_more_info`` verdict (LLM_VERIFY_ESCALATE, default on), at most
  LLM_ESCALATION_DAILY_MAX per rule and UTC day: the verdicts over the cap stay service-decided (they are in the review
  queue as before and eligible again the next day) and are counted as ``escalation_overflow`` in the job's progress
  (summed per day in the job health snapshot, ``discovery_common.stats``);
* reverify   - a harness decision replaced by a service re-ask because the subject's content changed (the hit keeps
  ``verified_at``);
* qa         - quality control: a sample of the CONFIDENT service verdicts, positive (pending_review / match) and
  negative (no_match - field rules store their negative field verdicts as no_match hits), at
  LLM_QA_SAMPLE_RATE: a verdict is in the sample when a hash of (subject, rule version, core prompts, subject
  hash, status) falls under the rate - stateless, the same verdict is sampled once, a new verdict gets a new draw.
  At most LLM_QA_DAILY_MAX QA items per UTC day, split evenly over the rules and the two verdict classes
  (stratified); sampled verdicts over the cap stay eligible for a later job.

Only service verdicts of the service model (no reviewer, ``decided_tier = 'service'``, not answered by a harness:
``model`` without " via "), of the rule's current version and core prompts (the pinned or the code's), on the subject's current content in
this branch, without a verify item for this verdict yet (``rule_hits.verify_key``). Object rules: the object hits
(field marks are by-products of the object's call). No model is called; one job records at most
``JOB_MAX_ITEMS`` items (more: requeued).
"""

import json
import math
from typing import Dict, List, Optional

from sqlalchemy import text

from discovery_common import db, jobs
from discovery_common.llm_work import JobProgress, prompt_hash, refresh_progress, set_progress
from discovery_common.mapping import marks_fields
from discovery_common import lifecycle
from config import get_settings
from logger import get_logger
from services.db_service import get_object_docs, get_object_fields
from services.score_service import LlmObject, verify_call

try:            # the core's verify prompt version (recorded on every verify item and harness decision)
    from appsec_discovery.ai.rules import VERIFY_PROMPT_VERSION
except Exception:           # pragma: no cover - the core is always installed in the scanner
    VERIFY_PROMPT_VERSION = None

logger = get_logger(__name__)

JOB_MAX_ITEMS = 500
SERVICE_MODEL_COND = "COALESCE(h.model, '') NOT LIKE '% via %'"
KEY_SQL = "(h.rule_version || ':' || COALESCE(h.prompt_version, '') || ':' || COALESCE(h.subject_hash, '') || ':' || h.status)"
# 0..9999, a stable draw per verdict (md5 of the subject and the verdict key)
DRAW_SQL = f"(('x' || substr(md5(h.subject_key::text || {KEY_SQL}), 1, 7))::bit(28)::int % 10000)"

_SELECT = """
    SELECT h.subject_key, h.object_key, h.field_name, h.project_id, h.status, h.reason, h.fields, h.model,
           h.rule_version, h.prompt_version, h.subject_hash, h.category, h.severity, h.verified_at,
           {key} AS verify_key, o.content_hash, o.name, o.type, o.parser, o.file, o.props
    FROM branch_objects b
    JOIN objects o ON o.content_hash = b.content_hash
    {fields}
    JOIN rule_hits h ON h.rule_id = :r AND h.subject_key = {subject}
    WHERE b.branch_id = :b AND b.content_hash IS NOT NULL
      AND h.reviewer IS NULL AND h.decided_tier = 'service' AND {service}
      AND h.rule_version = :v AND h.prompt_version IN (:pv, :code_pv) AND h.subject_hash = {current}
      AND h.verify_key IS DISTINCT FROM {key}
      AND NOT EXISTS (SELECT 1 FROM llm_work_items w WHERE w.purpose = 'verify' AND w.rule_id = :r
                      AND w.subject_key = h.subject_key AND w.status IN ('pending', 'leased', 'answered'))
      AND ({cond})
    ORDER BY {order}
    LIMIT :limit"""

# the stored hash of the field row (migration 0030) where it is filled, the function for rows written before it
FIELD_PARTS = {"fields": "JOIN object_fields f ON f.content_hash = b.content_hash", "subject": "f.field_key",
               "current": "COALESCE(f.llm_hash, llm_field_hash(f.field_name, f.field_type, f.comment, f.samples))"}
OBJECT_PARTS = {"fields": "", "subject": "o.object_key AND h.field_name IS NULL", "current": "o.content_hash::text"}

CLASSES = {
    "escalation": "h.status = 'need_more_info' AND h.verified_at IS NULL",
    "reverify": "h.verified_at IS NOT NULL",
    "qa_positive": f"h.status IN ('pending_review', 'match') AND h.verified_at IS NULL AND {DRAW_SQL} < :bp",
    "qa_negative": f"h.status = 'no_match' AND h.verified_at IS NULL AND {DRAW_SQL} < :bp",
}

TODAY_SQL = "(date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')"
QA_TODAY_SQL = text(f"""
    SELECT count(*) FROM llm_work_items WHERE purpose = 'verify' AND verify ->> 'sample' = 'qa'
      AND created_at >= {TODAY_SQL}""")
# the day's escalation items per rule (index llm_verify_rule_created, migration 0031)
ESCALATIONS_TODAY_SQL = text(f"""
    SELECT rule_id, count(*) AS n FROM llm_work_items
    WHERE purpose = 'verify' AND rule_id = ANY(:rules) AND created_at >= {TODAY_SQL}
      AND verify ->> 'sample' = 'escalation'
    GROUP BY rule_id""")

INSERT_SQL = text("""
    INSERT INTO llm_work_items (job_id, rule_id, rule_version, project_id, branch_id, mr_id, object_key, content_hash,
                                call_index, prompt_hash, system_prompt, user_prompt, json_schema, purpose, subject_key,
                                field_name, verify)
    VALUES (:job_id, :rule_id, :rule_version, :project_id, :branch_id, NULL, CAST(:object_key AS uuid),
            CAST(:content_hash AS uuid), 0, :prompt_hash, :system_prompt, :user_prompt, CAST(:json_schema AS jsonb),
            'verify', CAST(:subject_key AS uuid), :field_name, CAST(:verify AS jsonb))
    ON CONFLICT (rule_id, subject_key) WHERE status IN ('pending', 'leased', 'answered') AND purpose = 'verify'
    DO NOTHING
    RETURNING subject_key
""")

MARK_SQL = text("UPDATE rule_hits SET verify_key = :k WHERE rule_id = :r AND subject_key = CAST(:s AS uuid)")


def _params(rule, branch_id: int, bp: int, limit: int) -> dict:
    return {"r": rule.id, "b": branch_id, "v": rule.version, "pv": lifecycle.pinned_core_version(rule),
            "code_pv": lifecycle.code_core_version(rule), "limit": limit, "bp": bp}


def _select(session, rule, branch_id: int, cls: str, limit: int, bp: int) -> List[dict]:
    if limit <= 0:
        return []
    parts = OBJECT_PARTS if rule.target == "object" else FIELD_PARTS
    order = "h.subject_key" if cls.startswith("qa") else "h.project_id, h.subject_key"
    sql = _SELECT.format(key=KEY_SQL, service=SERVICE_MODEL_COND, cond=CLASSES[cls], order=order, **parts)
    return [dict(r) for r in session.execute(text(sql), _params(rule, branch_id, bp, limit)).mappings()]


def _count(session, rule, branch_id: int, cls: str, bp: int) -> int:
    """How many subjects of ``cls`` are eligible on the branch (the overflow over a cap)."""
    parts = OBJECT_PARTS if rule.target == "object" else FIELD_PARTS
    sql = _SELECT.format(key=KEY_SQL, service=SERVICE_MODEL_COND, cond=CLASSES[cls], order="1", **parts)
    sql = f"SELECT count(*) FROM ({sql.replace('LIMIT :limit', '')}) eligible"
    return int(session.execute(text(sql), {k: v for k, v in _params(rule, branch_id, bp, 0).items()
                                            if k != "limit"}).scalar() or 0)


def _verdict(status: str) -> str:
    return {"pending_review": "match", "match": "match", "no_match": "no_match"}.get(status, "need_more_info")


def select_subjects(rules, branch_id: int, settings=None, max_items: int = JOB_MAX_ITEMS,
                    overflow: Optional[Dict[str, int]] = None) -> List[tuple]:
    """``[(rule, sample, hit row)]`` to verify on the branch: escalations (within the rule's day cap,
    LLM_ESCALATION_DAILY_MAX; ``overflow["escalation"]`` counts the eligible ones left out) and reverifications
    first (up to ``max_items``), then the QA sample within the day's cap, stratified per rule and verdict class."""
    settings = settings or get_settings()
    bp = int(round(settings.llm_qa_sample_rate * 10000))
    chosen: List[tuple] = []
    with db.unit_of_work() as s:
        used_today: Dict[int, int] = {}
        if settings.llm_verify_escalate and rules:
            used_today = {r.rule_id: int(r.n) for r in s.execute(ESCALATIONS_TODAY_SQL, {"rules": [r.id for r in rules]})}
        for rule in rules:
            left = max_items - len(chosen)
            if settings.llm_verify_escalate:
                cap_left = max(0, settings.llm_escalation_daily_max - used_today.get(rule.id, 0))
                picked = _select(s, rule, branch_id, "escalation", min(left, cap_left), bp)
                chosen += [(rule, "escalation", r) for r in picked]
                used_today[rule.id] = used_today.get(rule.id, 0) + len(picked)
                if overflow is not None and len(picked) >= cap_left:
                    # the cap is reached: count the eligible escalations of the branch beyond it
                    eligible = _count(s, rule, branch_id, "escalation", bp)
                    overflow["escalation"] = overflow.get("escalation", 0) + max(0, eligible - len(picked))
            chosen += [(rule, "reverify", r) for r in _select(s, rule, branch_id, "reverify",
                                                               max_items - len(chosen), bp)]
        if bp <= 0 or not rules:
            return chosen
        used = int(s.execute(QA_TODAY_SQL).scalar() or 0)
        budget = min(settings.llm_qa_daily_max - used, max_items - len(chosen))
        if budget <= 0:
            return chosen
        per_stratum = max(1, math.ceil(budget / (2 * len(rules))))
        qa = []
        for rule in rules:
            for cls in ("qa_positive", "qa_negative"):
                qa += [(rule, "qa", r) for r in _select(s, rule, branch_id, cls, per_stratum, bp)]
        chosen += qa[:budget]
    return chosen


def _llm_objects(rows: List[dict]) -> Dict[object, LlmObject]:
    hashes = list({r["content_hash"] for r in rows})
    fields_by_hash = get_object_fields(hashes)
    docs_by_hash = get_object_docs(hashes)
    result = {}
    for r in rows:
        docs = docs_by_hash.get(r["content_hash"], (None, {}))
        result[r["content_hash"]] = LlmObject(
            object_key=r["object_key"], name=r["name"], fields=fields_by_hash.get(r["content_hash"], []),
            type=r["type"], parser=r["parser"], file=r["file"], props=r["props"], comment=docs[0], docs=docs[1])
    return result


def prepare(job_id: int, branch, rules, settings=None) -> Dict[str, int]:
    """Record the verify items of ``rules`` on ``branch`` as work items of job ``job_id``."""
    settings = settings or get_settings()
    overflow: Dict[str, int] = {}
    selected = select_subjects(rules, branch.id, settings, overflow=overflow)
    objects = _llm_objects([r for _, _, r in selected]) if selected else {}
    rows, keys, counts = [], [], {"escalation": 0, "qa": 0, "reverify": 0, "failed_prompts": 0,
                                  "escalation_overflow": int(overflow.get("escalation", 0))}
    for rule, sample, hit in selected:
        previous = {"verdict": _verdict(hit["status"]), "reason": hit["reason"], "fields": hit["fields"],
                    "category": hit["category"] if not rule.category else None}
        try:
            system, user, schema = verify_call(rule, objects[hit["content_hash"]], hit["field_name"], previous,
                                               settings)
        except Exception as e:
            counts["failed_prompts"] += 1
            logger.warning(f"Verify prompt of rule {rule.name}, subject {hit['subject_key']} not built: {e}")
            continue
        context = {
            "sample": sample, "service_status": hit["status"], "service_reason": hit["reason"], "service_fields": hit["fields"],
            "service_model": hit["model"], "subject_hash": hit["subject_hash"], "rule_version": hit["rule_version"],
            "prompt_version": hit["prompt_version"], "category": hit["category"], "severity": hit["severity"],
            "mark_fields": marks_fields(rule), "verify_key": hit["verify_key"],
            "verify_prompt_version": VERIFY_PROMPT_VERSION,
        }
        rows.append({
            "job_id": job_id, "rule_id": rule.id, "rule_version": rule.version, "project_id": hit["project_id"],
            "branch_id": branch.id, "object_key": str(hit["object_key"]), "content_hash": str(hit["content_hash"]),
            "prompt_hash": prompt_hash(system, user, schema), "system_prompt": system, "user_prompt": user,
            "json_schema": json.dumps(schema), "subject_key": str(hit["subject_key"]), "field_name": hit["field_name"],
            "verify": json.dumps(context, default=str),
        })
        keys.append((rule.id, str(hit["subject_key"]), hit["verify_key"], sample))
    inserted = 0
    if rows:
        with db.unit_of_work() as s:
            done = set()
            for row in rows:
                if s.execute(INSERT_SQL, row).first() is not None:
                    done.add((row["rule_id"], row["subject_key"]))
            for rule_id, subject, key, sample in keys:
                if (rule_id, subject) in done:
                    s.execute(MARK_SQL, {"k": key, "r": rule_id, "s": subject})
                    counts[sample] += 1
            inserted = len(done)
    counts["items"] = inserted
    counts["more"] = len(selected) >= JOB_MAX_ITEMS
    return counts


def run_job(job) -> Dict[str, int]:
    """The ``llm_verify`` job of ``payload.branch_id`` (``rule_ids``: those rules, else every enabled LLM rule)."""
    from services.db_service import get_branch_by_id
    from services.scan_service import is_inventory, llm_rules

    progress = JobProgress(job.id, executor="external", rule_ids=job.payload.get("rule_ids") or [])
    progress.base["purpose"] = "verify"
    branch = get_branch_by_id(job.payload["branch_id"])
    if branch is None or is_inventory(branch.project_id):
        progress.finish("done", items=0)
        return {"items": 0}
    wanted = {int(r) for r in job.payload.get("rule_ids") or []}
    rules = [r for r in llm_rules() if not wanted or r.id in wanted]
    stats = prepare(job.id, branch, rules)
    logger.info(f"Verify items of branch {branch.id} ({getattr(branch, 'project_path', None)}): {stats}")
    with db.unit_of_work() as s:
        has_items = bool(s.execute(text("SELECT EXISTS (SELECT 1 FROM llm_work_items WHERE job_id = :j)"),
                                   {"j": job.id}).scalar())
    counts = {k: v for k, v in stats.items() if k != "more"}
    if has_items:
        set_progress(job.id, {**progress.base, "phase": "awaiting_answers", **counts})
        refresh_progress([job.id])
    else:
        progress.finish("done", **{**counts, "items": 0})      # the escalation overflow is counted here too
    if stats.get("more") and not jobs.stop_requested():
        enqueue(branch.id, job.payload.get("rule_ids"), tag=f":{job.id}")
    return stats


def enqueue(branch_id: int, rule_ids=None, tag: str = "") -> Optional[int]:
    """Queue the ``llm_verify`` job of a branch (after a service LLM run on it); deduplicated per branch."""
    payload = {"branch_id": branch_id, "executor": "external", "purpose": "verify"}
    if rule_ids:
        payload["rule_ids"] = sorted({int(r) for r in rule_ids})
    return jobs.enqueue("llm_verify", payload, f"llm_verify:{branch_id}{tag}")
