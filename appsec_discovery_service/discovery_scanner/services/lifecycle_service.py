"""LLM rule lifecycle on the scanner side (``discovery_common.lifecycle``): the ``llm_rollout`` job (control worker,
every LLM_ROLLOUT_TICK_S; no model is called).

1. ``sync_versions``: what the scanner runs with vs the active version of every live LLM rule.

   * every rule gets an active ``rule_versions`` row (rules made before migration 0024 or inserted directly) pinned
     to the code's core prompts version and, once known, to the service model (LLM_API_MODEL, recorded in
     ``llm_runtime`` for the API too);
   * new core prompts (a deploy; ``classifier{N}`` / ``rule{N}`` per family) or another service model: a candidate
     version per affected rule - same prompt and scope, the new core prompts / model (``source`` core_bump |
     model_change). The active version stays pinned: its verdicts are not stale until the candidate is activated
     (a human, UI / REST: Rule studio "Versions"). LLM_CORE_BUMP_MODE=immediate (or LLM_REASK_INLINE) /
     LLM_MODEL_CHANGE_POLICY=reask activate it at once and start its rollout; LLM_MODEL_CHANGE_POLICY=ignore just
     records the new model on the active version (no verdict gets stale).

2. ``tick``: the controller of the running rollouts. Per rollout (rules by severity, then the oldest rollout): the
   stale machine verdicts of the rule per project (``lifecycle.MIGRATION_COND`` on ``rule_hits``, one grouped
   query) give the main branches still to migrate, ordered by the old verdicts (need_more_info first, then
   positive, then no_match; the most stale objects, the most recently seen); it queues ``llm_score`` slices
   (``rollout_id``, ``migration``, at most LLM_ROLLOUT_SLICE_OBJECTS objects, priority -10) within the budget:
   LLM_ROLLOUT_CALLS_PER_HOUR model calls of all rollouts in the last hour (the slices' progress counters),
   LLM_ROLLOUT_MAX_PARALLEL_JOBS slices queued / running, nothing while more than LLM_ROLLOUT_FRESH_BACKLOG_MAX
   fresh ``llm_score`` jobs are pending (fresh work first). Per-rollout ``budget`` overrides them (and
   ``max_calls``: pause once used). MR deltas are not migrated (their ``scan_mr`` asks their stale verdicts).
   A branch whose slice found nothing to ask is ``exhausted`` (stale hits out of the scope / on subjects gone from
   main) until its snapshot changes. Done: no stale verdict left on a branch that is not exhausted, no slice
   running. Auto-pause: the harness model's agreement on the QA sample of the new version (at least
   LLM_ROLLOUT_QA_MIN_SAMPLES since the start) below LLM_ROLLOUT_QA_AGREEMENT_MIN or more than
   LLM_ROLLOUT_QA_MAX_DROP below the old version's.
"""

import json
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from discovery_common import db, jobs, lifecycle
from discovery_common.models import JOB_PRIORITY_ROLLOUT
from config import get_settings
from logger import get_logger

logger = get_logger(__name__)

SYNC_LOCK = "SELECT pg_advisory_xact_lock(hashtext('discovery_rule_versions'))"

RUNTIME_SQL = text("""
    INSERT INTO llm_runtime (key, value, updated_at) VALUES ('service_model', :m, now())
    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
    WHERE llm_runtime.value IS DISTINCT FROM EXCLUDED.value""")

AUTO_CANDIDATE_SQL = text(f"""
    SELECT {lifecycle.VERSION_COLUMNS} FROM rule_versions
    WHERE rule_id = :r AND status IN ('draft', 'candidate') AND source = ANY(:sources)
      AND core_prompt_version IS NOT DISTINCT FROM :core AND model IS NOT DISTINCT FROM :model
    ORDER BY version DESC LIMIT 1""")


def _service_model(settings) -> Optional[str]:
    """The service model the scanner calls (None without LLM_API_URL: no model to pin)."""
    return settings.llm_api_model if settings.llm_api_url else None


def sync_versions(settings=None) -> Dict[str, int]:
    settings = settings or get_settings()
    code_model = _service_model(settings)
    stats = {"rules": 0, "pinned": 0, "model_recorded": 0, "candidates": 0, "activated": 0}
    with db.unit_of_work() as s:
        if code_model:
            s.execute(RUNTIME_SQL, {"m": code_model})
        rule_ids = [r[0] for r in s.execute(text(
            "SELECT id FROM rules WHERE kind = 'llm' AND deleted_at IS NULL ORDER BY id"))]
    for rule_id in rule_ids:
        try:
            with db.unit_of_work() as s:
                s.execute(text(SYNC_LOCK))
                _sync_rule(s, rule_id, settings, code_model, stats)
            stats["rules"] += 1
        except lifecycle.LifecycleError as e:
            logger.warning(f"LLM rule {rule_id}: versions not synced: {e}")
    if stats["pinned"] or stats["candidates"] or stats["activated"] or stats["model_recorded"]:
        logger.info(f"LLM rule versions synced: {stats}")
    return stats


def _sync_rule(s, rule_id: int, settings, code_model: Optional[str], stats: Dict[str, int]) -> None:
    rule = lifecycle.rule_row(s, rule_id, lock=True)
    active = lifecycle.ensure_active_version(s, rule_id, "scanner")
    code_core = lifecycle.code_core_version(rule)
    if active["core_prompt_version"] is None:
        s.execute(text("UPDATE rule_versions SET core_prompt_version = :c WHERE id = :id"),
                  {"c": code_core, "id": active["id"]})
        s.execute(text("UPDATE rules SET core_prompt_version = :c WHERE id = :r"), {"c": code_core, "r": rule_id})
        active["core_prompt_version"] = code_core
        stats["pinned"] += 1
    if code_model and active["model"] is None:
        _record_model(s, rule_id, active, code_model)
        stats["model_recorded"] += 1
    pinned_core, pinned_model = active["core_prompt_version"], active["model"]
    core_changed = pinned_core != code_core
    model_changed = bool(code_model) and pinned_model != code_model
    if model_changed and settings.llm_model_change_policy == "ignore":
        _record_model(s, rule_id, active, code_model)
        stats["model_recorded"] += 1
        model_changed = False
    if not (core_changed or model_changed):
        return
    want_core = code_core if core_changed else pinned_core
    want_model = code_model if model_changed else pinned_model
    source = "+".join(name for name, on in (("core_bump", core_changed), ("model_change", model_changed)) if on)
    candidate = s.execute(AUTO_CANDIDATE_SQL, {
        "r": rule_id, "sources": list(lifecycle.AUTO_SOURCES), "core": want_core, "model": want_model}
    ).mappings().first()
    if candidate is None:
        what = ", ".join(x for x in (core_changed and f"core prompts {pinned_core} -> {want_core}",
                                     model_changed and f"model {pinned_model} -> {want_model}") if x)
        candidate = lifecycle.create_version(
            s, rule_id, prompt=active["prompt"], target=active["target"], matchers=active["matchers"],
            core_prompt_version=want_core, model=want_model, source=source, created_by="scanner",
            note=f"the scanner runs with other {what}: activate this version to migrate the verdicts")
        stats["candidates"] += 1
    immediate = (settings.llm_reask_inline or (core_changed and settings.llm_core_bump_mode == "immediate")
                 or (model_changed and settings.llm_model_change_policy == "reask"))
    if immediate and candidate["status"] in ("draft", "candidate"):
        lifecycle.activate_version(s, candidate["id"], user="scanner", start_rollout=True, mode="immediate",
                                   keep_env=True, note=f"{source}: activated by the scanner", batch_jobs=True)
        stats["activated"] += 1


def _record_model(s, rule_id: int, active: dict, model: str) -> None:
    s.execute(text("UPDATE rule_versions SET model = :m WHERE id = :id"), {"m": model, "id": active["id"]})
    s.execute(text("UPDATE rules SET llm_model = :m WHERE id = :r"), {"m": model, "r": rule_id})
    active["model"] = model


# ---- the rollout controller --------------------------------------------------------------------------------------

ROLLOUTS_SQL = text(f"""
    SELECT o.id, o.rule_id, o.from_version, o.to_version, o.status, o.mode, o.budget, o.progress, o.started_at,
           r.name, r.severity, r.version AS rule_version, r.enabled, r.deleted_at
    FROM llm_rollouts o JOIN rules r ON r.id = o.rule_id
    WHERE o.status IN ({lifecycle.OPEN_SQL})
    ORDER BY o.id""")

SLICES_SQL = text("""
    SELECT id, status, payload, progress FROM jobs
    WHERE kind = 'llm_score' AND payload ? 'rollout_id'
      AND (status IN ('pending', 'running') OR (finished_at > now() - interval '1 hour'))""")

FRESH_BACKLOG_SQL = text("""
    SELECT count(*) FROM jobs WHERE kind = 'llm_score' AND status = 'pending' AND NOT (payload ? 'rollout_id')""")

# rules whose verdicts an llm_relabel job (relabel / adopt in slices) is still changing: a slice queued meanwhile
# would ask the model about verdicts the job is about to relabel
RELABELLING_SQL = text("""
    SELECT DISTINCT (payload ->> 'rule_id')::int FROM jobs
    WHERE kind = 'llm_relabel' AND status IN ('pending', 'running')""")

MAIN_BRANCHES_SQL = text("""
    SELECT g.project_id, g.id AS branch_id, g.scanned_commit, p.full_path FROM gitlab_branches g
    JOIN gitlab_projects p ON p.id = g.project_id
    WHERE g.is_main AND g.scanned_commit IS NOT NULL AND p.scan_mode = 'rules'""")

PATCH_SQL = text("UPDATE llm_rollouts SET progress = progress || CAST(:p AS jsonb) WHERE id = :id")

FINISH_SQL = text("""UPDATE llm_rollouts SET status = :s, finished_at = CASE WHEN :s IN ('done', 'cancelled')
                     THEN now() END, paused_reason = :why, progress = progress || CAST(:p AS jsonb)
                     WHERE id = :id AND status IN ('running', 'planned', 'paused')""")

QUALITY_SQL = text("""
    SELECT rule_version,
           count(*) FILTER (WHERE confidence = 'high' AND verdict IN ('match', 'no_match')) AS samples,
           count(*) FILTER (WHERE confidence = 'high' AND verdict IN ('match', 'no_match') AND verdict = service_verdict)
               AS agreed
    FROM llm_verifications
    WHERE rule_id = :r AND sample = 'qa' AND rule_version IN (:new, :old)
      AND (rule_version <> :new OR created_at >= COALESCE(CAST(:since AS timestamptz), '-infinity'))
    GROUP BY rule_version""")


def _calls(job_row) -> int:
    """Model calls a slice made / reserved: its asked objects (one call per object), its size while pending."""
    if job_row.status == "pending":
        return int((job_row.payload or {}).get("max_objects") or 0)
    p = job_row.progress or {}
    return max(0, int(p.get("done_objects") or 0) + int(p.get("failed_objects") or 0)
               - int(p.get("skipped_objects") or 0))


def _budget(settings, rollout) -> Dict[str, int]:
    b = rollout["budget"] or {}
    return {"calls_per_hour": int(b.get("calls_per_hour") or settings.llm_rollout_calls_per_hour),
            "max_parallel_jobs": int(b.get("max_parallel_jobs") or settings.llm_rollout_max_parallel_jobs),
            "slice_objects": int(b.get("slice_objects") or settings.llm_rollout_slice_objects),
            "fresh_backlog_max": int(b["fresh_backlog_max"]) if b.get("fresh_backlog_max") is not None
            else settings.llm_rollout_fresh_backlog_max,
            "max_calls": int(b["max_calls"]) if b.get("max_calls") else None}


def stale_branches(s, rule, code_model: Optional[str], exhausted: Dict[str, Any]) -> List[dict]:
    """Main branches with stale machine verdicts of ``rule``, in rollout order (see the module doc)."""
    from services.scan_service import _scope_matches
    params = {"rule_id": rule["id"], **lifecycle.version_params(rule, code_model, True)}
    params.pop("migration")
    rows = s.execute(text(lifecycle.STALE_HITS_SQL.format(cond=lifecycle.MIGRATION_COND)), params).mappings().all()
    mains = {r.project_id: r for r in s.execute(MAIN_BRANCHES_SQL)}
    out = []
    for row in rows:
        main = mains.get(row["project_id"])
        if main is None or not _scope_matches(rule["scope"], main.full_path):
            continue
        done = exhausted.get(str(main.branch_id))
        out.append({"branch_id": main.branch_id, "project_id": row["project_id"], "objects": int(row["objects"]),
                    "subjects": int(row["subjects"]), "bucket": row["bucket"], "last_seen_at": row["last_seen_at"],
                    "commit": main.scanned_commit, "exhausted": done is not None and done == main.scanned_commit})
    out.sort(key=lambda b: (b["bucket"], -b["objects"], -(b["last_seen_at"].timestamp() if b["last_seen_at"] else 0),
                            b["branch_id"]))
    return out


def _quality_drop(s, rollout, settings) -> Optional[str]:
    rows = {r.rule_version: r for r in s.execute(QUALITY_SQL, {
        "r": rollout["rule_id"], "new": rollout["to_version"], "old": rollout["from_version"] or -1,
        "since": rollout["started_at"]})}
    new = rows.get(rollout["to_version"])
    if new is None or new.samples < settings.llm_rollout_qa_min_samples:
        return None
    agreement = new.agreed / new.samples
    if agreement < settings.llm_rollout_qa_agreement_min:
        return (f"harness agreement of v{rollout['to_version']} {agreement:.0%} on {new.samples} QA samples is below "
                f"LLM_ROLLOUT_QA_AGREEMENT_MIN {settings.llm_rollout_qa_agreement_min:.0%}")
    old = rows.get(rollout["from_version"])
    if old is not None and old.samples >= settings.llm_rollout_qa_min_samples:
        before = old.agreed / old.samples
        if agreement < before - settings.llm_rollout_qa_max_drop:
            return (f"harness agreement dropped from {before:.0%} (v{rollout['from_version']}) to {agreement:.0%} "
                    f"(v{rollout['to_version']})")
    return None


def tick(settings=None) -> Dict[str, Any]:
    """One controller pass over the open rollouts (see the module doc); returns what it did."""
    from services.score_service import llm_configured
    settings = settings or get_settings()
    code_model = _service_model(settings)
    stats: Dict[str, Any] = {"running": 0, "queued": 0, "done": 0, "paused": 0, "waiting": {}}
    with db.unit_of_work() as s:
        rollouts = [dict(r) for r in s.execute(ROLLOUTS_SQL).mappings()]
        if not rollouts:
            return stats
        slices = list(s.execute(SLICES_SQL))
        backlog = int(s.execute(FRESH_BACKLOG_SQL).scalar() or 0)
        relabelling = {r[0] for r in s.execute(RELABELLING_SQL) if r[0] is not None}
    rollouts.sort(key=lambda r: (-lifecycle.SEVERITY_RANK.get(r["severity"] or "", 0), r["id"]))
    active = [j for j in slices if j.status in ("pending", "running")]
    used_hour = sum(_calls(j) for j in slices)
    global_left = settings.llm_rollout_calls_per_hour - used_hour
    parallel_left = settings.llm_rollout_max_parallel_jobs - len(active)

    for rollout in rollouts:
        rid = rollout["id"]
        mine = [j for j in slices if str((j.payload or {}).get("rollout_id")) == str(rid)]
        mine_active = [j for j in mine if j.status in ("pending", "running")]
        budget = _budget(settings, rollout)
        with db.unit_of_work() as s:
            rule = lifecycle.rule_row(s, rollout["rule_id"])
            if rule["deleted_at"] is not None or rule["version"] != rollout["to_version"]:
                why = "the rule was deleted" if rule["deleted_at"] is not None else \
                    f"the rule is at v{rule['version']} now"
                s.execute(FINISH_SQL, {"s": "cancelled", "why": None, "id": rid,
                                       "p": json.dumps({"waiting": None, "note": why})})
                continue
            progress = dict(rollout["progress"] or {})
            exhausted = dict(progress.get("exhausted") or {})
            branches = stale_branches(s, rule, code_model, exhausted)
            left = [b for b in branches if not b["exhausted"]]
            remaining = sum(b["objects"] for b in left)
            patch: Dict[str, Any] = {
                "remaining_objects": remaining, "remaining_subjects": sum(b["subjects"] for b in left),
                "branches_left": len(left), "slices_active": len(mine_active),
                "calls_last_hour": sum(_calls(j) for j in mine), "budget_effective": budget,
                "fresh_backlog": backlog, "updated_at": _now_iso(s)}
            if progress.get("planned_objects") is None or rollout["status"] == "planned":
                patch["planned_objects"] = remaining
            size = lifecycle.migration_size(s, rule, code_model=code_model)
            patch.update(protected_human=size["protected_human"], protected_harness=size["protected_harness"])
            if rollout["status"] != "running":
                patch["waiting"] = None
                s.execute(PATCH_SQL, {"p": json.dumps(patch, default=str), "id": rid})
                continue
            stats["running"] += 1
            calls_per_hour = max(1, budget["calls_per_hour"])
            patch["eta_s"] = int(remaining / calls_per_hour * 3600) if remaining else 0
            if remaining == 0 and not mine_active:
                s.execute(FINISH_SQL, {"s": "done", "why": None, "id": rid,
                                       "p": json.dumps({**patch, "waiting": None}, default=str)})
                stats["done"] += 1
                logger.info(f"Rollout {rid} of LLM rule {rule['name']} v{rollout['to_version']} done")
                continue
            reason = _quality_drop(s, rollout, settings)
            if reason is None and budget["max_calls"] and int(progress.get("calls") or 0) >= budget["max_calls"]:
                reason = f"budget max_calls {budget['max_calls']} used"
            if reason is not None:
                s.execute(FINISH_SQL, {"s": "paused", "why": reason, "id": rid,
                                       "p": json.dumps({**patch, "waiting": None}, default=str)})
                stats["paused"] += 1
                logger.warning(f"Rollout {rid} of LLM rule {rule['name']} paused: {reason}")
                continue
            waiting = None
            if not llm_configured(settings):
                waiting = "no service LLM (LLM_API_URL)"
            elif rule["enabled"] is False:
                waiting = "the rule is disabled"
            elif rule["id"] in relabelling:
                waiting = "a relabel / adopt job of the rule is running"
            elif backlog > budget["fresh_backlog_max"]:
                waiting = f"fresh work first: {backlog} llm_score jobs pending (> {budget['fresh_backlog_max']})"
            mine_left = min(global_left, calls_per_hour - sum(_calls(j) for j in mine))
            slots = min(parallel_left, budget["max_parallel_jobs"] - len(mine_active))
            if waiting is None and slots <= 0:
                waiting = "slices running (LLM_ROLLOUT_MAX_PARALLEL_JOBS)"
            if waiting is None and mine_left <= 0:
                waiting = f"calls budget of the hour used ({calls_per_hour}/h)"
            queued = 0
            if waiting is None:
                busy = {int((j.payload or {}).get("branch_id") or 0) for j in mine_active}
                for branch in left:
                    if slots <= 0 or mine_left <= 0:
                        break
                    if branch["branch_id"] in busy:
                        continue
                    size_n = min(budget["slice_objects"], mine_left)
                    job_id = jobs.enqueue("llm_score", lifecycle.slice_payload(rollout, branch["branch_id"], size_n),
                                          f"llm_rollout:{rid}:{branch['branch_id']}", conn=s,
                                          priority=JOB_PRIORITY_ROLLOUT, max_attempts=settings.job_max_attempts)
                    if job_id is None:
                        continue
                    queued += 1
                    slots -= 1
                    parallel_left -= 1
                    mine_left -= size_n
                    global_left -= size_n
                stats["queued"] += queued
            patch["waiting"] = waiting
            if waiting:
                stats["waiting"][rid] = waiting
            s.execute(PATCH_SQL, {"p": json.dumps(patch, default=str), "id": rid})
        if queued:
            logger.info(f"Rollout {rid} of LLM rule {rule['name']} v{rollout['to_version']}: {queued} slices queued, "
                        f"{remaining} objects left")
    return stats


def _now_iso(s) -> str:
    return str(s.execute(text("SELECT now()")).scalar().isoformat())


SLICE_DONE_SQL = text("""
    UPDATE llm_rollouts SET progress = progress || jsonb_build_object(
        'calls', COALESCE(CAST(progress ->> 'calls' AS bigint), 0) + :calls,
        'migrated_subjects', COALESCE(CAST(progress ->> 'migrated_subjects' AS bigint), 0) + :verdicts,
        'slices_done', COALESCE(CAST(progress ->> 'slices_done' AS bigint), 0) + 1,
        'exhausted', CASE WHEN :exhausted
                          THEN COALESCE(progress -> 'exhausted', '{}'::jsonb) || jsonb_build_object(:branch, :commit)
                          ELSE COALESCE(progress -> 'exhausted', '{}'::jsonb) END)
    WHERE id = :id""")


def slice_done(rollout_id: int, branch, asked: int, calls: int, verdicts: int = 0) -> None:
    """After a rollout slice: count its model calls; a slice that found nothing to ask marks its branch exhausted
    (until the branch's snapshot changes)."""
    with db.unit_of_work() as s:
        s.execute(SLICE_DONE_SQL, {"id": int(rollout_id), "calls": int(calls), "verdicts": int(verdicts),
                                   "exhausted": asked <= 0, "branch": str(branch.id),
                                   "commit": branch.scanned_commit or ""})


def rollout_status(rollout_id: int) -> Optional[str]:
    with db.unit_of_work() as s:
        return s.execute(text("SELECT status FROM llm_rollouts WHERE id = :id"), {"id": int(rollout_id)}).scalar()


def run_job(job) -> Dict[str, Any]:
    """The ``llm_rollout`` job: sync the rule versions, then one controller pass."""
    settings = get_settings()
    synced = sync_versions(settings)
    stats = tick(settings)
    return {"sync": synced, **stats}
