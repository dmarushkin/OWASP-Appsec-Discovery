"""Handlers of the scanner's job kinds (P2-4). Each takes a ``discovery_common.jobs.Job``;
returning completes the job, raising fails the attempt (retried with backoff until
``JOB_MAX_ATTEMPTS``), ``PermanentJobError`` fails it at once.

Failures carry their cause (``services.failures.ScanError``, raised where it is known: the
git line of a failed clone, the parser's error, the per-rule summary of an LLM run); the
handler puts the job's subject in front (``scan of 'grp/proj', MR !25: cannot clone source
branch 'x': remote branch not found ...``) so ``jobs.last_error`` and the UI show the real
reason. A permanent failure (the source branch of an MR was deleted, no parser configured) is
raised as ``PermanentJobError``: no retries, and the MR is marked processed.

Flow (GitLab polling, no webhooks):

    scheduler -> sync_projects (every PROJECTS_POLL_INTERVAL_S)
              -> sync_branches_mrs  per new / changed project
                   -> scan_branch   main branch with a new commit / activity   (GITLAB_SCAN_TYPES mains)
                        -> llm_score  after a successful main scan (LLM configured; not after a
                                      diff-based skip: the snapshot did not change)
    API / MCP -> llm_score  selected LLM rules (executor service)
              -> llm_prepare selected LLM rules (executor external): work items, no model call
    llm_work_submit -> llm_apply  answers of an external run (scheduler: safety net)
    API / MCP -> llm_trial  a candidate prompt of an LLM rule on a few subjects (service model, no hits)
    llm_score (service) -> llm_verify  verify items for the harness model (escalations, QA sample)
                   -> scan_mr       open MR with new activity (updated in the last day) (mrs)
    scheduler -> cleanup (every GC_INTERVAL_HOURS)
    scheduler -> llm_coverage (every LLM_COVERAGE_INTERVAL_S): recount stale LLM coverage rows
    scheduler -> llm_rollout (every LLM_ROLLOUT_TICK_S): rule versions vs core prompts / model, rollout slices
                   -> llm_score  a slice of a rule rollout (rollout_id, priority -10)
    scheduler -> stats_refresh (every STATS_REFRESH_S): the statistics snapshots the API serves
    API / scanner -> llm_relabel  relabel / adopt of a rule version's verdicts in slices (lifecycle.enqueue_relabel)

The sync reads GitLab sparingly (polling only): the project, its open MRs (one page of 100), the default branch
and the branches of the open MRs by name (not every branch of the repository) and the states of the MRs that
disappeared from the open list in one batched call; a project whose activity did not change is re-read only
every SYNC_UNCHANGED_EVERY_H.

Dedup keys contain the commit(s), so new commits pushed while a scan runs are queued as a
new job instead of being dropped. ``processed_at`` is set to the ``updated_at`` that was
seen when the job was queued (not to "now"), so activity during the scan is not lost.
"""

from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, Optional

from discovery_common import jobs
from discovery_common.jobs import Job
from discovery_common.llm_work import CURRENT_PROGRESS, FINAL_PHASES, JobProgress, set_progress
from sqlalchemy import text

from config import get_settings
from logger import get_logger
from services import cleanup_service
from services.db_service import (
    fail_ingest_batch, get_branch, get_branch_by_id, get_delta_owner, get_mr, get_project, gl_time, scan_lock, set_branch_processed, set_mr_processed,
    set_mr_target_commit, set_project_processed, upsert_branch, upsert_mr, upsert_project,
)
from services.gl_service import (
    get_gitlab_branches, get_gitlab_mr_states, get_gitlab_mrs_by_project, get_gitlab_project,
    get_gitlab_projects_list,
)
from services.failures import ScanError
from services.scan_service import ingest_branch, llm_score_branch, run_selected_llm_rules, scan_branch, scan_mr
from services.score_service import llm_configured

logger = get_logger(__name__)

# Kinds that clone code: they run inside a per-job workspace (services.workspace).
WORKSPACE_KINDS = ("scan_branch", "scan_mr")       # ingest needs no checkout


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def _seen(payload: dict, key: str = "updated_at") -> Optional[datetime]:
    value = payload.get(key)
    return datetime.fromisoformat(value) if value else None


def _enqueue(kind: str, payload: dict, dedup_key: str) -> Optional[int]:
    settings = get_settings()
    job_id = jobs.enqueue(kind, payload, dedup_key, max_attempts=settings.job_max_attempts)
    if job_id is not None:
        logger.info(f"Queued {kind} job {job_id}: {payload}")
    return job_id


def _needs_processing(row) -> bool:
    return row.processed_at is None or (row.updated_at is not None and row.processed_at < row.updated_at)


def _utcnow() -> datetime:
    """Naive UTC, like the inventory timestamps (``db_service.gl_time``)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _sync_due(project_db, settings, full: bool) -> bool:
    """A project is re-read when its GitLab activity (``updated_at`` = ``last_activity_at``) is newer than what was
    processed, when it was not processed for SYNC_UNCHANGED_EVERY_H (stale MRs released, deleted branches noticed),
    or - with that setting 0 - on the full sync after start-up."""
    if _needs_processing(project_db):
        return True
    every = settings.sync_unchanged_every_h
    if every > 0:
        return project_db.processed_at is None or project_db.processed_at < _utcnow() - timedelta(hours=every)
    return full


def _diff_skipped(progress) -> bool:
    """The scan ended in the ``skipped`` phase of the diff-based skip (``services.diff_service``: no parser file
    changed, the snapshot was moved to the commit): nothing new for the LLM rules."""
    return getattr(progress, "last_phase", None) == "skipped" and bool((getattr(progress, "last_extra", None) or {}).get("skipped"))


# ---- GitLab sync -----------------------------------------------------------------------------

def sync_projects(job: Job) -> None:
    """Upsert the projects of every GITLAB_PROJECTS_PREFIX; queue a branch / MR sync for the new or changed ones
    and for the ones not synced for SYNC_UNCHANGED_EVERY_H (``_sync_due``; ``payload.full``, the first sync after
    start-up, queues every project only when that setting is 0)."""

    settings = get_settings()
    full = bool(job.payload.get("full"))
    errors = []

    for prefix in settings.projects_prefixes:
        try:
            queued = 0
            for project_gl in get_gitlab_projects_list(prefix):
                project_db, _ = upsert_project(project_gl)
                if _sync_due(project_db, settings, full):
                    _enqueue("sync_branches_mrs",
                             {"project_id": project_db.id, "gitlab_id": project_gl.id,
                              "updated_at": _iso(project_db.updated_at)},
                             f"sync_branches_mrs:{project_db.id}")
                    queued += 1
            logger.info(f"For prefix {prefix} queued {queued} projects for sync")
        except Exception as e:      # one bad prefix must not block the others
            logger.error(f"Project sync of prefix {prefix} failed: {e}")
            errors.append(f"{prefix}: {e}")

    if errors:
        raise RuntimeError("; ".join(errors))


def sync_branches_mrs(job: Job) -> None:
    """Branches and MRs of one project (was the ``update_branches_mrs`` loop). Only the main
    branch and the branches of open, not stale MRs are tracked (retention), and only those are
    read from GitLab (by name: ``gl_service.get_gitlab_branches``); MRs no longer open are
    closed (their states read in one batched call) and their source branch released."""

    settings = get_settings()
    project_db = get_project(job.payload["project_id"])
    if project_db is None:
        logger.info(f"Project {job.payload['project_id']} is not tracked any more, skipped")
        return

    project_gl = get_gitlab_project(job.payload.get("gitlab_id") or project_db.gitlab_id)

    mrs_gl = list(get_gitlab_mrs_by_project(project_gl.id)) if 'mrs' in settings.scan_types else []
    active_mrs_gl = [mr_gl for mr_gl in mrs_gl if not cleanup_service.is_stale(gl_time(mr_gl.updated_at))]

    mr_branch_names = {mr_gl.source_branch for mr_gl in active_mrs_gl} | {mr_gl.target_branch for mr_gl in active_mrs_gl}
    wanted = [project_gl.default_branch] + sorted(mr_branch_names - {project_gl.default_branch})

    for branch_gl in get_gitlab_branches(project_gl, wanted):
        is_main = (branch_gl.name == project_gl.default_branch)

        branch_db, _ = upsert_branch(branch_gl, project_db.id, project_db.full_path, is_main)

        if is_main and 'mains' in settings.scan_types and _needs_processing(branch_db):
            _enqueue("scan_branch", {"branch_id": branch_db.id, "commit": branch_db.commit,
                                     "updated_at": _iso(branch_db.updated_at)},
                     f"scan_branch:{branch_db.id}:{branch_db.commit}")

    if 'mrs' in settings.scan_types:

        for mr_gl in active_mrs_gl:

            source_branch = get_branch(project_db.id, mr_gl.source_branch)
            target_branch = get_branch(project_db.id, mr_gl.target_branch)

            if not (source_branch and target_branch):
                continue

            mr_db, _ = upsert_mr(mr_gl, project_db.id, project_db.full_path, source_branch, target_branch)

            if mr_db.state == 'opened' and mr_db.updated_at > datetime.now() - timedelta(days=1) \
                    and _needs_processing(mr_db):
                _enqueue("scan_mr", {"mr_id": mr_db.id, "source_commit": mr_db.source_branch_commit,
                                     "target_commit": mr_db.target_branch_commit,
                                     "updated_at": _iso(mr_db.updated_at)},
                         f"scan_mr:{mr_db.id}:{mr_db.source_branch_commit}:{mr_db.target_branch_commit}")

        # Merged / closed MRs and stale ones: stop tracking their source branches.
        cleanup_service.close_missing_mrs(project_db.id, [mr_gl.iid for mr_gl in mrs_gl],
                                          fetch_states=lambda iids: get_gitlab_mr_states(project_gl.id, iids))
        cleanup_service.release_stale_mr_branches(project_db.id)

    # Only now (was: when the project was queued), so a failed sync is retried.
    set_project_processed(project_db.id, _seen(job.payload))


# ---- scans -----------------------------------------------------------------------------------

def scan_branch_job(job: Job) -> None:
    """Scan a main branch at its current commit; queue the LLM rules afterwards."""

    settings = get_settings()
    branch_id = job.payload["branch_id"]
    progress = JobProgress(job.id, executor=None)      # phases clone -> parse -> save -> done (scan_service)
    token = CURRENT_PROGRESS.set(progress)
    try:
        progress.phase("waiting")
        with scan_lock(branch_id):      # one scan per branch at a time; re-read the row after waiting
            branch = get_branch_by_id(branch_id)
            if branch is None or not branch.is_main:
                logger.info(f"Branch {branch_id} is not a tracked main branch any more, skipped")
                progress.phase("skipped", reason="not a tracked main branch")
                return

            subject = f"scan of '{branch.project_path}', branch '{branch.branch_name}'"
            try:
                ok = scan_branch(branch, force=bool(job.payload.get("force")), parsers=job.payload.get("parsers"))
            except ScanError as e:
                # a failed clone or a partial scan (a parser failed): retried with backoff (a permanent
                # cause fails at once); not marked processed, so the next sync of the project queues
                # it again (as before). The reason goes to last_error.
                raise e.as_job_error(subject) from e
            if not ok:
                raise RuntimeError(f"{subject} failed without a recorded reason (see the scanner log)")

            set_branch_processed(branch.id, _seen(job.payload))
            if getattr(progress, "last_phase", None) not in FINAL_PHASES:
                progress.phase("done")
            skipped = _diff_skipped(progress)
    finally:
        CURRENT_PROGRESS.reset(token)

    # a manual rescan (POST /projects/{id}/rescan) may ask for the keyword scan only; a diff-based skip
    # changed nothing the rules could look at
    if llm_configured(settings) and job.payload.get("llm", True) and not skipped:
        _enqueue("llm_score", {"branch_id": branch.id, "commit": branch.commit}, f"llm_score:{branch.id}:{branch.commit}")


def scan_mr_job(job: Job) -> None:
    """Scan an MR (delta vs its target). After the last failed attempt the MR is
    marked processed anyway, so it is not re-queued on every sync (as before: the old loop
    marked it processed even when the scan failed)."""

    mr = get_mr(job.payload["mr_id"])
    if mr is None or mr.source_branch_id is None or mr.target_branch_id is None:
        logger.info(f"MR {job.payload['mr_id']} is gone or has no tracked branches, skipped")
        return

    source_branch = get_branch_by_id(mr.source_branch_id)
    if source_branch is None or source_branch.is_main or get_branch_by_id(mr.target_branch_id) is None:
        # nothing to scan (scan_mr would skip it too): not worth a retry
        logger.info(f"MR {mr.mr_id} of {mr.project_path}: branches not tracked any more or source is main, skipped")
        set_mr_processed(mr.id, _seen(job.payload))
        return

    owner = get_delta_owner(mr.source_branch_id)
    if owner is not None and owner != mr.id:
        # the delta lives on the source branch: one delta per branch. Another (older) open MR
        # of the same source branch owns it (e.g. this MR backports the branch into another
        # target); scanning this one would overwrite that MR's delta vs its target.
        # When the owner closes, this MR is scanned again (cleanup_service.close_missing_mrs).
        logger.warning(f"MR {mr.mr_id} of {mr.project_path}: source branch {mr.source_branch_id} is also the source "
                       f"of the open MR row {owner}, which owns its delta: not scanned")
        set_mr_processed(mr.id, _seen(job.payload))
        return

    # the target branch may have moved since the MR row was written (was done by pull_code)
    target_branch = get_branch(mr.project_id, mr.target_branch)
    if target_branch is not None and mr.target_branch_commit != target_branch.commit:
        set_mr_target_commit(mr.id, target_branch.commit)
        mr.target_branch_commit = target_branch.commit

    subject = f"scan of '{mr.project_path}', MR !{mr.mr_id}"
    ok = requeued = False
    error: Optional[ScanError] = None
    progress = JobProgress(job.id, executor=None)      # phases clone -> parse -> save -> done | skipped (scan_service)
    token = CURRENT_PROGRESS.set(progress)
    try:
        progress.phase("waiting")
        with scan_lock(mr.source_branch_id):     # the delta is saved on the source branch
            ok = scan_mr(mr, parsers=job.payload.get("parsers"), llm=job.payload.get("llm", True))
        if ok and getattr(progress, "last_phase", None) not in FINAL_PHASES:
            progress.phase("done")
    except jobs.RequeueJob:
        requeued = True                          # stopping: the scan runs again, not processed yet
        raise
    except ScanError as e:
        error = e                                # the reason is raised below, after the bookkeeping
        closed_state = _closed_with_deleted_source(mr, e)
        if closed_state is not None:
            # the MR was merged / closed and its source branch deleted before we got to it: nothing to
            # scan any more, not a failure (the next sync stores the state and releases the branch)
            logger.info(f"MR {mr.mr_id} of {mr.project_path} is {closed_state} and its source branch is deleted: "
                        f"not scanned")
            progress.phase("skipped", reason=f"MR {closed_state}, source branch deleted: not scanned")
            error, ok = None, True
    finally:
        CURRENT_PROGRESS.reset(token)
        # a permanent failure (the source branch was deleted) is not retried: processed now, so the
        # MR is not queued again on every sync until it changes
        final = job.last_attempt or (error is not None and error.permanent)
        if ok or (final and not requeued):
            set_mr_processed(mr.id, _seen(job.payload))

    if error is not None:
        raise error.as_job_error(subject) from error
    if not ok:
        raise RuntimeError(f"{subject} failed without a recorded reason (see the scanner log)")


DELETED_SOURCE_PREFIX = "cannot clone source branch"


def _closed_with_deleted_source(mr, error: ScanError) -> Optional[str]:
    """The GitLab state ('merged', 'closed', 'deleted') of an MR whose source branch could not be cloned
    because it is gone, when the MR is not open any more; None otherwise (an open MR with a deleted
    source, another failure, GitLab unreadable: the failure stands)."""
    if not (error.permanent and error.reason.startswith(DELETED_SOURCE_PREFIX)):
        return None
    try:
        state = get_gitlab_mr_states(mr.project_path, [mr.mr_id]).get(int(mr.mr_id), "deleted")
    except Exception as e:
        logger.warning(f"Cannot read the state of MR {mr.mr_id} of {mr.project_path}: {e}")
        return None
    return None if state == "opened" else state


def _prepare_external(job: Job) -> None:
    """Record the model calls of an external run (``services.llm_work_service``), one bounded
    slice per call: when more is left the job is requeued (``RequeueJob``, no attempt used)."""
    branch = get_branch_by_id(job.payload["branch_id"])
    rule_ids = job.payload.get("rule_ids")
    if not rule_ids:
        raise jobs.PermanentJobError("an external LLM run needs rule_ids")
    if branch is None:
        logger.info(f"Branch {job.payload['branch_id']} is not tracked any more, skipped")
        JobProgress(job.id, executor="external", rule_ids=rule_ids).finish("done", items=0)
        return
    from services import llm_work_service
    stats = llm_work_service.prepare_external_run(job.id, branch, rule_ids, mr_id=job.payload.get("mr_id"))
    if stats.get("more"):
        raise jobs.RequeueJob(f"{stats['objects']} objects recorded, more to go")


def llm_prepare_job(job: Job) -> None:
    """The prepare phase of an external LLM run (``executor: external``, selected rules only):
    the model calls are recorded as work items for a model outside the service and the job
    ends; their answers are applied by ``llm_apply`` jobs. No model is called, so it runs on
    the control worker, not behind service runs on the LLM workers."""
    _prepare_external(job)


def llm_score_job(job: Job) -> None:
    """LLM rules on a branch, the model called by the service. ``executor: external``: an
    external run queued before migration 0016 (now ``llm_prepare``), prepared the same way."""
    branch = get_branch_by_id(job.payload["branch_id"])
    rule_ids = job.payload.get("rule_ids")
    executor = job.payload.get("executor") or "service"
    if executor == "external":
        _prepare_external(job)
        return
    progress = JobProgress(job.id, executor="service", rule_ids=rule_ids)
    if job.payload.get("rollout_id"):
        _rollout_slice(job, branch, rule_ids, progress)
        return
    if rule_ids:
        # selected rules only (POST /llm_rules/{id}/run): a main snapshot or an MR source delta
        if branch is None:
            logger.info(f"Branch {job.payload['branch_id']} is not tracked any more, skipped")
            return
        subject = f"LLM rules {sorted(int(r) for r in rule_ids)} on '{branch.project_path}', branch '{branch.branch_name}'"
        ok, error = _llm_run(lambda: run_selected_llm_rules(branch, rule_ids, progress=progress), progress)
        _enqueue_verify(branch.id, rule_ids)
        _raise_llm_failure(ok, error, subject)
        return
    if branch is None or not branch.is_main:
        logger.info(f"Branch {job.payload['branch_id']} is not a tracked main branch any more, skipped")
        return
    subject = f"LLM scoring of '{branch.project_path}', branch '{branch.branch_name}'"
    ok, error = _llm_run(lambda: llm_score_branch(branch, progress=progress), progress)
    _enqueue_verify(branch.id)
    _raise_llm_failure(ok, error, subject)


def _llm_run(run: Callable[[], bool], progress: JobProgress):
    """Run an LLM rule step: ``(ok, error)``; the progress ends ``done`` or ``incomplete`` with the
    summary of what failed (``progress.error``, shown on the job page and the rule's Runs tab)."""
    error: Optional[ScanError] = None
    try:
        ok = bool(run())
    except jobs.RequeueJob:
        raise
    except ScanError as e:
        ok, error = False, e
    progress.finish("done" if ok else "incomplete", **({"error": error.reason} if error is not None else {}))
    return ok, error


def _raise_llm_failure(ok: bool, error: Optional[ScanError], subject: str) -> None:
    if error is not None:
        raise error.as_job_error(subject) from error
    if not ok:
        raise RuntimeError(f"{subject} failed without a recorded reason (see the scanner log)")


def _rollout_slice(job: Job, branch, rule_ids, progress: JobProgress) -> None:
    """A slice of a rule rollout (``services.lifecycle_service``): the stale verdicts of the rule on one main branch
    (at most ``max_objects`` objects, the most useful first), then the slice is counted on the rollout."""
    from services import lifecycle_service
    rollout_id = int(job.payload["rollout_id"])
    progress.base["rollout_id"] = rollout_id
    if lifecycle_service.rollout_status(rollout_id) != "running":
        logger.info(f"Rollout {rollout_id} is not running any more: slice of branch {job.payload['branch_id']} skipped")
        progress.finish("skipped", reason="the rollout is not running")
        return
    if branch is None:
        logger.info(f"Branch {job.payload['branch_id']} is not tracked any more, rollout slice skipped")
        progress.finish("skipped", reason="the branch is not tracked")
        return
    ok, error = _llm_run(lambda: run_selected_llm_rules(
        branch, rule_ids, progress=progress, migration=True,
        max_objects=int(job.payload.get("max_objects") or 0) or None, rollout_id=rollout_id), progress)
    lifecycle_service.slice_done(rollout_id, branch, asked=progress.total,
                                 calls=max(0, progress.done + progress.failed - progress.skipped),
                                 verdicts=progress.done)
    _enqueue_verify(branch.id, rule_ids)
    _raise_llm_failure(ok, error, f"rollout {rollout_id}: LLM rules {sorted(int(r) for r in rule_ids)} on "
                                  f"'{branch.project_path}', branch '{branch.branch_name}'")


def llm_rollout_job(job: Job) -> None:
    """The rule lifecycle controller (``services.lifecycle_service``): sync the rule versions with the scanner's core
    prompts / service model, queue the next slices of the running rollouts within their budget. No model is called."""
    from services import lifecycle_service
    lifecycle_service.run_job(job)


def _enqueue_verify(branch_id: int, rule_ids=None) -> None:
    """After a service LLM run: the tiered workflow's verify items of the branch (``llm_verify``)."""
    try:
        from services import verify_service
        verify_service.enqueue(branch_id, rule_ids)
    except Exception as e:          # best effort: the next run queues it again
        logger.warning(f"Verify job of branch {branch_id} not queued: {e}")


def llm_verify_job(job: Job) -> None:
    """Verify items of a branch for the harness model (``services.verify_service``): service
    need_more_info verdicts, re-verifications and the QA sample. No model is called (control worker)."""
    from services import verify_service
    verify_service.run_job(job)


def llm_apply_job(job: Job) -> None:
    """Apply the submitted answers of an external LLM run (``payload.job_id``: the job that
    prepared it), a bounded slice per call (requeued while answers are left)."""
    from services import llm_work_service
    stats = llm_work_service.apply_answers(int(job.payload["job_id"]))
    if stats.get("more"):
        raise jobs.RequeueJob("more answers to apply")


def llm_trial_job(job: Job) -> None:
    """A prompt trial (``services.trial_service``): a candidate prompt of an LLM rule asked with the service
    model about the trial's subjects; writes only the trial (no hits). Requeued on a graceful stop."""
    from services import trial_service
    trial_service.run_trial(job)


# ---- external parsers ------------------------------------------------------------------------

def ingest_job(job: Job) -> None:
    """Apply the latest pushed state of an external parser (POST /ingest) to its external
    project's snapshot; then the LLM rules when the state asked for it. One job per pushed
    batch: jobs of older batches find the latest one processed and skip."""
    settings = get_settings()
    branch_id, parser = job.payload["branch_id"], job.payload["parser"]
    try:
        with scan_lock(branch_id):
            branch = get_branch_by_id(branch_id)
            if branch is None:
                logger.info(f"Branch {branch_id} is gone, ingest skipped")
                return
            stats = ingest_branch(branch, parser, force=bool(job.payload.get("force")))
    except Exception as e:
        if job.payload.get("batch_id"):
            fail_ingest_batch(job.payload["batch_id"], str(e), final=job.last_attempt)
        raise
    if stats and not stats.get("skipped") and (stats.get("llm") or job.payload.get("llm")) and llm_configured(settings):
        branch = get_branch_by_id(branch_id)
        _enqueue("llm_score", {"branch_id": branch.id, "commit": branch.scanned_commit},
                 f"llm_score:{branch.id}:{branch.scanned_commit}")


# ---- LLM coverage ----------------------------------------------------------------------------

def llm_coverage_job(job: Job) -> None:
    """Recount stale ``llm_coverage`` rows (``services.llm_coverage_service.refresh_stale``), a
    bounded slice per call, requeued while stale rows are left. No model is called."""
    from services import llm_coverage_service
    stats = llm_coverage_service.refresh_stale()
    if stats.get("more"):
        raise jobs.RequeueJob(f"{stats['recounted']} coverage rows recounted, more to go")


# ---- relabel / adopt in slices ---------------------------------------------------------------

RELABEL_SLICES_PER_RUN = 20       # then the job yields (RequeueJob): the other control jobs get their turn


def llm_relabel_job(job: Job) -> None:
    """Relabel (a version that differs only in core prompts / model) or adopt (a rollback) the machine verdicts of
    an LLM rule in slices (``discovery_common.lifecycle.relabel_slice``; queued by ``lifecycle.enqueue_relabel`` from
    the API or the scanner's version sync). Each slice is its own transaction; the job yields after
    ``RELABEL_SLICES_PER_RUN`` slices and on a graceful stop, and ends when a slice changes fewer rows than the
    batch. ``progress``: ``{phase, action, rule_id, to_version, rows, slices, batch}``."""
    from discovery_common import db, lifecycle
    payload = job.payload
    batch = max(1, int(payload.get("batch") or lifecycle.RELABEL_BATCH))
    with db.unit_of_work() as s:
        previous = s.execute(text("SELECT progress FROM jobs WHERE id = :id"), {"id": job.id}).scalar() or {}
    rows_total = int(previous.get("rows") or 0)
    slices_total = int(previous.get("slices") or 0)
    base = {"action": payload["action"], "rule_id": payload["rule_id"], "to_version": payload["to_version"],
            "from_version": payload.get("from_version"), "batch": batch}
    set_progress(job.id, {**base, "phase": "running", "rows": rows_total, "slices": slices_total,
                          **({"started_at": previous.get("started_at")} if previous.get("started_at") else
                             {"started_at": _utcnow().isoformat()})})
    for _ in range(RELABEL_SLICES_PER_RUN):
        with db.unit_of_work() as s:
            changed = lifecycle.relabel_slice(s, payload)
        rows_total += changed
        slices_total += 1
        set_progress(job.id, {"rows": rows_total, "slices": slices_total})
        if changed < batch:
            set_progress(job.id, {"phase": "done", "finished_at": _utcnow().isoformat()})
            logger.info(f"LLM rule {payload['rule_id']}: {payload['action']} to v{payload['to_version']} done, "
                        f"{rows_total} verdicts in {slices_total} slices")
            return
        if jobs.stop_requested():
            raise jobs.stopping(f"{payload['action']} of rule {payload['rule_id']}: {rows_total} verdicts so far")
    raise jobs.RequeueJob(f"{rows_total} verdicts {payload['action']}led so far, more to go")


# ---- statistics snapshots --------------------------------------------------------------------

def stats_refresh_job(job: Job) -> None:
    """Recompute the statistics snapshots (``discovery_common.stats``, table ``stats_snapshots``) the API serves
    instead of aggregating per request; ``progress``: the seconds each snapshot took."""
    from services import stats_service
    timings = stats_service.refresh_all(job_id=job.id)
    set_progress(job.id, {"phase": "done", "seconds": timings, "finished_at": _utcnow().isoformat()})


# ---- GC --------------------------------------------------------------------------------------

def cleanup_job(job: Job) -> None:
    stats = cleanup_service.cleanup()
    if stats is None:
        logger.info("Cleanup job: another process holds the GC lock, nothing to do")


HANDLERS: Dict[str, Callable[[Job], None]] = {
    "sync_projects": sync_projects,
    "sync_branches_mrs": sync_branches_mrs,
    "scan_branch": scan_branch_job,
    "scan_mr": scan_mr_job,
    "llm_score": llm_score_job,
    "llm_prepare": llm_prepare_job,
    "llm_apply": llm_apply_job,
    "ingest": ingest_job,
    "cleanup": cleanup_job,
    "llm_coverage": llm_coverage_job,
    "llm_trial": llm_trial_job,
    "llm_verify": llm_verify_job,
    "llm_rollout": llm_rollout_job,
    "llm_relabel": llm_relabel_job,
    "stats_refresh": stats_refresh_job,
}
