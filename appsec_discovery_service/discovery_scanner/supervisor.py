"""Scanner process model (P2-4): a supervisor, a scheduler and worker processes around the
Postgres job queue (``discovery_common.jobs``).

* Worker pools (one OS process per worker, started with the ``spawn`` method so no DB
  connection or GitLab session is inherited):
    - ``sync``    x SYNC_WORKERS    sync_projects, sync_branches_mrs: the GitLab polling (no webhooks). A sync of
                                   a project takes seconds to minutes of GitLab calls, thousands of projects: its
                                   own pool, so nothing else waits behind it.
    - ``control`` x CONTROL_WORKERS the jobs that call no model and must run promptly: llm_verify (verify items of
                                   the tiered workflow for a harness model), llm_prepare / llm_apply (the two
                                   phases of external LLM runs: record the work items, apply the answers),
                                   llm_coverage (recount stale LLM coverage rows), llm_rollout (the LLM rule
                                   lifecycle controller: rule versions vs core prompts / model, rollout slices),
                                   llm_relabel (relabel / adopt of verdicts in slices), stats_refresh (the
                                   statistics snapshots), cleanup. They work in bounded slices and requeue
                                   themselves, so one of them does not hold up the others for long.
    - ``scan``    x MAX_WORKERS     scan_branch, scan_mr, ingest (scans in their own mkdtemp workspace)
    - ``llm``     x LLM_WORKERS     llm_score (service runs: the scanner calls its LLM API) and llm_trial
                                   (prompt trials: a candidate prompt on a few subjects, service model, no hits)
* ``Scheduler`` (runs in the supervisor process) enqueues the periodic jobs: GitLab polling
  (``sync_projects`` every PROJECTS_POLL_INTERVAL_S, a full sync first after start-up),
  ``cleanup`` every GC_INTERVAL_HOURS (first one an interval after the first start),
  ``llm_coverage`` every LLM_COVERAGE_INTERVAL_S (the first one at start-up), ``llm_rollout`` every
  LLM_ROLLOUT_TICK_S, ``stats_refresh`` every STATS_REFRESH_S; and reaps expired job leases (the workers
  do not, on their claims). It reads the last job of the kind from the table, so restarts do not reset
  the schedule and several scanner replicas do not double it (dedup keys). No GitLab webhooks.
* ``Supervisor``: restarts crashed workers (with a backoff when they crash right after
  start), puts the jobs of a dead worker back to pending at once and removes its leftover
  workspaces; SIGTERM / SIGINT stop the workers gracefully: each worker sets its stop flag
  (``jobs.request_stop``), the running job hands itself back at its next safe point (an LLM run
  after storing the verdicts of the objects asked so far, a scan before clone / parse / save,
  llm_prepare / llm_apply / llm_coverage at a slice boundary) and is requeued without using an
  attempt; a worker still busy after SHUTDOWN_TIMEOUT_S is killed and its job re-queued.
"""

import multiprocessing as mp
import signal
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from pydantic import ValidationError

from discovery_common import jobs, llm_work
from config import ScannerSettings, format_settings_error, get_settings
from logger import get_logger

logger = get_logger(__name__)

SYNC_KINDS = ["sync_projects", "sync_branches_mrs"]
CONTROL_KINDS = ["llm_verify", "llm_apply", "llm_prepare", "llm_coverage", "llm_rollout", "llm_relabel",
                 "stats_refresh", "cleanup"]
SCAN_KINDS = ["scan_branch", "scan_mr", "ingest"]
LLM_KINDS = ["llm_score", "llm_trial"]
POOL_KINDS = {"sync": SYNC_KINDS, "control": CONTROL_KINDS, "scan": SCAN_KINDS, "llm": LLM_KINDS}

SYNC_KEY = "sync_projects"
# The full sync after start-up has a key of its own: a regular sync left pending by the
# previous run would otherwise swallow it (dedup) and the "full" flag would be lost.
FULL_SYNC_KEY = "sync_projects:full"
CLEANUP_KEY = "cleanup"
COVERAGE_KEY = "llm_coverage"
ROLLOUT_KEY = "llm_rollout"
STATS_KEY = "stats_refresh"


@dataclass(frozen=True)
class WorkerSpec:
    pool: str
    slot: int
    kinds: Tuple[str, ...]

    @property
    def name(self) -> str:
        return f"{self.pool}-{self.slot}"


def pool_sizes(settings: ScannerSettings) -> Dict[str, int]:
    """Workers per pool from the settings (SYNC_WORKERS, CONTROL_WORKERS, MAX_WORKERS, LLM_WORKERS)."""
    return {"sync": settings.sync_workers, "control": settings.control_workers, "scan": settings.max_workers,
            "llm": settings.llm_workers}


def worker_specs(settings: ScannerSettings) -> List[WorkerSpec]:
    specs = []
    for pool, count in pool_sizes(settings).items():
        specs += [WorkerSpec(pool, i, tuple(POOL_KINDS[pool])) for i in range(count)]
    return specs


def worker_config(settings: ScannerSettings, kinds) -> jobs.WorkerConfig:
    return jobs.WorkerConfig(
        kinds=list(kinds), lease_seconds=settings.job_lease_s, poll_seconds=settings.job_poll_s,
        backoff_base=settings.job_backoff_base_s, backoff_max=settings.job_backoff_max_s,
    )


# ---------------------------------------------------------------------------------------------
# Worker process
# ---------------------------------------------------------------------------------------------

def run_in_workspace(settings: ScannerSettings):
    """``Worker.around``: scan jobs run in their own mkdtemp workspace, removed afterwards."""
    from services.job_handlers import WORKSPACE_KINDS
    from services.workspace import job_workspace

    def around(job, call):
        if job.kind not in WORKSPACE_KINDS:
            return call()
        with job_workspace(job.id, settings.workspace_dir):
            return call()

    return around


def worker_main(spec: WorkerSpec) -> None:
    """Entry point of a worker process."""
    try:
        settings = get_settings()
    except ValidationError as e:
        logger.error(f"Invalid scanner configuration (check env variables):\n{format_settings_error(e)}")
        sys.exit(2)

    from services.db_service import configure as configure_db
    from services.job_handlers import HANDLERS

    configure_db()

    # the flag the running job's handler checks too (``jobs.stop_requested``): an LLM run hands its
    # job back after storing the verdicts it got, a scan at its next phase boundary, the control
    # jobs at their next slice boundary (``RequeueJob``, no attempt used)
    stop = jobs.stop_event()

    def on_signal(signum, frame):
        logger.info(f"Worker {spec.name}: signal {signum}, stopping: the running job is requeued at its next safe point")
        jobs.request_stop()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    worker = jobs.Worker(jobs.worker_name(spec.name), HANDLERS, worker_config(settings, spec.kinds),
                         around=run_in_workspace(settings))
    worker.run(stop)


# ---------------------------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------------------------

class Scheduler:
    """Enqueues the periodic jobs; ``tick()`` is cheap and called every second or so, the
    queue is looked at every ``every`` seconds."""

    def __init__(self, settings: ScannerSettings, every: float = 10.0, clock: Callable[[], float] = time.monotonic):
        self.settings = settings
        self.every = every
        self.clock = clock
        self.next_tick = clock()
        self.started = False

    def _enqueue(self, kind, payload, key, delay=0.0):
        job_id = jobs.enqueue(kind, payload, key, delay=delay, max_attempts=self.settings.job_max_attempts)
        if job_id is not None:
            logger.info(f"Scheduled {kind} job {job_id}" + (f" in {delay:.0f}s" if delay else ""))
        return job_id

    def tick(self) -> None:
        if self.clock() < self.next_tick:
            return
        self.next_tick = self.clock() + self.every
        settings = self.settings

        jobs.reap_expired(settings.job_lease_s)

        if not self.started:
            # first sync after start-up looks at every project (was update_projects' first run)
            self._enqueue("sync_projects", {"full": True}, FULL_SYNC_KEY)
            self.started = True
        elif jobs.due("sync_projects", settings.projects_poll_interval_s) is not False:
            self._enqueue("sync_projects", {}, SYNC_KEY)

        # answers of external LLM runs whose llm_apply job was not queued (it was running when
        # they were submitted): the submit queues one, this is the safety net
        try:
            for job_id in llm_work.enqueue_missing_applies(max_attempts=settings.job_max_attempts):
                logger.info(f"Scheduled llm_apply job {job_id}")
        except Exception as e:
            logger.warning(f"Scheduler: answered LLM work items not checked: {e}")

        # LLM coverage rows left stale (a rule edit, new core prompts, a missed recount): the job
        # recounts them in slices; nothing stale makes it a no-op
        if settings.llm_coverage_interval_s > 0 and jobs.due("llm_coverage", settings.llm_coverage_interval_s) is not False:
            self._enqueue("llm_coverage", {}, COVERAGE_KEY)

        # the rule lifecycle controller: rule versions vs the core prompts / service model (a deploy), the next
        # slices of the running rule rollouts (the first one at start-up)
        if settings.llm_rollout_tick_s > 0 and jobs.due("llm_rollout", settings.llm_rollout_tick_s) is not False:
            self._enqueue("llm_rollout", {}, ROLLOUT_KEY)

        # the statistics snapshots the API serves (discovery_common.stats): the first one at start-up
        if settings.stats_refresh_s > 0 and jobs.due("stats_refresh", settings.stats_refresh_s) is not False:
            self._enqueue("stats_refresh", {}, STATS_KEY)

        if settings.gc_interval_hours > 0:
            interval = settings.gc_interval_hours * 3600
            state = jobs.due("cleanup", interval)
            if state is None:           # never ran: first run one interval from now (as before)
                self._enqueue("cleanup", {}, CLEANUP_KEY, delay=interval)
            elif state:
                self._enqueue("cleanup", {}, CLEANUP_KEY)


# ---------------------------------------------------------------------------------------------
# Supervisor
# ---------------------------------------------------------------------------------------------

@dataclass
class _Slot:
    spec: WorkerSpec
    process: Optional[mp.process.BaseProcess] = None
    started_at: float = 0.0
    failures: int = 0
    next_start: float = 0.0
    restarts: int = 0


class Supervisor:

    QUICK_CRASH_S = 30.0       # a worker that dies sooner is restarted with a growing delay
    MAX_RESTART_DELAY_S = 60.0

    def __init__(self, settings: ScannerSettings, specs: Optional[List[WorkerSpec]] = None,
                 target: Callable = worker_main, scheduler: Optional[Scheduler] = None,
                 context: Optional[mp.context.BaseContext] = None, clock: Callable[[], float] = time.monotonic,
                 loop_seconds: float = 1.0):
        self.settings = settings
        self.target = target
        self.scheduler = scheduler
        self.context = context or mp.get_context("spawn")
        self.clock = clock
        self.loop_seconds = loop_seconds
        self.slots: Dict[str, _Slot] = {spec.name: _Slot(spec) for spec in (specs or worker_specs(settings))}
        self.stop = threading.Event()

    # -- process management ------------------------------------------------------------------

    def _start(self, slot: _Slot) -> None:
        process = self.context.Process(target=self.target, args=(slot.spec,), name=f"worker-{slot.spec.name}")
        process.start()
        slot.process, slot.started_at = process, self.clock()
        logger.info(f"Started worker {slot.spec.name} (pid {process.pid}, kinds {', '.join(slot.spec.kinds)})")

    def _reap(self, slot: _Slot, reason: str) -> None:
        """Bookkeeping for a worker process that is gone: re-queue its job, remove its workspaces."""
        process = slot.process
        worker_id = jobs.worker_name(slot.spec.name, process.pid)
        try:
            released = jobs.release_worker_jobs([worker_id], f"worker {worker_id} {reason}")
            if released:
                logger.warning(f"Re-queued {released} job(s) of worker {worker_id}")
        except Exception as e:    # the lease timeout re-queues them anyway
            logger.error(f"Cannot re-queue the jobs of worker {worker_id}: {e}")
        try:
            from services.workspace import remove_leftovers
            remove_leftovers(process.pid, self.settings.workspace_dir)
        except Exception as e:
            logger.error(f"Cannot remove the workspaces of worker {worker_id}: {e}")

    def check_workers(self) -> None:
        """Start missing workers, restart dead ones (with a backoff on quick crashes)."""
        now = self.clock()
        for slot in self.slots.values():
            process = slot.process
            if process is not None and process.is_alive():
                continue
            if process is not None:
                process.join(0)
                code = process.exitcode
                logger.error(f"Worker {slot.spec.name} (pid {process.pid}) exited with code {code}")
                self._reap(slot, f"exited with code {code}")
                if now - slot.started_at < self.QUICK_CRASH_S:
                    slot.failures += 1
                else:
                    slot.failures = 0
                delay = min(self.MAX_RESTART_DELAY_S, 2 ** slot.failures) if slot.failures else 0.0
                slot.next_start = now + delay
                slot.process = None
                if delay:
                    logger.info(f"Restarting worker {slot.spec.name} in {delay:.0f}s")
            if now >= slot.next_start:
                if slot.started_at:
                    slot.restarts += 1
                self._start(slot)

    def shutdown(self, timeout: Optional[float] = None) -> None:
        """SIGTERM every worker, wait up to ``timeout`` for the running jobs, then kill."""
        timeout = self.settings.shutdown_timeout_s if timeout is None else timeout
        running = [slot for slot in self.slots.values() if slot.process is not None and slot.process.is_alive()]
        logger.info(f"Stopping {len(running)} workers (waiting up to {timeout:.0f}s for running jobs)")
        for slot in running:
            slot.process.terminate()
        deadline = time.monotonic() + timeout
        for slot in running:
            slot.process.join(max(0.0, deadline - time.monotonic()))
        for slot in running:
            if slot.process.is_alive():
                logger.warning(f"Worker {slot.spec.name} (pid {slot.process.pid}) did not stop in time, killing it")
                slot.process.kill()
                slot.process.join(5)
                self._reap(slot, "killed at shutdown")
            elif slot.process.exitcode not in (0, None):
                self._reap(slot, f"exited with code {slot.process.exitcode}")

    # -- main loop -----------------------------------------------------------------------------

    def request_stop(self, signum=None, frame=None) -> None:
        if not self.stop.is_set():
            logger.info(f"Supervisor: signal {signum}, shutting down")
        self.stop.set()

    def run(self, install_signals: bool = True) -> None:
        if install_signals:
            signal.signal(signal.SIGTERM, self.request_stop)
            signal.signal(signal.SIGINT, self.request_stop)

        try:
            from services.workspace import remove_leftovers
            remove_leftovers(None, self.settings.workspace_dir)     # no worker runs yet
        except Exception as e:
            logger.error(f"Cannot clean the workspace directory: {e}")

        try:
            while not self.stop.is_set():
                self.check_workers()
                if self.scheduler is not None:
                    try:
                        self.scheduler.tick()
                    except Exception as e:
                        logger.error(f"Scheduler error: {e}")
                self.stop.wait(self.loop_seconds)
        finally:
            self.shutdown()
