"""Postgres job queue of the scanner (stage 6, P2-4).

Replaces the multiprocessing Manager dicts / queue: the state lives in the ``jobs`` table
(migration ``0004_jobs``), so it survives restarts and any number of worker processes
(or scanner containers) can share it.

* ``enqueue(kind, payload, dedup_key)``: ``INSERT ... ON CONFLICT DO NOTHING`` on the
  partial unique index ``jobs_dedup_active``: at most one *active* (pending / running) job
  per ``dedup_key``; the same key can be queued again once that job is done / failed.
* ``claim(worker_id)``: ``SELECT ... FOR UPDATE SKIP LOCKED LIMIT 1`` on the ready
  pending jobs (``run_after <= now()``, highest ``priority`` first, then the oldest: migration 0026),
  marks it running with a lease (``locked_by``, ``locked_at``) and counts the attempt. Two workers never
  get the same job.
* ``heartbeat``: renews the lease while the job runs (``Worker`` does it from a thread).
* ``reap_expired(lease)``: running jobs whose lease expired (the worker died or hangs)
  go back to pending (or to failed once ``max_attempts`` is used up). The scanner's scheduler
  runs it every few seconds; a ``Worker`` runs it at most every ``reap_every_s`` (default: the
  lease) as a safety net, not on every claim (a claim is one UPDATE).
* ``complete`` / ``fail``: ``fail`` retries with exponential backoff
  (``base * 2 ** (attempts - 1)``, capped) until ``max_attempts``; ``PermanentJobError``
  fails at once. Both only touch the job while the caller still holds its lease. ``last_error``
  is the cause for people (``error_text``: a ``JobError``'s message as is, else
  ``TypeName: message``), credentials stripped.
* ``requeue`` (a handler raises ``RequeueJob``): a long job done in bounded slices goes back
  to pending behind the jobs that are ready already; the attempt is not counted.
* graceful stop (``request_stop`` / ``stop_requested``, set by the worker's SIGTERM handler):
  long handlers check the flag at safe points (an LLM run after storing the verdicts it got, a
  scan between clone / parse / save, the control jobs between slices) and raise ``RequeueJob``
  (``stopping()``), so the work done so far is kept and the job continues on the next worker.

All times are the database's ``now()``, so worker clocks do not matter.
"""

import json
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.types import Text

from discovery_common import db
from discovery_common.log import get_logger
from discovery_common.models import JOB_KINDS
from discovery_common.redact import strip_secrets

logger = get_logger(__name__)

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_LEASE_S = 300.0
DEFAULT_BACKOFF_BASE_S = 30.0
DEFAULT_BACKOFF_MAX_S = 3600.0
ERROR_MAX_LEN = 4000


class JobError(Exception):
    """A handler failure whose message already tells people what went wrong and on what
    (``scan of 'grp/proj', MR !25: cannot clone source branch 'release/x': remote branch not
    found``): ``last_error`` is the message as is, without the exception type in front of it
    (any other exception is recorded as ``TypeName: message``)."""


class PermanentJobError(JobError):
    """Raised by a handler when retrying cannot help: the job fails at once."""


def error_text(exc: BaseException) -> str:
    """The ``last_error`` of a failed attempt: the message of a ``JobError``, else
    ``TypeName: message``; credentials are stripped (``redact.strip_secrets``)."""
    text = str(exc) if isinstance(exc, JobError) else f"{type(exc).__name__}: {exc}"
    return strip_secrets(text)


class RequeueJob(Exception):
    """Raised by a handler that did a bounded slice of a long job and wants to go on later
    (``llm_prepare`` / ``llm_apply`` on the control worker): the job goes back to pending
    (``run_after = now() + delay``, so jobs that were ready earlier run first) without using up
    an attempt. The handler must have saved its progress: the next run starts it afresh."""

    def __init__(self, reason: str = "", delay: float = 0.0):
        super().__init__(reason)
        self.delay = float(delay)


# Graceful stop of this worker process (SIGTERM): the Worker loop stops claiming, and handlers
# that check ``stop_requested()`` hand their job back (``RequeueJob``) at the next safe point.
_STOP = threading.Event()


def stop_event() -> threading.Event:
    return _STOP


def request_stop() -> None:
    _STOP.set()


def stop_requested() -> bool:
    return _STOP.is_set()


def stopping(where: str) -> RequeueJob:
    """The ``RequeueJob`` a handler raises when the worker is stopping (``where``: what was kept)."""
    return RequeueJob(f"stopping: {where}")


@dataclass
class Job:
    id: int
    kind: str
    payload: Dict[str, Any] = field(default_factory=dict)
    dedup_key: Optional[str] = None
    attempts: int = 0
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    locked_by: Optional[str] = None

    @property
    def last_attempt(self) -> bool:
        """True while running the last allowed attempt (a failure now is final)."""
        return self.attempts >= self.max_attempts


def worker_name(slot: Optional[str] = None, pid: Optional[int] = None) -> str:
    """``<host>:<slot>:<pid>``: unique per worker process, readable in ``jobs.locked_by``."""
    return f"{socket.gethostname()}:{slot or 'w'}:{pid or os.getpid()}"


def backoff_delay(attempts: int, base: float = DEFAULT_BACKOFF_BASE_S, cap: float = DEFAULT_BACKOFF_MAX_S) -> float:
    """Delay before the retry that follows attempt number ``attempts`` (1-based)."""
    return float(min(cap, base * (2 ** max(attempts - 1, 0))))


def _check_kind(kind: str) -> None:
    if kind not in JOB_KINDS:
        raise ValueError(f"unknown job kind {kind!r}, expected one of {JOB_KINDS}")


@dataclass
class _Result:
    rows: List[Any]
    rowcount: int

    def first(self):
        return self.rows[0] if self.rows else None

    def all(self):
        return self.rows


def _run(statement, params: Dict[str, Any], conn=None) -> _Result:
    """Execute in ``conn`` (the caller's transaction) or in a transaction of its own; the
    rows are fetched before that transaction ends."""
    def execute(c):
        result = c.execute(statement, params)
        return _Result(result.all() if result.returns_rows else [], result.rowcount)

    if conn is not None:
        return execute(conn)
    with db.get_engine().begin() as own:
        return execute(own)


ENQUEUE_SQL = text("""
    INSERT INTO jobs (kind, payload, dedup_key, max_attempts, run_after, priority)
    VALUES (:kind, CAST(:payload AS jsonb), :dedup_key, :max_attempts, now() + make_interval(secs => :delay), :priority)
    ON CONFLICT (dedup_key) WHERE status IN ('pending', 'running') DO NOTHING
    RETURNING id
""")


def enqueue(kind: str, payload: Optional[Dict[str, Any]] = None, dedup_key: Optional[str] = None, *,
            delay: float = 0.0, max_attempts: int = DEFAULT_MAX_ATTEMPTS, conn=None, priority: int = 0) -> Optional[int]:
    """Queue a job; returns its id, or None when an active job with ``dedup_key`` exists. ``priority``: claimed
    before the ready jobs of a lower one (rule rollout slices -10, prompt trials +5, everything else 0)."""
    _check_kind(kind)
    row = _run(ENQUEUE_SQL, {
        "kind": kind, "payload": json.dumps(payload or {}, default=str), "dedup_key": dedup_key,
        "max_attempts": max(1, int(max_attempts)), "delay": max(0.0, float(delay)), "priority": int(priority),
    }, conn).first()
    return row[0] if row else None


# An ingest job (POST /ingest) that fails without running its handler's except branch (the
# worker was killed / lost its lease on the last attempt) must not leave its batch
# 'committed': the API would answer a repeated push of the same state "unchanged" and never
# apply it. Jobs that end up failed here mark their committed batch failed too.
_FAIL_INGEST_BATCHES = """
    failed_batches AS (
        UPDATE ingest_batches b SET status = 'failed', error = r.last_error
        FROM {jobs} r
        WHERE r.kind = 'ingest' AND r.status = 'failed' AND b.status = 'committed'
          AND b.id::text = r.payload->>'batch_id')"""

REAP_SQL = text("""
    WITH reaped AS (
        UPDATE jobs SET
            status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'pending' END,
            finished_at = CASE WHEN attempts >= max_attempts THEN now() END,
            last_error = 'lease expired (worker ' || COALESCE(locked_by, '?') || ')',
            locked_by = NULL, locked_at = NULL, run_after = now(), updated_at = now()
        WHERE status = 'running' AND locked_at < now() - make_interval(secs => :lease)
        RETURNING id, kind, status, payload, last_error),""" + _FAIL_INGEST_BATCHES.format(jobs="reaped") + """
    SELECT id, kind, status FROM reaped
""")


def reap_expired(lease_seconds: float = DEFAULT_LEASE_S, conn=None) -> int:
    """Running jobs with an expired lease -> pending again (failed after the last attempt)."""
    rows = _run(REAP_SQL, {"lease": float(lease_seconds)}, conn).all()
    for row in rows:
        logger.warning(f"Job {row.id} ({row.kind}): lease expired, now {row.status}")
    return len(rows)


RELEASE_SQL = text("""
    WITH released AS (
        UPDATE jobs SET
            status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'pending' END,
            finished_at = CASE WHEN attempts >= max_attempts THEN now() END,
            last_error = :error, locked_by = NULL, locked_at = NULL, run_after = now(), updated_at = now()
        WHERE status = 'running' AND locked_by = ANY(:workers)
        RETURNING id, kind, status, payload, last_error),""" + _FAIL_INGEST_BATCHES.format(jobs="released") + """
    SELECT id FROM released
""").bindparams(bindparam("workers", type_=ARRAY(Text)))


def release_worker_jobs(worker_ids: Iterable[str], error: str, conn=None) -> int:
    """Jobs of workers known to be dead (the supervisor saw them exit): back to pending
    now instead of after the lease timeout."""
    workers = list(worker_ids)
    if not workers:
        return 0
    return len(_run(RELEASE_SQL, {"workers": workers, "error": strip_secrets(error)[:ERROR_MAX_LEN]}, conn).all())


CLAIM_SQL = text("""
    UPDATE jobs SET status = 'running', attempts = attempts + 1, locked_by = :worker,
                    locked_at = now(), started_at = now(), updated_at = now()
    WHERE id = (
        SELECT id FROM jobs
        WHERE status = 'pending' AND run_after <= now() AND (CAST(:kinds AS text[]) IS NULL OR kind = ANY(:kinds))
        ORDER BY priority DESC, run_after, id
        LIMIT 1
        FOR UPDATE SKIP LOCKED)
    RETURNING id, kind, payload, dedup_key, attempts, max_attempts, locked_by
""").bindparams(bindparam("kinds", type_=ARRAY(Text)))


def claim(worker_id: str, kinds: Optional[Sequence[str]] = None,
          lease_seconds: Optional[float] = DEFAULT_LEASE_S) -> Optional[Job]:
    """Take the next ready job (of ``kinds``, default any) or None. Expired leases are
    reaped first (``lease_seconds=None`` skips that; the ``Worker`` loop does, it reaps on
    its own schedule). ``started_at`` records the claim (migration 0031) and stays on the row."""
    if lease_seconds is not None:
        reap_expired(lease_seconds)
    row = _run(CLAIM_SQL, {"worker": worker_id, "kinds": list(kinds) if kinds else None}).first()
    if row is None:
        return None
    return Job(id=row.id, kind=row.kind, payload=dict(row.payload or {}), dedup_key=row.dedup_key,
               attempts=row.attempts, max_attempts=row.max_attempts, locked_by=row.locked_by)


HEARTBEAT_SQL = text("""
    UPDATE jobs SET locked_at = now(), updated_at = now()
    WHERE id = :id AND status = 'running' AND locked_by = :worker
""")


def heartbeat(job_id: int, worker_id: str) -> bool:
    """Renew the lease; False when the job is no longer ours (lease expired and reaped)."""
    return _run(HEARTBEAT_SQL, {"id": job_id, "worker": worker_id}).rowcount == 1


COMPLETE_SQL = text("""
    UPDATE jobs SET status = 'done', finished_at = now(), updated_at = now(), locked_by = NULL, locked_at = NULL,
                    last_error = NULL
    WHERE id = :id AND status = 'running' AND locked_by = :worker
""")


def complete(job_id: int, worker_id: str) -> bool:
    ok = _run(COMPLETE_SQL, {"id": job_id, "worker": worker_id}).rowcount == 1
    if not ok:
        logger.warning(f"Job {job_id}: completed by {worker_id} after its lease was lost")
    return ok


FAIL_SQL = text("""
    UPDATE jobs SET
        status = CASE WHEN :retry AND attempts < max_attempts THEN 'pending' ELSE 'failed' END,
        run_after = CASE WHEN :retry AND attempts < max_attempts
                         THEN now() + make_interval(secs => :delay) ELSE run_after END,
        finished_at = CASE WHEN :retry AND attempts < max_attempts THEN NULL ELSE now() END,
        last_error = :error, locked_by = NULL, locked_at = NULL, updated_at = now()
    WHERE id = :id AND status = 'running' AND locked_by = :worker
    RETURNING status, attempts, run_after
""")


def fail(job_id: int, worker_id: str, error: str, *, retry: bool = True, attempts: Optional[int] = None,
         backoff_base: float = DEFAULT_BACKOFF_BASE_S, backoff_max: float = DEFAULT_BACKOFF_MAX_S) -> Optional[str]:
    """Record a failed attempt: back to pending after the backoff delay, or ``failed`` when
    ``retry`` is False or the attempts are used up. Returns the new status (None when the
    lease was lost)."""
    delay = backoff_delay(attempts or 1, backoff_base, backoff_max)
    row = _run(FAIL_SQL, {"id": job_id, "worker": worker_id, "error": strip_secrets(error or "")[:ERROR_MAX_LEN],
                          "retry": bool(retry), "delay": delay}).first()
    if row is None:
        logger.warning(f"Job {job_id}: failure reported by {worker_id} after its lease was lost")
        return None
    return row.status


REQUEUE_SQL = text("""
    UPDATE jobs SET status = 'pending', attempts = GREATEST(attempts - 1, 0),
                    run_after = now() + make_interval(secs => :delay), locked_by = NULL, locked_at = NULL,
                    last_error = NULL, updated_at = now()
    WHERE id = :id AND status = 'running' AND locked_by = :worker
""")


def requeue(job_id: int, worker_id: str, delay: float = 0.0) -> bool:
    """Put a running job back to pending (``RequeueJob``); the attempt is not counted."""
    ok = _run(REQUEUE_SQL, {"id": job_id, "worker": worker_id, "delay": max(0.0, float(delay))}).rowcount == 1
    if not ok:
        logger.warning(f"Job {job_id}: requeued by {worker_id} after its lease was lost")
    return ok


# Done / failed jobs finished more than :days ago, :batch per run (cleanup_service). The
# newest job of every kind is kept (the scheduler reads it), so is an external LLM run with
# open work items.
PURGE_SQL = text("""
    DELETE FROM jobs WHERE id IN (
        SELECT j.id FROM jobs j
        WHERE j.status IN ('done', 'failed') AND j.finished_at < now() - make_interval(days => :days)
          AND j.id NOT IN (SELECT max(id) FROM jobs GROUP BY kind)
          AND NOT EXISTS (SELECT 1 FROM llm_work_items w
                          WHERE w.job_id = j.id AND w.status IN ('pending', 'leased', 'answered'))
        LIMIT :batch)
""")


# ``run_after`` (when the job was due), not ``created_at``: a job queued with a delay (the
# first cleanup runs one interval after start-up) would otherwise look "old" as soon as it
# finished and be scheduled again at once.
DUE_SQL = text("""
    SELECT max(run_after) IS NULL AS never,
           bool_or(status IN ('pending', 'running')) AS active,
           max(run_after) < now() - make_interval(secs => :interval) AS old
    FROM jobs WHERE kind = :kind
""")


def due(kind: str, interval_seconds: float, conn=None) -> Optional[bool]:
    """Periodic scheduling without local state: True when no job of ``kind`` is active and
    the last one was due (``run_after``) more than ``interval_seconds`` ago; None when there was never
    one (the caller decides what the first run is)."""
    row = _run(DUE_SQL, {"kind": kind, "interval": float(interval_seconds)}, conn).first()
    if row.never:
        return None
    return bool(not row.active and row.old)


def counts(conn=None) -> Dict[str, Dict[str, int]]:
    """``{kind: {status: count}}`` for logs and health checks."""
    result: Dict[str, Dict[str, int]] = {}
    for row in _run(text("SELECT kind, status, count(*) AS n FROM jobs GROUP BY kind, status"), {}, conn).rows:
        result.setdefault(row.kind, {})[row.status] = row.n
    return result


# ---------------------------------------------------------------------------------------------
# Worker loop
# ---------------------------------------------------------------------------------------------

Handler = Callable[[Job], Any]


class _Heartbeat(threading.Thread):
    """Renews the lease of a running job every ``interval`` seconds."""

    def __init__(self, job: Job, worker_id: str, interval: float):
        super().__init__(name=f"heartbeat-{job.id}", daemon=True)
        self.job, self.worker_id, self.interval = job, worker_id, interval
        self.stopped = threading.Event()
        self.lost = False

    def run(self):
        while not self.stopped.wait(self.interval):
            try:
                if not heartbeat(self.job.id, self.worker_id):
                    self.lost = True
                    logger.warning(f"Job {self.job.id} ({self.job.kind}): lease lost, another worker may run it")
                    return
            except Exception as e:      # DB hiccup: try again on the next beat
                logger.warning(f"Job {self.job.id}: heartbeat failed: {e}")

    def stop(self):
        self.stopped.set()
        self.join(timeout=5)


@dataclass
class WorkerConfig:
    kinds: Optional[List[str]] = None             # None: every kind
    lease_seconds: float = DEFAULT_LEASE_S
    heartbeat_seconds: Optional[float] = None     # default: lease / 3
    poll_seconds: float = 2.0
    backoff_base: float = DEFAULT_BACKOFF_BASE_S
    backoff_max: float = DEFAULT_BACKOFF_MAX_S
    # expired leases are reaped by this worker at most this often (default: the lease); the scanner's scheduler
    # reaps every few seconds anyway, so this is a safety net for deployments without one. 0: never here.
    reap_every_s: Optional[float] = None


class Worker:
    """Claims and runs jobs until ``stop`` is set. A handler returning normally completes
    the job; an exception is a failed attempt (retried with backoff), ``PermanentJobError``
    or an unknown kind fails it at once. ``around`` wraps every handler call (the scanner
    uses it for the per-job workspace)."""

    def __init__(self, worker_id: str, handlers: Dict[str, Handler], config: Optional[WorkerConfig] = None,
                 around: Optional[Callable[[Job, Callable[[], Any]], Any]] = None):
        self.worker_id = worker_id
        self.handlers = handlers
        self.config = config or WorkerConfig()
        self.around = around
        self._next_reap = 0.0           # the first claim reaps (a restarted scanner finds its dead workers' jobs)

    def _reap_if_due(self) -> None:
        every = self.config.reap_every_s
        if every is None:
            every = self.config.lease_seconds
        if every <= 0:
            return
        now = time.monotonic()
        if now < self._next_reap:
            return
        self._next_reap = now + every
        reap_expired(self.config.lease_seconds)

    def run_once(self) -> Optional[str]:
        """Claim and run one job: returns the job's resulting status, None when idle."""
        config = self.config
        self._reap_if_due()
        job = claim(self.worker_id, config.kinds, lease_seconds=None)
        if job is None:
            return None

        logger.info(f"Job {job.id} ({job.kind}) attempt {job.attempts}/{job.max_attempts} started by "
                    f"{self.worker_id}: {job.payload}")
        started = time.monotonic()
        beat = _Heartbeat(job, self.worker_id, config.heartbeat_seconds or max(config.lease_seconds / 3, 0.1))
        beat.start()
        try:
            handler = self.handlers.get(job.kind)
            if handler is None:
                raise PermanentJobError(f"no handler for job kind {job.kind!r}")
            if self.around is not None:
                self.around(job, lambda: handler(job))
            else:
                handler(job)
        except RequeueJob as e:
            beat.stop()
            if str(e).startswith("stopping"):
                logger.info(f"stopping: job {job.id} ({job.kind}) requeued after {time.monotonic() - started:.1f}s "
                            f"({str(e)[len('stopping: '):]})")
            else:
                logger.info(f"Job {job.id} ({job.kind}) yields after {time.monotonic() - started:.1f}s, requeued: {e}")
            return "pending" if requeue(job.id, self.worker_id, e.delay) else None
        except PermanentJobError as e:
            beat.stop()
            logger.error(f"Job {job.id} ({job.kind}) failed permanently: {error_text(e)}")
            return fail(job.id, self.worker_id, error_text(e), retry=False, attempts=job.attempts)
        except Exception as e:
            beat.stop()
            status = fail(job.id, self.worker_id, error_text(e), attempts=job.attempts,
                          backoff_base=config.backoff_base, backoff_max=config.backoff_max)
            logger.error(f"Job {job.id} ({job.kind}) attempt {job.attempts}/{job.max_attempts} failed "
                         f"({'will retry' if status == 'pending' else status}): {error_text(e)}")
            return status
        beat.stop()
        complete(job.id, self.worker_id)
        logger.info(f"Job {job.id} ({job.kind}) done in {time.monotonic() - started:.1f}s")
        return "done"

    def run(self, stop: threading.Event) -> None:
        """Loop until ``stop`` is set (checked between jobs; a running job is finished)."""
        logger.info(f"Worker {self.worker_id} started (kinds: {self.config.kinds or 'all'})")
        while not stop.is_set():
            try:
                status = self.run_once()
            except Exception as e:          # DB unavailable etc.: back off, keep the worker alive
                logger.error(f"Worker {self.worker_id}: queue error: {e}")
                status = None
            if status is None:
                stop.wait(self.config.poll_seconds)
        logger.info(f"Worker {self.worker_id} stopped")
