"""Job queue (P2-4) against a real Postgres: exclusive claims (SKIP LOCKED), dedup among
active jobs, retries with backoff, lease expiry of killed workers, worker loop."""

import multiprocessing as mp
import os
import signal
import threading
import time

import pytest
from sqlalchemy import create_engine, text

from discovery_common import db, jobs, testing


@pytest.fixture
def queue(pg_url):
    testing.migrate(pg_url)
    db.configure(pg_url)
    try:
        yield pg_url
    finally:
        db.configure(None)


def q(sql, **params):
    with db.get_engine().begin() as conn:
        result = conn.execute(text(sql), params)
        return result.all() if result.returns_rows else result.rowcount


def make_ready(job_id):
    q("UPDATE jobs SET run_after = now() WHERE id = :id", id=job_id)


# ---- enqueue / dedup -------------------------------------------------------------------------

def test_dedup_among_active_jobs(queue):
    first = jobs.enqueue("scan_branch", {"branch_id": 1}, "scan_branch:1:c1")
    assert first is not None
    assert jobs.enqueue("scan_branch", {"branch_id": 1}, "scan_branch:1:c1") is None      # pending
    other = jobs.enqueue("scan_branch", {"branch_id": 1}, "scan_branch:1:c2")             # new commit
    assert other not in (None, first)

    job = jobs.claim("w1")
    assert job.id == first and job.payload == {"branch_id": 1} and job.attempts == 1
    assert jobs.enqueue("scan_branch", {"branch_id": 1}, "scan_branch:1:c1") is None      # running

    assert jobs.complete(job.id, "w1") is True
    again = jobs.enqueue("scan_branch", {"branch_id": 1}, "scan_branch:1:c1")             # finished: allowed
    assert again not in (None, first)

    # no dedup key: never deduplicated
    assert jobs.enqueue("cleanup") and jobs.enqueue("cleanup")
    with pytest.raises(ValueError):
        jobs.enqueue("nope")


def test_dedup_holds_under_concurrent_enqueue(queue):
    ids, barrier = [], threading.Barrier(8)

    def enqueue():
        barrier.wait()
        ids.append(jobs.enqueue("sync_branches_mrs", {"project_id": 5}, "sync_branches_mrs:5"))

    threads = [threading.Thread(target=enqueue) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len([i for i in ids if i is not None]) == 1
    assert q("SELECT count(*) FROM jobs")[0][0] == 1


# ---- claim -----------------------------------------------------------------------------------

def test_two_workers_never_take_the_same_job(queue):
    total = 120
    for i in range(total):
        jobs.enqueue("scan_mr", {"mr_id": i}, f"scan_mr:{i}")

    taken = {}
    barrier = threading.Barrier(6)

    def work(name):
        barrier.wait()
        mine = taken.setdefault(name, [])
        while True:
            job = jobs.claim(name)
            if job is None:
                return
            mine.append(job.id)
            jobs.complete(job.id, name)

    threads = [threading.Thread(target=work, args=(f"w{i}",)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    all_ids = [job_id for ids in taken.values() for job_id in ids]
    assert len(all_ids) == total and len(set(all_ids)) == total
    assert sum(1 for ids in taken.values() if ids) > 1                      # really concurrent
    assert q("SELECT status, count(*) FROM jobs GROUP BY status") == [("done", total)]


def test_claim_skips_locked_rows_and_respects_run_after_and_kinds(queue):
    first = jobs.enqueue("scan_branch", {}, "a")
    second = jobs.enqueue("scan_branch", {}, "b")
    jobs.enqueue("scan_branch", {}, "later", delay=3600)
    llm = jobs.enqueue("llm_score", {}, "llm")

    engine = create_engine(queue)
    with engine.connect() as other:
        tx = other.begin()
        other.execute(text("SELECT id FROM jobs WHERE id = :id FOR UPDATE"), {"id": first})   # being claimed
        assert jobs.claim("w1", kinds=["scan_branch"]).id == second                       # skipped, not blocked
        assert jobs.claim("w2", kinds=["scan_branch"]) is None                            # 'later' is not ready
        tx.rollback()
    engine.dispose()

    assert jobs.claim("w3", kinds=["llm_score"]).id == llm
    assert jobs.claim("w4").id == first


# ---- retries / backoff -----------------------------------------------------------------------

def test_backoff_delay():
    assert [jobs.backoff_delay(n, 30, 3600) for n in (1, 2, 3, 4)] == [30, 60, 120, 240]
    assert jobs.backoff_delay(20, 30, 3600) == 3600


def test_failed_attempts_are_retried_with_backoff_until_max_attempts(queue):
    job_id = jobs.enqueue("scan_branch", {"branch_id": 1}, "scan_branch:1", max_attempts=3)
    calls = []

    def boom(job):
        calls.append(job.attempts)
        raise RuntimeError(f"clone failed #{job.attempts}")

    worker = jobs.Worker("w1", {"scan_branch": boom}, jobs.WorkerConfig(backoff_base=10, backoff_max=100))

    assert worker.run_once() == "pending"
    (status, attempts, error, wait), = q("SELECT status, attempts, last_error, "
                                         "extract(epoch FROM run_after - now()) FROM jobs WHERE id = :id", id=job_id)
    assert (status, attempts, error) == ("pending", 1, "RuntimeError: clone failed #1")
    assert 8 < wait <= 10                                    # base * 2**0
    assert worker.run_once() is None                         # not ready yet: backoff

    make_ready(job_id)
    assert worker.run_once() == "pending"
    wait = q("SELECT extract(epoch FROM run_after - now()) FROM jobs WHERE id = :id", id=job_id)[0][0]
    assert 18 < wait <= 20                                   # base * 2**1

    make_ready(job_id)
    assert worker.run_once() == "failed"                     # third and last attempt
    assert calls == [1, 2, 3]
    assert q("SELECT status, attempts, finished_at IS NOT NULL, locked_by FROM jobs WHERE id = :id", id=job_id) == [
        ("failed", 3, True, None)]

    # the dedup key is free again
    assert jobs.enqueue("scan_branch", {"branch_id": 1}, "scan_branch:1") is not None


def test_permanent_errors_and_unknown_handlers_fail_at_once(queue):
    def permanent(job):
        raise jobs.PermanentJobError("branch is gone")

    worker = jobs.Worker("w1", {"scan_branch": permanent})
    jobs.enqueue("scan_branch", {}, "x")
    assert worker.run_once() == "failed"
    jobs.enqueue("llm_score", {}, "y")
    assert worker.run_once() == "failed"
    # a JobError's message is the last_error as is (it names subject and cause); no type prefix
    assert sorted(r[0] for r in q("SELECT last_error FROM jobs")) == [
        "branch is gone", "no handler for job kind 'llm_score'"]


def test_last_error_never_holds_credentials(queue):
    """``fail`` strips URL userinfo / tokens from any error text, whatever the handler put in it."""
    def leaky(job):
        raise RuntimeError("git clone https://git:glpat-abcdefgh12345678@gitlab.example/grp/proj.git failed: "
                           "Authorization: Basic Z2l0OnNlY3JldA== rejected")

    worker = jobs.Worker("w1", {"scan_branch": leaky})
    jobs.enqueue("scan_branch", {}, "x", max_attempts=1)
    assert worker.run_once() == "failed"
    (error,), = q("SELECT last_error FROM jobs")
    assert error == "RuntimeError: git clone https://***@gitlab.example/grp/proj.git failed: Authorization: Basic *** rejected"
    assert jobs.release_worker_jobs(["w1"], "worker died: token glpat-abcdefgh12345678") == 0     # nothing running


def test_requeued_job_goes_behind_ready_jobs_without_using_an_attempt(queue):
    long_job = jobs.enqueue("llm_prepare", {}, "long", max_attempts=1)
    other = jobs.enqueue("sync_projects", {}, "sync")
    q("UPDATE jobs SET run_after = now() - interval '1 minute' WHERE id = :id", id=long_job)
    runs = []

    def prepare(job):
        runs.append((job.id, job.attempts))
        if len(runs) == 1:
            raise jobs.RequeueJob("more to go")

    worker = jobs.Worker("w1", {"llm_prepare": prepare, "sync_projects": lambda job: runs.append((job.id, job.attempts))})
    assert worker.run_once() == "pending"
    assert q("SELECT status, attempts, locked_by, last_error FROM jobs WHERE id = :id", id=long_job) == [
        ("pending", 0, None, None)]
    assert worker.run_once() == "done" and worker.run_once() == "done"
    assert runs == [(long_job, 1), (other, 1), (long_job, 1)]   # the other ready job ran in between
    assert q("SELECT status, attempts FROM jobs WHERE id = :id", id=long_job) == [("done", 1)]


def test_successful_job_is_done_and_around_wraps_it(queue):
    seen = []
    worker = jobs.Worker("w1", {"cleanup": lambda job: seen.append(("run", job.id))},
                         around=lambda job, call: (seen.append(("enter", job.id)), call(), seen.append(("exit", job.id))))
    job_id = jobs.enqueue("cleanup")
    assert worker.run_once() == "done"
    assert seen == [("enter", job_id), ("run", job_id), ("exit", job_id)]
    assert q("SELECT status, attempts, locked_by FROM jobs") == [("done", 1, None)]


# ---- leases ----------------------------------------------------------------------------------

def test_expired_lease_is_requeued_and_the_old_owner_cannot_finish_it(queue):
    job_id = jobs.enqueue("scan_mr", {"mr_id": 1}, "scan_mr:1", max_attempts=2)
    assert jobs.claim("dead", lease_seconds=60).id == job_id
    assert jobs.claim("w2", lease_seconds=60) is None                       # lease still valid

    q("UPDATE jobs SET locked_at = now() - interval '61 seconds' WHERE id = :id", id=job_id)
    job = jobs.claim("w2", lease_seconds=60)
    assert (job.id, job.attempts, job.locked_by) == (job_id, 2, "w2")
    assert q("SELECT last_error FROM jobs")[0][0] == "lease expired (worker dead)"

    assert jobs.complete(job_id, "dead") is False                           # not its job any more
    assert jobs.fail(job_id, "dead", "late") is None
    assert jobs.heartbeat(job_id, "dead") is False

    # the second (= last) attempt dies too: failed, not re-queued forever
    q("UPDATE jobs SET locked_at = now() - interval '61 seconds' WHERE id = :id", id=job_id)
    assert jobs.reap_expired(60) == 1
    assert q("SELECT status FROM jobs")[0][0] == "failed"


def _ingest_batch(status="committed"):
    project = q("INSERT INTO gitlab_projects (project_name, full_path, visibility, created_at, updated_at, source) "
                "VALUES ('ext', 'ext/proj', 'private', now(), now(), 'external') RETURNING id")[0][0]
    return q("INSERT INTO ingest_batches (project_id, parser, snapshot, status) VALUES (:p, 'ext', 's1', :st) "
             "RETURNING id", p=project, st=status)[0][0]


def test_ingest_job_lost_on_its_last_attempt_fails_its_batch(queue):
    """The worker died / lost its lease on the last attempt: the handler never marked the batch
    failed, so it stayed 'committed' and a repeated push of the same state was 'unchanged'."""
    batch = _ingest_batch()
    other = q("INSERT INTO ingest_batches (project_id, parser, snapshot, status) "
              "SELECT project_id, 'ext2', 's1', 'committed' FROM ingest_batches WHERE id = :b RETURNING id", b=batch)[0][0]
    job_id = jobs.enqueue("ingest", {"batch_id": batch, "parser": "ext"}, f"ingest:{batch}", max_attempts=2)

    assert jobs.claim("dead", kinds=["ingest"], lease_seconds=60).id == job_id
    q("UPDATE jobs SET locked_at = now() - interval '61 seconds' WHERE id = :id", id=job_id)
    jobs.reap_expired(60)                                                   # attempt 1 of 2: retried
    assert q("SELECT status FROM ingest_batches WHERE id = :b", b=batch) == [("committed",)]

    make_ready(job_id)
    assert jobs.claim("dead", kinds=["ingest"], lease_seconds=60).id == job_id
    q("UPDATE jobs SET locked_at = now() - interval '61 seconds' WHERE id = :id", id=job_id)
    assert jobs.reap_expired(60) == 1
    assert q("SELECT status, error FROM ingest_batches WHERE id = :b", b=batch) == [
        ("failed", "lease expired (worker dead)")]

    # a worker the supervisor saw exit, on the last attempt
    second = jobs.enqueue("ingest", {"batch_id": other, "parser": "ext2"}, f"ingest:{other}", max_attempts=2)
    for _ in range(2):
        make_ready(second)
        assert jobs.claim("host:w:1", kinds=["ingest"], lease_seconds=None).id == second
        jobs.release_worker_jobs(["host:w:1"], "worker exited with code -9")
    assert q("SELECT status FROM ingest_batches WHERE id = :b", b=other) == [("failed",)]


def test_heartbeat_keeps_a_long_job_leased(queue):
    job_id = jobs.enqueue("scan_branch", {}, "long")
    stolen = []

    def long_job(job):
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            stolen.append(jobs.claim("thief", lease_seconds=1))
            time.sleep(0.2)

    worker = jobs.Worker("w1", {"scan_branch": long_job}, jobs.WorkerConfig(lease_seconds=1, heartbeat_seconds=0.2))
    assert worker.run_once() == "done"
    assert not any(stolen)
    assert q("SELECT status, attempts FROM jobs WHERE id = :id", id=job_id) == [("done", 1)]


def test_release_worker_jobs(queue):
    a = jobs.enqueue("scan_branch", {}, "a")
    jobs.enqueue("scan_branch", {}, "b")
    jobs.claim("host:scan-0:11")
    jobs.claim("host:scan-1:12")
    assert jobs.release_worker_jobs(["host:scan-0:11"], "worker exited with code -9") == 1
    assert q("SELECT status, last_error, locked_by FROM jobs WHERE id = :id", id=a) == [
        ("pending", "worker exited with code -9", None)]
    assert jobs.release_worker_jobs([], "x") == 0


def _hanging_worker(url, lease):
    """Child process: claims the job and hangs in it (heartbeat running) until killed."""
    db.configure(url)
    worker = jobs.Worker(jobs.worker_name("victim"), {"scan_branch": lambda job: time.sleep(3600)},
                         jobs.WorkerConfig(lease_seconds=lease, heartbeat_seconds=lease / 4))
    worker.run_once()


def test_killed_worker_job_is_rerun_after_lease_timeout(queue):
    lease = 2.0
    job_id = jobs.enqueue("scan_branch", {"branch_id": 7}, "scan_branch:7")

    child = mp.get_context("spawn").Process(target=_hanging_worker, args=(queue, lease), daemon=True)
    child.start()
    try:
        deadline = time.monotonic() + 30
        while q("SELECT status FROM jobs WHERE id = :id", id=job_id)[0][0] != "running":
            assert time.monotonic() < deadline, "child did not claim the job"
            time.sleep(0.1)
        owner = q("SELECT locked_by FROM jobs WHERE id = :id", id=job_id)[0][0]
        assert owner.endswith(f":victim:{child.pid}")

        time.sleep(lease * 1.5)                                     # alive: heartbeat keeps the lease
        assert jobs.claim("rescuer", lease_seconds=lease) is None

        os.kill(child.pid, signal.SIGKILL)
        child.join(10)
    finally:
        if child.is_alive():
            child.kill()

    done = []
    worker = jobs.Worker("rescuer", {"scan_branch": lambda job: done.append((job.id, job.attempts))},
                         jobs.WorkerConfig(lease_seconds=lease))
    deadline = time.monotonic() + lease * 5
    while not done:
        assert time.monotonic() < deadline, "the killed worker's job was not re-run"
        worker.run_once()
        time.sleep(0.2)

    assert done == [(job_id, 2)]
    assert q("SELECT status, last_error FROM jobs WHERE id = :id", id=job_id) == [("done", None)]


# ---- scheduling helpers / retention ----------------------------------------------------------

def test_due_and_purge(queue):
    assert jobs.due("cleanup", 3600) is None                                  # never ran
    old = jobs.enqueue("cleanup")
    assert jobs.due("cleanup", 3600) is False                                 # active
    jobs.complete(jobs.claim("w").id, "w")
    assert jobs.due("cleanup", 3600) is False                                 # recent
    q("UPDATE jobs SET created_at = now() - interval '2 hours', run_after = now() - interval '2 hours', "
      "finished_at = now() - interval '10 days'")
    assert jobs.due("cleanup", 3600) is True

    newer = jobs.enqueue("cleanup")
    jobs.complete(jobs.claim("w").id, "w")
    q("UPDATE jobs SET finished_at = now() - interval '10 days' WHERE id = :id", id=newer)
    jobs.enqueue("scan_branch", {}, "pending-one")
    with db.get_engine().begin() as conn:                                     # what cleanup runs
        assert conn.execute(jobs.PURGE_SQL, {"days": 7, "batch": 5000}).rowcount == 1   # newest per kind is kept
    assert [r[0] for r in q("SELECT id FROM jobs WHERE kind = 'cleanup'")] == [newer]
    assert old != newer
    assert jobs.counts() == {"cleanup": {"done": 1}, "scan_branch": {"pending": 1}}


def test_due_counts_from_run_after_not_created_at(queue):
    """A job queued with a delay (the first cleanup, one interval after start-up) is not due
    again right after it ran: the interval counts from when it was due."""
    jobs.enqueue("cleanup", delay=0)
    q("UPDATE jobs SET created_at = now() - interval '2 hours', run_after = now() - interval '1 minute'")
    jobs.complete(jobs.claim("w").id, "w")
    assert jobs.due("cleanup", 3600) is False


# ---- started_at and the reap schedule (scale) --------------------------------------------------

def test_started_at_is_set_on_claim_and_kept_on_the_finished_row(queue):
    job_id = jobs.enqueue("scan_branch", {}, "s")
    assert q("SELECT started_at FROM jobs WHERE id = :id", id=job_id) == [(None,)]
    jobs.claim("w1")
    started, = q("SELECT started_at FROM jobs WHERE id = :id", id=job_id)[0]
    assert started is not None
    jobs.complete(job_id, "w1")
    # the lease is cleared, the start of the attempt stays: run / wait times can be computed
    assert q("SELECT locked_at, started_at = :s FROM jobs WHERE id = :id", id=job_id, s=started) == [(None, True)]

    retried = jobs.enqueue("scan_mr", {}, "r", max_attempts=2)
    jobs.claim("w1")
    jobs.fail(retried, "w1", "boom", attempts=1, backoff_base=0, backoff_max=0)
    first, = q("SELECT started_at FROM jobs WHERE id = :id", id=retried)[0]
    make_ready(retried)
    time.sleep(0.01)
    jobs.claim("w2")
    assert q("SELECT started_at > :f FROM jobs WHERE id = :id", id=retried, f=first) == [(True,)]  # the last attempt


def test_worker_reaps_expired_leases_on_its_own_schedule_not_on_every_claim(queue, monkeypatch):
    victim = jobs.enqueue("scan_branch", {}, "victim")
    assert jobs.claim("dead", lease_seconds=None).id == victim
    q("UPDATE jobs SET locked_at = now() - interval '61 seconds' WHERE id = :id", id=victim)

    reaps = []
    real = jobs.reap_expired
    monkeypatch.setattr(jobs, "reap_expired", lambda lease, conn=None: reaps.append(lease) or real(lease, conn))
    worker = jobs.Worker("w1", {"scan_branch": lambda job: None}, jobs.WorkerConfig(lease_seconds=60, reap_every_s=3600))
    assert worker.run_once() == "done"                      # the first claim reaps: the victim's job is run
    assert reaps == [60] and q("SELECT status FROM jobs WHERE id = :id", id=victim) == [("done",)]
    for _ in range(5):
        worker.run_once()                                   # idle claims within reap_every_s: no reap statement
    assert reaps == [60]

    never = jobs.Worker("w2", {}, jobs.WorkerConfig(lease_seconds=60, reap_every_s=0))
    never.run_once()
    assert reaps == [60]                                    # 0: this worker never reaps (the scheduler does)
