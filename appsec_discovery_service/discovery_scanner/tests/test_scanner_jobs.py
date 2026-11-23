"""Job queue on the scanner side (P2-4): handlers, per-job workspaces, scheduler, supervisor.

Unit tests run with the stubbed DB / GitLab of conftest.py; the scheduler and the
end-to-end worker test need Postgres (TEST_DATABASE_URL or TEST_PG_DOCKER=1)."""

import os
import signal
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import text


def job(kind, attempts=1, max_attempts=3, **payload):
    from discovery_common.jobs import Job
    return Job(id=99, kind=kind, payload=payload, attempts=attempts, max_attempts=max_attempts, locked_by="w")


@pytest.fixture
def handlers(scanner, monkeypatch):
    """services.job_handlers with scan_service stubbed and jobs.enqueue recorded."""
    from discovery_common import jobs

    calls = SimpleNamespace(enqueued=[], processed=[], target_commits=[], scans=[], closed=[], released=[])
    scanner.stub("services.scan_service", "services.scan_service",
                 scan_branch=lambda b, force=False, parsers=None: calls.scans.append(
                     ("branch", b.id) + (("force",) if force else ()) + ((tuple(parsers),) if parsers else ())) or True,
                 scan_mr=lambda m, parsers=None, llm=True: calls.scans.append(
                     ("mr", m.id, m.target_branch_commit) + (() if llm else ("no-llm",))
                     + ((tuple(parsers),) if parsers else ())) or True,
                 llm_score_branch=lambda b, progress=None: calls.scans.append(("llm", b.id)) or True,
                 run_selected_llm_rules=lambda b, ids, progress=None: calls.scans.append(
                     ("llm-rules", b.id, list(ids))) or True,
                 ingest_branch=lambda b, parser, force=False: calls.scans.append(("ingest", b.id, parser)) or None)
    monkeypatch.setattr(jobs, "enqueue", lambda kind, payload=None, dedup_key=None, **kw:
                        calls.enqueued.append((kind, payload, dedup_key)) or len(calls.enqueued))
    module = scanner.load("services.job_handlers")
    # job_handlers binds the DB functions at import: stub them on the module
    calls.progress = []
    calls.phases = []

    def progress(job_id, **kw):
        p = SimpleNamespace(finish=lambda phase="done", **extra: calls.progress.append((job_id, phase)))

        def phase(name, **extra):
            p.last_phase = name
            calls.phases.append((job_id, name))
        p.phase = phase
        return p
    module.JobProgress = progress
    module.set_mr_processed = lambda mr_id, when=None: calls.processed.append(("mr", mr_id, when))
    module.set_branch_processed = lambda branch_id, when=None: calls.processed.append(("branch", branch_id, when))
    module.set_project_processed = lambda project_id, when=None: calls.processed.append(("project", project_id, when))
    module.set_mr_target_commit = lambda mr_id, commit: calls.target_commits.append((mr_id, commit))
    module.gl_time = lambda value: datetime.fromisoformat(value)
    module.get_delta_owner = lambda source_branch_id: None
    calls.locks = []

    @contextmanager
    def scan_lock(branch_id):
        calls.locks.append(branch_id)
        yield

    module.scan_lock = scan_lock

    monkeypatch.setattr(module.cleanup_service, "close_missing_mrs",
                        lambda project_id, iids, fetch_state=None, fetch_states=None: calls.closed.append(
                            (project_id, sorted(iids), fetch_states)) or 0)
    monkeypatch.setattr(module.cleanup_service, "release_stale_mr_branches",
                        lambda project_id: calls.released.append(project_id) or 0)
    monkeypatch.setattr(module.cleanup_service, "is_stale", lambda updated_at: updated_at < datetime(2020, 1, 1))
    return SimpleNamespace(module=module, calls=calls, scanner=scanner)


SEEN = "2026-11-20T10:00:00"


# ---- scan_mr / scan_branch / llm_score -------------------------------------------------------

def mr_row(**kw):
    data = dict(id=7, mr_id=42, project_id=1, project_path="grp/proj", source_branch_id=11, target_branch_id=10,
                target_branch="main", target_branch_commit="old")
    data.update(kw)
    return SimpleNamespace(**data)


def tracked(handlers, source_is_main=False):
    handlers.module.get_branch_by_id = lambda branch_id: SimpleNamespace(id=branch_id, is_main=(
        branch_id == 10 or source_is_main))


def test_scan_mr_job_refreshes_target_commit_and_marks_processed_with_seen_time(handlers):
    dbs = handlers.module
    tracked(handlers)
    dbs.get_mr = lambda mr_id: mr_row()
    dbs.get_branch = lambda project_id, name: SimpleNamespace(id=10, commit="new")

    handlers.module.scan_mr_job(job("scan_mr", mr_id=7, updated_at=SEEN))

    assert handlers.calls.target_commits == [(7, "new")]
    assert handlers.calls.scans == [("mr", 7, "new")]
    assert handlers.calls.processed == [("mr", 7, datetime.fromisoformat(SEEN))]
    assert handlers.calls.locks == [11]                                       # the source branch


@pytest.mark.parametrize("attempts, processed", [(1, False), (3, True)])
def test_scan_mr_job_failure_is_retried_and_marked_processed_only_on_the_last_attempt(handlers, attempts, processed):
    dbs = handlers.module
    tracked(handlers)
    dbs.get_mr = lambda mr_id: mr_row()
    dbs.get_branch = lambda project_id, name: None
    handlers.module.scan_mr = lambda mr, parsers=None, llm=True: False

    with pytest.raises(RuntimeError, match="MR !42 failed without a recorded reason"):
        handlers.module.scan_mr_job(job("scan_mr", attempts=attempts, mr_id=7))
    assert bool(handlers.calls.processed) is processed

    def boom(mr, **kw):
        raise ConnectionError("gitlab down")

    handlers.calls.processed.clear()
    handlers.module.scan_mr = boom
    with pytest.raises(ConnectionError):
        handlers.module.scan_mr_job(job("scan_mr", attempts=attempts, mr_id=7))
    assert bool(handlers.calls.processed) is processed


def test_scan_mr_job_reports_the_real_cause_and_does_not_retry_a_deleted_source_branch(handlers):
    """The incident: the MR source branch was deleted. last_error names the subject and git's reason, the
    job fails at once (PermanentJobError) and the MR is marked processed on the first attempt."""
    from discovery_common import jobs
    from services.failures import ScanError

    dbs = handlers.module
    tracked(handlers)
    dbs.get_mr = lambda mr_id: mr_row()
    dbs.get_branch = lambda project_id, name: None

    def gone(mr, **kw):
        raise ScanError("cannot clone source branch 'release/2024-11': remote branch not found in upstream origin "
                        "(deleted?)", permanent=True)

    handlers.module.scan_mr = gone
    asked = []
    dbs.get_gitlab_mr_states = lambda project, iids: asked.append((project, list(iids))) or {42: "opened"}
    with pytest.raises(jobs.PermanentJobError) as err:
        handlers.module.scan_mr_job(job("scan_mr", attempts=1, mr_id=7, updated_at=SEEN))
    assert jobs.error_text(err.value) == ("scan of 'grp/proj', MR !42: cannot clone source branch 'release/2024-11': "
                                          "remote branch not found in upstream origin (deleted?)")
    assert handlers.calls.processed == [("mr", 7, datetime.fromisoformat(SEEN))]
    assert asked == [("grp/proj", [42])]                    # still open in GitLab: the failure stands

    # a transient cause (network): the reason is kept, the job is retried, processed on the last attempt only
    def flaky(mr, **kw):
        raise ScanError("cannot clone source branch 'feature': git clone failed: fatal: unable to access '<repo>': "
                        "Could not resolve host: gitlab.example")

    handlers.module.scan_mr = flaky
    for attempts, processed in ((1, []), (3, [("mr", 7, None)])):
        handlers.calls.processed.clear()
        with pytest.raises(ScanError) as err:
            handlers.module.scan_mr_job(job("scan_mr", attempts=attempts, mr_id=7))
        assert not isinstance(err.value, jobs.PermanentJobError)
        assert str(err.value).startswith("scan of 'grp/proj', MR !42: cannot clone source branch 'feature': git clone failed")
        assert handlers.calls.processed == processed


@pytest.mark.parametrize("states, state", [({42: "merged"}, "merged"), ({42: "closed"}, "closed"), ({}, "deleted")])
def test_scan_mr_job_closed_mr_with_a_deleted_source_branch_is_skipped_not_failed(handlers, states, state):
    """The MR was merged / closed and its source branch deleted before the scan got to it: not a failure,
    the job ends as skipped and the MR is processed."""
    from services.failures import ScanError

    dbs = handlers.module
    tracked(handlers)
    dbs.get_mr = lambda mr_id: mr_row()
    dbs.get_branch = lambda project_id, name: None
    dbs.get_gitlab_mr_states = lambda project, iids: states

    def gone(mr, **kw):
        raise ScanError("cannot clone source branch 'release/2024-11': remote branch not found in upstream origin "
                        "(deleted?)", permanent=True)

    dbs.scan_mr = gone
    dbs.scan_mr_job(job("scan_mr", attempts=1, mr_id=7, updated_at=SEEN))
    assert handlers.calls.processed == [("mr", 7, datetime.fromisoformat(SEEN))]
    assert handlers.calls.phases[-1][1] == "skipped"


def test_scan_mr_job_keeps_the_failure_when_gitlab_cannot_tell_the_state(handlers):
    from discovery_common import jobs
    from services.failures import ScanError

    dbs = handlers.module
    tracked(handlers)
    dbs.get_mr = lambda mr_id: mr_row()
    dbs.get_branch = lambda project_id, name: None

    def unreadable(project, iids):
        raise RuntimeError("502 Bad Gateway")

    dbs.get_gitlab_mr_states = unreadable
    dbs.scan_mr = lambda mr, **kw: (_ for _ in ()).throw(ScanError(
        "cannot clone source branch 'x': remote ref not found (branch deleted?)", permanent=True))
    with pytest.raises(jobs.PermanentJobError):
        dbs.scan_mr_job(job("scan_mr", attempts=1, mr_id=7))


def test_scan_branch_job_reports_the_parser_or_clone_failure(handlers):
    from discovery_common import jobs
    from services.failures import ScanError

    main = SimpleNamespace(id=10, is_main=True, commit="c1", project_path="grp/proj", branch_name="main")
    handlers.module.get_branch_by_id = lambda branch_id: main

    def partial(b, force=False, parsers=None):
        raise ScanError("partial scan at c1: parser 'golang' failed: semgrep exited with code 2")

    handlers.module.scan_branch = partial
    with pytest.raises(ScanError, match=r"^scan of 'grp/proj', branch 'main': partial scan at c1: parser 'golang' failed: "
                                        r"semgrep exited with code 2$"):
        handlers.module.scan_branch_job(job("scan_branch", attempts=1, branch_id=10))
    assert handlers.calls.processed == []

    def no_parsers(b, force=False, parsers=None):
        raise ScanError("no known parser is configured (PARSERS setting), nothing to scan", permanent=True)

    handlers.module.scan_branch = no_parsers
    with pytest.raises(jobs.PermanentJobError, match="^scan of 'grp/proj', branch 'main': no known parser is configured"):
        handlers.module.scan_branch_job(job("scan_branch", attempts=1, branch_id=10))


def test_llm_score_job_records_the_rule_failures_in_progress_and_last_error(handlers):
    from services.failures import ScanError

    dbs = handlers.module
    dbs.get_branch_by_id = lambda branch_id: SimpleNamespace(id=10, is_main=True, project_path="grp/proj", branch_name="main")
    finished = []

    def progress(job_id, **kw):
        p = SimpleNamespace(total=0, done=0, failed=0, skipped=0, base={})
        p.finish = lambda phase="done", **extra: finished.append((phase, extra))
        p.phase = lambda name, **extra: None
        return p

    handlers.module.JobProgress = progress
    reason = ("LLM rule 'db-tables': 3 of 120 objects failed: LlmError: LLM answer truncated at max_tokens=8192 (2), "
              "APITimeoutError: Request timed out (1) (117 verdicts stored)")

    def incomplete(b, progress=None):
        raise ScanError(reason)

    handlers.module.llm_score_branch = incomplete
    with pytest.raises(ScanError, match="^LLM scoring of 'grp/proj', branch 'main': LLM rule 'db-tables': 3 of 120 objects failed"):
        handlers.module.llm_score_job(job("llm_score", branch_id=10))
    assert finished == [("incomplete", {"error": reason})]

    # selected rules (POST /llm_rules/{id}/run) and a rollout slice the same way
    finished.clear()
    handlers.module.run_selected_llm_rules = lambda b, ids, progress=None, **kw: (_ for _ in ()).throw(
        ScanError("LLM rule 'x': candidates not selected: OperationalError: connection timed out"))
    with pytest.raises(ScanError, match=r"^LLM rules \[5\] on 'grp/proj', branch 'main': LLM rule 'x': candidates not selected"):
        handlers.module.llm_score_job(job("llm_score", branch_id=10, rule_ids=[5]))
    assert finished[0][0] == "incomplete" and finished[0][1]["error"].startswith("LLM rule 'x'")


def test_scan_mr_job_skips_an_mr_whose_source_branch_delta_belongs_to_another_mr(handlers):
    # the same source branch in two open MRs (e.g. a backport): the delta lives on the branch,
    # so only its owner (the oldest open MR of the branch) is scanned
    dbs = handlers.module
    tracked(handlers)
    dbs.get_mr = lambda mr_id: mr_row()
    dbs.get_branch = lambda project_id, name: SimpleNamespace(id=10, commit="new")
    dbs.get_delta_owner = lambda source_branch_id: 5 if source_branch_id == 11 else None

    handlers.module.scan_mr_job(job("scan_mr", mr_id=7, updated_at=SEEN))
    assert handlers.calls.scans == [] and handlers.calls.locks == []
    assert handlers.calls.processed == [("mr", 7, datetime.fromisoformat(SEEN))]

    dbs.get_delta_owner = lambda source_branch_id: 7                   # the owner itself is scanned
    handlers.module.scan_mr_job(job("scan_mr", mr_id=7, updated_at=SEEN))
    assert handlers.calls.scans == [("mr", 7, "new")]


def test_scan_mr_job_skips_gone_mrs(handlers):
    handlers.module.get_mr = lambda mr_id: None
    handlers.module.scan_mr_job(job("scan_mr", mr_id=7))
    handlers.module.get_mr = lambda mr_id: mr_row(source_branch_id=None)
    handlers.module.scan_mr_job(job("scan_mr", mr_id=7))
    assert handlers.calls.scans == [] and handlers.calls.processed == []

    # source branch is main (or untracked): nothing to scan, marked processed, no retry
    handlers.module.get_mr = lambda mr_id: mr_row()
    tracked(handlers, source_is_main=True)
    handlers.module.scan_mr_job(job("scan_mr", mr_id=7))
    assert handlers.calls.scans == [] and handlers.calls.processed == [("mr", 7, None)]


def test_parse_job_force_parsers_and_without_llm(handlers):
    """Jobs queued by POST /projects/parse: force, a parser subset, llm=false skips the LLM job."""
    main = SimpleNamespace(id=10, is_main=True, commit="c1", project_path="grp/proj", branch_name="main")
    handlers.module.get_branch_by_id = lambda branch_id: main
    handlers.module.llm_configured = lambda settings=None: True

    handlers.module.scan_branch_job(job("scan_branch", branch_id=10, force=True, llm=False, parsers=["protobuf"]))
    assert handlers.calls.scans == [("branch", 10, "force", ("protobuf",))]
    assert handlers.calls.enqueued == []

    handlers.module.scan_branch_job(job("scan_branch", branch_id=10))
    assert handlers.calls.scans[-1] == ("branch", 10)
    assert [e[0] for e in handlers.calls.enqueued] == ["llm_score"]


def test_llm_score_job_with_rule_ids_runs_selected_rules_on_any_branch(handlers):
    feature = SimpleNamespace(id=11, is_main=False, commit="f1", project_path="grp/proj", branch_name="feature")
    handlers.module.get_branch_by_id = lambda branch_id: feature if branch_id == 11 else None

    handlers.module.llm_score_job(job("llm_score", branch_id=11, rule_ids=[5], mr_id=7))
    assert handlers.calls.scans == [("llm-rules", 11, [5])]
    handlers.module.llm_score_job(job("llm_score", branch_id=99, rule_ids=[5]))      # gone: skipped
    handlers.module.llm_score_job(job("llm_score", branch_id=11))                      # whole set: mains only
    assert handlers.calls.scans == [("llm-rules", 11, [5])]

    handlers.module.run_selected_llm_rules = lambda b, ids, progress=None: False
    with pytest.raises(RuntimeError):
        handlers.module.llm_score_job(job("llm_score", branch_id=11, rule_ids=[5]))


def test_scan_branch_job(handlers):
    dbs = handlers.module
    main = SimpleNamespace(id=10, is_main=True, commit="c1", project_path="grp/proj", branch_name="main")
    dbs.get_branch_by_id = lambda branch_id: main

    handlers.module.scan_branch_job(job("scan_branch", branch_id=10, updated_at=SEEN))
    assert handlers.calls.processed == [("branch", 10, datetime.fromisoformat(SEEN))]
    assert handlers.calls.enqueued == []                                      # LLM not configured
    assert handlers.calls.locks == [10]                                       # one scan per branch
    # jobs.progress phases (the stubbed scan_branch reports none of its own): waiting -> done
    assert handlers.calls.phases == [(99, "waiting"), (99, "done")]

    handlers.module.llm_configured = lambda settings=None: True
    handlers.module.scan_branch_job(job("scan_branch", branch_id=10))
    assert handlers.calls.enqueued == [("llm_score", {"branch_id": 10, "commit": "c1"}, "llm_score:10:c1")]

    # failure: not marked processed (the next project sync queues it again), retried by the queue
    handlers.calls.processed.clear()
    handlers.module.scan_branch = lambda b, force=False, parsers=None: False
    with pytest.raises(RuntimeError):
        handlers.module.scan_branch_job(job("scan_branch", attempts=3, branch_id=10))
    assert handlers.calls.processed == []

    # no longer a tracked main branch: done, nothing scanned
    dbs.get_branch_by_id = lambda branch_id: SimpleNamespace(id=10, is_main=False)
    handlers.calls.phases.clear()
    handlers.module.scan_branch_job(job("scan_branch", branch_id=10))
    assert handlers.calls.phases == [(99, "waiting"), (99, "skipped")]


def test_llm_score_job(handlers):
    dbs = handlers.module
    dbs.get_branch_by_id = lambda branch_id: SimpleNamespace(id=10, is_main=True, project_path="p", branch_name="main")
    handlers.module.llm_score_job(job("llm_score", branch_id=10))
    assert handlers.calls.scans == [("llm", 10)]
    handlers.module.llm_score_branch = lambda b, progress=None: False
    with pytest.raises(RuntimeError):
        handlers.module.llm_score_job(job("llm_score", branch_id=10))


# ---- GitLab sync -----------------------------------------------------------------------------

def test_sync_projects_queues_new_and_changed_projects(handlers):
    rows = {
        1: SimpleNamespace(id=1, processed_at=None, updated_at=datetime(2026, 11, 1)),
        2: SimpleNamespace(id=2, processed_at=datetime(2026, 11, 2), updated_at=datetime(2026, 11, 1)),
        3: SimpleNamespace(id=3, processed_at=datetime(2026, 11, 1), updated_at=datetime(2026, 11, 2)),
    }
    handlers.scanner.setenv(GITLAB_PROJECTS_PREFIX="grp,bad")

    def projects(prefix):
        if prefix == "bad":
            raise ConnectionError("gitlab down")
        return [SimpleNamespace(id=100 + i) for i in rows]

    handlers.module.get_gitlab_projects_list = projects
    handlers.module.upsert_project = lambda project_gl: (rows[project_gl.id - 100], "checked")
    handlers.scanner.setenv(SYNC_UNCHANGED_EVERY_H="0")                # unchanged projects: only the full sync

    with pytest.raises(RuntimeError, match="bad: gitlab down"):        # other prefixes still synced
        handlers.module.sync_projects(job("sync_projects"))
    assert [(kind, p["project_id"], key) for kind, p, key in handlers.calls.enqueued] == [
        ("sync_branches_mrs", 1, "sync_branches_mrs:1"), ("sync_branches_mrs", 3, "sync_branches_mrs:3")]
    assert handlers.calls.enqueued[0][1]["gitlab_id"] == 101
    assert handlers.calls.processed == []                               # set by sync_branches_mrs now

    handlers.calls.enqueued.clear()
    handlers.scanner.setenv(GITLAB_PROJECTS_PREFIX="grp")
    handlers.module.sync_projects(job("sync_projects", full=True))
    assert [p["project_id"] for _, p, _ in handlers.calls.enqueued] == [1, 2, 3]

    # SYNC_UNCHANGED_EVERY_H: an unchanged project is re-read once its last sync is that old (full sync or not)
    handlers.calls.enqueued.clear()
    handlers.scanner.setenv(SYNC_UNCHANGED_EVERY_H="24")
    rows[2].processed_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)        # synced an hour ago, nothing new
    handlers.module.sync_projects(job("sync_projects", full=True))
    assert [p["project_id"] for _, p, _ in handlers.calls.enqueued] == [1, 3]
    handlers.calls.enqueued.clear()
    rows[2].processed_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=25)
    handlers.module.sync_projects(job("sync_projects"))
    assert [p["project_id"] for _, p, _ in handlers.calls.enqueued] == [1, 2, 3]


def test_sync_branches_mrs_queues_scans(handlers):
    handlers.scanner.setenv(GITLAB_SCAN_TYPES="mains,mrs")
    recent = (datetime.now() - timedelta(hours=1)).isoformat()
    project_gl = SimpleNamespace(id=101, default_branch="main")
    m = handlers.module
    m.get_project = lambda project_id: SimpleNamespace(id=1, gitlab_id=101, full_path="grp/proj")
    m.get_gitlab_project = lambda gitlab_id: project_gl
    m.get_gitlab_mrs_by_project = lambda gid: [
        SimpleNamespace(iid=5, source_branch="feature", target_branch="main", updated_at=recent),
        SimpleNamespace(iid=6, source_branch="stale", target_branch="main", updated_at="2019-01-01T00:00:00")]
    asked_branches = []
    all_branches = {n: SimpleNamespace(name=n) for n in ("main", "feature", "stale", "other")}
    m.get_gitlab_branches = lambda gl, names: asked_branches.append(list(names)) or [all_branches[n] for n in names]
    m.get_gitlab_mr_states = lambda gid, iids: {iid: "merged" for iid in iids}

    upserted = []
    branches = {"main": SimpleNamespace(id=10, commit="c1", processed_at=None, updated_at=datetime(2026, 11, 1)),
                "feature": SimpleNamespace(id=11, commit="f1", processed_at=None, updated_at=datetime(2026, 11, 1))}
    m.upsert_branch = lambda b, pid, path, is_main: upserted.append((b.name, is_main)) or (branches[b.name], "checked")
    m.get_branch = lambda pid, name: branches.get(name)
    mr_db = SimpleNamespace(id=7, state="opened", updated_at=datetime.now() - timedelta(hours=1), processed_at=None,
                            source_branch_commit="f1", target_branch_commit="c1")
    m.upsert_mr = lambda mr_gl, pid, path, source, target: (mr_db, "inserted")

    m.sync_branches_mrs(job("sync_branches_mrs", project_id=1, gitlab_id=101, updated_at=SEEN))

    assert upserted == [("main", True), ("feature", False)]               # stale MR and other branch untracked
    assert asked_branches == [["main", "feature"]]                      # by name: never every branch of the repo
    assert [(kind, key) for kind, _, key in handlers.calls.enqueued] == [
        ("scan_branch", "scan_branch:10:c1"), ("scan_mr", "scan_mr:7:f1:c1")]
    assert [(p, iids) for p, iids, _ in handlers.calls.closed] == [(1, [5, 6])] and handlers.calls.released == [1]
    assert handlers.calls.closed[0][2]([5, 6]) == {5: "merged", 6: "merged"}     # states in one batched call
    assert handlers.calls.processed == [("project", 1, datetime.fromisoformat(SEEN))]

    # already processed and no newer activity: nothing queued
    handlers.calls.enqueued.clear()
    branches["main"].processed_at = datetime(2026, 11, 1)
    mr_db.processed_at = mr_db.updated_at
    m.sync_branches_mrs(job("sync_branches_mrs", project_id=1, gitlab_id=101))
    assert handlers.calls.enqueued == []


# ---- workspaces ------------------------------------------------------------------------------

def test_job_workspace_is_private_and_removed(scanner, tmp_path):
    workspace = scanner.load("services.workspace")
    assert workspace.checkout_dir(1, 2, "c") == os.path.join("code", "1", "2", "c")

    with workspace.job_workspace(5, str(tmp_path)) as path:
        assert os.path.dirname(path) == str(tmp_path)
        assert os.path.basename(path).startswith(f"job5-{os.getpid()}-")
        assert workspace.checkout_dir(1, 2, "c") == os.path.join(path, "1", "2", "c")
        os.makedirs(workspace.checkout_dir(1, 2, "c"))
    assert not os.path.exists(path) and workspace.current() is None

    with pytest.raises(RuntimeError):
        with workspace.job_workspace(6, str(tmp_path)) as path:
            raise RuntimeError("scan failed")
    assert not os.path.exists(path)

    (tmp_path / "job7-4242-abc").mkdir()
    (tmp_path / "job8-4243-abc").mkdir()
    assert workspace.remove_leftovers(4242, str(tmp_path)) == 1
    assert [p.name for p in tmp_path.iterdir()] == ["job8-4243-abc"]
    assert workspace.remove_leftovers(None, str(tmp_path)) == 1


def test_only_scan_jobs_run_in_a_workspace(handlers, tmp_path):
    handlers.scanner.setenv(WORKSPACE_DIR=str(tmp_path))
    supervisor = handlers.scanner.load("supervisor")
    import importlib
    workspace = importlib.import_module("services.workspace")
    around = supervisor.run_in_workspace(handlers.scanner.settings())
    seen = {}
    for kind in ("scan_branch", "scan_mr", "llm_score", "sync_projects", "cleanup"):
        around(job(kind), lambda kind=kind: seen.__setitem__(kind, workspace.current()))
    assert {k for k, v in seen.items() if v} == {"scan_branch", "scan_mr"}
    assert all(str(v).startswith(str(tmp_path)) for v in seen.values() if v)
    assert list(tmp_path.iterdir()) == []


# ---- supervisor ------------------------------------------------------------------------------

def crashing_worker(spec):
    sys.exit(3)


def well_behaved_worker(spec):
    import threading
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *a: stop.set())
    stop.wait(60)
    sys.exit(0 if stop.is_set() else 4)


def test_supervisor_restarts_crashed_workers_with_backoff(scanner, monkeypatch):
    supervisor = scanner.load("supervisor")
    released = []
    monkeypatch.setattr(supervisor.jobs, "release_worker_jobs", lambda ids, error: released.append((ids, error)) or 0)
    now = [100.0]
    spec = supervisor.WorkerSpec("scan", 0, ("scan_branch",))
    sup = supervisor.Supervisor(scanner.settings(), specs=[spec], target=crashing_worker, clock=lambda: now[0])

    sup.check_workers()
    slot = sup.slots["scan-0"]
    first = slot.process
    first.join(30)
    assert first.exitcode == 3

    sup.check_workers()                                 # crashed right after start: restart in 2s
    assert slot.process is None and slot.next_start == 102.0 and slot.failures == 1
    assert released and released[0][0] == [f"{supervisor.jobs.worker_name('scan-0', first.pid)}"]
    assert "exited with code 3" in released[0][1]

    now[0] = 102.0
    sup.check_workers()
    assert slot.process is not None and slot.restarts == 1
    slot.process.join(30)
    sup.check_workers()
    assert slot.failures == 2 and slot.next_start == 106.0      # 2 ** failures
    sup.shutdown(timeout=1)


def test_supervisor_graceful_shutdown(scanner, monkeypatch):
    supervisor = scanner.load("supervisor")
    released = []
    monkeypatch.setattr(supervisor.jobs, "release_worker_jobs", lambda ids, error: released.append(ids) or 0)
    specs = [supervisor.WorkerSpec("scan", i, ("scan_branch",)) for i in range(2)]
    sup = supervisor.Supervisor(scanner.settings(), specs=specs, target=well_behaved_worker)
    sup.check_workers()
    processes = [slot.process for slot in sup.slots.values()]
    time.sleep(1.5)                                              # let them install the handler
    sup.shutdown(timeout=20)
    assert [p.exitcode for p in processes] == [0, 0]
    assert released == []                                        # clean exit: nothing to re-queue


def test_worker_specs(scanner):
    scanner.setenv(MAX_WORKERS="3", LLM_WORKERS="0", SYNC_WORKERS="2", CONTROL_WORKERS="1")
    supervisor = scanner.load("supervisor")
    specs = supervisor.worker_specs(scanner.settings())
    assert [s.name for s in specs] == ["sync-0", "sync-1", "control-0", "scan-0", "scan-1", "scan-2"]
    # the GitLab sync has a pool of its own: harness items / answers never wait behind it
    assert specs[0].kinds == ("sync_projects", "sync_branches_mrs")
    # the phases of external LLM runs call no model: the control worker runs them, even without LLM workers
    assert specs[2].kinds == ("llm_verify", "llm_apply", "llm_prepare", "llm_coverage", "llm_rollout", "llm_relabel",
                              "stats_refresh", "cleanup")
    scanner.setenv(MAX_WORKERS="1", LLM_WORKERS="2", SYNC_WORKERS="1", CONTROL_WORKERS="2")
    specs = supervisor.worker_specs(scanner.settings())
    assert [(s.name, s.kinds) for s in specs if s.pool == "llm"] == [("llm-0", ("llm_score", "llm_trial")),
                                                                      ("llm-1", ("llm_score", "llm_trial"))]
    assert [s.name for s in specs if s.pool in ("sync", "control")] == ["sync-0", "control-0", "control-1"]


def test_every_job_kind_has_a_handler_and_a_pool(handlers):
    from discovery_common.models import JOB_KINDS
    supervisor = handlers.scanner.load("supervisor")
    pools = supervisor.SYNC_KINDS + supervisor.CONTROL_KINDS + supervisor.SCAN_KINDS + supervisor.LLM_KINDS
    assert sorted(pools) == sorted(JOB_KINDS) and len(pools) == len(set(pools))
    assert set(handlers.module.HANDLERS) == set(JOB_KINDS)


# ---- with Postgres ---------------------------------------------------------------------------

def pg_q(sql, **params):
    from discovery_common import db
    with db.get_engine().begin() as conn:
        result = conn.execute(text(sql), params)
        return result.all() if result.returns_rows else result.rowcount


def test_scheduler_enqueues_periodic_jobs(pg_scanner):
    pg_scanner.setenv(GC_INTERVAL_HOURS="24", PROJECTS_POLL_INTERVAL_S="300", LLM_COVERAGE_INTERVAL_S="0",
                      LLM_ROLLOUT_TICK_S="0", STATS_REFRESH_S="0")
    supervisor = pg_scanner.load("supervisor")
    from discovery_common import jobs

    now = [0.0]
    scheduler = supervisor.Scheduler(pg_scanner.settings(), every=10, clock=lambda: now[0])
    scheduler.tick()
    rows = pg_q("SELECT kind, payload, status, run_after > now() + interval '23 hours' FROM jobs ORDER BY id")
    assert rows == [("sync_projects", {"full": True}, "pending", False), ("cleanup", {}, "pending", True)]

    scheduler.tick()                                             # before `every`: nothing looked at
    now[0] = 10
    scheduler.tick()                                             # both still pending: deduplicated
    assert pg_q("SELECT count(*) FROM jobs")[0][0] == 2

    sync = jobs.claim("w", kinds=["sync_projects"])
    jobs.complete(sync.id, "w")
    now[0] = 20
    scheduler.tick()                                             # done, but not old enough
    assert pg_q("SELECT count(*) FROM jobs")[0][0] == 2

    pg_q("UPDATE jobs SET created_at = now() - interval '301 seconds', run_after = now() - interval '301 seconds' "
         "WHERE id = :id", id=sync.id)
    now[0] = 30
    scheduler.tick()
    assert pg_q("SELECT kind, payload FROM jobs WHERE status = 'pending' ORDER BY id") == [
        ("cleanup", {}), ("sync_projects", {})]

    # a restarted scanner keeps the cleanup schedule (it is read from the table)
    again = supervisor.Scheduler(pg_scanner.settings(), every=10, clock=lambda: 0.0)
    again.tick()
    assert pg_q("SELECT count(*) FROM jobs WHERE kind = 'cleanup'")[0][0] == 1
    # ... and still starts with a full sync, although a regular one was left pending
    assert pg_q("SELECT payload FROM jobs WHERE kind = 'sync_projects' AND status = 'pending' ORDER BY id") == [
        ({},), ({"full": True},)]


def test_scan_lock_serialises_scans_of_one_branch(pg_scanner):
    """Two scan jobs of the same branch (different commits) never save concurrently."""
    import threading
    dbs = pg_scanner.db
    order = []
    first_in = threading.Event()

    def first():
        with dbs.scan_lock(5):
            order.append("first-in")
            first_in.set()
            time.sleep(0.5)
            order.append("first-out")

    def second():
        first_in.wait(5)
        with dbs.scan_lock(5):
            order.append("second-in")

    threads = [threading.Thread(target=first), threading.Thread(target=second)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert order == ["first-in", "first-out", "second-in"]
    with dbs.scan_lock(6):            # other branches are not blocked
        pass
    assert pg_q("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND classid = :c",
                c=dbs.SCAN_LOCK_CLASS)[0][0] == 0


def test_worker_scans_main_branch_in_a_removed_workspace(pg_scanner, tmp_path):
    """End to end: queued scan_branch job -> worker -> clone into the job's mkdtemp
    workspace -> core scan -> snapshot saved -> workspace removed; a failed clone is retried."""
    pg_scanner.setenv(PARSERS="protobuf", WORKSPACE_DIR=str(tmp_path), GITLAB_SCAN_TYPES="mains")
    from discovery_common import jobs
    from test_scanner_storage_pg import PROTO_V1, branch_gl, project_gl

    dbs = pg_scanner.db
    project, _ = dbs.upsert_project(project_gl())
    main, _ = dbs.upsert_branch(branch_gl("main"), project.id, project.full_path, True)

    workspace = pg_scanner.load("services.workspace")
    clones = []

    def clone(project_path, branch_name, project_id, branch_id, commit, shallow=False):
        folder = workspace.checkout_dir(project_id, branch_id, commit)
        clones.append(folder)
        if len(clones) == 1:
            return False                                            # first attempt: clone fails
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "users.proto"), "w") as f:
            f.write(PROTO_V1)
        return True

    pg_scanner.gl_service.clone_gitlab_project_code = clone
    pg_scanner.load("services.scan_service")
    handlers = pg_scanner.load("services.job_handlers")
    supervisor = pg_scanner.load("supervisor")

    settings = pg_scanner.settings()
    job_id = jobs.enqueue("scan_branch", {"branch_id": main.id, "updated_at": main.updated_at.isoformat()},
                          f"scan_branch:{main.id}:{main.commit}")
    worker = jobs.Worker("w1", handlers.HANDLERS, jobs.WorkerConfig(kinds=["scan_branch"], backoff_base=0),
                         around=supervisor.run_in_workspace(settings))

    assert worker.run_once() == "pending"                           # clone failed: retried
    assert worker.run_once() == "done"
    assert all(c.startswith(str(tmp_path)) for c in clones) and os.path.dirname(clones[0]) != os.path.dirname(clones[1])
    assert list(tmp_path.iterdir()) == []                           # both workspaces removed

    assert pg_q("SELECT status, attempts FROM jobs WHERE id = :id", id=job_id) == [("done", 2)]
    assert pg_q("SELECT count(*) FROM branch_objects WHERE branch_id = :b", b=main.id)[0][0] == 1
    # jobs.progress of the scan (GET /jobs, Jobs page): the last phase with the parser counts
    (progress,), = pg_q("SELECT progress FROM jobs WHERE id = :id", id=job_id)
    assert progress["phase"] == "done" and progress["objects"] == 1 and progress["by_parser"] == {"protobuf": 1}
    assert progress["failed_parsers"] == [] and progress["started_at"] and progress["finished_at"]
    assert "executor" not in progress and "error" not in progress       # attempt 1 (clone failed) dropped
    branch = dbs.get_branch_by_id(main.id)
    assert branch.scanned_commit == main.commit and branch.processed_at == main.updated_at


def test_scheduler_enqueues_stats_refresh_and_reaps_expired_leases(pg_scanner):
    pg_scanner.setenv(GC_INTERVAL_HOURS="0", PROJECTS_POLL_INTERVAL_S="300", LLM_COVERAGE_INTERVAL_S="0",
                      LLM_ROLLOUT_TICK_S="0", STATS_REFRESH_S="60", JOB_LEASE_S="60")
    supervisor = pg_scanner.load("supervisor")
    from discovery_common import jobs

    scheduler = supervisor.Scheduler(pg_scanner.settings(), every=10, clock=lambda: 0.0)
    scheduler.tick()
    assert pg_q("SELECT kind FROM jobs WHERE status = 'pending' ORDER BY id") == [("sync_projects",), ("stats_refresh",)]
    stats = jobs.claim("control", kinds=["stats_refresh"], lease_seconds=None)
    assert stats is not None
    pg_q("UPDATE jobs SET locked_at = now() - interval '61 seconds' WHERE id = :id", id=stats.id)
    pg_q("UPDATE jobs SET created_at = now() - interval '2 minutes', run_after = now() - interval '2 minutes' "
         "WHERE id = :id", id=stats.id)
    again = supervisor.Scheduler(pg_scanner.settings(), every=10, clock=lambda: 0.0)
    again.tick()                                                 # the scheduler reaps the expired lease ...
    assert pg_q("SELECT status, last_error FROM jobs WHERE id = :id", id=stats.id) == [
        ("pending", "lease expired (worker control)")]
    # ... and does not queue a second stats_refresh while one is active (reaped: pending again)
    assert pg_q("SELECT count(*) FROM jobs WHERE kind = 'stats_refresh'")[0][0] == 1


def test_llm_relabel_job_runs_in_slices_and_yields(pg_scanner, monkeypatch):
    """The handler: slices of ``batch`` rows, each its own transaction, RequeueJob after RELABEL_SLICES_PER_RUN
    slices, done when a slice changes fewer rows than the batch; progress carries the counts."""
    from discovery_common import db, jobs, lifecycle
    pg_scanner.setenv(STATS_REFRESH_S="0")
    handlers = pg_scanner.load("services.job_handlers")
    with db.unit_of_work() as s:
        rule = s.execute(text("""INSERT INTO rules (kind, name, category, severity, target, mode, scope, prompt, version,
                                 enabled) VALUES ('llm', 'contacts', 'contact', 'low', 'field', 'auto', '{}', 'p', 2, true)
                                 RETURNING id""")).scalar()
        for i in range(7):
            s.execute(text("""INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version,
                              status, prompt_version, model, decided_tier) VALUES (:r, gen_random_uuid(), 1,
                              gen_random_uuid(), 'f' || :i, 1, 'no_match', 'rule3', 'm', 'service')"""), {"r": rule, "i": i})
        # a human decision and a verdict of other core prompts are not relabelled
        s.execute(text("""INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version,
                          status, prompt_version, model, decided_tier, reviewer) VALUES (:r, gen_random_uuid(), 1,
                          gen_random_uuid(), 'human', 1, 'match', 'rule3', 'm', 'human', 'alice')"""), {"r": rule})
        s.execute(text("""INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version,
                          status, prompt_version, model, decided_tier) VALUES (:r, gen_random_uuid(), 1,
                          gen_random_uuid(), 'old', 1, 'match', 'rule2', 'm', 'service')"""), {"r": rule})
        job_id = lifecycle.enqueue_relabel(s, rule_id=rule, action="relabel", to_version=2, from_version=1, core="rule3",
                                           model="m", user="alice", batch=2)
        assert lifecycle.enqueue_relabel(s, rule_id=rule, action="relabel", to_version=2, from_version=1, core="rule3",
                                         model="m", batch=2) is None          # one active job per rule / version
    assert pg_q("SELECT priority, payload ->> 'action' FROM jobs WHERE id = :id", id=job_id) == [(5, "relabel")]

    monkeypatch.setattr(handlers, "RELABEL_SLICES_PER_RUN", 2)
    job = jobs.claim("control", kinds=["llm_relabel"], lease_seconds=None)
    with pytest.raises(jobs.RequeueJob):                        # 2 slices of 2: 4 rows, more to go
        handlers.llm_relabel_job(job)
    assert pg_q("SELECT progress ->> 'phase', (progress ->> 'rows')::int, (progress ->> 'slices')::int FROM jobs "
                "WHERE id = :id", id=job_id) == [("running", 4, 2)]
    jobs.requeue(job.id, "control")
    job = jobs.claim("control", kinds=["llm_relabel"], lease_seconds=None)
    handlers.llm_relabel_job(job)                               # 2 + 1 rows, the last slice is short: done
    assert pg_q("SELECT progress ->> 'phase', (progress ->> 'rows')::int, (progress ->> 'slices')::int FROM jobs "
                "WHERE id = :id", id=job_id) == [("done", 7, 4)]
    assert pg_q("SELECT rule_version, count(*) FROM rule_hits WHERE rule_id = :r GROUP BY 1 ORDER BY 1", r=rule) == [
        (1, 2), (2, 7)]
    assert pg_q("SELECT count(*) FROM hit_verdicts WHERE rule_id = :r AND source = 'relabel'", r=rule) == [(7,)]
