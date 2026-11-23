"""gl_service (P1-7): lazy per-process GitLab client, git auth without credential files."""

import os
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest


def test_import_does_not_create_client_or_read_env(scanner):
    scanner.use_real("services.gl_service")
    assert scanner.gitlab.instances == []


def test_client_is_lazy_cached_and_per_process(scanner, monkeypatch):
    gl_service = scanner.use_real("services.gl_service")

    first = gl_service.get_gitlab_client()
    assert gl_service.get_gitlab_client() is first
    assert (first.url, first.private_token) == ("https://gitlab.example", "glpat-test-token")

    # A forked worker gets its own client.
    monkeypatch.setattr(gl_service.os, "getpid", lambda: -1)
    assert gl_service.get_gitlab_client() is not first
    assert len(scanner.gitlab.instances) == 2


def test_projects_list_goes_through_client(scanner):
    gl_service = scanner.use_real("services.gl_service")
    client = gl_service.get_gitlab_client()
    client.projects.list = lambda **kw: [
        SimpleNamespace(path_with_namespace="grp/a"), SimpleNamespace(path_with_namespace="other/grp")]

    assert [p.path_with_namespace for p in gl_service.get_gitlab_projects_list("grp")] == ["grp/a"]


def test_clone_passes_token_via_env_only(scanner, monkeypatch, tmp_path):
    gl_service = scanner.use_real("services.gl_service")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    calls = []

    def fake_run(args, check=False, env=None, **kwargs):
        calls.append((args, env))
        if args[:2] == ["git", "clone"]:
            os.makedirs(os.path.join(args[-1], ".git"))
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(gl_service.subprocess, "run", fake_run)

    assert gl_service.clone_gitlab_project_code("grp/proj", "main", 1, 10, "abc") is True

    args, env = calls[-1]
    assert args == ["git", "clone", "--filter=blob:none", "--branch", "main", "--single-branch",
                    "https://gitlab.example/grp/proj.git/", "code/1/10/abc"]
    assert not any("glpat-test-token" in a for a in args)
    assert env["GIT_CONFIG_KEY_0"] == "http.https://gitlab.example/.extraHeader"
    assert env["GIT_CONFIG_VALUE_0"].startswith("Authorization: Basic ")
    # nothing written to disk: no credential store, no .gitconfig
    assert not (tmp_path / "home").exists()


@pytest.mark.parametrize("stderr, reason, permanent", [
    (b"Cloning into 'code/1/11/abc'...\nfatal: Remote branch release/2024-11 not found in upstream origin\n",
     "remote branch not found in upstream origin (deleted?)", True),
    (b"fatal: couldn't find remote ref refs/heads/feature\n", "remote ref not found (branch deleted?)", True),
    (b"remote: The project you were looking for could not be found or you don't have permission to view it.\n"
     b"fatal: repository 'https://gitlab.example/grp/proj.git/' not found\n",
     "repository not found (deleted, or not visible to the scanner's token)", True),
    (b"fatal: unable to access 'https://gitlab.example/grp/proj.git/': Could not resolve host: gitlab.example\n",
     "git clone failed: fatal: unable to access '<repo>': Could not resolve host: gitlab.example", False),
    (b"", "git clone failed with exit code 128", False),
    (b"error: unable to write file src/big.bin\nfatal: cannot create directory at 'src': No space left on device\n",
     "git clone failed: no space left on device (see WORKSPACE_DIR / WORKSPACE_MIN_FREE_GB)", False),
])
def test_clone_failure_raises_the_git_reason(scanner, monkeypatch, tmp_path, stderr, reason, permanent):
    """A failed clone is not a bare False any more: the last fatal line of git tells why, and a deleted
    branch / repository is permanent (the job is not retried)."""
    from services.failures import ScanError

    gl_service = scanner.use_real("services.gl_service")
    monkeypatch.chdir(tmp_path)

    def fake_run(args, check=False, env=None, **kwargs):
        assert kwargs.get("capture_output") is True            # stderr is read, not inherited
        raise subprocess.CalledProcessError(128, args, output=b"", stderr=stderr)

    monkeypatch.setattr(gl_service.subprocess, "run", fake_run)
    with pytest.raises(ScanError) as err:
        gl_service.clone_gitlab_project_code("grp/proj", "release/2024-11", 1, 11, "abc")
    assert str(err.value) == reason
    assert err.value.permanent is permanent


def test_clone_timeout_and_secrets_in_git_output(scanner, monkeypatch, tmp_path):
    from services.failures import ScanError

    gl_service = scanner.use_real("services.gl_service")
    monkeypatch.chdir(tmp_path)

    def timeout(args, check=False, env=None, **kwargs):
        raise subprocess.TimeoutExpired(args, kwargs.get("timeout", 600))

    monkeypatch.setattr(gl_service.subprocess, "run", timeout)
    with pytest.raises(ScanError, match=r"^git clone timed out after \d+s$") as err:
        gl_service.clone_gitlab_project_code("grp/proj", "main", 1, 10, "abc")
    assert err.value.permanent is False

    # a token in git's output (a misconfigured remote with userinfo, a leaked header) never reaches the reason
    def leaky(args, check=False, env=None, **kwargs):
        raise subprocess.CalledProcessError(128, args, stderr=(
            b"fatal: unable to access 'https://git:glpat-SECRET-token-value-1234@gitlab.example/grp/proj.git/': "
            b"The requested URL returned error: 500\nAuthorization: Basic Z2l0OnNlY3JldA==\n"))

    monkeypatch.setattr(gl_service.subprocess, "run", leaky)
    with pytest.raises(ScanError) as err:
        gl_service.clone_gitlab_project_code("grp/proj", "main", 1, 10, "abc")
    assert "glpat" not in str(err.value) and "Z2l0" not in str(err.value) and "git:" not in str(err.value)
    assert str(err.value).startswith("git clone failed: fatal: unable to access 'https://***@gitlab.example/grp/proj.git/'")


def test_project_prefix_matches_path_segments(scanner):
    gl_service = scanner.use_real("services.gl_service")
    match = gl_service.project_matches_prefix
    assert match("grp/payments", "grp/payments") and match("grp/payments", "grp/") and match("grp/payments", "grp")
    assert match("grp/payments/sub", "grp/payments")                     # subgroup of a project-like path
    assert not match("grp/payments-tools", "grp/payments")
    assert not match("grpx/a", "grp/") and not match("grpx/a", "grp")
    assert match("grp/payments-tools", "grp/payments*")                  # explicit string prefix


def test_projects_list_star_prefix_searches_without_star(scanner):
    gl_service = scanner.use_real("services.gl_service")
    client = gl_service.get_gitlab_client()
    searches = []
    client.projects.list = lambda **kw: searches.append(kw["search"]) or [
        SimpleNamespace(path_with_namespace="grp/proj"), SimpleNamespace(path_with_namespace="grp/proj-tools")]

    assert [p.path_with_namespace for p in gl_service.get_gitlab_projects_list("grp/proj")] == ["grp/proj"]
    assert len(gl_service.get_gitlab_projects_list("grp/proj*")) == 2
    assert searches == ["grp/proj", "grp/proj"]



def test_clone_shallow_for_mains(scanner, monkeypatch, tmp_path):
    gl_service = scanner.use_real("services.gl_service")
    monkeypatch.chdir(tmp_path)
    calls = []

    def fake_run(args, check=False, env=None, **kwargs):
        calls.append(args)
        if args[:2] == ["git", "clone"]:
            os.makedirs(os.path.join(args[-1], ".git"))
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(gl_service.subprocess, "run", fake_run)
    assert gl_service.clone_gitlab_project_code("grp/proj", "main", 1, 10, "abc", shallow=True) is True
    assert calls[-1][:6] == ["git", "clone", "--depth", "1", "--branch", "main"]
    assert gl_service.clone_gitlab_project_code("grp/proj", "feature", 1, 11, "def") is True
    assert "--depth" not in calls[-1]                                     # MR sources keep their history
    assert "--filter=blob:none" in calls[-1]                              # ... as a partial clone

    scanner.setenv(GIT_PARTIAL_CLONE="false")
    assert gl_service.clone_gitlab_project_code("grp/proj", "feature", 1, 12, "fed") is True
    assert "--filter=blob:none" not in calls[-1]


def _clone_recorder(gl_service, monkeypatch):
    calls = []

    def fake_run(args, check=False, env=None, **kwargs):
        calls.append(args)
        if args[:2] == ["git", "clone"]:
            os.makedirs(os.path.join(args[-1], ".git"))
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(gl_service.subprocess, "run", fake_run)
    return calls


def test_clone_refused_when_the_workspace_disk_is_low(scanner, monkeypatch, tmp_path):
    """No clone starts below WORKSPACE_MIN_FREE_GB: a transient failure with the cause, nothing cloned."""
    from services.failures import ScanError

    gl_service = scanner.use_real("services.gl_service")
    monkeypatch.chdir(tmp_path)
    calls = _clone_recorder(gl_service, monkeypatch)
    free = {"bytes": 2 * 1024 ** 3}
    monkeypatch.setattr(gl_service, "free_bytes", lambda directory: free["bytes"])

    scanner.setenv(WORKSPACE_MIN_FREE_GB="5")
    with pytest.raises(ScanError) as err:
        gl_service.clone_gitlab_project_code("grp/proj", "main", 1, 10, "abc", shallow=True)
    assert str(err.value) == "not enough disk space for a clone: 2.0 GB free in the workspace, WORKSPACE_MIN_FREE_GB=5"
    assert err.value.permanent is False
    assert calls == []

    free["bytes"] = 6 * 1024 ** 3
    assert gl_service.clone_gitlab_project_code("grp/proj", "main", 1, 10, "abc", shallow=True) is True

    free["bytes"] = 0
    scanner.setenv(WORKSPACE_MIN_FREE_GB="0")                            # 0: no check
    assert gl_service.clone_gitlab_project_code("grp/proj", "main", 1, 11, "abd", shallow=True) is True


def test_free_bytes_uses_the_nearest_existing_parent(scanner, tmp_path):
    gl_service = scanner.use_real("services.gl_service")
    assert gl_service.free_bytes(str(tmp_path / "not" / "yet" / "there")) > 0


def test_clone_refused_for_a_repository_above_the_limit(scanner, monkeypatch, tmp_path):
    """SCAN_MAX_REPO_MB: the size GitLab reports decides before the clone; a permanent failure. Missing
    statistics or a GitLab error do not block the clone."""
    from services.failures import ScanError

    gl_service = scanner.use_real("services.gl_service")
    monkeypatch.chdir(tmp_path)
    scanner.setenv(GITLAB_CACHE_TTL_S="0", SCAN_MAX_REPO_MB="100", WORKSPACE_MIN_FREE_GB="0")
    calls = _clone_recorder(gl_service, monkeypatch)
    answers = {}
    asked = []

    def project_get(project_path, statistics=False, **kw):
        asked.append((project_path, statistics))
        answer = answers[project_path]
        if isinstance(answer, Exception):
            raise answer
        return SimpleNamespace(statistics=answer)

    gl_service.get_gitlab_client().projects.get = project_get

    answers["grp/huge"] = {"repository_size": 300 * 1024 ** 2}
    with pytest.raises(ScanError) as err:
        gl_service.clone_gitlab_project_code("grp/huge", "main", 1, 10, "abc", shallow=True)
    assert str(err.value) == "repository too large: 300 MB, SCAN_MAX_REPO_MB=100"
    assert err.value.permanent is True
    assert calls == [] and asked == [("grp/huge", True)]

    answers["grp/small"] = {"repository_size": 10 * 1024 ** 2}
    answers["grp/nostats"] = None                                         # no Reporter access
    answers["grp/error"] = RuntimeError("502 Bad Gateway")
    for i, project in enumerate(["grp/small", "grp/nostats", "grp/error"]):
        assert gl_service.clone_gitlab_project_code(project, "main", 2, 20 + i, "abc", shallow=True) is True
    assert len(calls) == 3


def _counting_client(gl_service):
    calls = []
    client = gl_service.get_gitlab_client()

    def project_get(project_id, lazy=False):
        calls.append(project_id)
        time.sleep(0.02)
        if project_id == 404:
            raise RuntimeError("not found")
        return SimpleNamespace(id=project_id)

    client.projects.get = project_get
    return calls


def _cached_read(gl_service):
    return gl_service.cached("test_project")(lambda project_id: gl_service.get_gitlab_client().projects.get(project_id))


def test_gitlab_reads_are_cached_in_memory_until_the_ttl(scanner, monkeypatch):
    gl_service = scanner.use_real("services.gl_service")
    calls = _counting_client(gl_service)
    read = _cached_read(gl_service)
    now = [1000.0]
    monkeypatch.setattr(gl_service.time, "monotonic", lambda: now[0])

    assert read(7).id == 7
    assert read(7).id == 7
    read(8)
    assert calls == [7, 8]                                   # one request per unique read
    now[0] += 299
    read(7)
    assert calls == [7, 8]
    now[0] += 2                                              # older than GITLAB_CACHE_TTL_S (300)
    read(7)
    assert calls == [7, 8, 7]


def test_gitlab_cache_concurrency_errors_and_off_switch(scanner):
    gl_service = scanner.use_real("services.gl_service")
    calls = _counting_client(gl_service)
    read = _cached_read(gl_service)

    threads = [threading.Thread(target=read, args=(5,)) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert calls == [5]                                      # concurrent misses: one request

    for _ in range(2):
        with pytest.raises(RuntimeError):
            read(404)
    assert calls.count(404) == 2                             # errors are not cached

    scanner.setenv(GITLAB_CACHE_TTL_S="0")
    read(9)
    read(9)
    assert calls.count(9) == 2


def test_gitlab_cache_is_bounded(scanner, monkeypatch):
    gl_service = scanner.use_real("services.gl_service")
    calls = _counting_client(gl_service)
    read = _cached_read(gl_service)
    monkeypatch.setattr(gl_service, "CACHE_MAX_ENTRIES", 2)
    for project_id in (1, 2, 3, 1):
        read(project_id)
    assert calls == [1, 2, 3, 1]                             # 1 was evicted (least recently used)


def test_sync_reads_of_branches_and_mrs_are_never_cached(scanner):
    # a push after a cached read would otherwise be marked processed without a scan
    gl_service = scanner.use_real("services.gl_service")
    calls = _counting_client(gl_service)
    client = gl_service.get_gitlab_client()
    heads = ["c1"]
    project = lambda project_id, lazy=False: calls.append(project_id) or SimpleNamespace(  # noqa: E731
        id=project_id, default_branch="main",
        branches=SimpleNamespace(list=lambda all=True: [SimpleNamespace(name="main", commit={"id": heads[0]})],
                                 get=lambda name: SimpleNamespace(name=name, commit={"id": heads[0]})),
        mergerequests=SimpleNamespace(list=lambda **kw: iter([SimpleNamespace(iid=1, sha=heads[0])])))
    client.projects.get = project

    assert gl_service.get_gitlab_branches_by_project(7)[0].commit["id"] == "c1"
    assert gl_service.get_gitlab_mrs_by_project(7)[0].sha == "c1"
    assert gl_service.get_gitlab_branches(project(7), ["main"])[0].commit["id"] == "c1"
    heads[0] = "c2"                                          # pushed within GITLAB_CACHE_TTL_S
    assert gl_service.get_gitlab_branches_by_project(7)[0].commit["id"] == "c2"
    assert gl_service.get_gitlab_mrs_by_project(7)[0].sha == "c2"
    assert gl_service.get_gitlab_branches(project(7), ["main"])[0].commit["id"] == "c2"
    assert gl_service.get_gitlab_project(7).id == 7
    assert calls == [7, 7, 7, 7, 7, 7, 7]


def test_sync_reads_only_the_tracked_branches_and_batches_the_mr_states(scanner):
    """The sync asks GitLab for the default branch and the MR branches by name (not every branch of the repository,
    20 per page) and for the states of the MRs that left the open list in one call per 100."""
    gl_service = scanner.use_real("services.gl_service")
    client = gl_service.get_gitlab_client()
    import gitlab
    asked, listed = [], []

    def get_branch(name):
        asked.append(name)
        if name == "gone":
            error = gitlab.exceptions.GitlabGetError("404 Branch Not Found")
            error.response_code = 404
            raise error
        return SimpleNamespace(name=name)

    def list_mrs(**kw):
        listed.append(kw)
        return iter([SimpleNamespace(iid=i, state="merged" if i % 2 else "closed") for i in kw["iids"]])

    project = SimpleNamespace(id=7, branches=SimpleNamespace(get=get_branch), mergerequests=SimpleNamespace(list=list_mrs))
    client.projects.get = lambda project_id, lazy=False: project

    branches = gl_service.get_gitlab_branches(project, ["main", "feature", "main", "gone", None])
    assert [b.name for b in branches] == ["main", "feature"] and asked == ["main", "feature", "gone"]

    states = gl_service.get_gitlab_mr_states(7, list(range(1, 151)) + [1])
    assert len(states) == 150 and states[1] == "merged" and states[2] == "closed"
    assert [len(kw["iids"]) for kw in listed] == [100, 50] and all(kw["state"] == "all" for kw in listed)
    assert gl_service.get_gitlab_mr_states(7, []) == {}


def test_the_scanner_never_writes_to_gitlab():
    """Read-only GitLab (a read_api + read_repository token is enough): no MR notes, discussions, labels,
    statuses or pushes in the services that talk to GitLab (python-gitlab client or git)."""
    import re
    from pathlib import Path

    write = re.compile(r"\.(notes|discussions|labels|statuses|commits)\.(create|update|delete)\b|\.save\(\)"
                       r"|\.delete\(\)|add_gitlab_comment|\bgit\b[^\n]*\bpush\b|http_(post|put|delete)\(")
    services = Path(__file__).resolve().parents[1] / "services"
    sources = {p.name: p.read_text() for p in sorted(services.glob("*.py"))}
    gitlab_users = [name for name, text in sources.items()
                    if re.search(r"^import gitlab|get_gitlab_client\(|git_auth_env", text, re.M)]
    assert "gl_service.py" in gitlab_users
    offenders = [f"{name}: {m.group(0)}" for name in gitlab_users for m in write.finditer(sources[name])]
    assert offenders == []
