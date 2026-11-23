import functools
import threading
import time
from collections import OrderedDict
from typing import Optional

import gitlab
from config import get_settings, git_auth_env
import subprocess
import os
import shutil
from logger import get_logger
from os import path, listdir
from discovery_common.redact import strip_secrets
from services.failures import ScanError, git_failure
from services.workspace import checkout_dir

logger = get_logger(__name__)

# GitLab client, created lazily and once per process (it holds a requests session, which
# must not be shared across the scanner's forked workers).
_gl = None
_gl_pid = None


def get_gitlab_client():

    global _gl, _gl_pid

    if _gl is None or _gl_pid != os.getpid():
        settings = get_settings()
        _gl = gitlab.Gitlab(settings.gitlab_base_url, private_token=settings.gitlab_token.get_secret_value(),
                            timeout=settings.gitlab_timeout_s, retry_transient_errors=True)
        _gl_pid = os.getpid()

    return _gl

def project_matches_prefix(project_path: str, prefix: str) -> bool:
    """GITLAB_PROJECTS_PREFIX entry match on path segments: ``grp/`` (or ``grp``) is a
    namespace and matches every project below it; ``grp/proj`` matches that project (and
    projects of a ``grp/proj`` subgroup) but not ``grp/proj-tools``. A trailing ``*`` keeps
    the plain string prefix: ``grp/proj*`` also matches ``grp/proj-tools``."""
    if prefix.endswith("*"):
        return project_path.startswith(prefix[:-1])
    prefix = prefix.rstrip("/")
    return project_path == prefix or project_path.startswith(prefix + "/")


# ---- in-memory cache of GitLab reads ---------------------------------------------------------
# Per process: GitLab is read by the control worker (project list, MR states), so a unique
# read goes out at most once per GITLAB_CACHE_TTL_S there. The per-project sync reads
# (project, branches, open MRs) are not cached, see get_gitlab_branches_by_project. Scan workers (language detection)
# and other scanner replicas keep their own cache; a restarted worker starts empty.

CACHE_MAX_ENTRIES = 10_000
_cache: "OrderedDict[str, tuple]" = OrderedDict()
_cache_lock = threading.Lock()
_key_locks: dict = {}


def cached(kind: str):
    """Cache a GitLab read in memory for ``GITLAB_CACHE_TTL_S`` (0 disables): at most one request
    per unique (kind, arguments) per TTL in this process; concurrent misses of the same key
    wait for the first one. Errors of GitLab are not cached. Lazy results are materialised."""
    def decorate(fn):
        @functools.wraps(fn)
        def wrapper(*args):
            ttl = get_settings().gitlab_cache_ttl_s
            if ttl <= 0:
                return fn(*args)
            key = f"{kind}:{args!r}"

            def fresh():
                entry = _cache.get(key)
                if entry is not None and time.monotonic() - entry[0] < ttl:
                    _cache.move_to_end(key)
                    return True, entry[1]
                return False, None

            with _cache_lock:
                hit, value = fresh()
                if hit:
                    return value
                key_lock = _key_locks.setdefault(key, threading.Lock())
            with key_lock:
                with _cache_lock:
                    hit, value = fresh()          # filled while we waited
                    if hit:
                        return value
                value = fn(*args)
                with _cache_lock:
                    _cache[key] = (time.monotonic(), value)
                    _cache.move_to_end(key)
                    while len(_cache) > CACHE_MAX_ENTRIES:
                        old, _ = _cache.popitem(last=False)
                        _key_locks.pop(old, None)
                return value
        return wrapper
    return decorate


@cached("projects_list")
def get_gitlab_projects_list(search_prefix):

    logger.info(f"Fetching projects from GitLab for prefix {search_prefix}")

    projects = get_gitlab_client().projects.list(iterator=True, search_namespaces=True, search=search_prefix.rstrip("*"))

    filtered_projects = [proj for proj in projects if project_matches_prefix(proj.path_with_namespace, search_prefix)]

    logger.info(f"Fetched {len(filtered_projects)} projects.")

    return filtered_projects

# Not cached: project, branches and open MRs are read by sync_branches_mrs only, i.e. once per
# changed project, and its result decides what is marked processed (processed_at = the project's
# updated_at). A cached read from before a push would mark the push processed without a scan.

def get_gitlab_branches_by_project(project_id):
    """Every branch of a project (``branches.list(all=True)``: one page of 20 per call). The sync does not use
    it any more (``get_gitlab_branches``: only the branches it tracks); kept for tools and tests."""

    project = get_gitlab_client().projects.get(project_id, lazy=True)
    return project.branches.list(all=True)


def get_gitlab_branches(project_gl, names) -> list:
    """The branches ``names`` of a GitLab project object (``projects.get`` result or a lazy one), one
    ``GET /projects/:id/repository/branches/:name`` each, in the given order, duplicates and the branches GitLab
    does not know (deleted meanwhile: 404) left out. The sync reads only the default branch and the branches of
    the open MRs this way instead of listing every branch of the repository (hundreds, 20 per page)."""

    branches = []
    for name in dict.fromkeys(n for n in names if n):
        try:
            branches.append(project_gl.branches.get(name))
        except gitlab.exceptions.GitlabGetError as e:
            if getattr(e, "response_code", None) == 404:
                logger.info(f"Branch {name!r} of project {getattr(project_gl, 'id', '?')} is gone, skipped")
                continue
            raise
    return branches


def get_gitlab_mrs_by_project(project_id):
    """Fetch the open MRs of a given project ID from GitLab (not cached, see above); the project itself is not
    read again (``lazy``)."""

    project = get_gitlab_client().projects.get(project_id, lazy=True)
    return list(project.mergerequests.list(state='opened', order_by='updated_at', iterator=True, per_page=100))


MR_STATES_PER_CALL = 100


def get_gitlab_mr_states(project_id, iids) -> dict:
    """``{iid: state}`` of the MRs ``iids`` of a project in batches of ``MR_STATES_PER_CALL``
    (``GET /projects/:id/merge_requests?iids[]=...&state=all``) instead of one ``GET`` per MR; MRs GitLab does
    not list (deleted) are left out. Not cached: the states decide which source branches are released."""

    iids = [int(i) for i in dict.fromkeys(iids)]
    if not iids:
        return {}
    project = get_gitlab_client().projects.get(project_id, lazy=True)
    states = {}
    for start in range(0, len(iids), MR_STATES_PER_CALL):
        chunk = iids[start:start + MR_STATES_PER_CALL]
        for mr in project.mergerequests.list(iids=chunk, state='all', per_page=MR_STATES_PER_CALL, iterator=True):
            states[int(mr.iid)] = mr.state
    return states

def get_gitlab_project(project_id):
    """GitLab project by its GitLab id (``gitlab_projects.gitlab_id``); not cached (its
    ``default_branch`` decides which branch is main)."""

    return get_gitlab_client().projects.get(project_id)

@cached("mr_state")
def get_gitlab_mr_state(project_id, mr_iid):
    """Current state of an MR ('opened', 'merged', 'closed', ...)."""

    project = get_gitlab_client().projects.get(project_id, lazy=True)
    return project.mergerequests.get(mr_iid).state

def get_gitlab_compare(gitlab_project, from_commit, to_commit, straight=True) -> dict:
    """The GitLab compare of two commits (``GET /projects/:id/repository/compare``), raw: ``diffs``
    (``old_path`` / ``new_path`` / ``new_file`` / ``renamed_file`` / ``deleted_file``), ``commits``,
    ``compare_timeout``, ``compare_same_ref``. ``straight``: ``git diff from to`` (the exact difference of
    the two trees; the default); False: ``from`` the merge-base with ``to``, as ``git diff base...to``
    (what an MR changes). ``gitlab_project``: the GitLab project id or path. Not cached (every pair
    is asked once); errors propagate (``services.diff_service`` falls back to a full scan)."""

    project = get_gitlab_client().projects.get(gitlab_project, lazy=True)
    # the flag goes out as a query parameter: GitLab wants true / false, not Python's True
    return project.repository_compare(from_commit, to_commit, straight="true" if straight else "false")


def get_gitlab_merge_base(gitlab_project, commits) -> Optional[str]:
    """The merge base of ``commits`` (``GET /projects/:id/repository/merge_base``), or None when
    they have no common ancestor (GitLab answers 404 then)."""

    project = get_gitlab_client().projects.get(gitlab_project, lazy=True)
    try:
        result = project.repository_merge_base(list(commits))
    except gitlab.exceptions.GitlabGetError as e:
        if getattr(e, "response_code", None) == 404:
            return None
        raise
    return (result or {}).get("id") if isinstance(result, dict) else getattr(result, "id", None)


def free_bytes(directory: str) -> int:
    """Free bytes of the file system that holds ``directory`` (its nearest existing parent)."""
    probe = os.path.abspath(directory)
    while not os.path.exists(probe) and os.path.dirname(probe) != probe:
        probe = os.path.dirname(probe)
    return shutil.disk_usage(probe).free


@cached("repository_size")
def get_gitlab_repository_size(project_path) -> Optional[int]:
    """The repository size GitLab reports (``statistics.repository_size``, bytes: the whole history,
    so a shallow clone is smaller), None when the token cannot read the statistics."""
    project = get_gitlab_client().projects.get(project_path, statistics=True)
    stats = getattr(project, "statistics", None) or {}
    size = stats.get("repository_size") if isinstance(stats, dict) else None
    return int(size) if size is not None else None


def check_clone_limits(project_path, project_local_path) -> None:
    """Refuse a clone before it starts (``ScanError``):

    * WORKSPACE_MIN_FREE_GB: the file system of the workspace has less free space (clones share it
      with whatever else is on that disk, Postgres in a default compose): transient, the job is
      retried with backoff, the cause is shown on the Pipeline health page;
    * SCAN_MAX_REPO_MB: GitLab reports a larger repository: permanent, the job fails at once.
      A GitLab error or missing statistics (a token without Reporter access) does not block the clone."""
    settings = get_settings()
    gib = 1024 ** 3
    if settings.workspace_min_free_gb > 0:
        free = free_bytes(project_local_path)
        if free < settings.workspace_min_free_gb * gib:
            raise ScanError(f"not enough disk space for a clone: {free / gib:.1f} GB free in the workspace, "
                            f"WORKSPACE_MIN_FREE_GB={settings.workspace_min_free_gb:g}")
    if settings.scan_max_repo_mb > 0:
        try:
            size = get_gitlab_repository_size(project_path)
        except Exception as e:                      # the limit is a guard, not a reason to fail the scan
            logger.warning(strip_secrets(f"Cannot read the repository size of {project_path}: {e}"))
            size = None
        if size is not None and size > settings.scan_max_repo_mb * 1024 ** 2:
            raise ScanError(f"repository too large: {size / 1024 ** 2:.0f} MB, SCAN_MAX_REPO_MB="
                            f"{settings.scan_max_repo_mb}", permanent=True)


def clone_gitlab_project_code(project_path, branch_name, project_id, branch_id, branch_commit, shallow=False):
    """Clone ``branch_name`` into ``checkout_dir(project_id, branch_id, branch_commit)``: the
    running job's workspace (see ``services.workspace``). An existing non-empty checkout of
    the same commit is reused (an MR scan may need the target twice). Returns True; a failed
    clone raises ``ScanError`` with git's reason (``failures.git_failure``: the last ``fatal:``
    line, a deleted branch / repository is permanent, a timeout or network error is not)."""

    settings = get_settings()

    project_url = f"{settings.gitlab_base_url}/{project_path}.git/"

    project_local_path = checkout_dir(project_id, branch_id, branch_commit)

    # Check if code already exist
    if path.isdir(project_local_path) and listdir(path=project_local_path) :
        logger.info(f"Folder {project_local_path} already exists")
        return True

    check_clone_limits(project_path, project_local_path)

    # Clone the branch
    try:
        shutil.rmtree(project_local_path, ignore_errors=True)

        # shallow (--depth 1): main branches and MR targets only need the files; an MR source
        # keeps its history (merge-base with the target, see get_mr_changed_files) - as a partial
        # clone (GIT_PARTIAL_CLONE): all commits and trees, the file contents of the checkout only
        if shallow:
            depth = ["--depth", "1"]
        else:
            depth = ["--filter=blob:none"] if settings.git_partial_clone else []
        subprocess.run(["git", "clone", *depth, "--branch", branch_name, "--single-branch", project_url, project_local_path],
                       check=True, env=git_auth_env(settings), timeout=settings.git_timeout_s,
                       capture_output=True)

        if path.isdir(project_local_path) and listdir(path=project_local_path) :

            logger.info(f"Successfully cloned project {project_path}, branch {branch_name} to local path {project_local_path}")
            return True

        raise ScanError("git clone produced an empty checkout")

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        shutil.rmtree(project_local_path, ignore_errors=True)     # a partial checkout frees its space now
        reason, permanent = git_failure(e, repo_url=project_url, branch=branch_name)
        logger.error(f"Failed to clone {project_path}, branch {branch_name}: {reason}")
        raise ScanError(reason, permanent=permanent) from e


def get_mr_changed_files(project_id, source_branch_id, source_commit, target_branch, target_commit):
    """Files an MR changes: ``git diff --name-only <merge-base> HEAD`` in the source checkout.

    The MR delta is computed against the target snapshot at its head; when the source is
    behind the target, everything the target changed since the fork point would show up as
    MR changes. Restricting the delta to the files of this diff (what GitLab shows as the MR
    changes) removes that noise. The single-branch source clone gets the target branch with
    one fetch. Renames are reported as delete + add, so both paths are listed.

    Returns a set of repo-relative paths, or None when it cannot be computed (no git
    checkout, fetch failure, unrelated histories): the caller then keeps the full delta."""

    settings = get_settings()
    repo = checkout_dir(project_id, source_branch_id, source_commit)

    if not path.isdir(path.join(repo, ".git")):
        return None

    env = git_auth_env(settings)

    def git(*args):
        return subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True, text=True,
                              env=env, timeout=settings.git_timeout_s).stdout

    def has_commit(ref):
        try:
            git("cat-file", "-e", f"{ref}^{{commit}}")
            return True
        except subprocess.CalledProcessError:
            return False

    try:
        target_ref = target_commit if target_commit and has_commit(target_commit) else None

        if target_ref is None:
            remote_ref = f"refs/remotes/origin/{target_branch}"
            git("fetch", "--no-tags", "--quiet", "origin", f"+refs/heads/{target_branch}:{remote_ref}")
            # the MR's target commit, or the target head when that commit is gone (force push)
            target_ref = target_commit if target_commit and has_commit(target_commit) else remote_ref

        base = git("merge-base", "HEAD", target_ref).strip()
        out = git("diff", "--name-only", "--no-renames", "-z", base, "HEAD")

        return {p for p in out.split("\0") if p}

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        stderr = getattr(e, "stderr", None)
        logger.warning(strip_secrets(f"Cannot get the MR changes vs {target_branch} in {repo}: {e} {stderr or ''}".strip()))
        return None


@cached("project_lang")
def get_gitlab_project_lang(project_path, branch_name):

    lang = 'other'

    project = None

    file = None

    try:
        project = get_gitlab_client().projects.get(project_path)
    except gitlab.exceptions.GitlabGetError:
        logger.info(f"Detected lang for project {project_path} is {lang}")
        return lang

    if 'terraform' in project_path:

        lang = "tf"
        logger.info(f"Detected lang for project {project_path} is {lang}")

        return lang

    try:
        file = project.files.get(file_path='go.mod', ref=branch_name)
    except gitlab.exceptions.GitlabGetError:
        pass

    if file:
        lang = "go"
        logger.info(f"Detected lang for project {project_path} is {lang}")

        return lang
    
    try:
        file = project.files.get(file_path='package.json', ref=branch_name)
    except gitlab.exceptions.GitlabGetError:
        pass

    if file:
        lang = "js"
        logger.info(f"Detected lang for project {project_path} is {lang}")

        return lang
    
    return lang
