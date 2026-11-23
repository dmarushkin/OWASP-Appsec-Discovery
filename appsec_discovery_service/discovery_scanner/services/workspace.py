"""Per-job checkout workspace (P2-4).

Every job that clones code runs inside ``job_workspace(job_id)``: a fresh
``tempfile.mkdtemp`` directory, removed in ``finally`` when the job ends (success or not).
Clones of the job go to ``<workspace>/<project_id>/<branch_id>/<commit>``
(``checkout_dir``), so concurrent jobs never share or delete each other's checkouts (the
old shared ``./code`` cache could be removed by ``clean_cache`` while still cloning).

The directory name carries the worker's pid (``job<id>-<pid>-...``): when a worker dies
before its ``finally`` ran, the supervisor removes what it left (``remove_leftovers``).
Outside a job (tests, one-off calls) ``checkout_dir`` falls back to ``./code``.
"""

import glob
import os
import shutil
import tempfile
from contextlib import contextmanager
from typing import Iterator, Optional

from logger import get_logger

logger = get_logger(__name__)

DEFAULT_ROOT = "code"
BASE_NAME = "discovery-jobs"

_root: Optional[str] = None


def base_dir(configured: Optional[str] = None) -> str:
    """Parent directory of all job workspaces (WORKSPACE_DIR or <tmp>/discovery-jobs)."""
    return configured or os.path.join(tempfile.gettempdir(), BASE_NAME)


def current() -> Optional[str]:
    """The workspace of the running job, None outside a job."""
    return _root


def checkout_dir(project_id, branch_id, commit) -> str:
    return os.path.join(_root or DEFAULT_ROOT, str(project_id), str(branch_id), str(commit))


@contextmanager
def job_workspace(job_id, configured_base: Optional[str] = None) -> Iterator[str]:
    """``with job_workspace(job.id) as path:`` - checkouts of this job go under ``path``,
    which is removed afterwards."""
    global _root
    base = base_dir(configured_base)
    os.makedirs(base, exist_ok=True)
    path = tempfile.mkdtemp(prefix=f"job{job_id}-{os.getpid()}-", dir=base)
    previous, _root = _root, path
    try:
        yield path
    finally:
        _root = previous
        shutil.rmtree(path, ignore_errors=True)
        if os.path.exists(path):
            logger.error(f"Workspace {path} could not be removed")


def remove_leftovers(pid: Optional[int] = None, configured_base: Optional[str] = None) -> int:
    """Remove workspaces left by the dead worker ``pid`` (all of them when None: only safe
    while no worker runs, i.e. at supervisor start-up). Returns the number removed."""
    pattern = f"job*-{pid}-*" if pid is not None else "job*-*"
    removed = 0
    for path in glob.glob(os.path.join(base_dir(configured_base), pattern)):
        shutil.rmtree(path, ignore_errors=True)
        removed += 1
    if removed:
        logger.info(f"Removed {removed} leftover job workspaces" + (f" of worker pid {pid}" if pid else ""))
    return removed
