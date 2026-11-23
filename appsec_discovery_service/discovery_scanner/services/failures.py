"""Why a scan step failed, carried to the job's ``last_error`` (and the UI) instead of a log line.

``ScanError(reason, permanent=...)`` is raised at the point that knows the cause (a git clone,
a parser, an LLM rule run) and travels up to the job handler, which adds the subject
(``as_job_error("scan of 'grp/proj', MR !25")``): ``last_error`` then reads
``scan of 'grp/proj', MR !25: cannot clone source branch 'release/x': remote branch not found
in upstream origin (deleted?)``. ``permanent``: retrying cannot help (the branch is gone, the
configuration is wrong): the handler raises ``jobs.PermanentJobError`` so the job fails at once.

Variable parts (project paths, branch names, object names) are put in single quotes: the
``GET /jobs/errors`` grouping of the API replaces quoted parts, ids and hashes by ``#``, so the
failures of one cause on many subjects are one row of the Pipeline health page. Credentials
never get into a reason (``redact.strip_secrets``; git never prints the token: it is passed as
a header through the environment, see ``config.git_auth_env``).
"""

import re
import subprocess
from typing import Optional, Tuple

from discovery_common import jobs
from discovery_common.redact import describe, one_line, strip_secrets

REASON_MAX = 500


class ScanError(jobs.JobError):
    """A scan / LLM run step that failed for a known reason; ``permanent``: no retry can help."""

    def __init__(self, reason: str, *, permanent: bool = False):
        super().__init__(one_line(strip_secrets(reason), REASON_MAX))
        self.permanent = permanent

    @property
    def reason(self) -> str:
        return str(self)

    def prefixed(self, context: str) -> "ScanError":
        """The same failure with ``context`` in front (``cannot clone source branch 'x': ...``)."""
        return ScanError(f"{context}: {self.reason}", permanent=self.permanent)

    def as_job_error(self, context: str) -> jobs.JobError:
        """What the job handler raises: ``PermanentJobError`` (fails at once) or this error, with
        the job's subject in front: ``scan of 'grp/proj', MR !25: <reason>``."""
        message = f"{context}: {self.reason}" if context else self.reason
        return jobs.PermanentJobError(message) if self.permanent else ScanError(message)


def scan_error(exc: BaseException, context: Optional[str] = None) -> ScanError:
    """Any exception as a ``ScanError`` (a ``ScanError`` keeps its flag; ``RequeueJob`` must not get here)."""
    if isinstance(exc, ScanError):
        return exc.prefixed(context) if context else exc
    reason = describe(exc)
    return ScanError(f"{context}: {reason}" if context else reason)


# ---- git -------------------------------------------------------------------------------------

# stderr lines of git that mean the ref is gone: nothing to retry (the MR source branch was deleted,
# the repository was removed or is not visible to the token)
_MISSING_REF = (
    (re.compile(r"Remote branch .+ not found in upstream", re.I), "remote branch not found in upstream origin (deleted?)"),
    (re.compile(r"couldn't find remote ref", re.I), "remote ref not found (branch deleted?)"),
    (re.compile(r"repository .* not found|could not be found|not found(?:\.|$)", re.I),
     "repository not found (deleted, or not visible to the scanner's token)"),
    (re.compile(r"Authentication failed|HTTP 401|returned error: 401|403", re.I),
     "access denied by GitLab (the scanner's token has no access, or it expired)"),
)


def git_stderr_line(output) -> str:
    """The last meaningful stderr line of a git command (``fatal: ...`` preferred), redacted."""
    text = output.decode(errors="replace") if isinstance(output, bytes) else (output or "")
    lines = [line.strip() for line in str(text).splitlines() if line.strip()]
    lines = [line for line in lines if not line.lower().startswith("cloning into")]
    if not lines:
        return ""
    fatal = [line for line in lines if line.lower().startswith(("fatal:", "error:"))]
    return one_line(strip_secrets((fatal or lines)[-1]), REASON_MAX)


def git_failure(exc: BaseException, *, repo_url: Optional[str] = None, branch: Optional[str] = None,
                what: str = "git clone") -> Tuple[str, bool]:
    """``(reason, permanent)`` of a failed git subprocess: the last ``fatal:`` line of its stderr
    (the repository URL and the branch name replaced, so the reason groups across subjects),
    a missing ref / repository is permanent; a timeout or anything else is transient."""
    if isinstance(exc, subprocess.TimeoutExpired):
        return f"{what} timed out after {int(exc.timeout)}s", False
    stderr = getattr(exc, "stderr", None) or getattr(exc, "output", None) or ""
    line = git_stderr_line(stderr)
    if re.search(r"No space left on device|disk quota exceeded", line, re.I):
        return f"{what} failed: no space left on device (see WORKSPACE_DIR / WORKSPACE_MIN_FREE_GB)", False
    for pattern, meaning in _MISSING_REF:
        if pattern.search(line):
            return meaning, meaning.startswith(("remote", "repository"))
    if repo_url:
        line = line.replace(repo_url, "<repo>").replace(repo_url.rstrip("/"), "<repo>")
    if branch:
        line = line.replace(f"'{branch}'", "'<branch>'").replace(branch, "'<branch>'")
    code = getattr(exc, "returncode", None)
    if line:
        return f"{what} failed: {line}", False
    return f"{what} failed" + (f" with exit code {code}" if code is not None else " (no output)"), False


# ---- parsers ---------------------------------------------------------------------------------

def parser_failures(errors) -> str:
    """``parser 'golang' failed: <error>; parser 'swagger' failed: <error>`` from the core scan's
    ``{parser: error}``."""
    parts = []
    for parser, error in sorted((errors or {}).items()):
        text = one_line(strip_secrets(str(error)), 200)
        parts.append(f"parser '{parser}' failed" + (f": {text}" if text else ""))
    return "; ".join(parts) or "a parser failed"
