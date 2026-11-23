"""Diff-based scan skip (README "Service mode", SCAN_DIFF_SKIP).

Every new commit of a main branch used to mean a full clone and every parser. Most commits
touch no file a parser reads (docs, CI, tests of other languages, vendored code), so before
cloning the scanner asks the GitLab compare API (polling: there are no webhooks) which files
changed since the commit the snapshot reflects (``gitlab_branches.scanned_commit``) and checks
them against the files the parsers of the scan declare (core ``Parser.file_patterns``,
``appsec_discovery.affected_parsers``). When no changed file matters, the snapshot is moved to
the new commit (``db_service.skip_branch_scan``: ``scanned_commit`` and a scan marker, the
objects / hits / LLM verdicts untouched, no LLM run) and the job ends in seconds with
``progress = {"phase": "skipped", "skipped": "no parser files changed", "changed_files": N}``.

A full scan happens anyway (``Decision.reason`` says why) when:

* the snapshot is missing, or was made with another scan configuration (``scan_fingerprint``:
  core package version, parsers, keyword rules and scan mode; stored with every full scan);
* the last full scan is older than SCAN_FULL_RESCAN_DAYS (0: never on time alone);
* the scanned commit is not an ancestor of the new one (force push / rebase: the merge base
  API says so), or the compare is truncated (``compare_timeout``, SCAN_DIFF_MAX_FILES files or
  more);
* a changed file matches SCAN_ALWAYS_RESCAN_GLOBS, or (SCAN_LANGS gate on) the files the
  language detection reads;
* the compare API fails for any reason: logged, the scan goes on as before - the shortcut never
  fails a job.

Merge requests (SCAN_DIFF_SKIP_MRS): the stored delta of an MR source branch is skipped only
when neither the source (since the scanned source commit) nor the target (since the target
commit the delta was computed against, ``delta_target_commit``) moved in parser files. A full
MR scan reuses the compare of the merge base with the target (``mr_changed_files``: the files
the MR changes, as ``git diff --name-only <merge-base> HEAD`` lists them) for the delta filter,
so the source is cloned shallow; the git diff in the checkout stays the fallback.

With SCAN_DIFF_SKIP=false nothing here is called: every commit is cloned and parsed as before.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional, Sequence, Set

import appsec_discovery
from appsec_discovery.changes import affected_parsers, normalize_path, path_matches

from discovery_common.redact import describe

from config import get_settings
from logger import get_logger
from services.gl_service import get_gitlab_compare, get_gitlab_merge_base

logger = get_logger(__name__)

NO_PARSER_FILES = "no parser files changed"

# files the SCAN_LANGS language detection reads (gl_service.get_gitlab_project_lang): a change to them
# can flip the gate, so they count as parser files while the gate is on
LANG_FILES = ("go.mod", "package.json")


@dataclass
class Compare:
    """The files that differ between two commits (``compare_paths``)."""
    paths: Set[str] = field(default_factory=set)      # old and new path of every diff entry, normalised
    count: int = 0                                      # diff entries GitLab returned
    truncated: bool = False                             # compare_timeout / overflow / at the file limit
    same_ref: bool = False


@dataclass
class Decision:
    """Whether a scan can be skipped, and why (not)."""
    skip: bool
    reason: str
    changed_files: Optional[int] = None

    @property
    def progress(self) -> dict:
        """What the job's progress says about a skip (``scan_branch`` / ``scan_mr`` phase ``skipped``)."""
        return {"reason": self.reason, "skipped": NO_PARSER_FILES, "changed_files": self.changed_files or 0}


def scan_fingerprint(rules_version: str, parsers: Optional[Iterable[str]]) -> str:
    """Digest of the scan configuration a snapshot is made with: the core package version (parsers and their
    file patterns change with it), the parsers setting and the scan marker's ``rules_version`` (storage version,
    keyword rules fingerprint, inventory mode). Stored in ``gitlab_branches.scan_fingerprint`` by every full scan;
    a snapshot made with another one is not moved by a skip."""
    parts = f"core={appsec_discovery.__version__}|rules={rules_version}|parsers={','.join(sorted(parsers or []))}"
    return hashlib.sha256(parts.encode()).hexdigest()[:16]


def compare_paths(gitlab_project, from_commit: str, to_commit: str, *, straight: bool, max_files: int) -> Compare:
    """The files GitLab's compare of ``from_commit`` and ``to_commit`` lists (``straight``: the exact difference of
    the trees; False: since their merge base). ``truncated`` when GitLab timed out or stopped at a limit (its own
    ``max_files`` / ``max_patch_bytes``, or ``max_files`` here): the list cannot be trusted then."""
    raw = get_gitlab_compare(gitlab_project, from_commit, to_commit, straight=straight) or {}
    diffs = raw.get("diffs") or []
    paths: Set[str] = set()
    for diff in diffs:
        for key in ("old_path", "new_path"):
            path = normalize_path((diff or {}).get(key) or "")
            if path:
                paths.add(path)
    truncated = bool(raw.get("compare_timeout")) or bool(raw.get("overflow")) or len(diffs) >= max_files
    return Compare(paths=paths, count=len(diffs), truncated=truncated, same_ref=bool(raw.get("compare_same_ref")))


def is_ancestor(gitlab_project, commit: str, descendant: str) -> bool:
    """True when ``commit`` is an ancestor of ``descendant`` (their merge base is ``commit``)."""
    if commit == descendant:
        return True
    base = get_gitlab_merge_base(gitlab_project, [commit, descendant])
    return base is not None and base == commit


def always_rescan_globs(settings) -> List[str]:
    globs = list(settings.scan_always_rescan_globs)
    langs = [lang.lower() for lang in settings.scan_langs]
    if langs and "all" not in langs:
        globs += list(LANG_FILES)
    return globs


def relevant_changes(paths: Iterable[str], parser_names: Sequence[str], settings) -> Optional[str]:
    """Why the changed ``paths`` need a full scan, or None when none of them can alter the objects of the
    parsers ``parser_names``: the parsers that read one of them (``appsec_discovery.affected_parsers``), the
    SCAN_ALWAYS_RESCAN_GLOBS and, with the SCAN_LANGS gate on, the files the language detection reads."""
    paths = [normalize_path(p) for p in paths]
    paths = [p for p in paths if p]
    if not paths:
        return None
    globs = always_rescan_globs(settings)
    forced = sorted(p for p in paths if path_matches(p, globs)) if globs else []
    if forced:
        return f"changed file '{forced[0]}' matches SCAN_ALWAYS_RESCAN_GLOBS"
    affected = affected_parsers(paths, list(parser_names))
    if affected:
        read = sorted(p for p in paths if affected_parsers([p], list(parser_names)))
        return f"{len(read)} of {len(paths)} changed files are read by parsers {', '.join(affected)}"
    return None


def _snapshot_reusable(branch, fingerprint: str, settings, what: str) -> Optional[str]:
    """Why the snapshot of ``branch`` cannot be moved by a skip at all (no commit, another configuration, too old),
    or None."""
    if not getattr(branch, "scanned_commit", None):
        return f"{what} has no snapshot yet"
    if getattr(branch, "scan_fingerprint", None) != fingerprint:
        return "scan configuration changed (core version, parsers or keyword rules)"
    days = settings.scan_full_rescan_days
    if days > 0:
        last = getattr(branch, "full_scanned_at", None)
        if last is None:
            return "no full scan recorded yet"
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - last > timedelta(days=days):
            return f"last full scan older than SCAN_FULL_RESCAN_DAYS={days}"
    return None


def _moved(gitlab_project, from_commit: str, to_commit: str, parser_names, settings, what: str,
           ancestry: bool = True):
    """``(reason, changed_files)``: why the move of ``what`` from ``from_commit`` to ``to_commit`` needs a full scan
    (None: no parser file changed), and how many files changed."""
    if from_commit == to_commit:
        return None, 0
    if ancestry and not is_ancestor(gitlab_project, from_commit, to_commit):
        return f"{what} commit '{from_commit[:12]}' is not an ancestor of '{to_commit[:12]}' (force push or rebase)", None
    compare = compare_paths(gitlab_project, from_commit, to_commit, straight=True, max_files=settings.scan_diff_max_files)
    if compare.truncated:
        return f"compare of {what} is truncated ({compare.count} files, SCAN_DIFF_MAX_FILES={settings.scan_diff_max_files})", compare.count
    return relevant_changes(compare.paths, parser_names, settings), len(compare.paths)


def decide_main(branch, to_commit: str, fingerprint: str, parser_names: Sequence[str], settings=None) -> Decision:
    """Can the scan of a main branch at ``to_commit`` be skipped (its snapshot at ``scanned_commit`` moved there)?
    Never raises: a GitLab error is a full scan with the reason logged."""
    settings = settings or get_settings()
    if not settings.scan_diff_skip:
        return Decision(False, "SCAN_DIFF_SKIP is off")
    reason = _snapshot_reusable(branch, fingerprint, settings, "branch")
    if reason:
        return Decision(False, reason)
    try:
        reason, changed = _moved(branch.project_path, branch.scanned_commit, to_commit, parser_names, settings, "branch")
    except Exception as e:      # the shortcut never fails the job
        reason = f"compare failed: {describe(e)}"
        logger.warning(f"Diff skip of {branch.project_path}, branch {branch.branch_name}: {reason}; full scan")
        return Decision(False, reason)
    if reason:
        return Decision(False, reason, changed)
    return Decision(True, NO_PARSER_FILES, changed)


def decide_mr(mr, source_branch, fingerprint: str, parser_names: Sequence[str], settings=None) -> Decision:
    """Can the rescan of an MR be skipped? Only when its source branch's delta can be reused at all (snapshot,
    configuration, age), and neither the source (since the scanned source commit) nor the target (since the commit
    the delta was computed against) moved in parser files. Never raises."""
    settings = settings or get_settings()
    if not (settings.scan_diff_skip and settings.scan_diff_skip_mrs):
        return Decision(False, "SCAN_DIFF_SKIP_MRS is off")
    reason = _snapshot_reusable(source_branch, fingerprint, settings, "source branch")
    if reason:
        return Decision(False, reason)
    delta_target = getattr(source_branch, "delta_target_commit", None)
    if not delta_target:
        return Decision(False, "the target commit of the stored delta is unknown")
    try:
        reason, changed = _moved(mr.project_path, source_branch.scanned_commit, mr.source_branch_commit, parser_names,
                                 settings, "source branch")
        if reason:
            return Decision(False, reason, changed)
        # the target: its snapshot may have moved (fully or by a skip); only its parser files matter
        target_reason, target_changed = _moved(mr.project_path, delta_target, mr.target_branch_commit, parser_names,
                                               settings, "target branch", ancestry=False)
    except Exception as e:
        reason = f"compare failed: {describe(e)}"
        logger.warning(f"Diff skip of {mr.project_path}, MR !{getattr(mr, 'mr_id', '?')}: {reason}; full scan")
        return Decision(False, reason)
    total = (changed or 0) + (target_changed or 0)
    if target_reason:
        return Decision(False, target_reason, total)
    return Decision(True, NO_PARSER_FILES, total)


def mr_changed_files(mr, settings=None) -> Optional[Set[str]]:
    """The files an MR changes since its merge base with the target (compare ``target_commit..source_commit``, not
    straight): the same set ``gl_service.get_mr_changed_files`` reads with ``git diff --name-only <merge-base> HEAD``
    (both paths of a rename), without a history clone. None when it cannot be trusted (truncated) or the API
    failed: the caller falls back to the git diff."""
    settings = settings or get_settings()
    if not settings.scan_diff_skip:
        return None
    try:
        compare = compare_paths(mr.project_path, mr.target_branch_commit, mr.source_branch_commit, straight=False,
                                max_files=settings.scan_diff_max_files)
    except Exception as e:
        logger.warning(f"MR !{getattr(mr, 'mr_id', '?')} of {mr.project_path}: changed files not read from the "
                       f"compare API ({describe(e)}), using git")
        return None
    if compare.truncated:
        logger.info(f"MR !{getattr(mr, 'mr_id', '?')} of {mr.project_path}: compare truncated at {compare.count} "
                    f"files, using git for the changed files")
        return None
    return compare.paths
