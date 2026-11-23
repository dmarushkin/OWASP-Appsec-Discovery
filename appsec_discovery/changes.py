"""Which parsers a set of changed files can affect (``Parser.file_patterns``).

A consumer that knows the files changed between two commits (the service's diff-based scan
skip, a CI step) asks ``affected_parsers(paths, names)`` whether any of the parsers it would
run reads one of them; when none does, the objects of the two commits are the same and the
scan can be skipped. A parser without declared patterns (``file_patterns is None``) may read
anything, so every change affects it.

Paths are repository-relative (``api/users.proto``; a leading ``/`` or ``./`` is ignored). A
pattern without ``/`` is matched against the file name (``*.proto``), one with ``/`` against
the whole relative path (``migrations/*.sql``, ``**/schema.graphql``), case sensitively
(fnmatch, as the parsers walk the tree).
"""
import fnmatch
import posixpath
from typing import Dict, Iterable, List, Optional, Tuple

from appsec_discovery.parsers.base_parser import REGISTRY
from appsec_discovery.parsers.parser_factory import load_builtin_parsers
from appsec_discovery.runner import resolve_parser_names

__all__ = ["affected_parsers", "normalize_path", "parser_file_patterns", "path_matches"]


def normalize_path(path: str) -> str:
    """``path`` as the repository-relative POSIX path the patterns are matched against."""
    path = str(path or "").replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def path_matches(path: str, patterns: Iterable[str]) -> bool:
    """True when ``path`` matches one of ``patterns`` (see the module docstring)."""
    rel = normalize_path(path)
    if not rel:
        return False
    name = posixpath.basename(rel)
    for pattern in patterns:
        pattern = str(pattern)
        if "/" in pattern:
            pattern = normalize_path(pattern)
            if pattern.startswith("**/"):
                # ``**/x`` also matches ``x`` at the root
                if fnmatch.fnmatchcase(rel, pattern) or fnmatch.fnmatchcase(rel, pattern[3:]):
                    return True
            elif fnmatch.fnmatchcase(rel, pattern):
                return True
        elif fnmatch.fnmatchcase(name, pattern):
            return True
    return False


def parser_file_patterns(names: Optional[Iterable[str]] = None) -> Dict[str, Optional[Tuple[str, ...]]]:
    """``{parser name: file_patterns}`` of the parsers ``names`` (``'all'`` / None: every built-in
    non-deprecated parser, as ``run_parsers`` resolves them). An unknown parser, or one whose module
    failed to import, maps to None (anything may affect it, as its run fails the scan anyway)."""
    load_builtin_parsers()
    patterns: Dict[str, Optional[Tuple[str, ...]]] = {}
    for name in resolve_parser_names(names):
        cls = REGISTRY.get(name)            # no deprecation warning here: nothing is run
        declared = getattr(cls, "file_patterns", None) if cls is not None else None
        patterns[name] = None if declared is None else tuple(declared)
    return patterns


def affected_parsers(paths: Iterable[str], names: Optional[Iterable[str]] = None) -> List[str]:
    """The parsers among ``names`` (resolved as ``parser_file_patterns``) whose output can change
    when the files ``paths`` change: those reading one of the paths, and those without declared
    patterns. Empty when no change can matter to any of them."""
    changed = [normalize_path(p) for p in paths]
    changed = [p for p in changed if p]
    affected = []
    for name, patterns in parser_file_patterns(names).items():
        if patterns is None:
            affected.append(name)
        elif patterns and any(path_matches(p, patterns) for p in changed):
            affected.append(name)
    return affected
