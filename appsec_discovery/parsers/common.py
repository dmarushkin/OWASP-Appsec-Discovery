"""Path helpers shared by the parsers: relative paths and the source tree walker."""
import fnmatch
import os
from pathlib import Path
from typing import Callable, Iterable, List, Optional

__all__ = ["DEFAULT_PRUNE_DIRS", "relative_source_path", "walk_files"]

# directories with third-party code that no parser looks into (the semgrep run excludes them too)
DEFAULT_PRUNE_DIRS = frozenset({'node_modules', 'vendor'})


def relative_source_path(path: str, source_folder: str) -> str:
    """Return ``path`` relative to ``source_folder`` as ``/sub/dir/file`` (POSIX separators).

    The leading ``/`` is kept for compatibility with existing reports and hashes.
    Falls back to the legacy ``str.replace`` behaviour when ``path`` is not
    located under ``source_folder``.
    """
    try:
        rel = Path(path).resolve().relative_to(Path(source_folder).resolve())
        return '/' + rel.as_posix()
    except (ValueError, OSError):
        return path.replace(source_folder, '')


def walk_files(root: str, patterns: Iterable[str], *, prune_dirs: Iterable[str] = DEFAULT_PRUNE_DIRS,
               exclude: Optional[Callable[[str], bool]] = None) -> List[str]:
    """Sorted paths of the files under ``root`` whose name matches one of ``patterns`` (fnmatch).

    Directories named in ``prune_dirs`` are not entered. ``exclude`` receives the
    path relative to ``root`` (``/sub/file``) and drops the file when it returns True.
    """
    patterns = tuple(patterns)
    prune = frozenset(prune_dirs)
    found = []

    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in prune]
        for name in files:
            if not any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns):
                continue
            path = os.path.join(current, name)
            if exclude is not None and exclude(relative_source_path(path, root)):
                continue
            found.append(path)

    return sorted(found)
