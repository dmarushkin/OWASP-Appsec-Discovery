"""Shared matching and severity primitives (P1-3).

Used by the core scoring (``RuleScorer``, ``ExcludeScan``/``ExcludeScoring``,
LLM scoring) and by ``appsec_discovery_service`` so that every copy of the
"does this config value match" predicate has the same semantics:

* a value matches a pattern when ``re.match(pattern, value)`` succeeds
  (anchored at the start, case-sensitive) OR the pattern, lower-cased, is a
  substring of the lower-cased value;
* a pattern that is not a valid regex (``c++``, ``card(``) is used as a literal
  (``re.escape``) and a warning is logged once, instead of crashing the scan;
* patterns come from config files and from rules stored through the service API, so a
  regex match is bounded by ``MATCH_TIMEOUT_S`` (the ``regex`` module): a catastrophically
  backtracking pattern (``(a|aa)+$``) does not hang the scan, the timed-out regex match
  counts as no match (the substring test still applies) and a warning is logged once per
  pattern.

Severities stay plain strings in models, reports and the DB; ``Severity`` is a
``str`` Enum, and ordering goes through the separate ``RANK`` table.
"""
import logging
import re
import threading
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from typing import Iterable, List, Optional, Union

try:                                   # timeouts on matches; plain ``re`` (no timeout) without it
    import regex as _rx
except ImportError:                    # pragma: no cover - regex is a dependency
    _rx = None

logger = logging.getLogger(__name__)

__all__ = [
    "Severity", "RANK", "severity_rank", "max_severity",
    "Pattern", "Scorable", "merge_score", "MATCH_TIMEOUT_S", "safe_search",
]

# Upper bound of one regex match against one value (seconds).
MATCH_TIMEOUT_S = 0.1

_timed_out: set = set()
_timed_out_lock = threading.Lock()


def _warn_timeout(raw: str) -> None:
    with _timed_out_lock:
        first = raw not in _timed_out
        _timed_out.add(raw)
    if first:
        logger.warning('pattern %r took longer than %ss to match (catastrophic backtracking?): '
                       'treated as no match', raw, MATCH_TIMEOUT_S)


def timed_out_patterns() -> List[str]:
    """Patterns whose match timed out at least once in this process (for logs / health)."""
    with _timed_out_lock:
        return sorted(_timed_out)


def _bounded(rx, method: str, raw: str, value: str):
    if _rx is None or not isinstance(rx, _rx.Pattern):
        return getattr(rx, method)(value)
    try:
        return getattr(rx, method)(value, timeout=MATCH_TIMEOUT_S)
    except TimeoutError:
        _warn_timeout(raw)
        return None


def _compile_rx(raw: str, flags: int = 0):
    if _rx is not None:
        try:
            return _rx.compile(raw, flags)
        except (_rx.error, ValueError):
            pass               # not a regex for the regex module either: literal, as below
    return re.compile(raw, flags)


class Severity(str, Enum):
    info = 'info'
    low = 'low'
    medium = 'medium'
    high = 'high'
    critical = 'critical'

    def __str__(self) -> str:
        return self.value


RANK = {
    Severity.info: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}


def severity_rank(severity: Union[str, Severity, None]) -> int:
    """Rank of a severity, ``-1`` for ``None``. Raises ``ValueError`` on an unknown value."""
    if severity is None:
        return -1
    return RANK[Severity(severity)]


def max_severity(severities: Iterable[Union[str, Severity, None]]) -> Optional[Severity]:
    """Highest severity of ``severities`` (``None`` entries ignored), or ``None``."""
    best: Optional[Severity] = None
    for severity in severities:
        if severity is None:
            continue
        severity = Severity(severity)
        if best is None or RANK[severity] > RANK[best]:
            best = severity
    return best


@dataclass(frozen=True)
class Pattern:
    """A config pattern: regex match from the start OR case-insensitive substring."""

    raw: str
    rx: 're.Pattern[str]'

    @classmethod
    def of(cls, raw: str) -> 'Pattern':
        """Compiled pattern for ``raw`` (cached; a non-regex warns once and is used literally)."""
        return _compile(raw)

    def matches(self, value: Optional[str]) -> bool:
        return value is not None and (bool(_bounded(self.rx, 'match', self.raw, value))
                                      or self.raw.lower() in value.lower())


@lru_cache(maxsize=4096)
def _compile(raw: str) -> Pattern:
    try:
        return Pattern(raw, _compile_rx(raw))
    except re.error:
        logger.warning('pattern %r is not a valid regex, matching it as a literal', raw)
        return Pattern(raw, _compile_rx(re.escape(raw)))


@lru_cache(maxsize=1024)
def _compile_search(raw: str, flags: int):
    try:
        return _compile_rx(raw, flags)
    except re.error:
        logger.warning('pattern %r is not a valid regex, matching it as a literal', raw)
        return _compile_rx(re.escape(raw), flags)


def safe_search(raw: str, value: Optional[str], ignorecase: bool = True) -> bool:
    """``re.search(raw, value)`` (case-insensitive by default) bounded by ``MATCH_TIMEOUT_S``;
    a non-regex is searched literally, a timed-out search is no match (warning once)."""
    if value is None:
        return False
    rx = _compile_search(raw, re.IGNORECASE if ignorecase else 0)
    return bool(_bounded(rx, 'search', raw, value))


def merge_score(target, severity: Union[str, Severity], tags: Iterable[str]) -> None:
    """Merge a hit into ``target`` (anything with ``severity`` and ``tags`` attributes).

    The single merge helper: an unscored target takes ``severity`` and a copy of
    ``tags``; a scored one keeps the higher severity (by ``RANK``) and gains the
    tags it does not have yet, in order. Lists are never shared between targets.
    """
    severity = Severity(severity)

    if not target.severity:
        target.severity = severity.value
        target.tags = list(dict.fromkeys(tags))
        return

    current: List[str] = list(target.tags or [])
    for tag in tags:
        if tag not in current:
            current.append(tag)
    target.tags = current

    if RANK[severity] > severity_rank(target.severity):
        target.severity = severity.value


class Scorable:
    """Mixin for objects that carry ``severity: Optional[str]`` and ``tags: Optional[List[str]]``."""

    def apply_score(self, severity: Union[str, Severity], tags: Iterable[str]) -> None:
        merge_score(self, severity, tags)
