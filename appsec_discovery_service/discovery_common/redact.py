"""Failure texts that people read (``jobs.last_error``, ``jobs.progress.errors``).

* ``strip_secrets``: credentials never reach the database or the UI: the userinfo of URLs
  (``https://git:TOKEN@host/``), GitLab / generic bearer tokens and ``Authorization`` headers
  are replaced by a marker. Applied in ``jobs.fail`` (every ``last_error``) and by the
  scanner where it builds a reason from an exception / git output.
* ``describe``: ``"TypeName: message"`` of an exception, one line, trimmed, redacted.
* ``error_class``: the family of an error text for counts (the exception type and the first
  clause of its message: ``LlmError: LLM answer is not JSON``), so that the failures of one
  cause are counted together whatever object / id is in the message.
* ``ErrorLog``: a bounded record of per-subject failures of one job (the first
  ``MAX_ITEMS`` entries, counts by (rule, error class)), stored as ``progress.errors``.
"""

import re
from typing import Any, Dict, List, Optional

REDACTED = "***"
MAX_ITEMS = 20          # distinct failures kept with their subject
MAX_CLASSES = 20        # (rule, error class) counters kept; the rest is counted under 'other'
TEXT_MAX = 300          # characters of one error text in the log
CLASS_MAX = 100

_URL_USERINFO = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://)([^/\s@]+)@")
_TOKENS = re.compile(r"\b(glpat-[A-Za-z0-9_-]{8,}|gl[a-z]{2,4}-[A-Za-z0-9_-]{16,}|sk-[A-Za-z0-9_-]{16,}"
                     r"|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b")
_AUTH_HEADER = re.compile(r"(?i)(authorization:\s*(?:basic|bearer)\s+)[A-Za-z0-9+/=_.-]+")
_BEARER = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9_.-]{16,}")
_KV_SECRET = re.compile(r"(?i)\b((?:private[_-]?token|api[_-]?key|password|passwd|secret|token)\s*[=:]\s*)"
                        r"['\"]?[^\s'\",;&]{6,}")


def strip_secrets(text: Optional[str]) -> str:
    """``text`` without credentials: URL userinfo, known token formats, Authorization headers,
    ``token=...`` / ``password: ...`` values."""
    if not text:
        return ""
    text = str(text)
    text = _URL_USERINFO.sub(lambda m: f"{m.group(1)}{REDACTED}@", text)
    text = _AUTH_HEADER.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    text = _BEARER.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    text = _TOKENS.sub(REDACTED, text)
    text = _KV_SECRET.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    return text


def one_line(text: Optional[str], max_len: int = TEXT_MAX) -> str:
    """Whitespace collapsed, trimmed to ``max_len`` with an ellipsis."""
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(text) > max_len:
        text = text[:max(0, max_len - 1)].rstrip() + "…"
    return text


def describe(exc: BaseException, max_len: int = TEXT_MAX) -> str:
    """``"TypeName: message"`` (``"TypeName"`` alone when the message is empty), one line, redacted."""
    message = one_line(strip_secrets(str(exc)), max_len)
    name = type(exc).__name__
    if not message:
        return name
    if message.startswith(f"{name}:"):
        return message
    return one_line(f"{name}: {message}", max_len)


_CLASS_CUT = re.compile(r"(: |;| - | \(|\[|'|\")")


def error_class(text: Optional[str], max_len: int = CLASS_MAX) -> str:
    """The family of an error text: its exception type and the first clause of the message, cut
    at the first quote, parenthesis or inner colon (``LlmError: LLM answer is not JSON: '...'`` ->
    ``LlmError: LLM answer is not JSON``; ``TimeoutError`` stays ``TimeoutError``)."""
    text = one_line(text, 1000)
    if not text:
        return "unknown error"
    name, sep, message = text.partition(": ")
    if not sep:
        return one_line(text, max_len)
    cut = _CLASS_CUT.search(message)
    clause = message[:cut.start()] if cut else message
    clause = clause.strip().rstrip(".:,")
    return one_line(f"{name}: {clause}" if clause else name, max_len)


class ErrorLog:
    """Per-subject failures of one job, bounded: the first ``MAX_ITEMS`` entries with their
    subject, counts by (rule, error class) and the total. ``as_dict`` is what goes to
    ``jobs.progress.errors``; ``from_dict`` continues one read back from there."""

    def __init__(self):
        self.total = 0
        self.items: List[Dict[str, Any]] = []
        self.by_class: Dict[tuple, int] = {}
        self.other = 0

    def add(self, error: Any, *, rule_id: Optional[int] = None, rule_name: Optional[str] = None,
            object_name: Optional[str] = None, object_key: Optional[str] = None, field_name: Optional[str] = None,
            where: Optional[str] = None) -> str:
        """Record one failure (``error``: text or exception); returns the stored text."""
        text = describe(error) if isinstance(error, BaseException) else one_line(strip_secrets(str(error)))
        text = text or "unknown error"
        self.total += 1
        if len(self.items) < MAX_ITEMS:
            entry: Dict[str, Any] = {"error": text}
            if rule_id is not None:
                entry["rule_id"] = int(rule_id)
            if rule_name:
                entry["rule"] = rule_name
            if object_name:
                entry["object"] = object_name
            if object_key is not None:
                entry["object_key"] = str(object_key)
            if field_name:
                entry["field"] = field_name
            if where:
                entry["where"] = where
            self.items.append(entry)
        key = (rule_id, rule_name, error_class(text))
        if key in self.by_class or len(self.by_class) < MAX_CLASSES:
            self.by_class[key] = self.by_class.get(key, 0) + 1
        else:
            self.other += 1
        return text

    def __bool__(self) -> bool:
        return self.total > 0

    def __len__(self) -> int:
        return self.total

    def classes(self, rule_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """``[{rule_id, rule, error_class, count}]`` (of one rule), most frequent first."""
        rows = [{"rule_id": rid, "rule": rname, "error_class": cls, "count": n}
                for (rid, rname, cls), n in self.by_class.items() if rule_name is None or rname == rule_name]
        rows.sort(key=lambda r: (-r["count"], r["error_class"]))
        return rows

    def summary(self, rule_name: Optional[str] = None, max_classes: int = 3) -> str:
        """``"LlmError: LLM answer truncated at max_tokens=8192 (2), TimeoutError (1)"``."""
        rows = self.classes(rule_name)
        parts = [f"{r['error_class']} ({r['count']})" for r in rows[:max_classes]]
        rest = sum(r["count"] for r in rows[max_classes:]) + (self.other if rule_name is None else 0)
        if rest:
            parts.append(f"other ({rest})")
        return ", ".join(parts)

    def as_dict(self) -> Optional[Dict[str, Any]]:
        if not self.total:
            return None
        by_class = self.classes()
        if self.other:
            by_class.append({"rule_id": None, "rule": None, "error_class": "other", "count": self.other})
        return {"total": self.total, "items": list(self.items), "by_class": by_class}

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "ErrorLog":
        log = cls()
        if not data:
            return log
        log.total = int(data.get("total") or 0)
        log.items = [dict(e) for e in (data.get("items") or [])][:MAX_ITEMS]
        for row in data.get("by_class") or []:
            if row.get("error_class") == "other" and row.get("rule") is None and row.get("rule_id") is None:
                log.other += int(row.get("count") or 0)
            else:
                log.by_class[(row.get("rule_id"), row.get("rule"), row.get("error_class"))] = int(row.get("count") or 0)
        return log
