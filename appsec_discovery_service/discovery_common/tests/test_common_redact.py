"""Failure texts for people (``discovery_common.redact``): credentials stripped, error classes, the
bounded per-subject error log of a job's progress. No database."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from discovery_common import jobs  # noqa: E402
from discovery_common.redact import (  # noqa: E402
    MAX_CLASSES, MAX_ITEMS, ErrorLog, describe, error_class, one_line, strip_secrets,
)


@pytest.mark.parametrize("text, expected", [
    ("fatal: unable to access 'https://git:glpat-abcdefgh12345678@gitlab.example/grp/proj.git/': error 500",
     "fatal: unable to access 'https://***@gitlab.example/grp/proj.git/': error 500"),
    ("postgresql://user:db-secret@localhost/discovery is down", "postgresql://***@localhost/discovery is down"),
    ("token glpat-abcdefgh12345678 rejected", "token *** rejected"),
    ("Authorization: Basic Z2l0OnNlY3JldA==", "Authorization: Basic ***"),
    ("header 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig' refused", "header 'Authorization: Bearer ***' refused"),
    ("Bearer sk-abcdefghijklmnopqrstuvwxyz", "Bearer ***"),
    ("PRIVATE-TOKEN: glpat-xxxxxxxxxxxxxxxxxxxx expired", "PRIVATE-TOKEN: *** expired"),
    ("api_key=sk-1234567890abcdefghij&x=1", "api_key=***&x=1"),
    ("password: hunter22 is wrong", "password: *** is wrong"),
    ("no secret here: Could not resolve host: gitlab.example", "no secret here: Could not resolve host: gitlab.example"),
    (None, ""),
])
def test_strip_secrets(text, expected):
    assert strip_secrets(text) == expected


def test_describe_and_one_line():
    assert describe(ConnectionError("LLM is down")) == "ConnectionError: LLM is down"
    assert describe(TimeoutError()) == "TimeoutError"
    assert describe(RuntimeError("line one\n  line two\twith   spaces")) == "RuntimeError: line one line two with spaces"
    assert describe(ValueError("ValueError: already prefixed")) == "ValueError: already prefixed"
    assert describe(RuntimeError("x" * 500)).endswith("…") and len(describe(RuntimeError("x" * 500))) == 300
    assert describe(RuntimeError("https://git:glpat-abcdefgh12345678@gitlab.example/")) == \
        "RuntimeError: https://***@gitlab.example/"
    assert one_line("  a \n b c ", 4) == "a b…"


@pytest.mark.parametrize("text, expected", [
    ("LlmError: LLM answer is not JSON: 'blah blah'", "LlmError: LLM answer is not JSON"),
    ("LlmError: LLM answer truncated at max_tokens=8192 (raise LLM_MAX_TOKENS / ...)",
     "LlmError: LLM answer truncated at max_tokens=8192"),
    ("APITimeoutError: Request timed out.", "APITimeoutError: Request timed out"),
    ("TimeoutError", "TimeoutError"),
    ("LlmError: LLM answer has no 'fields' list: {...}", "LlmError: LLM answer has no"),
    ("", "unknown error"),
])
def test_error_class(text, expected):
    assert error_class(text) == expected


def test_error_log_is_bounded_and_summarised():
    log = ErrorLog()
    assert not log and log.as_dict() is None
    for i in range(3):
        log.add("LlmError: LLM answer truncated at max_tokens=8192 (raise LLM_MAX_TOKENS)", rule_id=3,
                rule_name="db-tables", object_name=f"table_{i}", object_key=f"k{i}", field_name="email")
    log.add(TimeoutError("Request timed out"), rule_id=3, rule_name="db-tables", object_name="t9", object_key="k9")
    log.add("OperationalError: connection lost", rule_id=4, rule_name="other-rule", where="candidate selection")
    assert len(log) == 5
    assert log.summary("db-tables") == "LlmError: LLM answer truncated at max_tokens=8192 (3), TimeoutError: Request timed out (1)"
    assert log.summary() == ("LlmError: LLM answer truncated at max_tokens=8192 (3), OperationalError: connection lost (1), "
                             "TimeoutError: Request timed out (1)")
    data = log.as_dict()
    assert data["total"] == 5 and data["items"][0] == {
        "error": "LlmError: LLM answer truncated at max_tokens=8192 (raise LLM_MAX_TOKENS)", "rule_id": 3,
        "rule": "db-tables", "object": "table_0", "object_key": "k0", "field": "email"}
    assert data["items"][4] == {"error": "OperationalError: connection lost", "rule_id": 4, "rule": "other-rule",
                                "where": "candidate selection"}
    assert data["by_class"][0] == {"rule_id": 3, "rule": "db-tables",
                                   "error_class": "LlmError: LLM answer truncated at max_tokens=8192", "count": 3}

    # bounded: MAX_ITEMS entries, MAX_CLASSES counters plus 'other'; a round trip keeps the counts
    for i in range(200):
        log.add(f"Kind{i}Error: something new", rule_id=3, rule_name="db-tables", object_key=f"x{i}")
    data = log.as_dict()
    assert data["total"] == 205 and len(data["items"]) == MAX_ITEMS
    assert len(data["by_class"]) == MAX_CLASSES + 1 and data["by_class"][-1]["error_class"] == "other"
    assert data["by_class"][-1]["count"] == 205 - sum(c["count"] for c in data["by_class"][:-1])
    assert ErrorLog.from_dict(data).as_dict() == data
    assert "other (" in log.summary()

    # a secret in an error is never stored
    log = ErrorLog()
    log.add("APIConnectionError: https://user:sk-abcdefghijklmnopqrstuv@llm.example/v1 refused")
    assert log.as_dict()["items"][0]["error"] == "APIConnectionError: https://***@llm.example/v1 refused"


def test_job_error_text_has_no_type_prefix_for_described_failures():
    """``last_error``: a JobError's message as is (it already names subject and cause), other exceptions
    with their type; credentials stripped in both."""
    assert jobs.error_text(jobs.PermanentJobError("scan of 'grp/proj', MR !25: cannot clone source branch 'x': gone")) \
        == "scan of 'grp/proj', MR !25: cannot clone source branch 'x': gone"
    assert jobs.error_text(ConnectionError("gitlab down")) == "ConnectionError: gitlab down"
    assert jobs.error_text(RuntimeError("clone https://git:glpat-abcdefgh12345678@gitlab.example/x.git failed")) == \
        "RuntimeError: clone https://***@gitlab.example/x.git failed"
