"""Rule patterns come from stored rules (service API): a catastrophically backtracking regex
must not hang a scan worker."""
import time

from appsec_discovery import matching
from appsec_discovery.matching import Pattern, safe_search

EVIL = "(a|aa)+$"
VALUE = "a" * 60 + "b"


def test_backtracking_pattern_match_times_out_as_no_match(caplog):
    start = time.monotonic()
    with caplog.at_level("WARNING"):
        assert Pattern.of(EVIL).matches(VALUE) is False
        assert Pattern.of(EVIL).matches(VALUE) is False
    assert time.monotonic() - start < 2
    assert EVIL in matching.timed_out_patterns()
    assert caplog.text.count("took longer than") <= 1                 # warned once per pattern


def test_backtracking_pattern_search_times_out_as_no_match():
    start = time.monotonic()
    assert safe_search("(x+x+)+y", "x" * 60) is False
    assert time.monotonic() - start < 2


def test_semantics_are_unchanged():
    assert Pattern.of("^card").matches("card_number") and not Pattern.of("^card").matches("my_card_x")
    assert Pattern.of("Card").matches("my_card")                         # substring, case-insensitive
    assert Pattern.of("card(").matches("xcard(y")                        # not a regex: literal
    assert Pattern.of("(phone|fax)$").matches("fax") and not Pattern.of("^(phone|fax)$").matches("faxes")
    assert safe_search("last_?name", "Client.LastName") and not safe_search("last_?name", "LastName", ignorecase=False)
    assert safe_search("c++", "c++ code")
