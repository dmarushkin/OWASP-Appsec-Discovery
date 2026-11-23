"""Golden snapshots of the current parser and scoring output.

Hermetic tests feed the recorded semgrep JSON (``tests/fixtures/<parser>/semgrep.json``)
to ``parse_report``; the native parsers (graphql, protobuf, swagger) read the samples
directly. The ``semgrep``-marked tests run the real binary and check that it still
produces the recorded snapshot.

A deliberate change of the output: ``uv run python -m tests.golden_support`` and
review/commit the diff of ``tests/golden`` and ``tests/fixtures`` separately.
"""
import json

import pytest

from tests.golden_support import (
    ALL_PARSERS,
    REPO_ROOT,
    SEMGREP_PARSERS,
    golden_path,
    load_golden,
    load_semgrep_fixture,
    make_parser,
    normalize,
    parse_hermetic,
    score_default,
)

REGEN_HINT = 'output changed; if intended run `uv run python -m tests.golden_support` and review tests/golden'


@pytest.mark.parametrize('parser_name', sorted(ALL_PARSERS))
def test_golden_parsed(parser_name):
    assert normalize(parse_hermetic(parser_name)) == load_golden(parser_name, 'parsed'), REGEN_HINT


@pytest.mark.parametrize('parser_name', sorted(ALL_PARSERS))
def test_golden_scored_default_config(parser_name):
    scored = score_default(parse_hermetic(parser_name))
    assert normalize(scored) == load_golden(parser_name, 'scored'), REGEN_HINT


@pytest.mark.parametrize('parser_name', sorted(ALL_PARSERS))
def test_golden_snapshots_are_hermetic(parser_name):
    for kind in ('parsed', 'scored'):
        text = golden_path(parser_name, kind).read_text()
        assert str(REPO_ROOT) not in text
        assert json.loads(text), f'{parser_name}.{kind} snapshot is empty'


@pytest.mark.parametrize('parser_name', sorted(SEMGREP_PARSERS))
def test_semgrep_fixture_paths_relative(parser_name):
    results = load_semgrep_fixture(parser_name)
    assert results
    assert all(r['path'].startswith('/') and str(REPO_ROOT) not in r['path'] for r in results)


@pytest.mark.semgrep
@pytest.mark.parametrize('parser_name', sorted(SEMGREP_PARSERS))
def test_golden_live_semgrep(parser_name):
    """The real semgrep + rules still give the recorded snapshot."""
    objects = make_parser(parser_name).run_scan()
    assert normalize(objects) == load_golden(parser_name, 'parsed'), REGEN_HINT
