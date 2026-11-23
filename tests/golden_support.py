"""Golden snapshots of the parsers' output (P2-1 safety net).

Layout:

* ``tests/fixtures/<parser>/semgrep.json`` - semgrep results recorded once
  (``Parser.run_semgrep`` output: paths already relative to the samples folder)
  for every semgrep-based parser. Feeding them to ``parse_report`` makes the
  golden tests hermetic: no semgrep binary is needed.
* ``tests/golden/<parser>.parsed.json`` - the parser output, normalised (see
  ``normalize``).
* ``tests/golden/<parser>.scored.json`` - the same objects after
  ``ScanPipeline`` filter + keyword scoring with the default config.

The snapshots capture the CURRENT behaviour, bugs included. A change that
intentionally alters parser or scoring output must regenerate them and the
diff of ``tests/golden`` must be reviewed (and committed separately)::

    uv run python -m tests.golden_support            # re-record everything
    uv run python -m tests.golden_support --no-semgrep  # keep recorded semgrep JSON
"""
import argparse
import json
from importlib import import_module
from pathlib import Path
from typing import Iterable, List

from appsec_discovery.models import CodeObject
from appsec_discovery.parsers import ParserFactory

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
FIXTURES_DIR = TESTS_DIR / 'fixtures'
GOLDEN_DIR = TESTS_DIR / 'golden'

# parser name -> samples folder (relative to tests/)
SEMGREP_PARSERS = {
    'golang': 'golang_samples',
    'java': 'java_samples',
    'python': 'python_samples',
}

# parsers that read the files themselves (no semgrep)
NATIVE_PARSERS = {
    'graphql': 'graphql_samples',
    'javascript': 'javascript_samples',
    'protobuf': 'protobuf_samples',
    'migrations': 'migrations_samples',
    'swagger': 'swagger_samples',
    'terraform': 'terraform_samples',
}

ALL_PARSERS = {**SEMGREP_PARSERS, **NATIVE_PARSERS}


def samples_path(parser_name: str) -> Path:
    return TESTS_DIR / ALL_PARSERS[parser_name]


def make_parser(parser_name: str):
    cls = ParserFactory.get_parser(parser_name)
    return cls(parser=parser_name, source_folder=str(samples_path(parser_name)))


def rules_folder(parser_name: str) -> str:
    module = import_module(f'appsec_discovery.parsers.{parser_name}.parser')
    return str(Path(module.__file__).resolve().parent / 'scanner_rules')


def semgrep_fixture_path(parser_name: str) -> Path:
    return FIXTURES_DIR / parser_name / 'semgrep.json'


def golden_path(parser_name: str, kind: str) -> Path:
    return GOLDEN_DIR / f'{parser_name}.{kind}.json'


def load_semgrep_fixture(parser_name: str) -> List[dict]:
    with open(semgrep_fixture_path(parser_name)) as f:
        return json.load(f)


def load_golden(parser_name: str, kind: str) -> list:
    with open(golden_path(parser_name, kind)) as f:
        return json.load(f)


def _sort_key(obj: dict):
    return (obj.get('file') or '', obj.get('line') or 0, obj.get('object_type') or '',
            obj.get('object_name') or '', obj.get('hash') or '')


def normalize(objects: Iterable[CodeObject]) -> list:
    """Objects as JSON-compatible dicts (``exclude_none``), sorted deterministically.

    Dict keys (properties, fields) are ordered by the JSON round-trip with
    ``sort_keys``; list order inside an object (e.g. ``tags``) is kept.
    """
    dumped = [obj.dict(exclude_none=True) for obj in objects]
    dumped.sort(key=_sort_key)
    return json.loads(json.dumps(dumped, sort_keys=True))


def parse_hermetic(parser_name: str) -> List[CodeObject]:
    """Parser output without running semgrep (recorded JSON for semgrep parsers)."""
    parser = make_parser(parser_name)
    if parser_name in SEMGREP_PARSERS:
        return parser.parse_report(load_semgrep_fixture(parser_name))
    return parser.run_scan()


def score_default(objects: List[CodeObject]) -> List[CodeObject]:
    """Filter + score with the default ``ScoreConfig`` (mutates ``objects``)."""
    from appsec_discovery.pipeline import ScanPipeline

    pipeline = ScanPipeline(use_config_ai=False)
    return pipeline.rule_scorer.score_all(pipeline.filter(objects))


def _dump(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    if str(REPO_ROOT) in text:
        raise RuntimeError(f'{path} would contain the absolute repo path; snapshots must be hermetic')
    path.write_text(text)


def record_semgrep(parser_name: str) -> None:
    parser = make_parser(parser_name)
    results = parser.run_semgrep(source_folder=parser.source_folder, rules_folder=rules_folder(parser_name))
    _dump(semgrep_fixture_path(parser_name), results)


def record_golden(parser_name: str) -> None:
    _dump(golden_path(parser_name, 'parsed'), normalize(parse_hermetic(parser_name)))
    _dump(golden_path(parser_name, 'scored'), normalize(score_default(parse_hermetic(parser_name))))


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description='Re-record semgrep fixtures and golden snapshots')
    ap.add_argument('--no-semgrep', action='store_true', help='keep the recorded semgrep JSON')
    ap.add_argument('parsers', nargs='*', default=list(ALL_PARSERS))
    args = ap.parse_args(argv)

    for name in args.parsers:
        if name in SEMGREP_PARSERS and not args.no_semgrep:
            record_semgrep(name)
        record_golden(name)
        print(f'recorded {name}')


if __name__ == '__main__':
    main()
