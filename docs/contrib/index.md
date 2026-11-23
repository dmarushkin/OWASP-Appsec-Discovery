---
hide:
  - footer
---

# Contributing

## Development setup

The core package is managed with [uv](https://docs.astral.sh/uv/) (Python 3.12, `pyproject.toml`, `uv.lock`);
`.devcontainer/` has a ready container.

```bash
uv sync --locked                        # the package, its dependencies and the dev group (pytest, alembic, sqlmodel, psycopg2)
uv run appsec-discovery --source tests/swagger_samples
uv run pytest                           # core tests; the Postgres-backed ones need TEST_DATABASE_URL
```

Service tests run in their own environments against a real Postgres (`TEST_DATABASE_URL=postgresql://...`):

```bash
cd appsec_discovery_service
uv run --no-project --with-requirements discovery_api/requirements-dev.txt pytest discovery_api/tests
uv run --no-project --with-requirements discovery_api/requirements-dev.txt pytest discovery_common/tests collectors/tests
```

`.github/workflows/python-package.yml` runs the same: core + scanner + `discovery_common` tests, the API / MCP
tests, image builds of the API, UI and scanner, the nginx config check, a docs link check, and the package build
(published to PyPI on a release).

## Writing a parser

A parser is a class in `appsec_discovery/parsers/<name>/parser.py` that registers itself by its `name`
(`appsec_discovery/parsers/base_parser.py`, `REGISTRY`; add the module name to `BUILTIN_PARSERS` in
`parser_factory.py`):

* **`SemgrepParser`** - ships `scanner_rules/*.yaml` next to the module; each rule declares
  `metadata: {parser, object_type, framework}` and its findings are dispatched to `handlers[object_type]`, which
  build `CodeObject`s from the metavariables. Declare `file_patterns` (the languages' files, e.g. `('*.go',)`).
* **`FileParser`** - walks the source tree (vendored directories pruned, files read with `read_text_file`:
  symlinks out of the tree, special files and files over 5 MB skipped), parses every file matching `globs`
  (which become `file_patterns`) and builds the objects.

Rules of the road: object identity is `object_identity(parser, relative file, object_type, logical_name)` -
lines are never part of it; object names carry no type word (it is `object_type`); fields are named by their
path (`input.Message.field`, `output.*`, `query.param.x`); comments go through `clean_comment` (cut at 1000
characters), samples through the secret filter (never a password / token / key value); every parser must survive
an untrusted repository (no network, no following symlinks, bounded memory).

## Tests

* `tests/<name>_samples/` holds the inputs of a parser, `tests/fixtures/<parser>/semgrep.json` the recorded
  Semgrep results (the golden tests need no Semgrep binary) and `tests/golden/<parser>.parsed.json` /
  `.scored.json` the expected objects (`test_golden.py`, `golden_support.py`); regenerate them after an intended
  change of a parser's output and review the diff.
* `tests/test_file_parser_safety.py` and `tests/test_ai_prompt_injection.py` are the safety suites every parser
  and prompt builder must pass.
* The service: `discovery_scanner/tests`, `discovery_api/tests`, `discovery_common/tests` (migrations are
  tested against a real Postgres, including the query plans of the candidate queries).

## Docs

`docs/` is a [mkdocs-material](https://squidfunk.github.io/mkdocs-material/) site (`mkdocs.yml`, extra `docs`
dependency group: `uv sync --group docs && uv run mkdocs serve`). The README stays short and links into `docs/`;
CI checks that every link resolves. No internal project names, hosts or secrets in examples (`grp/payments-api`).

## Pull requests

Fork, branch, run the tests, open a PR against `main` with a changelog line in `docs/changelog.md` for anything
a user can notice (a setting, an endpoint, a migration, a behaviour change).
