"""Shared fixtures and markers for the core (``appsec_discovery``) test suite.

Markers (registered below):

* ``semgrep`` - runs the real semgrep binary; skipped automatically when
  ``semgrep`` is not on PATH.
* ``llm_local`` - needs a local OpenAI-compatible LLM server (``LLM_BASE_URL``,
  default ``http://localhost:8080/v1``, e.g. the llama.cpp server).
* ``llm_api`` - calls a real LLM API; needs ``AI_API_KEY``.
* ``local_samples`` - runs over private code dropped into ``tests/local_samples``.

``llm_local``, ``llm_api`` and ``local_samples`` are opt-in: they are
deselected unless the ``-m`` expression names them (for example
``uv run pytest -m llm_api``). This is the conftest equivalent of
``addopts = -m 'not llm_local and not llm_api and not local_samples'``.
Within an opt-in run the tests still skip when their resource (LLM server,
API key, samples) is missing; nothing depends on an ``ENV`` variable.

Helpers live in ``tests/support.py`` (objects, configs, ``FakeLlm``)
and ``tests/golden_support.py`` (golden snapshots).
"""
import shutil
from pathlib import Path
from typing import Callable

import pytest

from tests.support import TESTS_DIR, FakeLlm, build_object, config_from

OPT_IN_MARKERS = ('llm_local', 'llm_api', 'local_samples')

MARKERS = {
    'semgrep': 'runs the real semgrep binary (skipped if semgrep is not installed)',
    'llm_local': 'opt-in: needs a local OpenAI-compatible LLM server at LLM_BASE_URL (select with -m llm_local)',
    'llm_api': 'opt-in: calls a real LLM API, needs AI_API_KEY (select with -m llm_api)',
    'local_samples': 'opt-in: scans private code in tests/local_samples (select with -m local_samples)',
}


def pytest_configure(config):
    for name, description in MARKERS.items():
        config.addinivalue_line('markers', f'{name}: {description}')
    # Legacy tests still exercise the deprecated ScanService wrapper on purpose.
    config.addinivalue_line('filterwarnings', 'ignore:ScanService is deprecated:DeprecationWarning')


def pytest_collection_modifyitems(config, items):
    has_semgrep = shutil.which('semgrep') is not None
    skip_semgrep = pytest.mark.skip(reason='semgrep executable not found')

    # An opt-in marker runs only when the -m expression names it, so an unrelated
    # expression such as `-m "not semgrep"` does not switch the opt-in tiers on.
    markexpr = config.getoption('markexpr', default='') or ''
    requested = {m for m in OPT_IN_MARKERS if m in markexpr}

    selected, deselected = [], []

    for item in items:
        if any(item.get_closest_marker(m) and m not in requested for m in OPT_IN_MARKERS):
            deselected.append(item)
            continue

        if not has_semgrep and item.get_closest_marker('semgrep'):
            item.add_marker(skip_semgrep)

        selected.append(item)

    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = selected


@pytest.fixture
def tests_dir() -> Path:
    return TESTS_DIR


@pytest.fixture
def samples_dir() -> Callable[[str], Path]:
    """``samples_dir('golang')`` -> ``tests/golang_samples`` (must exist)."""

    def _samples_dir(name: str) -> Path:
        path = TESTS_DIR / (name if name.endswith('_samples') else f'{name}_samples')
        assert path.is_dir(), f'no samples folder {path}'
        return path

    return _samples_dir


@pytest.fixture
def load_config():
    """``load_config('conf.yaml')``, ``load_config('score_tags: ...')`` or ``load_config()``."""
    return config_from


@pytest.fixture
def make_object():
    """``make_object(fields=['input.email'], properties={'path': '/x'}, parser='golang')``."""
    return build_object


@pytest.fixture
def fake_llm(monkeypatch) -> Callable[..., FakeLlm]:
    """``fake_llm(fields=['input.email'])`` installs and returns a ``FakeLlm`` backend."""

    def _install(**kwargs) -> FakeLlm:
        return FakeLlm(**kwargs).install(monkeypatch)

    return _install
