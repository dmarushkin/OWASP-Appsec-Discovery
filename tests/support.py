"""Test helpers shared by the core test suite (imported by conftest and tests)."""
import io
import json
import os
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Union

import pytest

from appsec_discovery.ai import FakeLlmBackend
from appsec_discovery.config_loader import load_config as _load_config
from appsec_discovery.models import CodeObject, CodeObjectField, CodeObjectProp, ScoreConfig

TESTS_DIR = Path(__file__).resolve().parent
CONFIG_SAMPLES_DIR = TESTS_DIR / 'config_samples'


def config_from(source: Union[str, Path, None] = None) -> ScoreConfig:
    """Load a ``ScoreConfig``.

    ``source`` is either the name of a file in ``tests/config_samples``
    (``'conf.yaml'``), a ``Path`` to a YAML file, YAML text, or ``None`` for
    the defaults. Uses the strict ``appsec_discovery.config_loader``.
    """
    if source is None:
        return ScoreConfig()

    if isinstance(source, Path):
        with open(source) as f:
            return _load_config(f)

    sample = CONFIG_SAMPLES_DIR / source
    if '\n' not in source and sample.is_file():
        with open(sample) as f:
            return _load_config(f)

    return _load_config(io.StringIO(source))


def build_object(
    *,
    fields: Union[Iterable[str], Dict[str, str], None] = None,
    properties: Optional[Dict[str, str]] = None,
    hash: str = 'hash',
    object_name: str = 'Obj',
    object_type: str = 'route',
    parser: str = 'swagger',
    file: str = '/api.yaml',
    line: int = 1,
    **extra,
) -> CodeObject:
    """Build a ``CodeObject``.

    ``fields`` is a list of field names (type ``string``) or a
    ``{name: type}`` mapping; ``properties`` maps prop name -> value.
    Any other ``CodeObject`` attribute (``severity``, ``tags``) can be passed.
    """
    if fields is None:
        fields = {}
    if not isinstance(fields, dict):
        fields = {name: 'string' for name in fields}

    return CodeObject(
        hash=hash,
        object_name=object_name,
        object_type=object_type,
        parser=parser,
        file=file,
        line=line,
        properties={
            name: CodeObjectProp(prop_name=name, prop_value=value)
            for name, value in (properties or {}).items()
        },
        fields={
            name: CodeObjectField(field_name=name, field_type=field_type)
            for name, field_type in fields.items()
        },
        **extra,
    )


class FakeLlm(FakeLlmBackend):
    """``FakeLlmBackend`` answering the structured classification prompt.

    The answer is ``{"fields": [{"name": f, "category": c} for f in fields for c in categories]}``
    where ``category`` may be a comma separated list. ``answer`` (a callable
    ``(system, user, json_schema) -> str``) overrides it, e.g. to raise.
    ``install(monkeypatch)`` makes ``AiService`` use this backend instead of
    building an OpenAI client; the ``AiApi`` configs it was asked to build a
    backend for are recorded in ``loads``.
    """

    def __init__(self, category: str = 'pii', fields: Iterable[str] = (),
                 answer: Optional[Callable[..., str]] = None, raw: Optional[str] = None):
        self.category = category
        self.fields = list(fields)
        self.raw = raw
        self.loads: List = []
        super().__init__(answer=answer if answer is not None else self._structured)

    def _structured(self, system, user, json_schema) -> str:
        if self.raw is not None:
            return self.raw
        cats = [c.strip() for c in self.category.split(',') if c.strip()]
        return json.dumps({'fields': [{'name': f, 'category': c} for f in self.fields for c in cats]})

    @property
    def prompts(self) -> List[str]:
        return [user for _, user, _ in self.calls]

    def install(self, monkeypatch) -> 'FakeLlm':
        from appsec_discovery.services import ai_service

        def _backend_from_config(ai_api):
            self.loads.append(ai_api)
            return self

        monkeypatch.setattr(ai_service, 'backend_from_config', _backend_from_config)
        return self


def require_llm_server() -> str:
    """Skip unless ``LLM_BASE_URL`` (an OpenAI-compatible server, e.g. llama.cpp) answers."""
    import urllib.request

    base_url = os.getenv('LLM_BASE_URL', 'http://localhost:8080/v1')
    try:
        urllib.request.urlopen(base_url.rstrip('/') + '/models', timeout=3)
    except Exception as e:
        pytest.skip(f'no OpenAI-compatible LLM server at {base_url}: {e}')
    return base_url


def require_api_key() -> str:
    key = os.getenv('AI_API_KEY')
    if not key:
        pytest.skip('AI_API_KEY is not set')
    return key


def require_local_samples() -> Path:
    """Skip unless private samples were dropped into ``tests/local_samples``."""
    path = TESTS_DIR / 'local_samples'
    if not path.is_dir() or not any(p.name != '.gitkeep' for p in path.iterdir()):
        pytest.skip('tests/local_samples is empty')
    return path
