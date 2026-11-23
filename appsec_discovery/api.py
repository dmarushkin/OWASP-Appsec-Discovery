"""Public library API of appsec_discovery (P1-1, P2-2).

    import appsec_discovery

    config = appsec_discovery.load_config_file('conf.yaml')
    result = appsec_discovery.scan('path/to/checkout', config, only_scored=True)
    for name, error in result.errors.items(): ...
    text = appsec_discovery.render_report(result.objects, 'sarif')

``ScanService``/``ReportService`` remain as deprecated wrappers over this API.
"""
import os
from typing import Any, Mapping, Optional, Union

import pydantic

from appsec_discovery.ai.backends import LlmBackend
from appsec_discovery.config_loader import load_config
from appsec_discovery.errors import ConfigError
from appsec_discovery.hits import apply_hit_statuses
from appsec_discovery.models import ScoreConfig
from appsec_discovery.pipeline import AiScorer, ScanPipeline
from appsec_discovery.reports import REPORT_FORMATS, render_report
from appsec_discovery.runner import ScanResult, run_parsers

__all__ = [
    "ConfigLike", "load_config", "load_config_file", "to_config",
    "run_parsers", "scan", "render_report", "REPORT_FORMATS",
    "ScanPipeline", "ScanResult", "AiScorer",
    "apply_hit_statuses",
]

ConfigLike = Union[ScoreConfig, Mapping[str, Any], str, os.PathLike, None]


def load_config_file(path: Union[str, os.PathLike]) -> ScoreConfig:
    """Load a YAML scoring config from a file path; raises ``ConfigError`` on invalid content."""
    try:
        with open(path) as stream:
            return load_config(stream)
    except OSError as e:
        raise ConfigError(f"cannot read config {os.fspath(path)!r}: {e}") from e


def to_config(config: ConfigLike) -> ScoreConfig:
    """Normalise ``config``: a ``ScoreConfig`` (used as is), a mapping (validated),
    a file path (``str``/``PathLike`` of a YAML file) or ``None`` (defaults)."""
    if config is None:
        return ScoreConfig()
    if isinstance(config, ScoreConfig):
        return config
    if isinstance(config, (str, os.PathLike)):
        return load_config_file(config)
    if isinstance(config, Mapping):
        try:
            return ScoreConfig(**config)
        except (pydantic.ValidationError, TypeError) as e:
            raise ConfigError(str(e)) from e
    raise TypeError(f"unsupported config type: {type(config).__name__}")


def scan(source: Union[str, os.PathLike], config: ConfigLike = None, *,
         ai: Optional[AiScorer] = None, only_scored: bool = False, project: Optional[str] = None,
         llm_backend: Optional[LlmBackend] = None) -> ScanResult:
    """Scan ``source`` with ``config``: parsers -> exclude_scan -> keyword scoring -> AI -> only_scored.

    ``ai`` overrides the AI scorer; when ``None`` one is built from the config's
    ``ai_api`` (if set; the deprecated ``ai_local`` maps to it). Parser failures do not raise: they are in
    ``ScanResult.errors`` (``ScanResult.all_failed`` when nothing ran). An invalid
    config raises ``ConfigError``.

    ``project`` narrows the config to that project's rules (``ScoreConfig.for_project``).
    ``llm_backend`` runs the config's LLM rules on that backend instead of one built
    from ``ai_api``. Every object carries its rule ``hits`` with their status.
    """
    pipeline = ScanPipeline(to_config(config), ai=ai, only_scored=only_scored, project=project,
                            llm_backend=llm_backend)
    return pipeline.run(os.fspath(source))
