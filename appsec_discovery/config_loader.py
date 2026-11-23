"""Strict loading of the scoring config (``ScoreConfig``) from YAML."""
from typing import IO, Union

import pydantic
import yaml

from appsec_discovery.errors import ConfigError
from appsec_discovery.models import ScoreConfig

__all__ = ["ConfigError", "load_config"]


def load_config(stream: Union[str, bytes, IO]) -> ScoreConfig:
    """Parse a YAML scoring config.

    An empty document yields the default ``ScoreConfig()``. Malformed YAML, a
    document that is not a mapping, or values that fail validation raise
    ``ConfigError`` instead of being silently ignored.
    """
    try:
        data = yaml.safe_load(stream)
    except yaml.YAMLError as e:
        raise ConfigError(f"invalid YAML: {e}") from e

    if data is None:
        data = {}

    if not isinstance(data, dict):
        raise ConfigError(f"config must be a YAML mapping, got {type(data).__name__}")

    try:
        return ScoreConfig(**data)
    except (pydantic.ValidationError, TypeError) as e:
        raise ConfigError(str(e)) from e
