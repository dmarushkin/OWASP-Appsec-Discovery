"""Deprecated: use ``appsec_discovery.scan`` / ``appsec_discovery.ScanPipeline`` instead."""
import logging
import warnings
from typing import List, Optional

from appsec_discovery.config_loader import load_config
from appsec_discovery.models import CodeObject, ScoreConfig
from appsec_discovery.pipeline import ScanPipeline
from appsec_discovery.runner import ScanResult

logger = logging.getLogger(__name__)


class ScanService:
    """Backward-compatible wrapper over ``ScanPipeline`` (deprecated).

    Same constructor, attributes and methods as before P1-1; every stage is
    delegated to ``ScanPipeline`` built from the current ``self.config``.
    """

    def __init__(self, source_folder=None, conf_file=None, only_scored_objects=False):

        warnings.warn(
            "ScanService is deprecated; use appsec_discovery.scan() or appsec_discovery.ScanPipeline",
            DeprecationWarning,
            stacklevel=2,
        )

        self.conf_file = conf_file
        self.source_folder = source_folder

        if conf_file:
            self.config = self.load_conf_from_yaml(conf_file)
        else:
            self.config = ScoreConfig()

        self.only_scored_objects = only_scored_objects

        # result of the last parser run (objects before filtering/scoring, per-parser errors)
        self.scan_result: Optional[ScanResult] = None

    def load_conf_from_yaml(self, score_config_file_stream) -> ScoreConfig:
        """Load the scoring config; raises ``ConfigError`` on invalid input."""
        return load_config(score_config_file_stream)

    def _pipeline(self) -> ScanPipeline:
        return ScanPipeline(self.config, only_scored=self.only_scored_objects)

    def scan_folder(self) -> List[CodeObject]:
        pipeline = self._pipeline()
        self.scan_result = pipeline.parse(self.source_folder)
        return pipeline.process(list(self.scan_result.objects))

    def filter_objects(self, parsed_objects: List[CodeObject]) -> List[CodeObject]:
        """Drop objects matched by ``exclude_scan`` (and not allowed by ``object_types``)."""
        return self._pipeline().filter(parsed_objects)

    def score_objects(self, filtered_objects: List[CodeObject]) -> List[CodeObject]:
        """Keyword scoring by ``score_tags`` with ``exclude_scoring`` (in place)."""
        return self._pipeline().rule_scorer.score_all(filtered_objects)
