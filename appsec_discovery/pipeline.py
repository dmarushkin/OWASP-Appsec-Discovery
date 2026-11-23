"""Composable scan pipeline (P1-1): parsers -> ExcludeFilter -> RuleScorer -> [LLM rules] -> only_scored.

Every scan entry point (``appsec_discovery.scan``, the CLI, the deprecated
``ScanService`` and ``appsec_discovery_service``) goes through ``ScanPipeline``
so the scan semantics are defined in exactly one place.
"""
import logging
from dataclasses import replace
from typing import Iterable, List, Optional, Protocol, runtime_checkable

from appsec_discovery.hits import has_open_hits
from appsec_discovery.models import CodeObject, ScoreConfig
from appsec_discovery.runner import ScanResult, run_parsers
from appsec_discovery.scoring import ExcludeFilter, RuleScorer

logger = logging.getLogger(__name__)

__all__ = ["AiScorer", "ScanPipeline", "ai_scorer_from_config"]


@runtime_checkable
class AiScorer(Protocol):
    """Anything that can (LLM-)score a list of objects; ``AiService`` satisfies it."""

    def ai_score_objects(self, code_objects: List[CodeObject]) -> List[CodeObject]:
        ...


def ai_scorer_from_config(config: ScoreConfig, *, backend=None, project: Optional[str] = None) -> Optional[AiScorer]:
    """The LLM rules runner (``AiService``) for ``config``, or ``None`` when there is nothing to run.

    The rules are ``config.effective_llm_rules()``: the explicit ``llm_rules`` or,
    without them, the implicit rule of an ``ai_api`` block (the deprecated
    ``ai_local`` is mapped to ``ai_api`` when the config is loaded). They run on
    ``backend`` when given, else on a backend built from ``config.ai_api``;
    without either the rules are skipped with a warning. ``ai_service`` (and the
    ``openai`` client) is imported only when there are rules to run.
    """
    rules = config.effective_llm_rules()
    if not rules:
        return None
    if backend is None and config.ai_api is None:
        logger.warning(f"{len(rules)} LLM rule(s) configured but no 'ai_api' (LLM endpoint): LLM rules skipped")
        return None

    from appsec_discovery.services.ai_service import AiService

    return AiService(exclude_scoring=config.effective_exclude_scoring(), ai_api=config.ai_api, backend=backend,
                     llm_rules=rules, project=project)


class ScanPipeline:
    """One scan configuration, reusable for many sources.

    ``ai``: an explicit ``AiScorer``; when ``None`` the LLM rules of the config
    (``llm_rules``, or the implicit rule of ``ai_api``) run on ``llm_backend``
    or on a backend built from ``config.ai_api``, which is what the CLI does.
    Pass ``use_config_ai=False`` to skip LLM rules regardless of the config.

    ``project``: the scanned project. When given, the config is narrowed with
    ``ScoreConfig.for_project`` (rules scoped to other projects are dropped);
    when ``None`` the config is used as is (the caller built it for the project).
    """

    def __init__(self, config: Optional[ScoreConfig] = None, *, ai: Optional[AiScorer] = None,
                 only_scored: bool = False, use_config_ai: bool = True, project: Optional[str] = None,
                 llm_backend=None):
        config = config if config is not None else ScoreConfig()
        self.project = project
        self.config = config.for_project(project) if project is not None else config
        self.only_scored = only_scored
        self.exclude_filter = ExcludeFilter.from_config(self.config)
        self.rule_scorer = RuleScorer.from_config(self.config)
        self._ai = ai
        self._use_config_ai = use_config_ai
        self._llm_backend = llm_backend

    @property
    def ai(self) -> Optional[AiScorer]:
        if self._ai is None and self._use_config_ai:
            self._ai = ai_scorer_from_config(self.config, backend=self._llm_backend, project=self.project)
        return self._ai

    # -- stages ---------------------------------------------------------------

    def parse(self, source: str) -> ScanResult:
        """Run the configured parsers; failures are isolated per parser (see ``run_parsers``)."""
        return run_parsers(source, self.config.parsers, exclude_scan=self.config.exclude_scan)

    def filter(self, objects: Iterable[CodeObject]) -> List[CodeObject]:
        return self.exclude_filter.filter(objects)

    def score(self, objects: Iterable[CodeObject]) -> List[CodeObject]:
        """Keyword rules (in place), then LLM rules when an AI scorer is configured."""
        scored = self.rule_scorer.score_all(objects)
        ai = self.ai
        if ai is not None:
            scored = ai.ai_score_objects(scored)
        return scored

    def select(self, objects: Iterable[CodeObject]) -> List[CodeObject]:
        """Drop unscored objects when ``only_scored`` is set.

        An object with an open hit (``pending_review``/``need_more_info``) counts
        as scored: it must reach the report so that someone can triage it.
        """
        return [obj for obj in objects if not self.only_scored or obj.severity or has_open_hits(obj)]

    def process(self, objects: Iterable[CodeObject]) -> List[CodeObject]:
        """filter -> score -> select over already parsed objects."""
        return self.select(self.score(self.filter(objects)))

    def process_result(self, parsed: ScanResult) -> ScanResult:
        """A new ``ScanResult`` with the processed objects and the parser errors of ``parsed``."""
        return replace(parsed, objects=self.process(parsed.objects),
                       errors=dict(parsed.errors), parsers=list(parsed.parsers))

    def run(self, source: str) -> ScanResult:
        """Parse ``source`` and process the objects; parser errors are kept in the result."""
        return self.process_result(self.parse(source))
