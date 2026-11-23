"""Keyword scoring of code objects (P1-3, stage 5b): ``RuleScorer`` and ``ExcludeFilter``.

Keyword rules come from ``score_tags`` (one ``Rule`` per keyword, mode
``score_tags_mode``) and ``score_rules`` (``ScoreRule``, P1-6). Every match that
is not excluded is recorded as a ``RuleHit`` on the object; ``match`` hits
(mode ``auto``) score the subject, ``review`` hits stay ``pending_review``.
"""
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

from appsec_discovery.errors import ConfigError
from appsec_discovery.hits import record_hit
from appsec_discovery.matching import Pattern, Severity
from appsec_discovery.models import (
    CodeObject, ExcludeScan, ExcludeScoring, HitSubject, RuleAction, RuleHit, RuleMode, ScoreConfig, ScoreRule,
)
from appsec_discovery.models.rules import status_for_mode

__all__ = ["Rule", "RuleScorer", "ExcludeFilter"]

KEYWORD = 'keyword'


@dataclass(frozen=True)
class Rule:
    tag: str
    severity: Severity
    pattern: Pattern

    @property
    def keyword(self) -> str:
        return self.pattern.raw

    @property
    def name(self) -> str:
        return f"score_tags/{self.tag}/{self.severity.value}"


def compile_rules(score_tags) -> List[Rule]:
    """``score_tags`` -> ``[Rule(tag, Severity, Pattern)]`` in config order.

    Raises ``ConfigError`` for an unknown severity key (structural error).
    """
    rules: List[Rule] = []
    for tag, severities in score_tags.items():
        for severity, keywords in severities.items():
            try:
                sev = Severity(str(severity).lower())
            except ValueError as e:
                raise ConfigError(f"unknown severity {severity!r} for tag {tag!r}") from e
            for keyword in keywords:
                rules.append(Rule(tag, sev, Pattern.of(keyword)))
    return rules


class RuleScorer:
    """Scores ``CodeObject``s by keyword rules, honouring ``exclude_scoring``.

    ``score_tags``: properties are matched on their value, fields on their
    name; rules are applied in config order, props before fields for each
    rule, so tag order is the same as before P1-3. ``score_rules`` follow,
    in order. Excludes are only evaluated for an actual match. Each match
    that is not excluded becomes a ``RuleHit``; with mode ``auto`` it is a
    ``match`` and raises the target's and the object's severity (see
    ``merge_score``), with mode ``review`` it is ``pending_review``.
    """

    def __init__(self, score_tags, exclude_scoring: Sequence[ExcludeScoring] = (),
                 score_rules: Sequence[ScoreRule] = (), score_tags_mode: str = RuleMode.auto.value):
        self.rules = compile_rules(score_tags)
        self.exclude_scoring = list(exclude_scoring)
        self.score_rules = [r for r in score_rules if r.enabled and r.action != RuleAction.exclude.value]
        self.score_tags_status = status_for_mode(score_tags_mode)

    @classmethod
    def from_config(cls, config: ScoreConfig) -> 'RuleScorer':
        return cls(config.score_tags, config.effective_exclude_scoring(),
                   score_rules=config.active_score_rules(), score_tags_mode=config.score_tags_mode)

    def _excluded(self, obj: CodeObject, tag: str, keyword: Optional[str], **target) -> bool:
        return any(
            exclude.matches(obj, tag=tag, keyword=keyword, **target)
            for exclude in self.exclude_scoring
        )

    def _tag_hit(self, rule: Rule, **subject) -> RuleHit:
        return RuleHit(rule=rule.name, rule_type=KEYWORD, keyword=rule.keyword, severity=rule.severity.value,
                       tags=[rule.tag], status=self.score_tags_status, **subject)

    @staticmethod
    def _score_rule_hit(rule: ScoreRule, **subject) -> RuleHit:
        return RuleHit(rule=rule.display_name, rule_id=rule.id, rule_type=KEYWORD, severity=rule.severity,
                       tags=[rule.tag], status=status_for_mode(rule.mode), object_tags=rule.tags or None,
                       **subject)

    def score(self, obj: CodeObject) -> CodeObject:
        """Score ``obj`` in place (recording its hits) and return it."""
        props = list(obj.properties.items())
        fields = list(obj.fields.values())

        for rule in self.rules:

            for prop_name, prop in props:
                if (rule.pattern.matches(prop.prop_value)
                        and not self._excluded(obj, rule.tag, rule.keyword, prop_name=prop_name)):
                    record_hit(obj, self._tag_hit(rule, subject=HitSubject.prop.value, prop_name=prop_name))

            for field in fields:
                if (rule.pattern.matches(field.field_name)
                        and not self._excluded(obj, rule.tag, rule.keyword, field=field)):
                    record_hit(obj, self._tag_hit(rule, subject=HitSubject.field.value,
                                                  field_name=field.field_name))

        for rule in self.score_rules:
            if not rule.object_matches(obj):
                continue
            if rule.fields_all:
                matched = rule.combination_fields(obj)
                if matched is not None and not self._excluded(obj, rule.tag, None):
                    record_hit(obj, self._score_rule_hit(rule, subject=HitSubject.object.value, fields=matched))
            elif rule.target == HitSubject.field.value:
                for field in fields:
                    if rule.field_matches(field) and not self._excluded(obj, rule.tag, None, field=field):
                        record_hit(obj, self._score_rule_hit(rule, subject=HitSubject.field.value,
                                                             field_name=field.field_name))
            elif not self._excluded(obj, rule.tag, None):
                record_hit(obj, self._score_rule_hit(rule, subject=HitSubject.object.value))

        return obj

    def score_all(self, objects: Iterable[CodeObject]) -> List[CodeObject]:
        return [self.score(obj) for obj in objects]


class ExcludeFilter:
    """Drops objects matched by ``exclude_scan`` or not allowed by ``object_types``."""

    def __init__(self, exclude_scan: Sequence[ExcludeScan] = (), object_types: Sequence[str] = ('all',)):
        self.exclude_scan = list(exclude_scan)
        self.object_types = [t.lower() for t in object_types]

    @classmethod
    def from_config(cls, config: ScoreConfig) -> 'ExcludeFilter':
        return cls(config.exclude_scan, config.object_types)

    def keep(self, obj: CodeObject) -> bool:
        if 'all' not in self.object_types and (obj.object_type or '').lower() not in self.object_types:
            return False
        return not any(exclude.matches(obj) for exclude in self.exclude_scan)

    def filter(self, objects: Iterable[CodeObject]) -> List[CodeObject]:
        return [obj for obj in objects if self.keep(obj)]
