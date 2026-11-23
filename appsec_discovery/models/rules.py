"""Rule models of the rules engine (stage 5b, P1-6).

Two kinds of rules produce *rule hits* on code objects:

* **keyword rules** - the ``score_tags`` table (one implicit rule per keyword,
  mode ``score_tags_mode``) and ``score_rules`` (``ScoreRule``: matchers on
  parser / object / object_type / field / field_type, with an ``action``);
* **LLM rules** - ``LlmRule``: a versioned system prompt run through an
  ``LlmBackend`` against a field or a whole object.

Every rule has a ``mode``: ``auto`` hits are ``match`` at once and change
the severity/tags of their subject; ``review`` hits start as
``pending_review`` and change nothing until a reviewer confirms them (status ``match``, see
``appsec_discovery.hits.apply_hit_statuses``). An LLM may also answer that it
needs more information (``need_more_info``), which never changes scores.

Severities, statuses and modes are stored as plain strings so that reports
(YAML/JSON/SARIF) and the service DB keep string values.
"""
import fnmatch
import hashlib
import logging
import re
from functools import lru_cache
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, root_validator, validator

from appsec_discovery.matching import Pattern, Severity, safe_search

logger = logging.getLogger(__name__)

__all__ = [
    "HitStatus", "RuleMode", "RuleAction", "HitSubject", "LlmTarget",
    "RuleHit", "ScoreRule", "LlmRule", "project_matches", "status_for_mode", "normalize_hit_status",
    "LEGACY_HIT_STATUSES",
]


class HitStatus(str, Enum):
    """Status of a hit: the verdict words of the rule (``match`` / ``no_match`` / ``need_more_info``) or
    ``pending_review`` (waits for a decision). Who decided is not part of the status."""
    pending_review = 'pending_review'
    need_more_info = 'need_more_info'
    match = 'match'
    no_match = 'no_match'

    def __str__(self) -> str:
        return self.value


# statuses of earlier releases, accepted (with a deprecation warning) for one more release
LEGACY_HIT_STATUSES = {'confirmed': HitStatus.match.value, 'rejected': HitStatus.no_match.value}
_legacy_status_warned = set()


def normalize_hit_status(value) -> str:
    """``HitStatus`` value of ``value``; the legacy ``confirmed`` / ``rejected`` are mapped to ``match`` /
    ``no_match`` with a deprecation warning (once per value). Raises ``ValueError`` for an unknown status."""
    text = str(getattr(value, 'value', value)).lower()
    if text in LEGACY_HIT_STATUSES:
        if text not in _legacy_status_warned:
            _legacy_status_warned.add(text)
            logger.warning("hit status %r is deprecated, use %r (accepted until the next release)",
                           text, LEGACY_HIT_STATUSES[text])
        return LEGACY_HIT_STATUSES[text]
    return _enum_value(HitStatus, text, 'hit status')


class RuleMode(str, Enum):
    auto = 'auto'        # hits are a match at once (they score right away)
    review = 'review'    # hits wait for a human (pending_review)

    def __str__(self) -> str:
        return self.value


class RuleAction(str, Enum):
    score = 'score'      # a hit scores its subject
    exclude = 'exclude'  # becomes an ExcludeScoring rule (suppresses other hits)

    def __str__(self) -> str:
        return self.value


class HitSubject(str, Enum):
    field = 'field'
    prop = 'prop'        # keyword rules match property values (e.g. a route path)
    object = 'object'

    def __str__(self) -> str:
        return self.value


class LlmTarget(str, Enum):
    field = 'field'      # the LLM picks matching fields of the object
    object = 'object'    # the LLM judges the whole object (fields and properties as context)

    def __str__(self) -> str:
        return self.value


def status_for_mode(mode) -> str:
    """Initial status of a hit made by a rule in ``mode``: auto -> match, review -> pending_review."""
    return HitStatus.match.value if RuleMode(mode) is RuleMode.auto else HitStatus.pending_review.value


# ``action: alert`` (score + an ``alert: true`` flag for the MR alerting that was removed) is
# accepted for one more release and treated as ``score``.
_DEPRECATED_ALERT_ACTION = 'alert'
_alert_action_warned = False


def _warn_alert_action() -> None:
    global _alert_action_warned
    if not _alert_action_warned:
        _alert_action_warned = True
        logger.warning("score rule action 'alert' is deprecated and treated as 'score' "
                       "(alerting was removed); it will be rejected in the next release")


def _enum_value(enum, value, what):
    try:
        return enum(str(value).lower()).value
    except ValueError:
        raise ValueError(f"unknown {what} {value!r}, expected one of {[e.value for e in enum]}") from None


def project_matches(pattern: Optional[str], project: Optional[str]) -> bool:
    """A project scope is a case-insensitive glob (``group/*``) or an exact project path."""
    if pattern is None or pattern == '':
        return True
    if project is None:
        return False
    return fnmatch.fnmatchcase(project.lower(), pattern.lower())


class RuleHit(BaseModel):
    """One hit of one rule on one subject (a field, a property or the object itself).

    ``rule`` is the rule name, ``rule_type`` ``keyword`` or ``llm``. ``status``
    is a ``HitStatus`` value; only ``match`` hits change severity/tags.
    """
    rule: str
    rule_type: str
    rule_id: Optional[str]          # id of the rule in an external store (the service DB)
    rule_version: Optional[str]     # LLM rules: prompt version
    model: Optional[str]            # LLM rules: model that produced the hit
    subject: str
    field_name: Optional[str]
    prop_name: Optional[str]
    keyword: Optional[str]          # keyword rules from score_tags: the keyword that matched
    severity: str
    tags: List[str]
    status: str
    reason: Optional[str]           # LLM rules: the model's explanation
    fields: Optional[List[str]]     # object hits: the fields that made the object match
                                    # (combination rules, LLM object rules)
    object_tags: Optional[List[str]]  # the rule's ``tags``: set on the object once the hit is a match

    @validator('severity', pre=True)
    def _severity(cls, value):
        return _enum_value(Severity, value, 'severity')

    @validator('status', pre=True)
    def _status(cls, value):
        return normalize_hit_status(value)

    @validator('subject', pre=True)
    def _subject(cls, value):
        return _enum_value(HitSubject, value, 'hit subject')

    @property
    def subject_name(self) -> Optional[str]:
        return self.field_name if self.subject == HitSubject.field.value else self.prop_name

    def key(self, object_hash: str) -> str:
        """Stable identity of the hit within a scan: object hash + rule + subject.

        Use it to store a triage decision and give it back with ``apply_hit_statuses``.
        """
        parts = [object_hash or '', self.rule_type, self.rule_id or self.rule, self.keyword or '',
                 self.subject, self.subject_name or '']
        return hashlib.md5('#'.join(parts).encode('utf-8')).hexdigest()


@lru_cache(maxsize=1024)
def _field_search(pattern: str) -> 're.Pattern[str]':
    """A ``fields_all`` / ``fields_none`` group: regex searched case-insensitively (a
    non-regex is used literally)."""
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error:
        logger.warning('pattern %r is not a valid regex, matching it as a literal', pattern)
        return re.compile(re.escape(pattern), re.IGNORECASE)


class _Rule(BaseModel):
    id: Optional[str]
    name: Optional[str]
    mode: str = RuleMode.auto.value
    enabled: bool = True

    @validator('mode', pre=True)
    def _mode(cls, value):
        return _enum_value(RuleMode, value, 'rule mode')

    @validator('id', pre=True)
    def _id(cls, value):
        return None if value is None else str(value)

    @validator('tags', pre=True, check_fields=False)
    def _tags(cls, value):
        if value is None:
            return []
        if isinstance(value, str):
            value = value.split(',')
        return list(dict.fromkeys(str(t).strip() for t in value if str(t).strip()))


class ScoreRule(_Rule):
    """A keyword rule with object-level matchers (P1-6).

    Every set matcher must match: ``parser`` exactly (case-insensitive),
    ``object`` (object name), ``object_type``, ``field`` (field name) and
    ``field_type`` as ``Pattern``s (regex from the start or substring).
    ``project`` (a glob) limits the rule to one project, see ``ScoreConfig.for_project``.

    A rule with ``field`` or ``field_type`` hits every matching field (subject
    ``field``); otherwise it hits the object itself (subject ``object``).

    Field combinations (object hits): ``fields_all`` is a list of field-name
    regexes (groups, searched anywhere in the field name, case-insensitive, so
    nested names like ``Request.client.LastName`` match ``last_?name``); the
    object matches when at least ``min_groups``
    groups (default: all) have a matching field, and no field matches a
    ``fields_none`` pattern. Example: ``fields_all: ["last_?name|fio", "phone"]``
    hits an object with a last name and a phone, not one with a first name only.
    The hit lists the fields that satisfied the groups (``RuleHit.fields``).
    ``action``: ``score`` (default) or ``exclude`` (turned into an
    ``ExcludeScoring`` rule: hits on the matching objects/fields, with ``tag``
    if set, are suppressed). The removed ``alert`` action is still accepted for
    one release and treated as ``score`` (a deprecation warning is logged once).
    """
    project: Optional[str]
    parser: Optional[str]
    object_name: Optional[str]
    object_type: Optional[str]
    field_name: Optional[str]
    field_type: Optional[str]
    severity: str = Severity.medium.value
    tag: Optional[str]
    action: str = RuleAction.score.value
    fields_all: List[str] = []
    fields_none: List[str] = []
    min_groups: Optional[int]
    tags: List[str] = []             # tags set on the object when a hit is a match

    _matchers = ('parser', 'object_name', 'object_type', 'field_name', 'field_type', 'fields_all')
    _patterns = ('object_name', 'object_type', 'field_name', 'field_type')

    @root_validator(pre=True, allow_reuse=True)
    def _aliases(cls, values):
        # P1-6 / DB column names: object, field
        values = dict(values)
        for alias, name in (('object', 'object_name'), ('field', 'field_name')):
            if alias in values:
                if values.get(name) is not None:
                    raise ValueError(f"set either {alias!r} or {name!r}, not both")
                values[name] = values.pop(alias)
        return values

    @validator('severity', pre=True)
    def _severity(cls, value):
        return _enum_value(Severity, value, 'severity')

    @validator('action', pre=True)
    def _action(cls, value):
        if str(value).lower() == _DEPRECATED_ALERT_ACTION:
            _warn_alert_action()
            return RuleAction.score.value
        return _enum_value(RuleAction, value, 'rule action')

    @root_validator(skip_on_failure=True, allow_reuse=True)
    def _check(cls, values):
        # empty strings count as unset
        for name in cls._matchers:
            if values.get(name) == '':
                values[name] = None
        if not any(values.get(name) for name in cls._matchers):
            raise ValueError("a score rule needs at least one of parser, object, object_type, field, field_type")
        if values.get('action') != RuleAction.exclude.value and not values.get('tag'):
            raise ValueError(f"a score rule with action {values.get('action')!r} needs a tag")
        for name in cls._patterns:
            if values.get(name) is not None:
                Pattern.of(values[name])  # compile (and warn about a non-regex) at load time
        groups = [g for g in values.get('fields_all') or [] if g]
        values['fields_all'] = groups
        values['fields_none'] = [g for g in values.get('fields_none') or [] if g]
        for pattern in groups + values['fields_none']:
            _field_search(pattern)
        if values['fields_none'] and not groups:
            raise ValueError("fields_none needs fields_all")
        if groups and (values.get('field_name') or values.get('field_type')):
            raise ValueError("fields_all (a combination: object hit) cannot be combined with field / field_type")
        min_groups = values.get('min_groups')
        if min_groups is not None:
            if not groups:
                raise ValueError("min_groups needs fields_all")
            if not 1 <= min_groups <= len(groups):
                raise ValueError(f"min_groups must be between 1 and {len(groups)} (the number of fields_all groups)")
        return values

    @property
    def target(self) -> str:
        return HitSubject.field.value if (self.field_name or self.field_type) else HitSubject.object.value

    @property
    def display_name(self) -> str:
        return self.name or (f"score_rules/{self.id}" if self.id else f"score_rules/{self.tag or 'exclude'}")

    def object_matches(self, obj) -> bool:
        return ((self.parser is None or (obj.parser or '').lower() == self.parser.lower())
                and (self.object_name is None or Pattern.of(self.object_name).matches(obj.object_name))
                and (self.object_type is None or Pattern.of(self.object_type).matches(obj.object_type)))

    def combination_fields(self, obj) -> Optional[List[str]]:
        """``fields_all`` rules: the names of the fields that satisfied the groups, in the
        object's order, when the object matches the combination; None when it does not."""
        names = [f.field_name for f in obj.fields.values()]
        if any(safe_search(p, n) for p in self.fields_none for n in names):
            return None
        hit_groups, matched = 0, []
        for pattern in self.fields_all:
            group = [n for n in names if safe_search(pattern, n)]
            if group:
                hit_groups += 1
                matched.extend(group)
        if hit_groups < (self.min_groups or len(self.fields_all)):
            return None
        return list(dict.fromkeys(n for n in names if n in set(matched)))

    def field_matches(self, field) -> bool:
        return ((self.field_name is None or Pattern.of(self.field_name).matches(field.field_name))
                and (self.field_type is None or Pattern.of(self.field_type).matches(field.field_type)))

    def to_exclude_scoring(self):
        from appsec_discovery.models.config import ExcludeScoring

        return ExcludeScoring(parser=self.parser, object_name=self.object_name, object_type=self.object_type,
                              field_name=self.field_name, field_type=self.field_type, tag=self.tag)


class LlmRule(_Rule):
    """An LLM rule: a versioned system prompt, run through the configured ``LlmBackend``.

    * ``target: field`` - the model gets the object and its candidate fields
      and names the fields that match the rule (one hit per field);
    * ``target: object`` - the model gets the whole object (type, file,
      properties, every field with its type) and judges the object (one hit);
      with ``mark_fields: true`` the fields the model names as making the object
      match get a hit each too (same rule, status, severity, tag and reason, one
      model call per object as without it).

    ``category`` names what the rule looks for; the hit tag is ``tag`` or
    ``llm-<category>``. A rule without ``category`` (field target only) is the
    built-in classifier: the model sorts fields into pii/finance/auth/other and
    the hit gets one ``llm-<category>`` tag per category (that is the implicit
    rule an ``ai_api`` block without ``llm_rules`` runs).

    Scope filters (empty = everything): ``projects`` (globs), ``object_types``
    and ``parsers`` (exact, case-insensitive).
    """
    name: str
    category: Optional[str]
    tag: Optional[str]
    severity: str = Severity.medium.value
    system_prompt: Optional[str]     # None: the built-in prompt of the target
    prompt_version: Optional[str]    # bump when the prompt changes (stored with every hit)
    target: str = LlmTarget.field.value
    mark_fields: bool = False        # target object: also hit the fields the model names
    tags: List[str] = []             # tags set on the object when a hit is a match
    projects: List[str] = []
    object_types: List[str] = []
    parsers: List[str] = []

    @validator('severity', pre=True)
    def _severity(cls, value):
        return _enum_value(Severity, value, 'severity')

    @validator('target', pre=True)
    def _target(cls, value):
        return _enum_value(LlmTarget, value, 'llm rule target')

    @validator('prompt_version', pre=True)
    def _version(cls, value):
        return None if value is None else str(value)

    @root_validator(skip_on_failure=True, allow_reuse=True)
    def _check(cls, values):
        if values.get('target') == LlmTarget.object.value and not (values.get('category') or values.get('tag')):
            raise ValueError("an llm rule with target 'object' needs a category (or a tag)")
        if values.get('mark_fields') and values.get('target') != LlmTarget.object.value:
            raise ValueError("mark_fields only applies to llm rules with target 'object'")
        return values

    @property
    def is_classifier(self) -> bool:
        """The built-in multi-category field classifier (no category, no tag)."""
        return not self.category and not self.tag and self.target == LlmTarget.field.value

    @property
    def hit_tag(self) -> str:
        return self.tag or f"llm-{self.category}"

    def applies_to(self, obj, project: Optional[str] = None) -> bool:
        """Scope check: ``object_types``/``parsers`` always, ``projects`` only when ``project`` is known."""
        if self.object_types and (obj.object_type or '').lower() not in {t.lower() for t in self.object_types}:
            return False
        if self.parsers and (obj.parser or '').lower() not in {p.lower() for p in self.parsers}:
            return False
        if project is not None and self.projects and not any(project_matches(p, project) for p in self.projects):
            return False
        return True
