import logging

from pydantic import BaseModel, root_validator, validator
from typing import Iterable, List, Dict, Optional, Union

from appsec_discovery.matching import Pattern, Severity
from appsec_discovery.models.rules import LlmRule, RuleAction, RuleMode, ScoreRule, project_matches

logger = logging.getLogger(__name__)

# Default endpoint of a local llama.cpp server (same as appsec_discovery.ai.DEFAULT_LOCAL_BASE_URL;
# not imported from there so that loading a config never imports the AI layer).
DEFAULT_LOCAL_LLM_URL = 'http://localhost:8080/v1'
STRUCTURED_MODES = ('auto', 'json_schema', 'json_object', 'none')

default_rules = {
    'pii': {
       'high': [
          'full_name',
          'fullname',
          'first_name',
          'firstname',
          'last_name',
          'lastname',
          'phone',
          'passport',
          'ssn'
       ],
       'medium': [
          'address',
          'email'
       ],
       'low': [
          'city'
       ]
    },
    'finance': {
       'high': [
          'pan',
          'card_number',
          'cardnumber'
       ],
       'medium': [
          'account_number',
          'accountnumber',
          'balance',
          'amount'
       ],
       'low': [
       ]
    },
    'auth': {
       'high': [
          'password',
          'pincode',
          'codeword',
          'token'
       ],
       'medium': [
          'login',
          'email',
          'phone',
          'username',
       ],
       'low': [
       ]
    },
}

def _pattern_matches(raw: Optional[str], value: Optional[str]) -> bool:
    """An unset criterion matches anything; a set one is a ``Pattern``."""
    return raw is None or Pattern.of(raw).matches(value)


def _parser_matches(raw: Optional[str], value: Optional[str]) -> bool:
    """``parser`` is compared exactly, case-insensitively (not a pattern)."""
    return raw is None or (value is not None and raw.lower() == value.lower())


class _ExcludeRule(BaseModel):

    _patterns: tuple = ()

    def __init__(self, **data):
        super().__init__(**data)
        # Compile (and warn about non-regex patterns) once, at config load time.
        for name in self._patterns:
            raw = getattr(self, name)
            if raw is not None:
                Pattern.of(raw)

    def _is_empty(self) -> bool:
        # A rule with no criteria set never matches (an empty string counts as unset).
        return not any(getattr(self, name) for name in self.__fields__)

    def _object_matches(self, obj) -> bool:
        return (
            _parser_matches(self.parser, obj.parser)
            and _pattern_matches(self.file, obj.file)
            and _pattern_matches(self.object_name, obj.object_name)
            and _pattern_matches(self.object_type, obj.object_type)
        )


class ExcludeScan(_ExcludeRule):
    file: Optional[str]
    parser: Optional[str]
    object_name: Optional[str]
    object_type: Optional[str]

    _patterns = ('file', 'object_name', 'object_type')

    def matches(self, obj) -> bool:
        """True when ``obj`` (a ``CodeObject``) must be dropped from the scan."""
        return not self._is_empty() and self._object_matches(obj)

class ExcludeScoring(_ExcludeRule):
    # All set criteria must match. `keyword` matches the exact score_tags keyword
    # that triggered the hit; it only affects keyword scoring, never LLM scoring
    # (LLM tags have no keyword).
    file: Optional[str]
    parser: Optional[str]
    object_name: Optional[str]
    object_type: Optional[str]
    prop_name: Optional[str]
    field_name: Optional[str]
    field_type: Optional[str]
    tag: Optional[str]
    keyword: Optional[str]

    _patterns = ('file', 'object_name', 'object_type', 'prop_name', 'field_name', 'field_type')

    def matches(self, obj, *, prop_name: Optional[str] = None, field=None,
                tag: Union[str, Iterable[str], None] = None, keyword: Optional[str] = None) -> bool:
        """True when a scoring hit on ``obj`` must be suppressed.

        Pass ``prop_name`` for a hit on a property or ``field`` (a
        ``CodeObjectField``) for a hit on a field: ``prop_name`` criteria only
        apply to properties and ``field_name``/``field_type`` only to fields.
        ``tag`` is the tag of the hit (or the list of LLM tags: the rule's tag
        must be one of them). ``keyword`` is the score_tags keyword that hit;
        LLM scoring passes ``None``, so a rule with ``keyword`` never excludes
        LLM tags (intentional).
        """
        if self._is_empty() or not self._object_matches(obj):
            return False

        if field is not None:
            if self.prop_name is not None:
                return False
            if not (_pattern_matches(self.field_name, field.field_name)
                    and _pattern_matches(self.field_type, field.field_type)):
                return False
        else:
            if self.field_name is not None or self.field_type is not None:
                return False
            if not _pattern_matches(self.prop_name, prop_name):
                return False

        if self.tag is not None:
            tags = [tag] if isinstance(tag, str) else list(tag or [])
            if self.tag not in tags:
                return False

        return self.keyword is None or self.keyword == keyword

class AiApi(BaseModel):
    """Any OpenAI-compatible chat-completions endpoint: OpenAI, DeepSeek, a local llama.cpp
    server (``http://localhost:8080/v1``), vLLM, Ollama, ..."""
    base_url: str
    api_key: Optional[str] = None       # a local server needs none
    model: str
    system_prompt: Optional[str] = None  # None: appsec_discovery.ai.DEFAULT_SYSTEM_PROMPT
    timeout: float = 120.0              # seconds per request
    max_retries: int = 2                # connection errors, 429 and 5xx are retried with backoff
    max_tokens: Optional[int] = 8192
    structured: str = 'auto'            # auto | json_schema | json_object | none

    @validator('structured')
    def _known_structured_mode(cls, value):
        value = str(value).lower()
        if value not in STRUCTURED_MODES:
            raise ValueError(f"unknown structured mode {value!r}, expected one of {list(STRUCTURED_MODES)}")
        return value

class AiLocal(BaseModel):
    """DEPRECATED: in-process llama.cpp models are gone. An ``ai_local`` block is mapped to
    ``ai_api`` pointing at a local OpenAI-compatible server (``base_url``, default
    ``http://localhost:8080/v1``), e.g. ``llama-server -hf <model_id>``.
    ``model_folder`` and ``gguf_file`` are ignored (the server loads the model)."""
    base_url: Optional[str] = None
    model_folder: Optional[str] = None
    model_id: Optional[str] = None
    gguf_file: Optional[str] = None
    system_prompt: Optional[str] = None

    def to_ai_api(self) -> AiApi:
        return AiApi(base_url=self.base_url or DEFAULT_LOCAL_LLM_URL, model=self.model_id or 'local-model',
                     system_prompt=self.system_prompt)

# Name of the LLM rule implied by an ``ai_api`` block without ``llm_rules``.
IMPLICIT_LLM_RULE = 'llm-default'


class ScoreConfig(BaseModel):
    parsers: List[str] = ['all']
    object_types: List[str] = ['all']
    score_tags: Dict[str,Dict[str,List[str]]] = default_rules
    # mode of the keyword rules from score_tags: auto (hits match) | review (hits pending_review)
    score_tags_mode: str = RuleMode.auto.value
    # keyword rules with object-level matchers (P1-6), applied after score_tags
    score_rules: List[ScoreRule] = []
    # LLM rules; None (unset) + ai_api -> one implicit rule (the built-in classifier, mode auto)
    llm_rules: Optional[List[LlmRule]]
    ai_local: Optional[AiLocal]   # DEPRECATED alias, mapped to ai_api (see AiLocal)
    ai_api: Optional[AiApi]       # the LLM endpoint every LLM rule runs on
    exclude_scan: List[ExcludeScan] = []
    exclude_scoring: List[ExcludeScoring] = []

    @validator('score_tags_mode', pre=True)
    def _known_mode(cls, value):
        value = str(value).lower()
        if value not in [m.value for m in RuleMode]:
            raise ValueError(f"unknown score_tags_mode {value!r}, expected one of {[m.value for m in RuleMode]}")
        return value

    # -- rules ----------------------------------------------------------------------------------------

    def active_score_rules(self) -> List[ScoreRule]:
        """Enabled ``score_rules`` that score (action ``score``)."""
        return [r for r in self.score_rules if r.enabled and r.action != RuleAction.exclude.value]

    def effective_exclude_scoring(self) -> List[ExcludeScoring]:
        """``exclude_scoring`` plus the enabled ``score_rules`` with action ``exclude``."""
        return list(self.exclude_scoring) + [
            r.to_exclude_scoring() for r in self.score_rules if r.enabled and r.action == RuleAction.exclude.value
        ]

    def effective_llm_rules(self) -> List[LlmRule]:
        """Enabled LLM rules. Without ``llm_rules`` an ``ai_api`` block (or the deprecated
        ``ai_local``) means one implicit rule: the built-in field classifier, mode auto,
        severity medium, the ``ai_api.system_prompt`` - i.e. the pre-rules LLM scoring."""
        if self.llm_rules is None:
            if self.ai_api is None:
                return []
            return [LlmRule(name=IMPLICIT_LLM_RULE, system_prompt=self.ai_api.system_prompt)]
        return [r for r in self.llm_rules if r.enabled]

    def for_project(self, project: Optional[str]) -> 'ScoreConfig':
        """A copy with the rules scoped to ``project`` (P1-6: one config per project).

        ``score_rules`` with a ``project`` glob and ``llm_rules`` with ``projects``
        are kept only when they match ``project``; unscoped rules are always kept.
        ``project=None`` drops every project-scoped rule.
        """
        values = {
            'score_rules': [r for r in self.score_rules if project_matches(r.project, project)],
        }
        if self.llm_rules is not None:
            values['llm_rules'] = [
                r for r in self.llm_rules
                if not r.projects or (project is not None and any(project_matches(p, project) for p in r.projects))
            ]
        return self.copy(update=values)

    @root_validator(skip_on_failure=True, allow_reuse=True)
    def _ai_local_is_deprecated(cls, values):
        ai_local = values.get('ai_local')
        if ai_local is None:
            return values
        if values.get('ai_api') is not None:
            logger.warning("Config: 'ai_local' is deprecated and ignored because 'ai_api' is also set")
            return values
        ai_api = ai_local.to_ai_api()
        logger.warning(f"Config: 'ai_local' is deprecated (models no longer run in-process); using an "
                       f"OpenAI-compatible server at {ai_api.base_url} with model {ai_api.model!r}. "
                       f"Run e.g. `llama-server -hf <repo>` there, or switch the config to 'ai_api'.")
        values['ai_api'] = ai_api
        return values

    @validator('score_tags')
    def _known_severities(cls, score_tags):
        # A typo in a severity key used to surface as a KeyError mid-scan; now it is a
        # validation error (-> ConfigError from load_config). Keys are normalised to lower case.
        known = [s.value for s in Severity]
        result = {}
        for tag, severities in score_tags.items():
            result[tag] = {}
            for severity, keywords in severities.items():
                key = str(severity).lower()
                if key not in known:
                    raise ValueError(f"unknown severity {severity!r} for tag {tag!r}, expected one of {known}")
                result[tag].setdefault(key, []).extend(keywords)
        return result
