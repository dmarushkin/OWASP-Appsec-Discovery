"""Request / response schemas of the REST API and the MCP tools (pydantic v2).

Rules are one table (``rules``) with two API resources: ``/keyword_rules`` and
``/llm_rules``. Their matchers live in ``rules.scope`` (jsonb) and are flattened here.
Read schemas carry every column; write schemas only what a user may set (react-admin sends
the whole record on PUT, unknown / read-only fields are ignored).

Patterns (``*_re``) are not compiled strictly: the core matches a pattern as a regex from
the start, or as a substring when it is not a valid regex (see ``appsec_discovery.matching
.Pattern``), so a literal keyword is a valid pattern.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class RuleMode(str, Enum):
    auto = "auto"        # hits are a match at once
    review = "review"    # hits wait in the review queue


class KeywordAction(str, Enum):
    score = "score"      # hits score their subject
    exclude = "exclude"  # core exclusion: suppresses other hits, never hits itself


class LlmTarget(str, Enum):
    field = "field"
    object = "object"


class HitStatus(str, Enum):
    pending_review = "pending_review"
    need_more_info = "need_more_info"
    match = "match"              # was "confirmed" (migration 0023)
    no_match = "no_match"        # was "rejected"


class ReviewAction(str, Enum):
    confirm = "confirm"
    reject = "reject"
    request_info = "request_info"
    reopen = "reopen"


ACTION_STATUS = {
    ReviewAction.confirm: HitStatus.match.value,
    ReviewAction.reject: HitStatus.no_match.value,
    ReviewAction.request_info: HitStatus.need_more_info.value,
    ReviewAction.reopen: HitStatus.pending_review.value,
}

PATTERN_MAX = 500
TEXT_MAX = 200
TAGS_MAX = 20


def clean_tags(tags) -> Optional[List[str]]:
    """Stripped, unique, non-empty tags (each up to TEXT_MAX characters); None when empty."""
    out = []
    for tag in tags or []:
        tag = str(tag).strip()
        if len(tag) > TEXT_MAX:
            raise ValueError(f"tag longer than {TEXT_MAX} characters")
        if tag and tag not in out:
            out.append(tag)
    return out or None


def nested_quantifier(pattern: str) -> Optional[str]:
    """A part of ``pattern`` that backtracks catastrophically on a near-miss (``(a+)+$``,
    ``(\\w*)*``, ``(x+|y)+``: a repeated group whose body - or one alternative of it - is
    itself an unbounded repeat), or None. Rule patterns run on names from scanned code and
    ingest, in the scanner and in dry runs; such a group is always rewritable (``a+``).
    A pattern that is not a valid regex is matched literally, so it is never one."""
    import re
    try:
        try:
            from re import _parser as sre_parse, _constants as sre_c       # Python 3.11+
        except ImportError:                                                # pragma: no cover
            import sre_parse, sre_constants as sre_c
        tree = sre_parse.parse(pattern)
    except (re.error, ImportError, RecursionError):
        return None
    repeats = (sre_c.MAX_REPEAT, sre_c.MIN_REPEAT) + ((sre_c.POSSESSIVE_REPEAT,) if hasattr(sre_c, "POSSESSIVE_REPEAT") else ())

    def unbounded(item) -> bool:
        op, av = item
        return op in repeats and av[1] == sre_c.MAXREPEAT

    def body_items(items):
        items = list(items)
        while len(items) == 1 and items[0][0] == sre_c.SUBPATTERN:
            items = list(items[0][1][-1])
        return items

    def single_repeat(items) -> bool:
        items = body_items(items)
        if len(items) == 1 and unbounded(items[0]):
            return True
        if len(items) == 1 and items[0][0] == sre_c.BRANCH:
            return any(single_repeat(alt) for alt in items[0][1][1])
        return False

    def walk(items) -> bool:
        for op, av in items:
            if op in repeats:
                if av[1] == sre_c.MAXREPEAT and single_repeat(av[2]):
                    return True
                if walk(av[2]):
                    return True
            elif op == sre_c.SUBPATTERN and walk(av[-1]):
                return True
            elif op == sre_c.BRANCH and any(walk(alt) for alt in av[1]):
                return True
            elif op in (sre_c.ASSERT, sre_c.ASSERT_NOT) and walk(av[1]):
                return True
        return False

    return pattern if walk(tree) else None


def check_patterns(model, names) -> None:
    for name in names:
        value = getattr(model, name, None)
        for pattern in (value if isinstance(value, list) else [value]):
            if pattern and nested_quantifier(pattern):
                raise ValueError(f"{name}: {pattern!r} has a nested quantifier (like (a+)+) that can take hours to "
                                 "match a near-miss name: simplify it (e.g. (a+)+ -> a+)")


def _clean(value):
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return value


class _Input(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    @model_validator(mode="before")
    @classmethod
    def _unset_empty(cls, data):
        # null / blank values mean "not set": the field default applies
        if isinstance(data, dict):
            return {k: v for k, v in ((k, _clean(v)) for k, v in data.items()) if v is not None}
        return data


KEYWORD_SCOPE_KEYS = ("project_re", "parser", "object_re", "object_type_re", "field_re", "field_type_re",
                      "fields_all", "fields_none", "min_groups")
KEYWORD_MATCHERS = ("parser", "object_re", "object_type_re", "field_re", "field_type_re", "fields_all")
LLM_PATTERN_KEYS = ("project_re", "object_re", "object_type_re", "field_re", "field_type_re")
# scope of an LLM rule: the patterns + mark_fields (target object: the named fields get hits too)
LLM_SCOPE_KEYS = LLM_PATTERN_KEYS + ("mark_fields",)


class KeywordRuleIn(_Input):
    """A keyword rule: every set matcher must match. ``field_re``/``field_type_re`` make it a
    field rule (one hit per matching field), otherwise it hits the object.

    Field combinations: ``fields_all`` is a list of field-name regexes (groups, searched
    anywhere in the name, case-insensitive); the object is hit when at least ``min_groups``
    groups (default all) have a matching field and no field matches ``fields_none``. The hit
    lists the fields that matched, e.g. ``["last_?name|fio", "phone"]``: last name + phone."""
    name: str = Field(min_length=1, max_length=TEXT_MAX)
    category: Optional[str] = Field(default=None, max_length=TEXT_MAX)
    severity: Severity = Severity.medium
    mode: RuleMode = RuleMode.auto
    enabled: bool = True
    action: KeywordAction = KeywordAction.score
    project_re: Optional[str] = Field(default=None, max_length=PATTERN_MAX)
    parser: Optional[str] = Field(default=None, max_length=TEXT_MAX)
    object_re: Optional[str] = Field(default=None, max_length=PATTERN_MAX)
    object_type_re: Optional[str] = Field(default=None, max_length=PATTERN_MAX)
    field_re: Optional[str] = Field(default=None, max_length=PATTERN_MAX)
    field_type_re: Optional[str] = Field(default=None, max_length=PATTERN_MAX)
    fields_all: Optional[List[str]] = Field(default=None, max_length=20)
    fields_none: Optional[List[str]] = Field(default=None, max_length=20)
    min_groups: Optional[int] = Field(default=None, ge=1)
    tags: Optional[List[str]] = Field(default=None, max_length=TAGS_MAX)     # set on the object of match hits

    @model_validator(mode="after")
    def _check(self):
        import re
        self.tags = clean_tags(self.tags)
        self.fields_all = [g.strip() for g in self.fields_all or [] if g and g.strip()] or None
        self.fields_none = [g.strip() for g in self.fields_none or [] if g and g.strip()] or None
        for pattern in (self.fields_all or []) + (self.fields_none or []):
            if len(pattern) > PATTERN_MAX:
                raise ValueError(f"field pattern longer than {PATTERN_MAX} characters")
            try:
                re.compile(pattern)
            except re.error as e:
                raise ValueError(f"invalid field pattern {pattern!r}: {e}") from None
        check_patterns(self, ("project_re", "object_re", "object_type_re", "field_re", "field_type_re",
                              "fields_all", "fields_none"))
        if not any(getattr(self, name) for name in KEYWORD_MATCHERS):
            raise ValueError("a keyword rule needs at least one of parser, object_re, object_type_re, field_re, "
                             "field_type_re, fields_all")
        if self.action != KeywordAction.exclude and not self.category:
            raise ValueError(f"a keyword rule with action {self.action.value!r} needs a category")
        if self.fields_all and (self.field_re or self.field_type_re):
            raise ValueError("fields_all (a combination: object hit) cannot be combined with field_re / field_type_re")
        if self.fields_none and not self.fields_all:
            raise ValueError("fields_none needs fields_all")
        if self.min_groups is not None and not (self.fields_all and self.min_groups <= len(self.fields_all)):
            raise ValueError("min_groups needs fields_all and must not exceed the number of its groups")
        if self.fields_all and self.action == KeywordAction.exclude:
            raise ValueError("fields_all cannot be used with action 'exclude'")
        return self

    @property
    def target(self) -> str:
        return "field" if (self.field_re or self.field_type_re) else "object"

    def scope(self) -> Dict[str, Any]:
        scope = {key: getattr(self, key) for key in KEYWORD_SCOPE_KEYS if getattr(self, key)}
        scope["action"] = self.action.value
        return scope


class LlmRuleIn(_Input):
    """An LLM rule: ``prompt`` is the system prompt (None: the built-in prompt). Without
    ``category`` a field rule is the built-in classifier (pii / finance / auth / other)."""
    name: str = Field(min_length=1, max_length=TEXT_MAX)
    category: Optional[str] = Field(default=None, max_length=TEXT_MAX)
    severity: Severity = Severity.medium
    mode: RuleMode = RuleMode.auto      # like keyword rules (UI, REST and MCP alike)
    enabled: bool = True
    target: LlmTarget = LlmTarget.field
    prompt: Optional[str] = Field(default=None, max_length=20000)
    project_re: Optional[str] = Field(default=None, max_length=PATTERN_MAX)
    object_re: Optional[str] = Field(default=None, max_length=PATTERN_MAX)
    object_type_re: Optional[str] = Field(default=None, max_length=PATTERN_MAX)
    field_re: Optional[str] = Field(default=None, max_length=PATTERN_MAX)
    field_type_re: Optional[str] = Field(default=None, max_length=PATTERN_MAX)
    # target object: an object verdict (match / need_more_info) also hits each field the model
    # named (same status, severity, reason); still one model call per object
    mark_fields: bool = False
    tags: Optional[List[str]] = Field(default=None, max_length=TAGS_MAX)     # set on the object of match hits

    @model_validator(mode="after")
    def _check(self):
        self.tags = clean_tags(self.tags)
        check_patterns(self, LLM_PATTERN_KEYS)
        if self.target == LlmTarget.object and not self.category:
            raise ValueError("an llm rule with target 'object' needs a category")
        if self.target == LlmTarget.object and (self.field_re or self.field_type_re):
            raise ValueError("field_re / field_type_re only apply to llm rules with target 'field'")
        if self.mark_fields and self.target != LlmTarget.object:
            raise ValueError("mark_fields only applies to llm rules with target 'object'")
        return self

    def scope(self) -> Dict[str, Any]:
        # mark_fields is stored only when set, so rules without it keep their scope (and version)
        return {key: getattr(self, key) for key in LLM_SCOPE_KEYS if getattr(self, key)}


class _RuleOut(BaseModel):
    id: int
    name: Optional[str]
    category: Optional[str]
    severity: Optional[str]
    mode: Optional[str]
    enabled: bool
    target: Optional[str]
    version: int
    builtin: Optional[str] = None       # 'core' (the built-in keyword scoring: kw-fields / kw-props) | None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    updated_by: Optional[str] = None
    deleted_at: Optional[datetime] = None
    pending_hits: Optional[int] = None
    tags: Optional[List[str]] = None


class KeywordRuleOut(_RuleOut):
    action: Optional[str] = None
    project_re: Optional[str] = None
    parser: Optional[str] = None
    object_re: Optional[str] = None
    object_type_re: Optional[str] = None
    field_re: Optional[str] = None
    field_type_re: Optional[str] = None
    fields_all: Optional[List[str]] = None
    fields_none: Optional[List[str]] = None
    min_groups: Optional[int] = None


class LlmRuleOut(_RuleOut):
    prompt: Optional[str] = None
    project_re: Optional[str] = None
    object_re: Optional[str] = None
    object_type_re: Optional[str] = None
    field_re: Optional[str] = None
    field_type_re: Optional[str] = None
    mark_fields: bool = False


class HitOut(BaseModel):
    id: str                              # "<rule_id>:<subject_key>"
    rule_id: int
    rule_name: Optional[str] = None
    rule_kind: Optional[str] = None
    rule_enabled: Optional[bool] = None
    rule_version: int
    current_rule_version: Optional[int] = None
    subject_key: str
    project_id: int
    project_path: Optional[str] = None
    object_key: str
    object_name: Optional[str] = None
    object_type: Optional[str] = None
    parser: Optional[str] = None
    file: Optional[str] = None
    field_name: Optional[str] = None
    status: str
    category: Optional[str] = None
    severity: Optional[str] = None
    model: Optional[str] = None
    reason: Optional[str] = None
    reviewer: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    # who set the status: 'human' (a review), 'machine' (auto rule, LLM verdict); None while open
    decided_by: Optional[str] = None
    decided_via: Optional[str] = None     # where a human decision was made: rest | mcp
    # tiered workflow (migrations 0020, 0021): service (service model / scan) | harness (the harness model
    # verified it) | human
    decided_tier: Optional[str] = None
    verifier_model: Optional[str] = None
    verified_at: Optional[datetime] = None
    asked_by_model: Optional[bool] = None   # the harness model asked a human (question in the note)
    machine_status: Optional[str] = None    # the service model's status when a human / the harness model decided
    note: Optional[str] = None
    # object hits of combination / LLM object rules: the fields that made the object match
    fields: Optional[List[str]] = None
    # tags the hit sets on its object once it is a match: the rule's tags + the hit's own (manual labels)
    tags: Optional[List[str]] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    in_main: Optional[bool] = None
    in_open_mr: Optional[bool] = None
    # LLM hits (``discovery_common.lifecycle``): the machine verdict is of an older version of the rule (rule version,
    # core prompts, service model): kept and scoring until the rule's rollout asks it again (stale-while-revalidate)
    prompt_version: Optional[str] = None
    stale: Optional[bool] = None
    stale_reason: Optional[str] = None
    # the review actions the status allows (confirm | reject | request_info | reopen), in list rows too
    allowed_actions: Optional[List[str]] = None
    # a review of an object hit of an LLM rule with mark_fields: how many of its service-tier field hits got the same
    # decision (None when the review cascades to nothing)
    cascaded: Optional[int] = None


class FieldContext(BaseModel):
    name: str
    type: Optional[str] = None
    line: Optional[int] = None
    is_subject: bool = False


class ObjectContext(BaseModel):
    object_key: str
    content_hash: str
    name: Optional[str] = None
    type: Optional[str] = None
    parser: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    props: Optional[Dict[str, Any]] = None
    fields: List[FieldContext] = []
    source: str                          # 'main' | 'mr' | 'orphan' (no live branch has it)


class Presence(BaseModel):
    branch_id: int
    branch_name: str
    is_main: bool
    change: Optional[str] = None         # MR delta: added | modified | removed
    mr_iid: Optional[int] = None
    mr_title: Optional[str] = None


class SiblingHit(BaseModel):
    id: str
    rule_name: Optional[str] = None
    field_name: Optional[str] = None
    status: str
    category: Optional[str] = None
    severity: Optional[str] = None


class RuleBrief(BaseModel):
    id: int
    name: Optional[str] = None
    kind: Optional[str] = None
    target: Optional[str] = None
    mode: Optional[str] = None
    version: int
    enabled: bool
    prompt: Optional[str] = None


class HitDetail(HitOut):
    rule: Optional[RuleBrief] = None
    object: Optional[ObjectContext] = None
    presence: List[Presence] = []
    other_hits: List[SiblingHit] = []
    allowed_actions: List[str] = []
    # what the service model said about the hit's current rule version (``hit_verdicts``), kept when a human or the
    # harness model decided since; the hit's ``reason`` while the service verdict is the current one
    service_reason: Optional[str] = None


class ReviewIn(_Input):
    action: ReviewAction
    category: Optional[str] = Field(default=None, max_length=TEXT_MAX)
    severity: Optional[Severity] = None
    note: Optional[str] = Field(default=None, max_length=5000)


class HitUpdateIn(_Input):
    """Change category / severity / note without a status transition."""
    category: Optional[str] = Field(default=None, max_length=TEXT_MAX)
    severity: Optional[Severity] = None
    note: Optional[str] = Field(default=None, max_length=5000)


class ParseOneIn(BaseModel):
    """``POST /projects/{id}/parse`` options (all optional)."""
    model_config = ConfigDict(extra="forbid")
    parsers: Optional[List[str]] = None   # only these parsers (default: the scanner's PARSERS)
    mains: bool = True       # parse the main branch (skipped when parsed with the same rules / parsers, see force)
    mrs: bool = True         # parse open merge requests
    llm: bool = False        # also run the LLM rules (else: POST /llm_rules/run over the stored snapshots)
    force: bool = False      # parse the main branch even when a parse with the same rules / parsers exists


class ParseIn(ParseOneIn):
    """``POST /projects/parse``: ``project_ids`` None = every project."""
    project_ids: Optional[List[int]] = None


class ScanMode(str, Enum):
    rules = "rules"            # keyword + LLM rules categorise objects
    inventory = "inventory"    # objects / fields only; people label them (manual labels)


class ProjectUpdateIn(BaseModel):
    """``PATCH /projects/{id}``."""
    model_config = ConfigDict(extra="ignore")
    scan_mode: ScanMode
    parse: bool = True         # queue a parse of the project after a mode switch


class LabelIn(BaseModel):
    """``POST /objects/{object_key}/labels``: label the object, or one field (``field_name``)."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    category: str = Field(min_length=1, max_length=TEXT_MAX)
    severity: Severity = Severity.medium
    field_name: Optional[str] = Field(default=None, max_length=TEXT_MAX)
    note: Optional[str] = Field(default=None, max_length=4000)
    tags: Optional[List[str]] = Field(default=None, max_length=TAGS_MAX)     # tags set on the object

    @model_validator(mode="after")
    def _tags(self):
        self.tags = clean_tags(self.tags)
        return self


class LlmExecutor(str, Enum):
    service = "service"        # the scanner calls its LLM API (LLM_API_URL)
    external = "external"      # a model outside the service answers work items (llm_work_claim / submit)


class LlmRuleRunIn(BaseModel):
    """``POST /llm_rules/{id}/run``: run the rule over projects already parsed."""
    model_config = ConfigDict(extra="forbid")
    project_ids: Optional[List[int]] = None    # None: every project (in rules mode)
    mrs: bool = False                          # also the deltas of open merge requests
    executor: LlmExecutor = LlmExecutor.service


class LlmRulesRunIn(LlmRuleRunIn):
    """``POST /llm_rules/run``: several LLM rules in one go (one job per branch)."""
    rule_ids: List[int] = Field(min_length=1)


class LlmWorkClaimIn(BaseModel):
    """``POST /llm_work/claim``: lease work items of external LLM runs."""
    model_config = ConfigDict(extra="forbid")
    job_id: Optional[int] = None               # one run (its llm_prepare job id), default any
    limit: int = Field(default=3, ge=1, le=10)
    lease_seconds: int = Field(default=300, ge=30, le=900)
    # nothing to claim: take over the pending service run job_id (else the oldest) - see take_over
    take_over_pending: bool = False
    # score: model calls of external LLM runs; verify: the tiered workflow's verify items (a harness model)
    purpose: Literal["score", "verify"] = "score"


class LlmTakeOverIn(BaseModel):
    """``POST /llm_work/take_over``: pending service LLM runs become external runs (same job ids)."""
    model_config = ConfigDict(extra="forbid")
    job_id: Optional[int] = None               # that pending llm_score job, default the oldest ones
    limit: int = Field(default=1, ge=1, le=5)


class LlmWorkAnswerIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: int
    answer: Union[str, Dict[str, Any], List[Any]]
    model: Optional[str] = Field(default=None, max_length=100)
    lease: Optional[str] = Field(default=None, max_length=100)


class LlmWorkSubmitIn(BaseModel):
    """``POST /llm_work/submit``: answers of leased items (``lease`` per item or for all)."""
    model_config = ConfigDict(extra="forbid")
    items: List[LlmWorkAnswerIn] = Field(min_length=1, max_length=100)
    lease: Optional[str] = Field(default=None, max_length=100)


class LlmWorkReleaseIn(BaseModel):
    """``POST /llm_work/release``: ``ids`` + ``lease`` (claimed items back to pending), or ``job_id``
    + ``all_unanswered`` (everything unanswered of that external run back to the service)."""
    model_config = ConfigDict(extra="forbid")
    ids: Optional[List[int]] = Field(default=None, min_length=1, max_length=100)
    lease: Optional[str] = Field(default=None, min_length=1, max_length=100)
    job_id: Optional[int] = None
    all_unanswered: bool = False

    @model_validator(mode="after")
    def _mode(self):
        if self.all_unanswered:
            if self.job_id is None or self.ids:
                raise ValueError("all_unanswered needs job_id (and no ids)")
        elif not (self.ids and self.lease):
            raise ValueError("ids and lease are required (or job_id with all_unanswered)")
        return self


class BulkReviewIn(BaseModel):
    """``POST /hits/review_bulk``."""
    model_config = ConfigDict(extra="forbid")
    hit_ids: List[str] = Field(min_length=1, max_length=50)
    action: ReviewAction
    note: str = Field(min_length=1, max_length=4000)
    category: Optional[str] = Field(default=None, max_length=TEXT_MAX)
    severity: Optional[Severity] = None
    dry_run: bool = True


class DecideIn(_Input):
    """``POST /hits/decide`` (contract 6): one review action on every hit of ``filter`` (the filters of ``GET /hits``,
    e.g. ``{"cluster": "schema:ab12...", "status": ["pending_review"], "group": "grp/payments"}``). ``dry_run``
    (default) reports ``matched`` and what is kept; the apply needs ``expected_total`` = that figure."""
    filter: Dict[str, Any] = Field(min_length=1)
    action: ReviewAction
    note: str = Field(min_length=1, max_length=4000)
    category: Optional[str] = Field(default=None, max_length=TEXT_MAX)
    severity: Optional[Severity] = None
    expected_total: Optional[int] = Field(default=None, ge=0)
    dry_run: bool = True
    # human decisions are kept unless a human re-decides them on purpose; the harness model's questions are skipped
    include_human: bool = False
    include_harness: bool = False
    skip_questions: bool = True


class DryRunIn(BaseModel):
    """``POST /rules/dry_run``: a new rule (kind + rule) or an existing one (rule_id + patch)."""
    model_config = ConfigDict(extra="forbid")
    kind: Optional[str] = None
    rule: Optional[Dict[str, Any]] = None
    rule_id: Optional[int] = None
    project_ids: Optional[List[int]] = None
    sample: int = Field(default=20, ge=0, le=50)


class LabelItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    object_id: str
    field_name: Optional[str] = None


class LabelBulkIn(BaseModel):
    """``POST /objects/labels``: the same manual label on up to 50 objects / fields."""
    model_config = ConfigDict(extra="forbid")
    items: List[LabelItem] = Field(min_length=1, max_length=50)
    category: str = Field(min_length=1, max_length=TEXT_MAX)
    severity: Severity = Severity.medium
    tags: Optional[List[str]] = Field(default=None, max_length=TAGS_MAX)
    note: Optional[str] = Field(default=None, max_length=4000)
    dry_run: bool = True

    @model_validator(mode="after")
    def _tags(self):
        self.tags = clean_tags(self.tags)
        return self


class MrScanIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    llm: bool = True


INGEST_MAX_OBJECTS = 50_000          # per request (POST /ingest or one session chunk)
INGEST_MAX_FIELDS = 500_000          # per request, all objects together
INGEST_MAX_OBJECT_FIELDS = 5_000
SESSION_MAX_OBJECTS = 1_000_000      # per upload session
SESSION_MAX_FIELDS = 10_000_000
PROPS_MAX = 50
INT32_MAX = 2**31 - 1
EXTERNAL_PREFIX = "external/"
PropValue = Union[str, int, float, bool, None]


def prop_text(value) -> str:
    """One canonical text per prop value (the content hash of an object depends on it)."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


INGEST_COMMENT_MAX = 4000
INGEST_SAMPLES_MAX = 20
INGEST_SAMPLE_MAX = 1000


class IngestField(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=255)
    type: Optional[str] = Field(default=None, max_length=255)
    line: Optional[int] = Field(default=None, ge=0, le=INT32_MAX)     # e.g. the column's ordinal_position
    # e.g. the column description (MS_Description, COMMENT ON COLUMN) and a few example values.
    # Samples are stored as sent: send masked / synthetic values, not real personal data.
    # The scanner keeps the first 1000 characters of a comment and 5 samples of 200 characters.
    comment: Optional[str] = Field(default=None, max_length=INGEST_COMMENT_MAX)
    samples: Optional[List[str]] = Field(default=None, max_length=INGEST_SAMPLES_MAX)

    @field_validator("samples")
    @classmethod
    def _samples(cls, value):
        if value and any(len(v) > INGEST_SAMPLE_MAX for v in value):
            raise ValueError(f"a sample is at most {INGEST_SAMPLE_MAX} characters")
        return value


class IngestObject(BaseModel):
    """One object of an external parser, e.g. a table: name ``dbo.Clients``, type ``table``,
    file (its location) ``db01/billing``, props ``{"server", "database", "schema", ...}``,
    fields = columns. Identity = (parser, file, type, name): keep them stable between pushes
    (same case, same format), else the objects come back as new ones."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=500)
    type: str = Field(min_length=1, max_length=100)
    file: Optional[str] = Field(default=None, max_length=500)
    line: Optional[int] = Field(default=None, ge=0, le=INT32_MAX)
    props: Dict[str, PropValue] = Field(default_factory=dict)
    fields: List[IngestField] = Field(default_factory=list, max_length=INGEST_MAX_OBJECT_FIELDS)
    comment: Optional[str] = Field(default=None, max_length=INGEST_COMMENT_MAX)   # e.g. the table description

    @model_validator(mode="after")
    def _check(self):
        if len(self.props) > PROPS_MAX:
            raise ValueError(f"object {self.name!r}: at most {PROPS_MAX} props")
        for key, value in self.props.items():
            if not key or len(key) > 100 or len(prop_text(value)) > 1000:
                raise ValueError(f"object {self.name!r}: prop keys up to 100, values up to 1000 characters")
        names = [f.name for f in self.fields]
        if len(names) != len(set(names)):
            raise ValueError(f"object {self.name!r} has duplicate field names")
        return self

    def payload(self) -> Dict[str, Any]:
        data = self.model_dump(exclude_none=True)
        data["props"] = {k: prop_text(v) for k, v in self.props.items()}
        return data


class IngestObjectsIn(BaseModel):
    """Objects of one request (a session chunk)."""
    model_config = ConfigDict(extra="forbid")
    objects: List[IngestObject] = Field(max_length=INGEST_MAX_OBJECTS)

    @model_validator(mode="after")
    def _check(self):
        if sum(len(o.fields) for o in self.objects) > INGEST_MAX_FIELDS:
            raise ValueError(f"at most {INGEST_MAX_FIELDS} fields per request: split it (upload sessions)")
        keys = [(o.type, o.file or "", o.name) for o in self.objects]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate objects (same type, file and name)")
        return self


class IngestTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    project: str = Field(min_length=len(EXTERNAL_PREFIX) + 1, max_length=255,
                         pattern=r"^external(/[A-Za-z0-9_][A-Za-z0-9._\-]*)+$")
    parser: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_.:\-]*$")
    snapshot: Optional[str] = Field(default=None, max_length=100)   # a version label (default: now)
    llm: bool = False          # also run the LLM rules on the snapshot afterwards

    @model_validator(mode="after")
    def _parser(self):
        from discovery_common.models import PARSER_TYPES
        if self.parser in PARSER_TYPES:
            raise ValueError(f"parser {self.parser!r} is a built-in parser name: use your own (e.g. mssql, postgres)")
        return self


class IngestIn(IngestTarget, IngestObjectsIn):
    """``POST /ingest``: the full state of one external parser for one external project
    (``external/...``) in one request; objects missing from it are removed from the snapshot."""


class IngestSessionIn(IngestTarget):
    """``POST /ingest/sessions``: start an upload of a large state in chunks."""


class ApiTokenIn(BaseModel):
    """``POST /tokens``: a service token - scope ``ingest`` (a collector: ``project_prefixes`` under ``external/``
    required) and / or ``mcp`` (a harness / agent client with its own reviewer identity ``token:<name>``)."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=100)
    project_prefixes: List[str] = Field(default_factory=list, max_length=50)
    scopes: List[str] = Field(default_factory=lambda: ["ingest"])

    @model_validator(mode="after")
    def _check(self):
        if set(self.scopes) - {"ingest", "mcp"} or not self.scopes:
            raise ValueError("scopes: some of 'ingest', 'mcp'")
        if "ingest" in self.scopes and not self.project_prefixes:
            raise ValueError("project_prefixes: an ingest token needs at least one path under external/")
        for prefix in self.project_prefixes:
            if not prefix.startswith(EXTERNAL_PREFIX) or len(prefix) <= len(EXTERNAL_PREFIX) or ".." in prefix:
                raise ValueError(f"project prefix {prefix!r} must be a path under {EXTERNAL_PREFIX}")
        if ":" in self.name or "/" in self.name:
            raise ValueError("name must not contain ':' or '/'")
        return self


# ---- prompt trials and proposals (services.trials_service) ---------------------------------------------

class TrialVerdict(str, Enum):
    match = "match"
    no_match = "no_match"
    need_more_info = "need_more_info"


class TrialSubjectIn(BaseModel):
    """A subject of a prompt trial with the verdict the caller expects (``object_key``: the object; a field rule
    also needs ``field_name``)."""
    model_config = ConfigDict(extra="forbid")
    object_key: str = Field(min_length=1, max_length=100)
    field_name: Optional[str] = Field(default=None, max_length=1000)
    expected: TrialVerdict


class PromptTrialIn(BaseModel):
    """``POST /llm_rules/{id}/trials``: try a candidate prompt with the service model on ``subjects`` (or the
    mislabelled subjects of human decisions, ``from_mislabeled``, or ``sample`` random subjects of the rule's scope)
    plus ``include_controls`` agreed ones."""
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(min_length=1, max_length=20000)
    subjects: Optional[List[TrialSubjectIn]] = None
    # true: the disagreements of humans and of the harness model; or only "human" / "verification"
    from_mislabeled: Union[bool, Literal["human", "verification"]] = False
    include_controls: int = Field(default=20, ge=0, le=1000)
    rerun_current: bool = True
    note: Optional[str] = Field(default=None, max_length=2000)
    # random subjects in the rule's scope (a new rule without decisions): expected = the current verdict when a hit
    # exists, else none (shown, not counted in the metrics)
    sample: int = Field(default=0, ge=0, le=200)


class PromptProposalIn(BaseModel):
    """``POST /llm_rules/{id}/proposals``: propose a tried prompt to a human."""
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(min_length=1, max_length=20000)
    trial_id: int
    rationale: str = Field(min_length=1, max_length=5000)


class RequestHumanIn(BaseModel):
    """``POST /hits/{id}/request_human``: the harness model asks a human about a machine hit."""
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=2000)
    model: Optional[str] = Field(default=None, max_length=100)


class RolloutBudgetIn(BaseModel):
    """Overrides of the scanner's LLM_ROLLOUT_* defaults for one rollout."""
    model_config = ConfigDict(extra="forbid")
    calls_per_hour: Optional[int] = Field(default=None, ge=1)
    max_parallel_jobs: Optional[int] = Field(default=None, ge=1)
    slice_objects: Optional[int] = Field(default=None, ge=1)
    fresh_backlog_max: Optional[int] = Field(default=None, ge=0)
    max_calls: Optional[int] = Field(default=None, ge=1)


class ProposalDecisionIn(BaseModel):
    """``POST /prompt_proposals/{id}/accept`` (a candidate version of the rule; ``activate``: also activate it and
    start its rollout; ``run``: the same, the name of the previous release) / ``reject``."""
    model_config = ConfigDict(extra="forbid")
    note: Optional[str] = Field(default=None, max_length=2000)
    run: bool = False
    activate: bool = False
    budget: Optional[RolloutBudgetIn] = None


class VersionActivateIn(BaseModel):
    """``POST /llm_rule_versions/{id}/activate`` (``start_rollout``: running at once, else planned) and
    ``/rollback``."""
    model_config = ConfigDict(extra="forbid")
    start_rollout: bool = True
    budget: Optional[RolloutBudgetIn] = None
    note: Optional[str] = Field(default=None, max_length=2000)


class VersionCreateIn(BaseModel):
    """``POST /llm_rules/{id}/versions``: a candidate from the active version with these changes."""
    model_config = ConfigDict(extra="forbid")
    prompt: Optional[str] = Field(default=None, max_length=20000)
    target: Optional[str] = None
    project_re: Optional[str] = Field(default=None, max_length=2000)
    object_re: Optional[str] = Field(default=None, max_length=2000)
    object_type_re: Optional[str] = Field(default=None, max_length=2000)
    field_re: Optional[str] = Field(default=None, max_length=2000)
    field_type_re: Optional[str] = Field(default=None, max_length=2000)
    mark_fields: Optional[bool] = None
    note: Optional[str] = Field(default=None, max_length=2000)


class RolloutActionIn(BaseModel):
    """``POST /llm_rollouts/{id}/start | pause | resume | cancel``."""
    model_config = ConfigDict(extra="forbid")
    reason: Optional[str] = Field(default=None, max_length=2000)
    budget: Optional[RolloutBudgetIn] = None
