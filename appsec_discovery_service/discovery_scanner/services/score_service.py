"""LLM rules of the scanner (stage 5b).

Every enabled LLM rule of the ``rules`` table runs on its candidate subjects only (see
``db_service.get_llm_candidates``): the built-in classifier (a field rule without category)
through ``appsec_discovery.ai.classify``, other rules through the core's
``run_field_rule`` / ``run_object_rule`` with the rule's prompt. Verdicts:

* positive (classifier category / ``match``) -> a hit, ``match`` (mode auto) or
  ``pending_review`` (mode review);
* ``need_more_info`` -> a machine ``need_more_info`` hit (in the review queue);
* negative -> a machine ``no_match`` hit, so the subject is not asked again until the
  rule's version changes.
"""

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from appsec_discovery.ai import LlmBackend, LlmError, OpenAICompatibleBackend, PROMPT_VERSION, classify, is_candidate_field
from appsec_discovery.ai.rules import MATCH, NEED_MORE_INFO, RULE_PROMPT_VERSION, run_field_rule, run_object_rule
from appsec_discovery.matching import Severity
from appsec_discovery.models import LlmRule
from discovery_common.mapping import marks_fields
from logger import get_logger

from config import get_settings

logger = get_logger(__name__)

def llm_eligible_field(name: str, type_: Optional[str]) -> bool:
    """Fields that are sent to the LLM (ints/strings that are not ids, dates, paging, ...)."""
    return is_candidate_field(name, type_)


@dataclass
class LlmObject:
    """One object to ask about: all its eligible fields go into the prompt, verdicts are
    returned for ``candidates`` only (field names; for an object rule the object itself)."""
    object_key: object
    name: str
    fields: List[Tuple[str, str]]
    candidates: Set[str] = field(default_factory=set)
    type: Optional[str] = None
    parser: Optional[str] = None
    file: Optional[str] = None
    props: Optional[Dict[str, str]] = None
    comment: Optional[str] = None                 # code comment of the object
    # code comments / samples of the fields: {field_name: (comment, samples)}
    docs: Dict[str, Tuple[Optional[str], Optional[List[str]]]] = field(default_factory=dict)


@dataclass
class LlmVerdict:
    object_key: object
    field_name: Optional[str]          # None: verdict on the object (object rules)
    positive: bool
    category: Optional[str]
    severity: Optional[str]
    model: str
    need_more_info: bool = False
    reason: Optional[str] = None
    fields: Optional[List[str]] = None  # object rules: the fields that make the object match


class LlmVerdicts(list):
    """Verdicts of one rule run; ``failed``: objects whose LLM call or answer failed (they got
    no verdict, so they stay candidates and are asked again; ``errors``: their error by object
    key); ``deferred``: objects whose call was recorded for the external executor."""
    failed: int = 0

    def __init__(self, *args):
        super().__init__(*args)
        self.failed = 0
        self.deferred = 0
        self.errors: Dict[object, str] = {}

    def fail(self, obj, ex) -> None:
        self.failed += 1
        self.errors[obj.object_key] = f"{type(ex).__name__}: {ex}"


class LlmCallDeferred(Exception):
    """Raised by ``RecordingBackend``: the call is recorded, its answer comes later (external
    executor), so the object gets no verdict now."""


class PromptChanged(LlmError):
    """``ReplayBackend``: the rebuilt call is not the one that was answered."""


class RecordingBackend:
    """``LlmBackend`` of the external executor's prepare phase: records every call
    ``(system, user, json_schema)`` instead of asking a model."""

    model = "external"

    def __init__(self):
        self.calls: List[Tuple[Optional[str], str, Optional[dict]]] = []

    def complete(self, system, user, *, json_schema=None) -> str:
        self.calls.append((system, user, json_schema))
        raise LlmCallDeferred()


class ReplayBackend:
    """``LlmBackend`` of the apply phase: answers call ``i`` with ``answers[i]`` =
    ``(prompt_hash, answer)`` when the rebuilt call has the same hash; else ``mismatch`` is set
    and ``PromptChanged`` raised (the object or the rule changed since the prompt was recorded)."""

    def __init__(self, answers: Sequence[Tuple[str, str]], model: str):
        self.answers = list(answers)
        self.model = model
        self.calls = 0
        self.mismatch: Optional[int] = None

    def complete(self, system, user, *, json_schema=None) -> str:
        from discovery_common.llm_work import prompt_hash
        index = self.calls
        self.calls += 1
        if index >= len(self.answers) or prompt_hash(system, user, json_schema) != self.answers[index][0]:
            self.mismatch = index
            raise PromptChanged(f"call {index} differs from the recorded prompt")
        return self.answers[index][1]


def llm_configured(settings=None) -> bool:
    settings = settings or get_settings()
    return bool(settings.llm_api_url)


def core_prompts_version() -> str:
    """Versions of the core's classifier and rule prompts (part of the LLM scan marker)."""
    return f"core{PROMPT_VERSION}.{RULE_PROMPT_VERSION}"


def to_core_llm_rule(rule) -> Optional[LlmRule]:
    """A ``rules`` row of kind llm as the core's ``LlmRule`` (scope is applied by the
    scanner, from the DB regexes). None (with a warning) when the row is not a valid rule."""
    try:
        return LlmRule(
            id=rule.id, name=rule.name or f"llm:{rule.id}", category=rule.category or None,
            severity=rule.severity or Severity.medium.value, system_prompt=rule.prompt or None,
            prompt_version=str(rule.version), target=rule.target or "field", mode=rule.mode or "review",
            mark_fields=marks_fields(rule),
        )
    except Exception as e:
        logger.warning(f"LLM rule {rule.id} ({rule.name}) is not valid, skipped: {e}")
        return None


def _as_code_object(obj: LlmObject):
    """Duck-typed core ``CodeObject`` for the core prompt builders."""
    return SimpleNamespace(
        object_name=obj.name, object_type=obj.type, parser=obj.parser, file=obj.file,
        properties={k: SimpleNamespace(prop_name=k, prop_value=v) for k, v in (obj.props or {}).items()},
        fields={n: SimpleNamespace(field_name=n, field_type=t, comment=obj.docs.get(n, (None, None))[0],
                                   samples=obj.docs.get(n, (None, None))[1]) for n, t in obj.fields},
        comment=obj.comment,
    )


def llm_rule_verdicts(rule, objects: Sequence[LlmObject], backend: LlmBackend,
                      on_object: Optional[Callable[[LlmObject, bool], None]] = None) -> List[LlmVerdict]:
    """Run one LLM rule with a category (field or object target) on ``objects``.

    Field rules return a verdict for every candidate field (fields the model does not name
    are negative); object rules one verdict per object. Objects that fail are skipped.
    ``on_object(obj, ok)`` is called after each object (progress)."""
    core_rule = to_core_llm_rule(rule)
    if core_rule is None:
        return LlmVerdicts()
    verdicts = LlmVerdicts()
    model = getattr(backend, "model", None)

    for obj in objects:
        try:
            code_object = _as_code_object(obj)
            if core_rule.target == "object":
                verdict, reason, fields = run_object_rule(core_rule, code_object, backend)
                verdicts.append(LlmVerdict(
                    object_key=obj.object_key, field_name=None, positive=(verdict == MATCH),
                    need_more_info=(verdict == NEED_MORE_INFO), category=rule.category, severity=rule.severity,
                    model=model, reason=reason, fields=fields or None))
            else:
                candidates = [name for name, _ in obj.fields if name in obj.candidates]
                answers = run_field_rule(core_rule, code_object, candidates, backend)
                for name in candidates:
                    verdict, reason = answers.get(name, (None, None))
                    verdicts.append(LlmVerdict(
                        object_key=obj.object_key, field_name=name, positive=(verdict == MATCH),
                        need_more_info=(verdict == NEED_MORE_INFO), category=rule.category, severity=rule.severity,
                        model=model, reason=reason))

        except LlmCallDeferred:
            verdicts.deferred += 1
            continue
        except Exception as ex:
            verdicts.fail(obj, ex)
            logger.error(f"Error while running LLM rule {rule.name} on {obj.name}: {ex}")
            if on_object is not None:
                on_object(obj, False)
            continue
        if on_object is not None:
            on_object(obj, True)

    return verdicts


_backend: Optional[LlmBackend] = None


class RateLimitedBackend:
    """The service backend behind the shared token bucket (``discovery_common.llm_rate``, LLM_RATE_PER_MIN): every
    ``complete`` takes one token first, waiting while the bucket is empty (and giving up with ``LlmError`` on a
    graceful stop, so the run hands its job back instead of starting a call)."""

    def __init__(self, backend: LlmBackend, rate_per_min: float):
        self.backend = backend
        self.rate_per_min = float(rate_per_min)
        self.model = getattr(backend, "model", None)

    def complete(self, system, user, *, json_schema=None) -> str:
        from discovery_common import jobs, llm_rate
        if not llm_rate.wait(self.rate_per_min, stop=jobs.stop_requested):
            raise LlmError("stopping: no model call started (rate limit wait interrupted)")
        return self.backend.complete(system, user, json_schema=json_schema)


def get_llm_backend(settings=None) -> LlmBackend:
    """One OpenAI-compatible backend (one HTTP client, thread-safe: the chunk of a rule run calls it from
    LLM_CONCURRENCY threads) per process; behind the shared rate limit when LLM_RATE_PER_MIN is set."""
    global _backend
    if _backend is None:
        settings = settings or get_settings()
        api_key = settings.llm_api_key.get_secret_value() if settings.llm_api_key else None
        backend = OpenAICompatibleBackend(
            base_url=settings.llm_api_url, model=settings.llm_api_model, api_key=api_key,
            timeout=settings.llm_timeout_s, max_retries=settings.llm_max_retries,
            max_tokens=settings.llm_max_tokens, structured=settings.llm_structured,
        )
        if settings.llm_rate_per_min > 0:
            backend = RateLimitedBackend(backend, settings.llm_rate_per_min)
        _backend = backend
    return _backend


def llm_score_objects(objects: Sequence[LlmObject], backend: Optional[LlmBackend] = None,
                      prompt: Optional[str] = None, severity: Optional[str] = None,
                      on_object: Optional[Callable[[LlmObject, bool], None]] = None) -> Optional[List[LlmVerdict]]:
    """The built-in classifier (an LLM field rule without category; ``prompt``: its system prompt, default the
    core's classifier prompt).
    Ask the LLM about each object and return a verdict for every candidate field:
    positive (private data, with category) or negative. Negative verdicts are stored too
    (as machine-made no_match hits), so a field is not sent again until the prompt version
    changes. Returns None when no LLM is configured. Objects that fail are skipped."""

    settings = get_settings()
    if backend is None:
        if not llm_configured(settings):
            return None
        backend = get_llm_backend(settings)

    verdicts = LlmVerdicts()

    for obj in objects:

        try:
            chosen = [name for name, type_ in obj.fields if llm_eligible_field(name, type_)]
            candidates = [name for name in chosen if name in obj.candidates]
            if not candidates:
                if on_object is not None:
                    on_object(obj, True)
                continue

            categories = classify(obj.name, chosen, backend, prompt,
                                  docs=obj.docs, object_comment=obj.comment)

            for name in candidates:
                cats = categories.get(name) or []
                positive = bool(cats)
                category = cats[0] if positive else None
                verdicts.append(LlmVerdict(
                    object_key=obj.object_key, field_name=name, positive=positive,
                    category=category,
                    severity=(severity or Severity.medium.value) if positive else None,
                    model=backend.model,
                ))
                if positive:
                    logger.info(f"For object {obj.name} field {name} scored as {category}")

        except LlmCallDeferred:
            verdicts.deferred += 1
            continue
        except Exception as ex:
            verdicts.fail(obj, ex)
            logger.error(f"Error while ai scoring {obj.name}: {ex}")
            if on_object is not None:
                on_object(obj, False)
            continue
        if on_object is not None:
            on_object(obj, True)

    return verdicts


def verify_call(rule, obj: LlmObject, field_name: Optional[str], previous: Dict,
                settings=None) -> Tuple[str, str, Dict]:
    """``(system, user, json_schema)`` of a verify call (tiered workflow, ``services.verify_service``): the
    harness model checks the service verdict ``previous`` about ``field_name`` of ``obj`` (None: the object) with the
    rule's own system prompt and the core's delimited object block (``appsec_discovery.ai.rules``)."""
    from appsec_discovery.ai.rules import build_verify_prompt, verify_schema, verify_system_prompt
    core_rule = to_core_llm_rule(rule)
    if core_rule is None:
        raise LlmError(f"LLM rule {rule.name} is not valid")
    code_object = _as_code_object(obj)
    return (verify_system_prompt(core_rule), build_verify_prompt(core_rule, code_object, field_name, previous),
            verify_schema([name for name, _ in obj.fields], object_target=field_name is None))
