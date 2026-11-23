"""LLM rules runner (the ``AiScorer`` used by ``ScanPipeline``).

Runs every ``LlmRule`` in scope on every object through one ``LlmBackend``
(so one OpenAI client per run). Each rule is one structured request per
object; errors are isolated per object and rule. Results are recorded as
``RuleHit``s: mode ``auto`` -> ``match`` (scores the subject), mode
``review`` -> ``pending_review``; a ``need_more_info`` verdict is recorded
with that status and never scores.

Without explicit ``llm_rules`` the service runs one implicit rule, the
built-in classifier (pii/finance/auth/other, severity medium, mode auto):
exactly the pre-rules LLM scoring.
"""
import logging
from typing import List, Optional, Sequence

from appsec_discovery.ai import LlmBackend, backend_from_config, classify, select_candidate_fields
from appsec_discovery.ai.classifier import PROMPT_VERSION
from appsec_discovery.ai.rules import NEED_MORE_INFO, NO_MATCH, RULE_PROMPT_VERSION, run_field_rule, run_object_rule
from appsec_discovery.hits import record_hit
from appsec_discovery.matching import Severity
from appsec_discovery.models import (
    AiApi, AiLocal, CodeObject, ExcludeScoring, HitStatus, HitSubject, LlmRule, LlmTarget, RuleHit,
)
from appsec_discovery.models.config import IMPLICIT_LLM_RULE
from appsec_discovery.models.rules import status_for_mode

logger = logging.getLogger(__name__)

# Severity of the implicit rule's hits (the classifier gives a category, not a severity).
AI_SEVERITY = Severity.medium

LLM = 'llm'


def implicit_llm_rule(ai_api: Optional[AiApi]) -> LlmRule:
    """The rule an ``ai_api`` block without ``llm_rules`` stands for."""
    return LlmRule(name=IMPLICIT_LLM_RULE, system_prompt=ai_api.system_prompt if ai_api is not None else None,
                   severity=AI_SEVERITY.value)


def rule_version(rule: LlmRule) -> str:
    """Version stored with a hit: the classifier's PROMPT_VERSION, or ``<engine>.<rule>`` for other rules."""
    if rule.is_classifier:
        return rule.prompt_version or PROMPT_VERSION
    return f"{RULE_PROMPT_VERSION}.{rule.prompt_version or '0'}"


class AiService:

    def __init__(self, exclude_scoring: List[ExcludeScoring], ai_local: Optional[AiLocal] = None,
                 ai_api: Optional[AiApi] = None, backend: Optional[LlmBackend] = None,
                 llm_rules: Optional[Sequence[LlmRule]] = None, project: Optional[str] = None):
        """``backend`` overrides the one built from ``ai_api`` (or the deprecated ``ai_local``,
        mapped to a local OpenAI-compatible server). ``llm_rules=None`` runs the implicit rule.
        ``project`` (if known) is checked against the rules' ``projects`` scope."""
        if ai_api is None and ai_local is not None:
            ai_api = ai_local.to_ai_api()
        if backend is None and ai_api is None:
            raise ValueError("AiService needs ai_api (or a backend)")
        self.ai_api = ai_api
        self.exclude_scoring = exclude_scoring
        self.system_prompt = ai_api.system_prompt if ai_api is not None else None
        self.rules: List[LlmRule] = (
            [implicit_llm_rule(ai_api)] if llm_rules is None else [r for r in llm_rules if r.enabled]
        )
        self.project = project
        self._backend = backend

    @property
    def backend(self) -> LlmBackend:
        if self._backend is None:
            self._backend = backend_from_config(self.ai_api)
        return self._backend

    # -- helpers ------------------------------------------------------------------------------------

    def _excluded(self, obj: CodeObject, tags: List[str], field=None) -> bool:
        # keyword=None: LLM tags have no keyword, so an exclude rule that sets
        # `keyword` never applies to LLM scoring (intentional).
        return any(exclude.matches(obj, field=field, tag=tags, keyword=None) for exclude in self.exclude_scoring)

    def _hit(self, rule: LlmRule, tags: List[str], verdict: str, reason: Optional[str], **subject) -> RuleHit:
        status = HitStatus.need_more_info.value if verdict == NEED_MORE_INFO else status_for_mode(rule.mode)
        return RuleHit(rule=rule.name, rule_id=rule.id, rule_type=LLM, rule_version=rule_version(rule),
                       model=getattr(self.backend, 'model', None), severity=rule.severity, tags=tags,
                       status=status, reason=reason, object_tags=rule.tags or None, **subject)

    # -- rules --------------------------------------------------------------------------------------

    def _run_classifier(self, rule: LlmRule, obj: CodeObject) -> List[RuleHit]:
        candidates = select_candidate_fields((f.field_name, f.field_type) for f in obj.fields.values())
        if not candidates:
            return []
        docs = {f.field_name: (f.comment, f.samples) for f in obj.fields.values() if f.comment or f.samples}
        categories = classify(obj.object_name, candidates, self.backend, rule.system_prompt, docs, obj.comment)
        hits = []
        for field in obj.fields.values():
            cats = categories.get(field.field_name)
            if not cats:
                continue
            tags = [f'llm-{cat}' for cat in cats]
            if self._excluded(obj, tags, field=field):
                continue
            hits.append(self._hit(rule, tags, 'match', None, subject=HitSubject.field.value,
                                  field_name=field.field_name))
        return hits

    def _run_field_rule(self, rule: LlmRule, obj: CodeObject) -> List[RuleHit]:
        candidates = select_candidate_fields((f.field_name, f.field_type) for f in obj.fields.values())
        verdicts = run_field_rule(rule, obj, candidates, self.backend)
        hits = []
        for field in obj.fields.values():
            if field.field_name not in verdicts:
                continue
            verdict, reason = verdicts[field.field_name]
            if self._excluded(obj, [rule.hit_tag], field=field):
                continue
            hits.append(self._hit(rule, [rule.hit_tag], verdict, reason, subject=HitSubject.field.value,
                                  field_name=field.field_name))
        return hits

    def _run_object_rule(self, rule: LlmRule, obj: CodeObject) -> List[RuleHit]:
        verdict, reason, fields = run_object_rule(rule, obj, self.backend)
        if verdict == NO_MATCH or self._excluded(obj, [rule.hit_tag]):
            return []
        hits = [self._hit(rule, [rule.hit_tag], verdict, reason, subject=HitSubject.object.value,
                          fields=fields or None)]
        if rule.mark_fields:
            # the same verdict on each field the model named (no extra model call)
            for name in fields or []:
                field = obj.fields.get(name)
                if field is None or self._excluded(obj, [rule.hit_tag], field=field):
                    continue
                hits.append(self._hit(rule, [rule.hit_tag], verdict, reason, subject=HitSubject.field.value,
                                      field_name=name))
        return hits

    def run_rule(self, rule: LlmRule, obj: CodeObject) -> List[RuleHit]:
        """Hits of ``rule`` on ``obj`` (not recorded); raises when the LLM call or its answer fails."""
        if rule.is_classifier:
            return self._run_classifier(rule, obj)
        if rule.target == LlmTarget.object.value:
            return self._run_object_rule(rule, obj)
        return self._run_field_rule(rule, obj)

    def _record(self, rule: LlmRule, obj: CodeObject, hits: List[RuleHit]) -> None:
        for hit in hits:
            if record_hit(obj, hit):
                logger.info(f"Rule {rule.name}: {obj.object_name} {hit.subject} {hit.subject_name or ''} "
                            f"-> {hit.tags} ({hit.status})")

    def ai_score_object(self, obj: CodeObject) -> CodeObject:
        """Run every rule in scope on ``obj`` (in place); raises on the first failing rule.

        A rule's hits are recorded only after its answer was parsed, so a failure
        never leaves a rule half applied.
        """
        for rule in self.rules:
            if rule.applies_to(obj, self.project):
                self._record(rule, obj, self.run_rule(rule, obj))
        return obj

    def ai_score_objects(self, code_objects: List[CodeObject]) -> List[CodeObject]:
        """Run the rules on every object; a failing rule is skipped for that object (logged)."""
        for obj in code_objects:
            for rule in self.rules:
                if not rule.applies_to(obj, self.project):
                    continue
                try:
                    self._record(rule, obj, self.run_rule(rule, obj))
                except Exception as ex:
                    logger.error(f"Error while running LLM rule {rule.name} on {obj.object_name}: {ex}")
        return code_objects
