"""Rules (``rules`` table): keyword and LLM rules, used by REST and MCP alike.

* An edit of what a rule matches (scope, prompt, target, action, an LLM rule's
  ``mark_fields``) bumps ``version``: the scanner re-proposes the rule's ``pending_review``
  hits, decided hits are never touched. LLM rules (``discovery_common.lifecycle``): the edit is a
  new ``rule_versions`` row, active at once (``candidate=True``: a candidate, the rule unchanged);
  the machine verdicts of the old version stay, flagged stale, until the rollout of the new one asks
  them again (``planned``: a human starts it; LLM_ROLLOUT_DEFAULT=immediate: running at once).
  Name, category, severity, mode and ``enabled`` are metadata and keep the version; a category /
  severity edit of an LLM rule goes to its machine hits at once (no model call).
* Delete is a soft delete (``deleted_at`` + ``enabled = false``): hits keep their rule.
* Built-in rules (``scope.source = 'core'``): ``kw-fields`` / ``kw-props`` (the core keyword scoring,
  disabled on new installs) can only be enabled/disabled, switch mode or get tags. There is no
  env-managed LLM rule any more (migration 0028).
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from discovery_common import lifecycle
from discovery_common.models import HitStatus, Rule, RuleHit
from schemas import (
    KEYWORD_SCOPE_KEYS, LLM_SCOPE_KEYS, KeywordRuleIn, KeywordRuleOut, LlmRuleIn, LlmRuleOut,
)
from services.errors import Conflict, Invalid, NotFound
from services.paging import ListParams, as_ints, as_list, escape_like

KINDS = ("keyword", "llm")
# scope keys that are not matchers: kept across edits, never part of the version
META_SCOPE_KEYS = ("source", "legacy_status", "legacy_risk_score", "prompt_ver")
CORE_EDITABLE = ("enabled", "mode", "tags")

SORTABLE = {
    "id": Rule.id, "name": Rule.name, "category": Rule.category, "severity": Rule.severity, "mode": Rule.mode,
    "enabled": Rule.enabled, "version": Rule.version, "updated_at": Rule.updated_at, "target": Rule.target,
    "created_at": Rule.created_at,
}
TEXT_FILTERS = {"name": Rule.name, "category": Rule.category}
EXACT_FILTERS = {"id": Rule.id, "severity": Rule.severity, "mode": Rule.mode, "enabled": Rule.enabled,
                 "target": Rule.target}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def builtin(rule: Rule) -> Optional[str]:
    source = (rule.scope or {}).get("source")
    return source if source == "core" else None


def _matchers(rule_or_scope, kind: str) -> Dict[str, Any]:
    scope = rule_or_scope if isinstance(rule_or_scope, dict) else (rule_or_scope.scope or {})
    keys = KEYWORD_SCOPE_KEYS + ("action",) if kind == "keyword" else LLM_SCOPE_KEYS
    # unset, blank and false (mark_fields) values are not part of what a rule matches
    return {key: scope.get(key) for key in keys if scope.get(key) not in (None, "") and scope.get(key) is not False}


def to_out(rule: Rule, pending: Optional[int] = None):
    scope = rule.scope or {}
    common = dict(
        id=rule.id, name=rule.name, category=rule.category, severity=rule.severity, mode=rule.mode,
        enabled=rule.enabled is not False, target=rule.target, version=rule.version, builtin=builtin(rule),
        created_at=rule.created_at, updated_at=rule.updated_at, updated_by=rule.updated_by,
        deleted_at=rule.deleted_at, pending_hits=pending, tags=rule.tags or None,
    )
    if rule.kind == "llm":
        values = {k: scope.get(k) for k in LLM_SCOPE_KEYS}
        values["mark_fields"] = bool(values.get("mark_fields"))
        return LlmRuleOut(prompt=rule.prompt, **values, **common)
    action = scope.get("action") or "score"
    return KeywordRuleOut(action=action, **{k: scope.get(k) for k in KEYWORD_SCOPE_KEYS}, **common)


def _pending_counts(session: Session, rule_ids: List[int]) -> Dict[int, int]:
    if not rule_ids:
        return {}
    rows = session.execute(
        select(RuleHit.rule_id, func.count())
        .where(RuleHit.rule_id.in_(rule_ids),
               RuleHit.status.in_([HitStatus.pending_review.value, HitStatus.need_more_info.value]))
        .group_by(RuleHit.rule_id)
    ).all()
    return {rule_id: count for rule_id, count in rows}


def _typed(name: str, values: list) -> list:
    """Filter values in the column's type: a bad one is Invalid (422), not a 500 from Postgres."""
    if name == "id":
        return as_ints(values)
    if name == "enabled":
        out = []
        for v in values:
            if isinstance(v, bool):
                out.append(v)
            elif str(v).strip().lower() in ("true", "false", "1", "0"):
                out.append(str(v).strip().lower() in ("true", "1"))
            else:
                raise Invalid("enabled must be true or false")
        return out
    return [str(v) for v in values]


def list_rules(session: Session, kind: str, params: ListParams) -> Tuple[list, int]:
    filters = dict(params.filters)
    stmt = select(Rule).where(Rule.kind == kind)

    if not filters.pop("include_deleted", False):
        stmt = stmt.where(Rule.deleted_at.is_(None))
    if "q" in filters:
        stmt = stmt.where(Rule.name.ilike(f"%{escape_like(str(filters.pop('q')))}%", escape="\\"))
    for name, column in TEXT_FILTERS.items():
        if name in filters:
            stmt = stmt.where(column.ilike(f"%{escape_like(str(filters.pop(name)))}%", escape="\\"))
    for name, column in EXACT_FILTERS.items():
        if name in filters:
            values = _typed(name, as_list(filters.pop(name)))
            stmt = stmt.where(column.in_(values)) if len(values) != 1 else stmt.where(column == values[0])
    if filters:
        raise Invalid(f"unknown filters: {sorted(filters)}")

    total = session.scalar(select(func.count()).select_from(stmt.subquery()))

    if params.sort is not None and params.sort not in SORTABLE:
        raise Invalid(f"cannot sort by {params.sort!r}, allowed: {sorted(SORTABLE)}")
    column = SORTABLE[params.sort or "id"]
    stmt = stmt.order_by(column.desc() if params.descending else column.asc(), Rule.id.asc())
    rules = list(session.scalars(stmt.offset(params.offset).limit(params.limit)))

    pending = _pending_counts(session, [r.id for r in rules])
    return [to_out(r, pending.get(r.id, 0)) for r in rules], total


def get_rule(session: Session, kind: str, rule_id: int, include_deleted: bool = True) -> Rule:
    rule = session.get(Rule, rule_id)
    if rule is None or rule.kind != kind or (rule.deleted_at is not None and not include_deleted):
        raise NotFound(f"{kind} rule {rule_id} not found")
    return rule


def _validate(kind: str, data: Dict[str, Any]):
    schema = KeywordRuleIn if kind == "keyword" else LlmRuleIn
    try:
        return schema.model_validate(data)
    except ValidationError as e:
        raise Invalid("; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or 'rule'}: {err['msg']}" for err in e.errors()
        )) from None


def _flush(session: Session, name: Optional[str]) -> None:
    try:
        session.flush()
    except IntegrityError as e:
        if "rules_name_live" in str(e.orig):
            raise Conflict(f"a rule named {name!r} already exists") from None
        raise


def create_rule(session: Session, kind: str, data: Dict[str, Any], user: str) -> Rule:
    if kind not in KINDS:
        raise NotFound(f"unknown rule kind {kind!r}")
    rule_in = _validate(kind, data)
    now = _now()
    rule = Rule(
        kind=kind, name=rule_in.name, category=rule_in.category, severity=rule_in.severity.value,
        mode=rule_in.mode.value, enabled=rule_in.enabled, scope=rule_in.scope(), version=1,
        target=rule_in.target if kind == "keyword" else rule_in.target.value,
        prompt=rule_in.prompt if kind == "llm" else None, tags=rule_in.tags,
        created_at=now, updated_at=now, updated_by=user,
    )
    session.add(rule)
    _flush(session, rule.name)
    if kind == "llm":
        rule.core_prompt_version = lifecycle.code_core_version(rule)
        session.flush()
        lifecycle.ensure_active_version(session, rule.id, user)
    return rule


def _lifecycle(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except lifecycle.LifecycleError as e:
        raise {"not_found": NotFound, "invalid": Invalid}.get(e.kind, Conflict)(str(e)) from None


def update_rule(session: Session, kind: str, rule_id: int, data: Dict[str, Any], user: str,
                candidate: bool = False) -> Rule:
    rule = get_rule(session, kind, rule_id, include_deleted=False)
    source = builtin(rule)

    if source == "core":
        changes = {k: data[k] for k in CORE_EDITABLE if k in data and data[k] is not None}
        if "mode" in changes and changes["mode"] not in ("auto", "review"):
            raise Invalid("mode must be 'auto' or 'review'")
        if "tags" in changes:
            from schemas import clean_tags
            try:
                changes["tags"] = clean_tags(changes["tags"] if isinstance(changes["tags"], list) else [])
            except ValueError as e:
                raise Invalid(str(e)) from None
        for key, value in changes.items():
            setattr(rule, key, value)
        rule.updated_at, rule.updated_by = _now(), user
        _flush(session, rule.name)
        return rule

    if data.get("mode") is None or data.get("mode") == "":
        # an update without mode keeps the rule's mode (the create default auto must not switch a review rule)
        data = {**data, "mode": rule.mode}
    rule_in = _validate(kind, data)
    old_matchers = _matchers(rule, kind)
    old = (old_matchers, rule.prompt, rule.target)

    meta = {k: v for k, v in (rule.scope or {}).items() if k in META_SCOPE_KEYS and k != "source"}
    new_scope = {**meta, **rule_in.scope()}
    new_target = rule_in.target if kind == "keyword" else rule_in.target.value
    new_prompt = rule_in.prompt if kind == "llm" else rule.prompt

    changed = (_matchers(new_scope, kind), new_prompt, new_target) != old
    if kind == "llm":
        return _update_llm_rule(session, rule, rule_in, new_scope, new_target, new_prompt, changed, user, candidate)
    rule.name, rule.category, rule.severity = rule_in.name, rule_in.category, rule_in.severity.value
    rule.mode, rule.enabled = rule_in.mode.value, rule_in.enabled
    rule.scope, rule.target, rule.prompt = new_scope, new_target, new_prompt
    rule.tags = rule_in.tags          # read at query time: no version bump, objects re-tagged at once
    if changed:
        rule.version = (rule.version or 1) + 1
    rule.updated_at, rule.updated_by = _now(), user
    _flush(session, rule.name)
    return rule


def _update_llm_rule(session: Session, rule: Rule, rule_in, new_scope, new_target, new_prompt, changed: bool,
                     user: str, candidate: bool) -> Rule:
    """Metadata at once (category / severity propagated to the machine hits); a matcher change is a new version:
    a candidate (``candidate``) or active at once with a rollout (planned, or running with
    LLM_ROLLOUT_DEFAULT=immediate)."""
    from config import get_settings
    old_category, old_severity = rule.category, rule.severity
    classifier = lifecycle.core_family({"target": new_target, "category": rule_in.category}) == "classifier"
    rule.name, rule.category, rule.severity = rule_in.name, rule_in.category, rule_in.severity.value
    rule.mode, rule.enabled = rule_in.mode.value, rule_in.enabled
    rule.tags = rule_in.tags
    rule.updated_at, rule.updated_by = _now(), user
    if not changed:
        rule.scope = new_scope          # the same matchers
    _flush(session, rule.name)
    lifecycle.propagate_metadata(session, rule.id, category=rule.category, severity=rule.severity,
                                 old_category=old_category, old_severity=old_severity, classifier=classifier)
    if changed:
        active = _lifecycle(lifecycle.ensure_active_version, session, rule.id, user)
        version = _lifecycle(lifecycle.create_version, session, rule.id, prompt=new_prompt, target=new_target,
                             matchers=new_scope, core_prompt_version=lifecycle.code_core_version(
                                 {"target": new_target, "category": rule.category}),
                             model=active["model"], source="manual", created_by=user)
        if not candidate:
            mode = get_settings().llm_rollout_default
            _lifecycle(lifecycle.activate_version, session, version["id"], user=user,
                       start_rollout=mode == "immediate", mode=mode)
        session.expire(rule)
    return rule


def delete_rule(session: Session, kind: str, rule_id: int, user: str) -> Rule:
    rule = get_rule(session, kind, rule_id, include_deleted=False)
    if builtin(rule) == "core":
        raise Conflict("the core keyword rules cannot be deleted, disable them instead")
    now = _now()
    rule.deleted_at, rule.enabled, rule.updated_at, rule.updated_by = now, False, now, user
    _flush(session, rule.name)
    if rule.kind == "llm":
        from sqlalchemy import text as _text
        session.execute(_text(f"""UPDATE llm_rollouts SET status = 'cancelled', finished_at = now(),
                                         note = COALESCE(note || E'\\n', '') || 'the rule was deleted'
                                  WHERE rule_id = :r AND status IN ({lifecycle.OPEN_SQL})"""), {"r": rule.id})
    return rule


def brief_list(session: Session, kind: Optional[str] = None, include_disabled: bool = False) -> List[dict]:
    """Compact listing for MCP: every live rule (optionally of one kind)."""
    stmt = select(Rule).where(Rule.deleted_at.is_(None)).order_by(Rule.kind, Rule.id)
    if kind:
        if kind not in KINDS:
            raise Invalid(f"kind must be one of {list(KINDS)}")
        stmt = stmt.where(Rule.kind == kind)
    if not include_disabled:
        stmt = stmt.where(Rule.enabled.is_not(False))
    rules = list(session.scalars(stmt))
    pending = _pending_counts(session, [r.id for r in rules])
    result = []
    for rule in rules:
        out = to_out(rule, pending.get(rule.id, 0)).model_dump(mode="json", exclude_none=True)
        out["kind"] = rule.kind
        result.append(out)
    return result
