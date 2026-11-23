"""Core ``CodeObject`` -> storage records (P2-5 mapper).

Duck-typed on ``appsec_discovery.models.CodeObject`` (``hash``, ``object_name``,
``object_type``, ``parser``, ``file``, ``line``, ``properties``, ``fields``, ``hits``), so this
module does not import the core package (the API image does not ship it).

The object identity is the core's ``CodeObject.hash`` (``object_identity`` after P1-8):
lines are never part of a key, they only go to ``branch_objects.line/field_lines``.

Rule hits (stage 5b): the core records every keyword match as a ``RuleHit`` on
``CodeObject.hits`` (``score_tags`` keywords: ``rule_id`` None; the DB keyword rules passed
as ``ScoreConfig.score_rules``: ``rule_id`` = ``rules.id``). They are carried as plain
``HitRecord``s; the scanner needs a core that records hits (appsec-discovery >= 1.0).
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

from discovery_common import keys


def plain(value) -> Optional[str]:
    """Severity / enum value as a plain string (core hands out ``Severity`` str-Enums)."""
    return None if value is None else str(getattr(value, "value", value))


@dataclass
class FieldRecord:
    name: str
    type: Optional[str]
    key: uuid.UUID
    line: Optional[int] = None
    comment: Optional[str] = None           # code comment / description
    samples: Optional[List[str]] = None     # example values


@dataclass
class HitRecord:
    """A core ``RuleHit``: ``subject`` is ``field`` | ``prop`` | ``object``."""
    rule: str
    rule_id: Optional[str]
    subject: str
    field_name: Optional[str]
    prop_name: Optional[str]
    severity: Optional[str]
    tags: List[str]
    status: Optional[str]
    reason: Optional[str] = None
    fields: Optional[List[str]] = None          # object hits: the fields that made the object match


@dataclass
class ObjectRecord:
    project_id: int
    object_key: uuid.UUID
    content_hash: uuid.UUID
    parser: str
    type: str
    name: str
    file: Optional[str]
    line: Optional[int]
    props: Dict[str, str]
    fields: Dict[str, FieldRecord]
    hits: List[HitRecord] = field(default_factory=list)
    comment: Optional[str] = None           # code comment / description of the object

    @property
    def field_lines(self) -> Optional[Dict[str, int]]:
        lines = {name: f.line for name, f in self.fields.items() if f.line is not None}
        return lines or None

    def object_row(self) -> dict:
        # names_hash / llm_hash (migration 0030): what the LLM rules see of the version, stored with the row
        # (``keys.names_hash`` / ``field_subject_hash``, the twins of the SQL functions of migration 0018)
        return {
            "content_hash": self.content_hash, "object_key": self.object_key, "project_id": self.project_id,
            "parser": self.parser, "type": self.type, "name": self.name, "file": self.file,
            "props": self.props or None, "comment": self.comment,
            "names_hash": keys.names_hash(self.name, self.fields.keys()),
        }

    def field_rows(self) -> List[dict]:
        return [
            {"content_hash": self.content_hash, "field_name": f.name, "field_type": f.type,
             "field_key": f.key, "project_id": self.project_id, "comment": f.comment, "samples": f.samples,
             "llm_hash": keys.field_subject_hash(f.name, f.type, f.comment, f.samples)}
            for f in self.fields.values()
        ]


def _hit_records(obj) -> List[HitRecord]:
    return [
        HitRecord(rule=h.rule, rule_id=h.rule_id, subject=plain(h.subject), field_name=h.field_name,
                  prop_name=h.prop_name, severity=plain(h.severity), tags=list(h.tags or []),
                  status=plain(h.status), reason=getattr(h, "reason", None),
                  fields=list(getattr(h, "fields", None) or []) or None)
        for h in getattr(obj, "hits", None) or []
    ]


def from_code_object(obj, project_id: int) -> ObjectRecord:
    obj_key = keys.object_key(project_id, obj.parser, obj.hash)

    props = {p.prop_name: p.prop_value for p in (obj.properties or {}).values()}

    fields = {}
    for f in (obj.fields or {}).values():
        fields[f.field_name] = FieldRecord(
            name=f.field_name, type=f.field_type, key=keys.field_key(obj_key, f.field_name),
            line=f.line, comment=getattr(f, "comment", None), samples=list(getattr(f, "samples", None) or []) or None,
        )
    comment = getattr(obj, "comment", None)

    return ObjectRecord(
        project_id=project_id,
        object_key=obj_key,
        content_hash=keys.content_hash(obj_key, {n: f.type for n, f in fields.items()}, props, docs(comment, fields)),
        parser=obj.parser, type=obj.object_type, name=obj.object_name, file=obj.file, line=obj.line,
        props=props, fields=fields, hits=_hit_records(obj),
        comment=comment,
    )


def docs(comment: Optional[str], fields: Dict[str, "FieldRecord"]) -> Dict[str, str]:
    """The documentation part of the content hash (see ``keys.content_hash``)."""
    result = {"": comment or ""}
    for name, f in fields.items():
        if f.comment or f.samples:
            result[name] = (f.comment or "") + keys.PAIR_SEP + keys.ITEM_SEP.join(f.samples or [])
    return result


def dedupe(records: Iterable[ObjectRecord]) -> List[ObjectRecord]:
    """One record per ``object_key`` (first wins): parsers may emit the same identity twice,
    and a branch holds one row per key."""
    seen = {}
    for record in records:
        seen.setdefault(record.object_key, record)
    return list(seen.values())


def compute_delta(records: Iterable[ObjectRecord], target: Dict[uuid.UUID, uuid.UUID],
                  complete: bool = True) -> List[Tuple[str, uuid.UUID, Optional[ObjectRecord]]]:
    """MR source delta vs the target snapshot: ``[(change, object_key, record|None)]``.
    ``complete=False`` (partial source scan) reports no removals."""
    delta = []
    source_keys = set()
    for record in records:
        source_keys.add(record.object_key)
        target_hash = target.get(record.object_key)
        if target_hash is None:
            delta.append(("added", record.object_key, record))
        elif target_hash != record.content_hash:
            delta.append(("modified", record.object_key, record))
    if complete:
        for object_key in target:
            if object_key not in source_keys:
                delta.append(("removed", object_key, None))
    return delta


def restrict_delta(delta, changed_files: Iterable[str],
                   removed_files: Dict[uuid.UUID, Optional[str]]) -> List[Tuple[str, uuid.UUID, Optional[ObjectRecord]]]:
    """Keep the delta entries whose object lives in one of ``changed_files`` (the MR diff vs
    the merge-base, repo-relative). Object files are stored as ``/relative/path``.
    ``removed_files`` maps the object keys of ``removed`` entries to their file in the
    target. Entries with no known file are kept."""
    files = {f.lstrip("/") for f in changed_files}
    kept = []
    for change, object_key, record in delta:
        file = record.file if record is not None else removed_files.get(object_key)
        if file is None or file.lstrip("/") in files:
            kept.append((change, object_key, record))
    return kept


def hit_row(rule, project_id: int, object_key: uuid.UUID, field_name: Optional[str], status: str, *,
            severity=None, category=None, model=None, rule_version=None, reason=None, fields=None,
            names_hash: Optional[str] = None, subject_hash: Optional[str] = None) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "rule_id": rule.id, "subject_key": keys.subject_key(object_key, field_name),
        "project_id": project_id, "object_key": object_key, "field_name": field_name,
        "rule_version": rule_version or rule.version, "model": model, "prompt_version": None, "category": category, "severity": severity,
        "status": status, "reason": reason, "fields": list(fields) if fields else None,
        "names_hash": names_hash, "subject_hash": subject_hash,
        "first_seen_at": now, "last_seen_at": now,
    }


def llm_candidate(hit, rule_version: int, prompt_version: str, subject_hash: Optional[str],
                  names_hash: Optional[str], *, migration: bool = True, code_prompt_version: Optional[str] = None,
                  pinned_model: Optional[str] = None, code_model: Optional[str] = None) -> bool:
    """Python twin of the scanner's candidate condition (``discovery_common.lifecycle.CANDIDATE_COND``; the API's
    dry-run estimate uses it): is a subject asked (again) by an LLM rule? ``hit``: the rule's hit on the subject (a
    mapping or row with reviewer, status, rule_version, prompt_version, model, subject_hash, names_hash,
    decided_tier) or None; ``subject_hash`` / ``names_hash``: the subject's current values (``keys``; ``names_hash``
    only for object rules, else None). A NULL stored hash never asks again. ``prompt_version``: the core prompts
    version the rule is pinned to (``code_prompt_version``: the code's, default the same).

    * FRESH (every run): no hit; a machine verdict on another subject content (``subject_hash``); a reopened pending
      hit of an older rule version; object rules: another object name / set of field names (``names_hash``) - even
      when a human decided the hit (the scanner then carries the decision over or asks for a re-review);
    * MIGRATION (``migration``: a rollout slice, or LLM_REASK_INLINE): a machine verdict (not the harness tier) of an
      older rule version, other core prompts or another service model (``lifecycle.is_migration``)."""
    from discovery_common import lifecycle
    if lifecycle.is_fresh(hit, rule_version, subject_hash, names_hash):
        return True
    return bool(migration) and lifecycle.is_migration(hit, rule_version, prompt_version, code_prompt_version,
                                                      pinned_model, code_model)


def marks_fields(rule) -> bool:
    """An LLM object rule with ``scope.mark_fields``: an object verdict (match / need_more_info)
    also makes one field hit per field the model named (same status, category, severity, reason,
    model and version). The field hits are a by-product of the object's one model call: LLM
    candidates, re-asks and the dry run stay per object."""
    return getattr(rule, "target", None) == "object" and bool((getattr(rule, "scope", None) or {}).get("mark_fields"))
