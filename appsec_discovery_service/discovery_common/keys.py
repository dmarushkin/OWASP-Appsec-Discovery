"""Storage keys (see the storage design: identity for decisions, content for diff).

* ``object_key``   - identity of an object: project + parser + the core's identity hash
  (``CodeObject.hash``). Lines, fields, props, severity, branch and commit are NOT part
  of it, so it is stable across branches and commits.
* ``content_hash`` - identity + sorted ``field_name:field_type`` + sorted ``prop=value``.
  Changes exactly when the object's shape changes; positions (lines) are not in it.
* ``field_key``    - ``object_key`` + field name: the subject of field-level rules
  (``rule_hits.subject_key``). Field type is deliberately not in it.

All keys are ``md5(...)`` cast to ``uuid``. Migration ``0002`` computes the same keys in
SQL (``md5(... )::uuid`` with ``COLLATE "C"`` ordering); ``test_common_keys`` checks that
both implementations agree, so do not change one without the other.

What an LLM verdict was made on (``rule_hits.names_hash`` / ``subject_hash``, migration ``0018``;
hex md5 text, not keys): the scanner stores both on every LLM hit and asks a rule again when the
current values differ (see ``scanner services.db_service.LLM_CANDIDATE_COND``).

* ``names_hash``   - object name + sorted field names (object rules: every field of the object;
  field rules / field marks: the one field). Changes when the object is renamed or a field is
  added / removed / renamed - an object rule then asks again even about a hit a human decided.
* ``subject_hash`` - object rules: the object's ``content_hash`` (text); field rules: field name,
  type, comment and samples (``field_subject_hash``). Changes with the content the model saw; a
  machine verdict is then asked again (human decisions on content-only changes are kept).

Migration ``0018`` defines the same hashes as SQL functions (``llm_names_hash``,
``llm_field_hash``), used by the candidate queries, the coverage counts and the backfill;
``test_common_keys`` checks that they agree with these functions.
"""

import hashlib
import uuid
from typing import Any, Iterable, Mapping, Optional, Tuple

# Separators that do not occur in identifiers, so "a:b" + "c" never equals "a" + "b:c".
PART_SEP = "#"
ITEM_SEP = "\x1f"   # between fields / between props
PAIR_SEP = "\x1e"   # between a name and its type / value


def md5_uuid(text: str) -> uuid.UUID:
    return uuid.UUID(hashlib.md5(text.encode("utf-8")).hexdigest())


def object_key(project_id: int, parser: str, identity_hash: str) -> uuid.UUID:
    return md5_uuid(PART_SEP.join((str(project_id), parser or "", identity_hash or "")))


def _items(pairs: Iterable[Tuple[str, Optional[str]]]) -> str:
    # sorted() orders by code point, which is what Postgres does with COLLATE "C" on UTF-8.
    return ITEM_SEP.join(f"{name}{PAIR_SEP}{value or ''}" for name, value in sorted(pairs, key=lambda p: p[0]))


def content_hash(obj_key: uuid.UUID, fields: Mapping[str, Optional[str]], props: Mapping[str, Optional[str]],
                 docs: Optional[Mapping[str, Optional[str]]] = None) -> uuid.UUID:
    """``fields``: ``{field_name: field_type}``; ``props``: ``{prop_name: prop_value}``; ``docs``: the
    comments and samples (``{'': object comment, name: 'comment<sep>samples'}``), a part of the hash
    only when there are any, so objects without documentation keep the hash they had before it."""
    parts = [str(obj_key), _items(fields.items()), _items(props.items())]
    docs = {name: value for name, value in (docs or {}).items() if value}
    if docs:
        parts.append(_items(docs.items()))
    return md5_uuid(PART_SEP.join(parts))


def field_key(obj_key: uuid.UUID, field_name: str) -> uuid.UUID:
    return md5_uuid(PART_SEP.join((str(obj_key), field_name)))


def subject_key(obj_key: uuid.UUID, field_name: Optional[str] = None) -> uuid.UUID:
    """``rule_hits.subject_key``: the object key for object rules, the field key for field rules."""
    return obj_key if field_name is None else field_key(obj_key, field_name)


def _md5_hex(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def names_hash(object_name: Optional[str], field_names: Iterable[str]) -> str:
    """``rule_hits.names_hash``: the object name and its (sorted) field names; SQL
    ``llm_names_hash(name, field_names[])``. Field hits pass their one field."""
    return _md5_hex(PART_SEP.join((object_name or "", ITEM_SEP.join(sorted(field_names)))))


def field_subject_hash(field_name: str, field_type: Optional[str], comment: Optional[str],
                       samples: Optional[Iterable[Any]]) -> str:
    """``rule_hits.subject_hash`` of a field hit: name, type, comment and samples (in their
    order); SQL ``llm_field_hash(name, type, comment, samples jsonb)``. Samples are strings
    (JSON null elements are skipped, like ``string_agg`` does)."""
    joined = ITEM_SEP.join(str(s) for s in (samples or []) if s is not None)
    return _md5_hex(PAIR_SEP.join((field_name or "", field_type or "", comment or "", joined)))


def object_subject_hash(content_hash: Any) -> str:
    """``rule_hits.subject_hash`` of an object hit: the content hash of the version asked about."""
    return str(content_hash)
