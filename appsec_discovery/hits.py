"""Rule hits on code objects: recording, applying and re-triaging (stage 5b).

A hit is recorded on ``CodeObject.hits``; only a ``match`` hit changes the
severity/tags of its subject (field or property) and of the object, through
the single merge helper (``Scorable.apply_score``). Hits are applied in the
order they are recorded, so tag order is the order of the rules.
"""
from typing import Iterable, List, Mapping, Optional

from appsec_discovery.models import CodeObject, HitStatus, HitSubject, RuleHit
from appsec_discovery.models.rules import normalize_hit_status

__all__ = ["record_hit", "apply_hit", "recompute_scores", "apply_hit_statuses", "hits_of", "has_open_hits",
           "OPEN_STATUSES"]

# statuses that wait for a decision
OPEN_STATUSES = (HitStatus.pending_review.value, HitStatus.need_more_info.value)


def apply_hit(obj: CodeObject, hit: RuleHit) -> None:
    """Merge a ``match`` ``hit`` into its subject and the object (no-op for any other status)."""
    if hit.status != HitStatus.match.value:
        return
    if hit.subject == HitSubject.field.value:
        field = obj.fields.get(hit.field_name)
        if field is not None:
            field.apply_score(hit.severity, hit.tags)
    elif hit.subject == HitSubject.prop.value:
        prop = obj.properties.get(hit.prop_name)
        if prop is not None:
            prop.apply_score(hit.severity, hit.tags)
    # the rule's ``tags`` go to the object only (the subject keeps the hit's own tag)
    obj.apply_score(hit.severity, list(hit.tags or []) + [t for t in hit.object_tags or [] if t not in (hit.tags or [])])


def record_hit(obj: CodeObject, hit: RuleHit) -> bool:
    """Add ``hit`` to ``obj.hits`` and apply it when it is a ``match``.

    A second hit with the same key (same rule on the same subject) is ignored;
    returns whether the hit was added.
    """
    key = hit.key(obj.hash)
    hits = obj.hits if obj.hits is not None else []
    if any(h.key(obj.hash) == key for h in hits):
        return False
    hits.append(hit)
    obj.hits = hits
    apply_hit(obj, hit)
    return True


def hits_of(obj: CodeObject, subject: Optional[str] = None, name: Optional[str] = None) -> List[RuleHit]:
    """Hits of ``obj``, optionally only those on ``subject`` (and on the field/prop ``name``)."""
    return [
        h for h in obj.hits or []
        if (subject is None or h.subject == subject) and (name is None or h.subject_name == name)
    ]


def has_open_hits(obj: CodeObject) -> bool:
    """``obj`` has a hit waiting for triage (``pending_review`` or ``need_more_info``)."""
    return any(h.status in OPEN_STATUSES for h in obj.hits or [])


def recompute_scores(obj: CodeObject) -> CodeObject:
    """Reset severity/tags of the object, its fields and properties and re-apply the ``match`` hits.

    Scores that did not come from hits are lost: every core scorer records hits.
    """
    for target in [obj, *obj.fields.values(), *obj.properties.values()]:
        target.severity = None
        target.tags = None
    for hit in obj.hits or []:
        apply_hit(obj, hit)
    return obj


def apply_hit_statuses(objects: Iterable[CodeObject], statuses: Mapping[str, str]) -> List[CodeObject]:
    """Apply stored triage decisions: ``statuses`` maps ``RuleHit.key(obj.hash)`` to a ``HitStatus``.

    Hits whose status changes are updated and the scores of their objects are
    recomputed, so a ``review`` hit set to ``match`` now scores and an ``auto`` hit set
    to ``no_match`` no longer does. The legacy statuses ``confirmed`` / ``rejected`` are
    accepted as ``match`` / ``no_match`` with a deprecation warning (until the next
    release). Returns the objects (changed in place).
    """
    objects = list(objects)
    for obj in objects:
        changed = False
        for hit in obj.hits or []:
            status = statuses.get(hit.key(obj.hash))
            if status is None:
                continue
            status = normalize_hit_status(status)
            if status != hit.status:
                hit.status = status
                changed = True
        if changed:
            recompute_scores(obj)
    return objects
