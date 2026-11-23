"""Pure report renderers (P2-2): ``List[CodeObject]`` -> report text.

Renderers never touch files or stdout; callers (the CLI, ``ReportService``,
library users) decide where the string goes.

SARIF output (2.1.0):

* the tool's ``semanticVersion`` is the installed package version;
* one rule per ``<parser>.<object_type>`` with a description of its own;
* an object with scored fields yields one result per scored field; any other
  object (unscored, or scored only through its properties) yields one result for
  the object, and an object with both scored fields and scored properties gets
  an object result as well;
* every result carries ``partialFingerprints.discoveryHash`` (the object hash;
  field results add ``discoveryFieldHash``), a ``security-severity`` property
  for scored results, ``startLine >= 1`` and a URI relative to ``%SRCROOT%``
  (no leading ``/``, percent-encoded);
* rule hits (stage 5b) are listed in ``properties.hits`` of the result for
  their subject (field hits on the field result, object and property hits on
  the object result) with rule, type, severity, tags and status. A field whose
  only hits wait for triage (``pending_review``/``need_more_info``) still gets
  a result, of ``kind: review`` (``level: none``, as SARIF requires for a kind other than
  ``fail``); so does an object with only open object hits.
  ``no_match`` hits are listed but never create a result; ``match`` hits score their subject
  (a result of the default ``kind: fail``).

YAML and JSON reports dump the objects, including ``hits`` with their status.
"""
import hashlib
import json
from typing import Callable, Dict, List, Optional
from urllib.parse import quote

import sarif_om as om
import yaml
from jschema_to_python.to_json import to_json

from appsec_discovery import __version__
from appsec_discovery.hits import OPEN_STATUSES, hits_of
from appsec_discovery.matching import Severity
from appsec_discovery.models import CodeObject, CodeObjectField, HitStatus, HitSubject, RuleHit

__all__ = ["REPORT_FORMATS", "RENDERERS", "render_report", "render_json", "render_yaml", "render_sarif"]

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/dmarushkin/appsec-discovery"

# GitHub code scanning buckets: critical > 9.0, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9
SECURITY_SEVERITY = {
    Severity.critical: "9.5",
    Severity.high: "8.0",
    Severity.medium: "5.5",
    Severity.low: "2.0",
}

SARIF_LEVEL = {
    Severity.critical: "error",
    Severity.high: "error",
    Severity.medium: "warning",
    Severity.low: "warning",
}


def _dump(obj: CodeObject) -> dict:
    return obj.dict(exclude_none=True)


def render_json(objects: List[CodeObject]) -> str:
    return json.dumps([_dump(obj) for obj in objects], indent=4)


def render_yaml(objects: List[CodeObject]) -> str:
    return yaml.dump([_dump(obj) for obj in objects], default_flow_style=False, sort_keys=False)


# -- SARIF ------------------------------------------------------------------------------------------


def _severity(value: Optional[str]) -> Optional[Severity]:
    if not value:
        return None
    try:
        return Severity(str(value).lower())
    except ValueError:
        return None


def _level(severity: Optional[Severity], kind: str = "fail") -> str:
    # SARIF 2.1.0 (3.27.9/3.27.10): a result whose kind is not "fail" must have level "none"
    if kind != "fail":
        return "none"
    return SARIF_LEVEL.get(severity, "note") if severity is not None else "note"


def _hit_summary(hit: RuleHit) -> dict:
    summary = {"rule": hit.rule, "type": hit.rule_type, "severity": hit.severity, "tags": list(hit.tags),
               "status": hit.status}
    if hit.reason:
        summary["reason"] = hit.reason
    return summary


def _properties(severity: Optional[Severity], tags: Optional[List[str]], hits: List[RuleHit] = ()) -> dict:
    properties = {}
    if severity is not None and tags:
        properties["tags"] = list(tags)
    if severity in SECURITY_SEVERITY:
        properties["security-severity"] = SECURITY_SEVERITY[severity]
    if hits:
        properties["hits"] = [_hit_summary(hit) for hit in hits]
    return properties


def _open(hits: List[RuleHit]) -> bool:
    return any(hit.status in OPEN_STATUSES for hit in hits)


def _kind(severity: Optional[Severity], hits: List[RuleHit]) -> str:
    """``review`` for a result that exists only because of hits waiting for triage, else the
    SARIF default ``fail`` (omitted from the output)."""
    return "review" if severity is None and _open(hits) else "fail"


def _uri(path: Optional[str]) -> str:
    """A URI reference relative to ``%SRCROOT%``: POSIX separators, no leading ``/``, percent-encoded."""
    path = (path or "").replace("\\", "/").lstrip("/")
    return quote(path, safe="/")


def _rule_id(obj: CodeObject) -> str:
    return f"{obj.parser}.{obj.object_type}"


def _rule(rule_id: str, obj: CodeObject) -> om.ReportingDescriptor:
    short = f"Discovered {obj.object_type} object ({obj.parser} parser)"
    full = (f"A {obj.object_type} object extracted by the {obj.parser} parser. Results of this rule are "
            f"scored by keyword rules or an LLM: scored results point to the sensitive fields of the object, "
            f"unscored results are inventory notes.")
    return om.ReportingDescriptor(
        id=rule_id,
        name=f"{obj.parser}-{obj.object_type}".replace(".", "-"),
        short_description={"text": short},
        full_description={"text": full},
        help={"text": f"Review how {obj.object_type} objects found by the {obj.parser} parser handle "
                      f"sensitive data and make sure access to them is authorized."},
        properties={},
        default_configuration={},
    )


def _location(file: Optional[str], line: Optional[int], snippet: str) -> om.Location:
    start_line = max(line or 1, 1)
    return om.Location(
        physical_location=om.PhysicalLocation(
            artifact_location=om.ArtifactLocation(uri=_uri(file), uri_base_id="%SRCROOT%"),
            region=om.Region(start_line=start_line),
            context_region=om.Region(start_line=start_line, snippet=om.ArtifactContent(text=snippet)),
        )
    )


def _field_hash(obj: CodeObject, field_name: str) -> str:
    return hashlib.md5(f"{obj.hash}#{field_name}".encode()).hexdigest()


def _object_hits(obj: CodeObject) -> List[RuleHit]:
    return [hit for hit in obj.hits or [] if hit.subject != HitSubject.field.value]


def _object_result(obj: CodeObject, snippet: str) -> om.Result:
    severity = _severity(obj.severity)
    hits = _object_hits(obj)
    kind = _kind(severity, hits)
    return om.Result(
        rule_id=_rule_id(obj),
        level=_level(severity, kind),
        kind=kind,
        properties=_properties(severity, obj.tags, hits),
        message=om.Message(text=f"[{_rule_id(obj)}] {obj.object_name}"),
        partial_fingerprints={"discoveryHash": obj.hash},
        locations=[_location(obj.file, obj.line, snippet)],
    )


def _field_result(obj: CodeObject, field: CodeObjectField, snippet: str) -> om.Result:
    severity = _severity(field.severity)
    hits = hits_of(obj, HitSubject.field.value, field.field_name)
    tags = f" ({', '.join(field.tags)})" if field.tags else ""
    if severity is None and _open(hits):
        tags = f" (review: {', '.join(dict.fromkeys(t for h in hits if h.status in OPEN_STATUSES for t in h.tags))})"
    kind = _kind(severity, hits)
    return om.Result(
        rule_id=_rule_id(obj),
        level=_level(severity, kind),
        kind=kind,
        properties=_properties(severity, field.tags, hits),
        message=om.Message(text=f"[{_rule_id(obj)}] {obj.object_name}: field {field.field_name}{tags}"),
        partial_fingerprints={"discoveryHash": obj.hash, "discoveryFieldHash": _field_hash(obj, field.field_name)},
        # a field's own location only when the parser recorded one, else the object's
        locations=[_location(field.file, field.line, snippet) if field.file
                   else _location(obj.file, obj.line, snippet)],
    )


def _results(obj: CodeObject) -> List[om.Result]:
    snippet = yaml.safe_dump(_dump(obj), sort_keys=False)

    # fields with a score, or with hits waiting for triage
    scored_fields = [field for field in obj.fields.values()
                     if field.severity or _open(hits_of(obj, HitSubject.field.value, field.field_name))]
    # properties with a score, or (not no_match) object/property hits
    scored_props = (any(prop.severity for prop in obj.properties.values())
                    or any(hit.status != HitStatus.no_match.value for hit in _object_hits(obj)))

    results = []
    if not scored_fields or scored_props:
        results.append(_object_result(obj, snippet))
    results.extend(_field_result(obj, field, snippet) for field in scored_fields)
    return results


def render_sarif(objects: List[CodeObject]) -> str:
    rules: Dict[str, om.ReportingDescriptor] = {}
    results: List[om.Result] = []

    for obj in objects:
        rule_id = _rule_id(obj)
        if rule_id not in rules:
            rules[rule_id] = _rule(rule_id, obj)
        results.extend(_results(obj))

    report = om.SarifLog(
        schema_uri=SARIF_SCHEMA_URI,
        version="2.1.0",
        runs=[
            om.Run(
                tool=om.Tool(
                    driver=om.ToolComponent(
                        name="appsec-discovery",
                        semantic_version=__version__,
                        information_uri=INFORMATION_URI,
                        rules=list(rules.values()),
                    )
                ),
                results=results,
            )
        ],
    )
    return to_json(report)


# -- dispatch ---------------------------------------------------------------------------------------

RENDERERS: Dict[str, Callable[[List[CodeObject]], str]] = {
    "yaml": render_yaml,
    "json": render_json,
    "sarif": render_sarif,
}

REPORT_FORMATS = tuple(RENDERERS)


def render_report(objects: List[CodeObject], fmt: str) -> str:
    """Render ``objects`` as ``fmt`` (``yaml``, ``json`` or ``sarif``, case-insensitive)."""
    try:
        renderer = RENDERERS[str(fmt).lower()]
    except KeyError:
        raise ValueError(f"unknown report format: {fmt!r}, expected one of {list(REPORT_FORMATS)}") from None
    return renderer(list(objects))
