"""Run a set of parsers over a source folder with per-parser failure isolation."""
import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence

from appsec_discovery.errors import SemgrepError, UnknownParserError
from appsec_discovery.matching import Pattern
from appsec_discovery.models import CodeObject
from appsec_discovery.parsers import ParserFactory
from appsec_discovery.parsers.base_parser import FileParser, SemgrepParser
from appsec_discovery.parsers.parser_factory import is_deprecated
from appsec_discovery.parsers.semgrep import Finding, SemgrepRunner

logger = logging.getLogger(__name__)

__all__ = ["ScanResult", "UnknownParserError", "resolve_parser_names", "run_parsers"]


@dataclass
class ScanResult:
    """Objects found by the parsers plus the errors of the parsers that failed.

    ``parsers`` lists every parser that was attempted; ``errors`` maps the name
    of each failed parser to a human readable error message.
    """
    objects: List[CodeObject] = field(default_factory=list)
    errors: Dict[str, str] = field(default_factory=dict)
    parsers: List[str] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        """At least one parser failed."""
        return bool(self.errors)

    @property
    def all_failed(self) -> bool:
        """Parsers were attempted and every one of them failed."""
        return bool(self.parsers) and all(name in self.errors for name in self.parsers)


def resolve_parser_names(names: Optional[Iterable[str]]) -> List[str]:
    """Expand ``'all'`` (or ``None``) to every available non-deprecated parser and drop duplicates.

    A deprecated parser (``db``, ``client``) still runs when it is named explicitly.
    """
    if names is None:
        names = ['all']
    names = list(names)

    if 'all' in names:
        names = [name for name in ParserFactory.get_parser_types() if not is_deprecated(name)]

    return list(dict.fromkeys(names))


def _file_excluder(exclude_scan) -> Optional[Callable[[str], bool]]:
    """Predicate on a relative file path built from the ``exclude_scan`` rules that only
    constrain ``file`` (such a rule drops every object of the file anyway)."""
    patterns = [
        Pattern.of(rule.file) for rule in exclude_scan or ()
        if rule.file and not (rule.parser or rule.object_name or rule.object_type)
    ]
    if not patterns:
        return None
    return lambda rel: any(p.matches(rel) for p in patterns)


def _is_semgrep_parser(cls) -> bool:
    return isinstance(cls, type) and issubclass(cls, SemgrepParser) and cls.has_rules()


def _combined_semgrep(source: str, group: Dict[str, type]) -> Optional[Dict[str, List[dict]]]:
    """One semgrep process for the rules of every parser in ``group``.

    Returns the findings per parser name (routed by the rules' ``metadata.parser``),
    or ``None`` when the combined run failed (the caller falls back to per-parser runs).
    """
    rules_dirs = [str(cls.rules_path()) for cls in group.values()]
    try:
        results = SemgrepRunner().run(source, rules_dirs, label='+'.join(group))
    except SemgrepError as ex:
        logger.warning(f"Combined semgrep run failed for {source}, falling back to one run per parser: {ex}")
        return None

    by_parser: Dict[str, List[dict]] = {name: [] for name in group}
    class_names = {cls.name: name for name, cls in group.items()}
    unrouted = set()

    for raw in results:
        finding = Finding(raw)
        target = class_names.get(finding.parser or '')
        if target is None:
            unrouted.add(finding.rule_id)
            continue
        by_parser[target].append(raw)

    if unrouted:
        logger.warning(f"semgrep findings without a known metadata.parser are skipped: {sorted(unrouted)}")

    return by_parser


def run_parsers(source: str, names: Optional[Iterable[str]] = None, *,
                exclude_scan: Sequence = ()) -> ScanResult:
    """Run the parsers ``names`` (default: all) over ``source``.

    A parser that is unknown or raises does not abort the run: its error is
    recorded in ``ScanResult.errors`` and the remaining parsers still run.

    The semgrep-based parsers share one semgrep process (all their rule folders);
    if that run fails each of them runs semgrep on its own, so one broken rule set
    only fails its parser. ``exclude_scan`` rules that only name files let the
    file-based parsers skip those files before reading them.
    """
    result = ScanResult()
    classes: Dict[str, type] = {}

    names = resolve_parser_names(names)

    for name in names:
        try:
            classes[name] = ParserFactory.get_parser(name)
        except Exception as ex:
            classes[name] = ex

    semgrep_group = {name: cls for name, cls in classes.items() if _is_semgrep_parser(cls)}
    combined = _combined_semgrep(source, semgrep_group) if len(semgrep_group) > 1 else None
    excluder = _file_excluder(exclude_scan)

    for name in names:

        result.parsers.append(name)
        cls = classes[name]

        try:
            if isinstance(cls, Exception):
                raise cls
            parser = cls(parser=name, source_folder=source)
            if excluder is not None and isinstance(parser, FileParser):
                parser.exclude_file = excluder
            if combined is not None and name in combined:
                objects = parser.parse_report(combined[name])
            else:
                objects = parser.run_scan()
        except Exception as ex:
            message = f"{type(ex).__name__}: {ex}"
            logger.error(f"Parser {name} failed for {source}: {message}")
            logger.debug("Parser failure details", exc_info=True)
            result.errors[name] = message
            continue

        if objects:
            result.objects.extend(objects)

    return result
