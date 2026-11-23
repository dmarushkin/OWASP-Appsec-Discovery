"""Parser framework (P1-5): registry, ``SemgrepParser``/``FileParser`` templates, ``ObjectCollector``.

* Every concrete parser class with a ``name`` registers itself in ``REGISTRY``
  (``__init_subclass__``); ``ParserFactory`` is a thin shim over it.
* ``SemgrepParser`` subclasses ship ``scanner_rules/*.yaml`` next to their module.
  Each rule declares ``metadata: {parser, object_type, framework}``; findings are
  dispatched to ``handlers[object_type]``. A rule without a handler is logged.
* ``FileParser`` subclasses walk the source tree (vendored directories pruned),
  parse every matching file and build objects from the parsed files.
* Object identity (``CodeObject.hash``) comes from ``Parser.identity`` ->
  ``object_identity(parser, relative file, object_type, logical_name)``.
"""
import inspect
import logging
import os
import stat
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable, ClassVar, Dict, List, Optional, Tuple, Type

from appsec_discovery.models import CodeObject, CodeObjectField, CodeObjectProp, object_identity
from appsec_discovery.models.code_object import clean_comment
from appsec_discovery.parsers.comments import leading_comment
from appsec_discovery.parsers.common import DEFAULT_PRUNE_DIRS, relative_source_path, walk_files
from appsec_discovery.parsers.semgrep import DEFAULT_SEMGREP_TIMEOUT, Finding, SemgrepRunner

logger = logging.getLogger(__name__)

__all__ = [
    "REGISTRY", "Parser", "SemgrepParser", "FileParser", "ObjectCollector", "Finding",
    "DEFAULT_SEMGREP_TIMEOUT", "MAX_FILE_BYTES", "read_text_file", "relative_source_path",
]

REGISTRY: Dict[str, Type['Parser']] = {}

# files larger than this are not read by the parsers (the semgrep runs skip them too)
MAX_FILE_BYTES = 5 * 1024 * 1024


def read_text_file(path, root, max_bytes: int = MAX_FILE_BYTES, label: str = 'parser') -> Optional[str]:
    """Text of the source file ``path`` (under the scanned folder ``root``); None when it is skipped.

    Untrusted repositories: a symlink that resolves outside ``root`` is not followed, anything but
    a regular file (a FIFO, a device such as ``/dev/zero``) is not read, and a file larger than
    ``max_bytes`` is skipped without being read whole. The text is UTF-8 (a BOM is dropped); a file
    that is not valid UTF-8 is still read, its undecodable bytes replaced (identifiers and SQL /
    config syntax are ASCII), so one legacy-encoded comment does not drop the whole file. Line
    ends are normalised to ``\\n``.
    Skips are logged at info level, unreadable files at warning level.
    """
    try:
        real = os.path.realpath(path)
        real_root = os.path.realpath(root)
        if os.path.commonpath([real, real_root]) != real_root:
            logger.info(f"{label}: {path} is a link outside of the scanned folder ({real}), skipped")
            return None
        info = os.stat(real)
        if not stat.S_ISREG(info.st_mode):
            logger.info(f"{label}: {path} is not a regular file, skipped")
            return None
        if info.st_size > max_bytes:
            logger.info(f"{label}: {path} is larger than {max_bytes} bytes ({info.st_size}), skipped")
            return None
        with open(real, 'rb') as file:
            data = file.read(max_bytes + 1)
    except (OSError, ValueError) as ex:
        logger.warning(f"{label}: cannot read {path}: {ex}")
        return None
    if len(data) > max_bytes:          # grew after the stat
        logger.info(f"{label}: {path} is larger than {max_bytes} bytes, skipped")
        return None
    try:
        text = data.decode('utf-8-sig')
    except UnicodeDecodeError as ex:
        logger.info(f"{label}: {path} is not valid UTF-8 ({ex.reason} at byte {ex.start}), "
                    f"undecodable bytes are replaced")
        text = data.decode('utf-8-sig', errors='replace')
    # universal newlines, as text-mode ``open`` reads them
    return text.replace('\r\n', '\n').replace('\r', '\n')


class Parser(ABC):

    # registry name (the name used in ``ScoreConfig.parsers``); classes without one are not registered
    name: ClassVar[str]
    # still accepted by name (with a warning) but not part of ``parsers: [all]``
    deprecated: ClassVar[bool] = False

    # The files this parser reads, as glob patterns (``appsec_discovery.changes.path_matches``: a
    # pattern without ``/`` is matched against the file name, one with ``/`` against the whole
    # repository-relative path). Consumers that know which files changed between two commits
    # (the service's diff-based scan skip) use it to tell whether a change can alter the
    # parser's output. ``None``: not declared, every change may matter; ``()``: reads nothing.
    # ``FileParser`` subclasses get their ``globs``; semgrep parsers declare the languages' files.
    file_patterns: ClassVar[Optional[Tuple[str, ...]]] = None

    # seconds; None disables the timeout
    semgrep_timeout: Optional[float] = DEFAULT_SEMGREP_TIMEOUT

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        name = cls.__dict__.get('name')
        if isinstance(name, str) and not inspect.isabstract(cls):
            REGISTRY[name] = cls
        if 'file_patterns' not in cls.__dict__ and 'globs' in cls.__dict__:
            # a file parser reads exactly the files it walks (``globs``)
            cls.file_patterns = tuple(cls.__dict__['globs'])

    def __init__(self, parser: Optional[str] = None, source_folder: str = '.',
                 semgrep_timeout: Optional[float] = None):

        self.parser = parser or getattr(type(self), 'name', None) or type(self).__name__
        self.source_folder = source_folder
        self.root = Path(source_folder).resolve()

        if semgrep_timeout is not None:
            self.semgrep_timeout = semgrep_timeout

    @abstractmethod
    def parse_report(self, scanner_data) -> List[CodeObject]:
        pass

    @abstractmethod
    def run_scan(self) -> List[CodeObject]:
        pass

    # -- helpers ----------------------------------------------------------------

    def relpath(self, path: str) -> str:
        """``path`` relative to the scanned folder as ``/sub/file``."""
        return relative_source_path(path, self.source_folder)

    def identity(self, file: str, object_type: str, logical_name: str) -> str:
        """``CodeObject.hash`` of an object of this parser (see ``object_identity``)."""
        return object_identity(getattr(type(self), 'name', None) or self.parser, file, object_type, logical_name)

    def run_semgrep(self, source_folder: str, rules_folder: str) -> List[dict]:
        """Run semgrep with ``rules_folder`` over ``source_folder`` (see ``SemgrepRunner.run``)."""
        return SemgrepRunner(timeout=self.semgrep_timeout).run(source_folder, [rules_folder], label=self.parser)


class ObjectCollector:
    """Accumulates ``CodeObject``s of one parse, keyed by their identity hash."""

    def __init__(self, parser: Parser):
        self.parser = parser
        self._objects: Dict[str, CodeObject] = {}

    def get(self, object_type: str, logical_name: str, file: str) -> Optional[CodeObject]:
        return self._objects.get(self.parser.identity(file, object_type, logical_name))

    def get_or_create(self, *, object_type: str, logical_name: str, file: str, object_name: str,
                      line: int, properties: Optional[Dict[str, str]] = None) -> CodeObject:
        """The object with this identity; created (with ``properties``) on first use.

        ``object_name``, ``line`` and ``properties`` of an existing object are not changed.
        """
        key = self.parser.identity(file, object_type, logical_name)
        obj = self._objects.get(key)

        if obj is None:
            obj = CodeObject(
                hash=key,
                object_name=object_name,
                object_type=object_type,
                parser=self.parser.parser,
                file=file,
                line=line,
                properties={},
                fields={},
            )
            for prop_name, prop_value in (properties or {}).items():
                self.add_prop(obj, prop_name, prop_value)
            self._objects[key] = obj

        return obj

    @staticmethod
    def add_prop(obj: CodeObject, name: str, value: str) -> None:
        """Set property ``name`` (overwrites)."""
        obj.properties[name] = CodeObjectProp(prop_name=name, prop_value=value)

    @staticmethod
    def add_field(obj: CodeObject, name: str, field_type: str, file: Optional[str] = None,
                  line: Optional[int] = None, comment: Optional[str] = None,
                  samples: Optional[List[str]] = None) -> CodeObjectField:
        """Add field ``name`` unless the object already has it (first occurrence wins)."""
        field = obj.fields.get(name)
        if field is None:
            field = CodeObjectField(field_name=name, field_type=field_type, file=file, line=line,
                                    comment=comment, samples=samples)
            obj.fields[name] = field
        return field

    def objects(self) -> List[CodeObject]:
        return list(self._objects.values())


class SemgrepParser(Parser):
    """Template for parsers driven by semgrep rules in ``scanner_rules`` next to the module.

    ``handlers`` maps a rule's ``metadata.object_type`` to the name of the method
    ``handle_x(finding, collector)`` that turns the finding into objects.
    """

    handlers: ClassVar[Dict[str, str]] = {}

    @classmethod
    def rules_path(cls) -> Path:
        module = sys.modules[cls.__module__]
        return Path(module.__file__).resolve().parent / 'scanner_rules'

    @classmethod
    def has_rules(cls) -> bool:
        return cls.rules_path().is_dir()

    def run_scan(self) -> List[CodeObject]:
        if not self.has_rules():
            return []
        results = self.run_semgrep(source_folder=self.source_folder, rules_folder=str(self.rules_path()))
        return self.parse_report(results)

    def handler_for(self, finding: Finding) -> Optional[Callable[[Finding, ObjectCollector], None]]:
        method = self.handlers.get(finding.object_type or '')
        return getattr(self, method) if method else None

    # source files larger than this are not read for comments / samples
    max_source_bytes: ClassVar[int] = MAX_FILE_BYTES

    def parse_report(self, semgrep_data) -> List[CodeObject]:
        # lines of the source files read for comments / samples during this parse (each file once)
        self._source_cache: Dict[str, List[str]] = {}
        try:
            return self._parse_findings(semgrep_data)
        finally:
            self._source_cache = {}

    def _parse_findings(self, semgrep_data) -> List[CodeObject]:

        collector = ObjectCollector(self)
        unhandled = set()

        for raw in semgrep_data or []:
            finding = Finding(raw)

            if finding.parser and finding.parser != getattr(type(self), 'name', self.parser):
                # a finding of another parser's rule (combined semgrep run); not ours
                continue

            handler = self.handler_for(finding)
            if handler is None:
                if finding.rule_id not in unhandled:
                    unhandled.add(finding.rule_id)
                    logger.warning(f"{self.parser}: no handler for rule {finding.rule_id!r} "
                                   f"(metadata.object_type={finding.object_type!r}), its findings are skipped")
                continue

            handler(finding, collector)

        self.collect_extra(collector)

        objects = collector.objects()
        logger.info(f"For scan {self.parser} data parse {len(objects)} objects")
        return objects

    def collect_extra(self, collector: ObjectCollector) -> None:
        """Hook after the findings: objects or fields not driven by semgrep (java reads the
        sources itself). Does nothing by default."""

    # -- source text: comments and samples ---------------------------------------

    def source_lines(self, path: str) -> List[str]:
        """Lines of the scanned file ``path`` (``/sub/file``); [] when it cannot be read.

        Cached for the current ``parse_report``; never raises.
        """
        cache = getattr(self, '_source_cache', None)
        if cache is None:
            cache = self._source_cache = {}
        if path not in cache:
            cache[path] = self._read_source(path)
        return cache[path]

    def _read_source(self, path: str) -> List[str]:
        if not path:
            return []
        text = read_text_file(self.root / path.lstrip('/'), self.root, self.max_source_bytes, label=self.parser)
        return text.splitlines() if text is not None else []

    def comment_at(self, path: str, line: Optional[int]) -> Optional[str]:
        """The code comment above (and after) ``line`` of ``path``; None when there is none."""
        if not line:
            return None
        try:
            return leading_comment(self.source_lines(path), line)
        except Exception as ex:  # documentation is best effort, never fail the scan
            logger.debug(f"{self.parser}: comment of {path}:{line} failed: {ex}")
            return None

    def object_comment(self, finding: Finding, line: Optional[int]) -> Optional[str]:
        """Comment of the object declared at ``line`` (override for docstrings etc.)."""
        return self.comment_at(finding.path, line)

    def field_comment(self, finding: Finding, line: Optional[int]) -> Optional[str]:
        """Comment of the field declared at ``line``."""
        return self.comment_at(finding.path, line)

    def field_samples(self, finding: Finding, line: Optional[int]) -> Optional[List[str]]:
        """Literal example values of the field at ``line`` (tags, annotations, defaults); None by default."""
        return None

    @staticmethod
    def set_comment(obj: CodeObject, comment: Optional[str]) -> None:
        """Set ``obj.comment`` (normalised like the model validator; attribute assignment skips it)."""
        obj.comment = clean_comment(comment)

    def _safe(self, method: Callable, finding: Finding, line: Optional[int]):
        try:
            return method(finding, line)
        except Exception as ex:  # documentation is best effort, never fail the scan
            logger.debug(f"{self.parser}: {method.__name__} of {finding.path}:{line} failed: {ex}")
            return None

    # -- shared handlers --------------------------------------------------------

    def collect_dto(self, finding: Finding, collector: ObjectCollector, *, object_name: str, field_name: str,
                    field_type: str, line: Optional[int] = None, properties: Optional[Dict[str, str]] = None,
                    object_line: Optional[int] = None, field_line: Optional[int] = None) -> None:
        """One DTO field: object ``<object_name>`` (no type / framework words: those are
        ``object_type`` and the ``framework`` property) keyed by the structure name.

        ``object_line`` is the line of the structure declaration (default: the ``$OBJECT``
        metavariable), used for the object comment; ``field_line`` the line the field comment and
        samples are read from (default: ``line``, the line reported for the field).
        """
        framework = finding.framework
        line = line if line is not None else finding.line
        props = {'framework': framework, 'object': object_name}
        props.update(properties or {})
        is_new = collector.get('dto', object_name, finding.path) is None
        obj = collector.get_or_create(
            object_type='dto',
            logical_name=object_name,
            file=finding.path,
            object_name=object_name,
            line=line,
            properties=props,
        )
        if is_new:
            self.set_comment(obj, self._safe(self.object_comment, finding,
                                             object_line if object_line is not None else finding.mv_line('$OBJECT')))
        if field_name not in obj.fields:
            doc_line = field_line if field_line is not None else line
            collector.add_field(obj, field_name, field_type, file=finding.path, line=line,
                                comment=self._safe(self.field_comment, finding, doc_line),
                                samples=self._safe(self.field_samples, finding, doc_line))


class FileParser(Parser):
    """Template for parsers that read the files themselves (no semgrep).

    ``run_scan`` walks the source folder (``prune_dirs`` are not entered), keeps the
    files whose name matches ``globs`` and ``accept_file``, parses each one with
    ``parse_file`` (a file that fails is logged and skipped) and hands
    ``{relative path: parsed}`` to ``build_objects``.
    """

    globs: ClassVar[Tuple[str, ...]] = ()
    prune_dirs: ClassVar[frozenset] = DEFAULT_PRUNE_DIRS
    # larger files are skipped (see ``read_text_file``: links outside the folder and
    # non-regular files are skipped too, non-UTF-8 bytes are replaced)
    max_file_bytes: ClassVar[int] = MAX_FILE_BYTES

    # True when an object can take content from other files (graphql types and
    # protobuf messages are resolved across the files of a schema/package). Such a
    # parser must read every file, so ``exclude_file`` is not applied while walking:
    # skipping a file there would change the fields of objects in the other files.
    # The ``exclude_scan`` filter still drops the objects of excluded files afterwards.
    objects_span_files: ClassVar[bool] = False

    # set by the runner from ``exclude_scan`` rules that only name files: receives
    # the relative path, True skips the file before it is read
    exclude_file: Optional[Callable[[str], bool]] = None

    def find_files(self) -> List[str]:
        exclude = None if self.objects_span_files else self.exclude_file
        return walk_files(self.source_folder, self.globs, prune_dirs=self.prune_dirs, exclude=exclude)

    def accept_file(self, path: str, text: str) -> bool:
        """Content check after reading; False skips the file silently."""
        return True

    @abstractmethod
    def parse_file(self, path: str, text: str):
        """Parse one file; ``path`` is the absolute path, ``text`` its content."""

    @abstractmethod
    def build_objects(self, parsed: dict) -> List[CodeObject]:
        """Objects from ``{relative path: parse_file result}``."""

    def parse_report(self, parsed) -> List[CodeObject]:
        return self.build_objects(parsed or {})

    def run_scan(self) -> List[CodeObject]:

        parsed = {}

        for path in self.find_files():

            rel = self.relpath(path)

            text = read_text_file(path, self.root, self.max_file_bytes, label=self.parser)
            if text is None:
                continue

            try:
                if not self.accept_file(path, text):
                    continue
                parsed[rel] = self.parse_file(path, text)
            except Exception as ex:
                logger.warning(f"Failed to parse {self.parser} file {rel}: {type(ex).__name__}: {ex}")

        return self.parse_report(parsed)
