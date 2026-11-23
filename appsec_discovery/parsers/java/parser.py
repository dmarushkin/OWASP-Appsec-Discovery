"""Java data classes: JPA entities and DTOs (records, Lombok, Jackson / Gson, swagger models).

Two sources feed one set of objects:

* the semgrep rule ``scanner_rules/dto.yaml`` (kept for compatibility): classes with
  ``@Table(name = ...)`` and their ``@Column(name = ...)`` fields / getters. These are the
  "legacy" objects: ``object_type`` ``dto``, ``object_name`` ``<Class>`` (formerly ``Javax dto <Class>``), identity
  from the simple class name, field names = column names, line = the first column. The rule is
  cheap: semgrep only parses the files that mention ``Table`` and ``Column``.
* ``JavaSource``, a native structural scanner (see ``source.py``), for everything else. A rule
  that matches records or the fields of any class cannot be prefiltered (semgrep then parses
  every Java file: 20-40 s on a large service against ~1 s here), loses nested classes (a match
  in ``Outer.Inner`` is reported once, for ``Outer``) and flattens types (``Map<String
  List<Long>>``). The scanner also gives the comments and annotations of each member.

Object kinds (the first that applies):

* legacy ``dto``: a class with ``@Table(name = ...)`` / ``@javax.persistence.Table(name = ...)``
  (not ``protected``; the forms the semgrep rule matches), also when semgrep reported no column
  of it, so the identity does not depend on how its columns are annotated;
* ``entity`` ``<Outer.Inner>``: ``@Entity`` / ``@Table`` / ``@MappedSuperclass`` /
  ``@Embeddable`` (javax, jakarta, Spring Data...) or JDBI rows (``@ColumnName`` members). Fields
  are the persistent members (JPA rules: instance fields that are not ``static`` / ``transient`` /
  ``@Transient`` / to-many relations, or the getters with property access) named by the column:
  ``@Column(name)`` / ``@Column("x")`` / ``@JoinColumn(name)`` / ``@ColumnName("x")``, else the
  field / property name;
* ``dto`` ``<Outer.Inner>``: records (framework ``record``), Lombok ``@Data`` /
  ``@Value`` / ``@Builder`` / ``@Getter`` / ``@Setter`` classes, Jackson (``@JsonNaming``... on the
  class, ``@JsonProperty``... on a field / getter / constructor parameter, ``@JsonCreator``), Gson ``@SerializedName``, swagger ``@Schema`` /
  ``@ApiModel`` models. Fields are the record components / instance fields named by the Java
  name (like the golang and python parsers; a ``@JsonProperty`` / ``@JsonNaming`` wire name is a
  serialisation detail and would make names depend on naming strategies).

New kinds are named and keyed by the nested name (``Outer.Inner``), their line is the line of
the class name and a field line is the line of the field name. Test sources (``src/test``...,
``*Test.java``) and generated / build output (``build``, ``target``, ``*generated*``) are skipped.

Comments: the comment block right above the declaration (above its annotations), comments
between the annotations and the trailing comment on the line the declaration ends (``;``), for
a class the one after ``{``; a record component without a comment takes the record's javadoc
``@param``. Samples: ``example`` / ``examples`` / ``defaultValue`` / ``allowableValues`` of the
annotations (Java escapes resolved) and a string / number literal initializer of a field.
"""
import logging
import os
import re
from typing import Dict, List, Optional, Tuple

from appsec_discovery.parsers.base_parser import Finding, ObjectCollector, SemgrepParser
from appsec_discovery.parsers.comments import DECLARATION_END, leading_comment, trailing_comment
from appsec_discovery.parsers.common import DEFAULT_PRUNE_DIRS
from appsec_discovery.parsers.java.source import JavaSource, Member, TypeDecl, unescape_java

logger = logging.getLogger(__name__)

STRING = r'"((?:[^"\\]|\\.)*)"'
# ``@Schema(example = "...")`` / ``@ApiModelProperty(example = "...")`` / ``defaultValue = "..."``
EXAMPLE = re.compile(r'\b(?:example|defaultValue)\s*=\s*' + STRING)
# ``allowableValues = "a,b"`` (swagger 2 annotations) or ``allowableValues = {"a", "b"}`` (OpenAPI 3 @Schema)
ALLOWABLE_ONE = re.compile(r'\ballowableValues\s*=\s*' + STRING)
ALLOWABLE_LIST = re.compile(r'\b(?:allowableValues|examples)\s*=\s*\{([^}]*)\}')
EXAMPLES_ONE = re.compile(r'\bexamples\s*=\s*' + STRING)
STRING_LITERAL = re.compile(STRING)
# swagger 2 ``allowableValues = "range[1, 5]"`` is a range, not values
RANGE = re.compile(r'^range[\[(]', re.IGNORECASE)
STRING_INIT = re.compile(r'^' + STRING + r'$', re.S)
NUMBER_INIT = re.compile(r'^[-+]?(?:0[xX][0-9a-fA-F_]+[lL]?|(?:\d[\d_]*\.?[\d_]*|\.\d[\d_]*)(?:[eE][-+]?\d+)?[lLfFdD]?)$')
NAME_ELEMENT = re.compile(r'\bname\s*=\s*(?=")')
VALUE_ONLY = re.compile(r'^\s*(?:value\s*=\s*)?' + STRING + r'\s*$', re.S)
GETTER = re.compile(r'^(?:get|is)([A-Z_$][\w$]*)$')

# directories that are not production sources: build output, generated code, tests
BUILD_DIRS = frozenset({'build', 'target', '.gradle', '.mvn', '.idea', '.git'})
TEST_DIRS = frozenset({'test', 'tests', 'testFixtures', 'integrationTest', 'integration-test', 'intTest',
                       'testIntegration', 'jmh'})
TEST_FILE = re.compile(r'(?:Test|Tests|TestCase|IT|ITCase)\.java$')
# a file without any of these cannot declare an object (cheap prefilter before scanning)
MARKERS = re.compile(r'\brecord\b|@\s*(?:[\w$]+\s*\.\s*)*(?:Entity|Table|MappedSuperclass|Embeddable|Data|Value|Builder|'
                     r'SuperBuilder|Getter|Setter|Json\w+|SerializedName|ColumnName|Schema|ApiModel\w*)\b')

LEGACY_TABLE = frozenset({'Table', 'javax.persistence.Table'})
ENTITY_CLASS = frozenset({'Entity', 'Table', 'MappedSuperclass', 'Embeddable'})
COLUMN = frozenset({'Column', 'JoinColumn', 'ColumnName'})
ID = frozenset({'Id', 'EmbeddedId'})
JPA_MAPPING = ID | COLUMN | frozenset({'Basic', 'ManyToOne', 'OneToOne', 'Enumerated', 'Lob', 'Temporal', 'Version',
                                       'GeneratedValue', 'Embedded', 'Convert', 'Type', 'JdbcTypeCode'})
NOT_PERSISTED = frozenset({'Transient', 'OneToMany', 'ManyToMany', 'ElementCollection'})
LOMBOK_CLASS = frozenset({'Data', 'Value', 'Builder', 'SuperBuilder', 'Getter', 'Setter', 'Jacksonized'})
JACKSON_CLASS = frozenset({'JsonNaming', 'JsonInclude', 'JsonIgnoreProperties', 'JsonPropertyOrder', 'JsonTypeName',
                           'JsonRootName', 'JsonTypeInfo', 'JsonAutoDetect', 'JsonSerialize', 'JsonDeserialize'})
JACKSON_MEMBER = frozenset({'JsonProperty', 'JsonAlias', 'JsonFormat', 'JsonUnwrapped', 'JsonInclude'})
JACKSON_METHOD = frozenset({'JsonCreator', 'JsonProperty', 'JsonGetter', 'JsonSetter'})
JACKSON_PARAM = re.compile(r'@\s*(?:[\w$]+\s*\.\s*)*JsonProperty\b')
GSON_MEMBER = frozenset({'SerializedName', 'Expose'})
SWAGGER_CLASS = frozenset({'Schema', 'ApiModel'})
SWAGGER_MEMBER = frozenset({'Schema', 'ApiModelProperty'})
JDBI_MEMBER = frozenset({'ColumnName'})
ENTITY_FRAMEWORKS = (('jakarta.persistence', 'jakarta'), ('javax.persistence', 'javax'),
                     ('org.springframework.data', 'spring-data'), ('org.hibernate', 'hibernate'))


def annotation_samples(text: str) -> List[str]:
    """Literal example / allowed / default values from the annotations in ``text`` (the literal
    contents as written: escapes are resolved by the caller with ``unescape_java``)."""
    samples: List[str] = []
    for value in EXAMPLE.findall(text):
        samples.append(value)
    for value in EXAMPLES_ONE.findall(text):
        samples.append(value)
    for value in ALLOWABLE_ONE.findall(text):
        if not RANGE.match(value.strip()):
            samples.extend(item.strip() for item in value.split(','))
    for group in ALLOWABLE_LIST.findall(text):
        samples.extend(STRING_LITERAL.findall(group))
    return samples


def literal_default(init: Optional[str]) -> Optional[str]:
    """The value of a string / number literal initializer; None for anything else."""
    if not init:
        return None
    init = init.strip()
    found = STRING_INIT.match(init)
    if found and not init.startswith('"""'):
        return unescape_java(found.group(1))
    if NUMBER_INIT.match(init):
        if init[:2].lower() == '0x':
            return init.rstrip('lL')
        return init.rstrip('lLfFdD').replace('_', '')
    return None


def member_samples(member: Member) -> Optional[List[str]]:
    samples: List[str] = []
    for annotation in member.annotations:
        if annotation.args:
            samples.extend(unescape_java(value) for value in annotation_samples(annotation.text))
    default = literal_default(member.init)
    if default is not None:
        samples.append(default)
    return samples or None


def _excluded_dir(parts: List[str], index: int) -> bool:
    """``parts[index]`` is a build output / generated / test directory. ``build`` / ``target`` /
    ``test``... count as module directories (before ``src``) or right under ``src`` (``src/test``),
    not as Java packages (``src/main/java/x/target``)."""
    part = parts[index]
    if 'generated' in part.lower():
        return True
    in_sources = 'src' in parts[:index]
    if part in BUILD_DIRS:
        return not in_sources
    if part in TEST_DIRS:
        return not in_sources or (index > 0 and parts[index - 1] == 'src')
    return False


def is_excluded_path(rel: str) -> bool:
    """Test sources, build output and generated code (``rel``: ``/sub/File.java``)."""
    parts = rel.strip('/').split('/')
    if any(_excluded_dir(parts, i) for i in range(len(parts) - 1)):
        return True
    return bool(TEST_FILE.search(parts[-1]))


def _literal(args: Optional[str], element: bool = True) -> Optional[str]:
    """``name = "x"`` (or a lone ``"x"`` / ``value = "x"``) of annotation arguments."""
    if not args:
        return None
    found = NAME_ELEMENT.search(args)
    if found:
        value = STRING_LITERAL.match(args, found.end())
        return unescape_java(value.group(1)) if value else None
    found = VALUE_ONLY.match(args)
    return unescape_java(found.group(1)) if found and element else None


def column_name(member: Member) -> Optional[str]:
    for annotation in member.annotated(COLUMN):
        name = _literal(annotation.args)
        if name:
            return name
    return None


def property_name(getter: str) -> str:
    """JavaBeans property of ``getFoo`` / ``isFoo`` (``getURL`` -> ``URL``)."""
    found = GETTER.match(getter)
    if not found:
        return getter
    name = found.group(1)
    if len(name) > 1 and name[0].isupper() and name[1].isupper():
        return name
    return name[0].lower() + name[1:]


def _getters(decl: TypeDecl) -> List[Member]:
    return [m for m in decl.methods if m.kind == 'method' and not m.params and GETTER.match(m.name)
            and m.type != 'void' and 'static' not in m.modifiers]


def _jackson_methods(decl: TypeDecl) -> bool:
    """``@JsonCreator`` constructors / factories, ``@JsonProperty`` parameters or accessors."""
    return any(m.annotated(JACKSON_METHOD) or JACKSON_PARAM.search(m.params) for m in decl.methods)


def _property_access(decl: TypeDecl, fields: List[Member], getters: List[Member]) -> bool:
    for annotation in decl.annotated({'Access'}):
        if annotation.args and 'PROPERTY' in annotation.args:
            return True
        if annotation.args and 'FIELD' in annotation.args:
            return False
    if any(g.annotated(ID) for g in getters):
        return True
    if any(f.annotated(ID) for f in fields):
        return False
    return not any(f.annotated(JPA_MAPPING) for f in fields) and any(g.annotated(JPA_MAPPING) for g in getters)


def entity_members(decl: TypeDecl) -> List[Tuple[str, Member]]:
    """``(column name, member)`` of the persistent members of an entity / JDBI row."""
    if decl.kind == 'record':
        members = list(decl.components)
    else:
        fields = [f for f in decl.fields if 'static' not in f.modifiers]
        getters = _getters(decl)
        if _property_access(decl, fields, getters):
            persistent = getters
        else:
            persistent = [f for f in fields if 'transient' not in f.modifiers]
        persistent = [m for m in persistent if not m.annotated(NOT_PERSISTED)]
        # members of the other access type that are mapped explicitly
        explicit = [m for m in fields + getters if m.annotated(COLUMN) and m not in persistent]
        members = sorted(persistent + explicit, key=lambda m: m.start)
    result = []
    for member in members:
        name = column_name(member) or (property_name(member.name) if member.kind == 'method' else member.name)
        result.append((name, member))
    return result


def dto_members(decl: TypeDecl) -> List[Tuple[str, Member]]:
    if decl.kind == 'record':
        return [(m.name, m) for m in decl.components]
    return [(m.name, m) for m in decl.fields if 'static' not in m.modifiers]


def is_legacy(decl: TypeDecl) -> bool:
    """A class the semgrep rule reports: ``@Table(name = ...)`` / ``@javax.persistence.Table(name = ...)``."""
    if decl.kind != 'class' or 'protected' in decl.modifiers:
        return False
    return any(a.name in LEGACY_TABLE and a.args and re.search(r'\bname\s*=', a.args) for a in decl.annotations)


def classify(decl: TypeDecl, source: JavaSource) -> Tuple[Optional[str], str]:
    """``(object_type, framework)`` of a declaration; ``(None, '')`` when it is not a data class."""
    if decl.kind not in ('class', 'record'):
        return None, ''
    names = {a.simple for a in decl.annotations}
    member_names = {a.simple for m in decl.fields + decl.components for a in m.annotations}
    entity = decl.annotated(ENTITY_CLASS)
    if entity:
        return 'entity', entity_framework(entity[0].name, source)
    if member_names & JDBI_MEMBER:
        return 'entity', 'jdbi'
    if decl.kind == 'record':
        return 'dto', 'record'
    if names & LOMBOK_CLASS:
        return 'dto', 'lombok'
    if names & JACKSON_CLASS or member_names & JACKSON_MEMBER or _jackson_methods(decl):
        return 'dto', 'jackson'
    if member_names & GSON_MEMBER:
        return 'dto', 'gson'
    if names & SWAGGER_CLASS or member_names & SWAGGER_MEMBER:
        return 'dto', 'swagger'
    return None, ''


def entity_framework(annotation: str, source: JavaSource) -> str:
    for prefix, framework in ENTITY_FRAMEWORKS:
        if annotation.startswith(prefix + '.'):
            return framework
    for prefix, framework in ENTITY_FRAMEWORKS:
        if any(imp.startswith(prefix + '.') for imp in source.imports):
            return framework
    return 'jpa'


class JavaParser(SemgrepParser):

    name = 'java'
    handlers = {'dto': 'handle_dto'}
    # the semgrep rules (language java) and ``java_files`` read *.java only
    file_patterns = ('*.java',)

    def parse_report(self, semgrep_data):
        self._java_cache: Dict[str, Optional[JavaSource]] = {}
        try:
            return super().parse_report(semgrep_data)
        finally:
            self._java_cache = {}

    # -- sources ----------------------------------------------------------------------

    def java_source(self, path: str) -> Optional[JavaSource]:
        """The scanned structure of ``path`` (``/sub/File.java``); None when unreadable."""
        cache = getattr(self, '_java_cache', None)
        if cache is None:
            cache = self._java_cache = {}
        if path not in cache:
            lines = self.source_lines(path)
            source = None
            if lines:
                try:
                    source = JavaSource('\n'.join(lines))
                except Exception as ex:  # never fail the scan on one odd file
                    logger.debug(f"java: cannot scan {path}: {ex}")
            cache[path] = source
        return cache[path]

    def java_files(self) -> List[str]:
        """Relative paths of the production ``.java`` files under the source folder."""
        found = []
        for current, dirs, files in os.walk(self.root):
            base = self.relpath(current).strip('/').split('/') if current != str(self.root) else []
            base = [part for part in base if part]
            dirs[:] = sorted(d for d in dirs
                             if d not in DEFAULT_PRUNE_DIRS and not _excluded_dir(base + [d], len(base)))
            for name in sorted(files):
                if name.endswith('.java'):
                    rel = self.relpath(os.path.join(current, name))
                    if not is_excluded_path(rel):
                        found.append(rel)
        return found

    def _member_at(self, finding: Finding, line: Optional[int]) -> Optional[Member]:
        source = self.java_source(finding.path)
        if source is None or not line:
            return None
        start, end = source.offset_of_line(line), source.offset_of_line(line + 1)
        decl = source.innermost_type(start)
        if decl is None:
            return None
        for member in decl.fields + decl.methods + decl.components:
            if member.start < end and member.end > start:
                return member
        return None

    # -- legacy objects (semgrep findings) ----------------------------------------------

    def handle_dto(self, finding: Finding, collector: ObjectCollector) -> None:
        if is_excluded_path(finding.path):
            return
        line = finding.mv_line('$DB_FIELD') or finding.line  # the @Column name
        source = self.java_source(finding.path)
        if source is not None:
            decl = source.innermost_type(source.offset_of_line(line))
            if decl is not None and decl.name != finding.mv('$OBJECT'):
                return  # a column of a nested class, reported for the outer class too
        db_table = finding.mv('$DB_NAME')
        self.collect_dto(finding, collector,
                         object_name=finding.mv('$OBJECT'),
                         field_name=finding.mv('$DB_FIELD'),
                         field_type=finding.mv('$TYPE'),
                         line=line,
                         properties={'db_table': db_table} if db_table else None,
                         field_line=finding.line)

    def object_comment(self, finding: Finding, line: Optional[int]) -> Optional[str]:
        source = self.java_source(finding.path)
        if source is not None:
            for decl in source.all_types:
                if decl.name == finding.mv('$OBJECT') and source.line_of(decl.name_pos) == line:
                    return decl.comment
        return super().object_comment(finding, line)

    def field_comment(self, finding: Finding, line: Optional[int]) -> Optional[str]:
        member = self._member_at(finding, finding.mv_line('$DB_FIELD') or line)
        if member is not None:
            return member.comment
        # no structure (unreadable source): the comment above the first annotation of the match
        # and the trailing one of the declaration line
        lines = self.source_lines(finding.path)
        if not line or not lines:
            return None
        end = (finding.raw.get('end') or {}).get('line') or line
        parts = [leading_comment(lines, line, trailing=False)]
        if 1 <= end <= len(lines):
            parts.append(trailing_comment(lines[end - 1]))
        return '\n'.join(p for p in parts if p) or None

    def field_samples(self, finding: Finding, line: Optional[int]) -> Optional[List[str]]:
        member = self._member_at(finding, finding.mv_line('$DB_FIELD') or line)
        if member is not None:
            return member_samples(member)
        lines = self.source_lines(finding.path)
        if not lines or not line:
            return None
        start = min(finding.line or line, line)
        # the annotations above the match; a line that ends a declaration is not one of them
        while start > 1 and lines[start - 2].strip().startswith('@') and not DECLARATION_END.search(lines[start - 2].strip()):
            start -= 1
        end = max((finding.raw.get('end') or {}).get('line') or line, line)
        samples = [unescape_java(v) for v in annotation_samples('\n'.join(lines[start - 1:end]))]
        return samples or None

    # -- objects from the scanner -------------------------------------------------------

    def collect_extra(self, collector: ObjectCollector) -> None:
        for rel in self.java_files():
            lines = self.source_lines(rel)
            if not lines or not any(MARKERS.search(text) for text in lines):
                continue
            source = self.java_source(rel)
            if source is None:
                continue
            for decl in source.all_types:
                try:
                    if is_legacy(decl):
                        self._collect_legacy(rel, source, decl, collector)
                    else:
                        self._collect_type(rel, source, decl, collector)
                except Exception as ex:  # one odd declaration must not fail the scan
                    logger.debug(f"java: {rel}:{decl.qualname} skipped: {ex}")

    @staticmethod
    def _comment(decl: TypeDecl, member: Member) -> Optional[str]:
        if member.comment:
            return member.comment
        return decl.param_docs.get(member.name) if member.kind == 'component' else None

    def _collect_legacy(self, rel: str, source: JavaSource, decl: TypeDecl, collector: ObjectCollector) -> None:
        """A ``@Table(name)`` class: the legacy object (created by the semgrep findings, or here
        with the same identity / name / line when semgrep reported none of its columns), plus
        the persistent members the rule does not match (``@Column`` without name, plain fields)."""
        members = entity_members(decl)
        if not members:
            return
        obj = collector.get('dto', decl.name, rel)
        if obj is None:
            table = next((_literal(a.args, element=False) or '' for a in decl.annotations if a.name in LEGACY_TABLE), '')
            props = {'framework': 'javax', 'object': decl.name}
            if table:
                props['db_table'] = table
            obj = collector.get_or_create(object_type='dto', logical_name=decl.name, file=rel,
                                          object_name=decl.name,
                                          line=self._legacy_line(source, members[0][1]), properties=props)
            self.set_comment(obj, decl.comment)
        for name, member in members:
            if name not in obj.fields:
                collector.add_field(obj, name, member.type, file=rel, line=self._legacy_line(source, member),
                                    comment=self._comment(decl, member), samples=member_samples(member))

    @staticmethod
    def _legacy_line(source: JavaSource, member: Member) -> int:
        """The line of the ``@Column`` name value (what the semgrep rule reports), else of the name."""
        for annotation in member.annotated({'Column'}):
            found = NAME_ELEMENT.search(annotation.args or '')
            if found:
                return source.line_of(annotation.args_start + found.end())
        return source.line_of(member.name_pos)

    def _collect_type(self, rel: str, source: JavaSource, decl: TypeDecl, collector: ObjectCollector) -> None:
        kind, framework = classify(decl, source)
        if kind is None:
            return
        members = entity_members(decl) if kind == 'entity' else dto_members(decl)
        if not members:
            return
        props = {'framework': framework, 'object': decl.qualname}
        if kind == 'entity':
            table = next((_literal(a.args) for a in decl.annotated({'Table'}) if _literal(a.args)), None)
            if table:
                props['db_table'] = table
        is_new = collector.get(kind, decl.qualname, rel) is None
        obj = collector.get_or_create(object_type=kind, logical_name=decl.qualname, file=rel,
                                      object_name=decl.qualname,
                                      line=source.line_of(decl.name_pos), properties=props)
        if is_new:
            self.set_comment(obj, decl.comment)
        for name, member in members:
            if name not in obj.fields:
                collector.add_field(obj, name, member.type, file=rel, line=source.line_of(member.name_pos),
                                    comment=self._comment(decl, member), samples=member_samples(member))
