import ast
import inspect
import re
import textwrap
from typing import List, Optional, Sequence

from appsec_discovery.parsers.base_parser import Finding, ObjectCollector, SemgrepParser

# a line that starts a string literal (docstring candidate)
STRING_START = re.compile(r'''^[rRuU]?("""|\'\'\'|"|')''')
# lines looked at for a multi-line statement / docstring
MAX_STATEMENT_LINES = 30
# keyword arguments with example values: ``Field(..., example=1)``, ``examples=[...]``, ``default=...``
SAMPLE_KEYWORDS = ('example', 'examples', 'default')


def _literal(node: ast.AST):
    """The value of a literal string / number node (or a list/tuple/set of them); None otherwise."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float)) \
            and not isinstance(node.value, bool):
        return [node.value]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) and isinstance(node.operand, ast.Constant) \
            and isinstance(node.operand.value, (int, float)) and not isinstance(node.operand.value, bool):
        return [-node.operand.value]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values = []
        for item in node.elts:
            values.extend(_literal(item) or [])
        return values or None
    return None


def parse_statement(lines: Sequence[str], index: int):
    """``(ast statement, index of its last line)`` of the statement starting at ``lines[index]``
    (0-based), joining continuation lines; ``(None, index)`` when it does not parse."""
    for end in range(index, min(len(lines), index + MAX_STATEMENT_LINES)):
        chunk = textwrap.dedent('\n'.join(lines[index:end + 1]))
        try:
            tree = ast.parse(chunk)
        except (SyntaxError, ValueError):
            continue
        if tree.body:
            return tree.body[0], end
    return None, index


def string_literal_at(lines: Sequence[str], index: int, skip_blank: bool = False) -> Optional[str]:
    """The string literal statement (docstring) starting at ``lines[index]`` (0-based); None otherwise."""
    while skip_blank and 0 <= index < len(lines) and not lines[index].strip():
        index += 1
    if not 0 <= index < len(lines) or not STRING_START.match(lines[index].strip()):
        return None
    node, _ = parse_statement(lines, index)
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
        return inspect.cleandoc(node.value.value)
    return None


def docstring_after_header(lines: Sequence[str], line: int) -> Optional[str]:
    """Docstring of the ``class`` / ``def`` whose header starts at ``line`` (1-based)."""
    index = line - 1
    for end in range(index, min(len(lines), index + MAX_STATEMENT_LINES)):
        code = lines[end].split('#', 1)[0].rstrip()
        if code.endswith(':'):
            return string_literal_at(lines, end + 1, skip_blank=True)
    return None


def field_samples_from_source(lines: Sequence[str], line: int) -> List[str]:
    """Literal ``example`` / ``examples`` / ``default`` values of the field statement at ``line``
    (1-based), plus a literal default of an annotated field (``x: int = 5``). Nothing is executed."""
    node, _ = parse_statement(lines, line - 1)
    if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
        return []
    value = node.value
    samples: List = []
    if isinstance(value, ast.Call):
        keywords = {kw.arg: kw.value for kw in value.keywords if kw.arg}
        for name in SAMPLE_KEYWORDS:
            if name in keywords:
                samples.extend(_literal(keywords[name]) or [])
        # pydantic ``Field("x")`` / ``Field(default="x")``: the first positional argument is the default
        if not samples and value.args and isinstance(value.func, (ast.Name, ast.Attribute)) \
                and (getattr(value.func, 'id', None) or getattr(value.func, 'attr', None)) == 'Field':
            samples.extend(_literal(value.args[0]) or [])
    elif isinstance(node, ast.AnnAssign):
        samples.extend(_literal(value) or [])
    return samples


def enclosing_class_line(lines: Sequence[str], line: Optional[int]) -> Optional[int]:
    """Line (1-based) of the innermost ``class`` statement whose body holds the statement at
    ``line``; None when it is not inside a class or the source is not readable."""
    if not line or not 1 <= line <= len(lines):
        return None
    text = lines[line - 1]
    indent = len(text) - len(text.lstrip())
    for index in range(line - 2, -1, -1):
        text = lines[index]
        stripped = text.strip()
        if not stripped or stripped.startswith('#'):
            continue
        text_indent = len(text) - len(text.lstrip())
        if text_indent >= indent:
            continue
        if re.match(r'^\s*class\s', text):
            return index + 1
        if re.match(r'^\s*(async\s+)?def\s', text):
            return None         # a local of a function, not a class body
        indent = text_indent    # ``if TYPE_CHECKING:`` and co. inside the class body
        if indent == 0:
            return None
    return None


class PythonParser(SemgrepParser):

    name = 'python'
    handlers = {'dto': 'handle_dto', 'route': 'handle_route'}
    # the semgrep rules (language python) target *.py and *.pyi; docstrings are read from the same files
    file_patterns = ('*.py', '*.pyi')

    def handle_dto(self, finding: Finding, collector: ObjectCollector) -> None:
        object_line = self._class_line(finding)
        field_line = finding.mv_line('$FIELD') or finding.line
        owner = enclosing_class_line(self.source_lines(finding.path), field_line)
        if owner is not None and object_line is not None and owner != object_line:
            return      # a field of a class nested in $OBJECT belongs to the nested class only
        self.collect_dto(finding, collector,
                         object_name=finding.mv('$OBJECT', strip_quotes=False),
                         field_name=finding.mv('$FIELD', strip_quotes=False),
                         field_type=finding.mv('$TYPE', strip_quotes=False),
                         # the field's own line (a dataclass match starts at its decorator)
                         line=finding.mv_line('$FIELD') or finding.line,
                         field_line=finding.mv_line('$FIELD') or finding.line,
                         object_line=object_line)

    def handle_route(self, finding: Finding, collector: ObjectCollector) -> None:
        framework = finding.framework.title()
        path = finding.mv('$PATH')
        func = finding.mv('$FUNC')
        method = finding.mv('$METHOD')

        # one object per HTTP method; identity is "METHOD path" (or just the path)
        if method:
            logical_name = f"{method.upper()} {path}"
            object_name = f"{method.upper()} {path} ({func})"
        else:
            logical_name = path
            object_name = f"{path} ({func})"

        properties = {'framework': framework, 'func': func, 'path': path}
        if method:
            properties['method'] = method

        is_new = collector.get('route', logical_name, finding.path) is None
        obj = collector.get_or_create(object_type='route', logical_name=logical_name, file=finding.path,
                                      object_name=object_name, line=finding.mv_line('$PATH') or finding.line,
                                      properties=properties)
        if is_new:
            self.set_comment(obj, self._safe(self.route_comment, finding, finding.mv_line('$PATH')))

    # -- comments and samples -------------------------------------------------------

    def _class_line(self, finding: Finding) -> Optional[int]:
        """Line of the ``class`` statement of the DTO: ``$OBJECT`` may be bound to the class
        name or to a ``__tablename__`` value inside the class body."""
        line = finding.mv_line('$OBJECT') or finding.line
        lines = self.source_lines(finding.path)
        if not line or not 1 <= line <= len(lines):
            return line
        indent = len(lines[line - 1]) - len(lines[line - 1].lstrip())
        for index in range(line - 1, -1, -1):
            text = lines[index]
            if not text.strip():
                continue
            text_indent = len(text) - len(text.lstrip())
            if re.match(r'^\s*class\s', text) and (index == line - 1 or text_indent < indent):
                return index + 1
            if index != line - 1 and text_indent < indent and not text.lstrip().startswith(('@', '#')):
                break
        return line

    def _def_line(self, finding: Finding) -> Optional[int]:
        """Line of the handler ``def`` when ``$FUNC`` is bound to a function definition."""
        line = finding.mv_line('$FUNC')
        lines = self.source_lines(finding.path)
        if line and 1 <= line <= len(lines) and re.match(r'^\s*(async\s+)?def\s', lines[line - 1]):
            return line
        return None

    def route_comment(self, finding: Finding, line: Optional[int]) -> Optional[str]:
        """Comment above the route (decorator / ``path(...)`` entry), above the decorated
        ``def``, else the handler docstring."""
        comment = self.comment_at(finding.path, line)
        def_line = self._def_line(finding)
        if comment or not def_line:
            return comment
        return self.comment_at(finding.path, def_line) or \
            docstring_after_header(self.source_lines(finding.path), def_line)

    def object_comment(self, finding: Finding, line: Optional[int]) -> Optional[str]:
        """Comment above the class, else its docstring."""
        comment = self.comment_at(finding.path, line)
        if comment or not line:
            return comment
        return docstring_after_header(self.source_lines(finding.path), line)

    def field_comment(self, finding: Finding, line: Optional[int]) -> Optional[str]:
        """Comment above / after the field, else an attribute docstring right after the statement."""
        comment = self.comment_at(finding.path, line)
        lines = self.source_lines(finding.path)
        if comment or not line or not 1 <= line <= len(lines):
            return comment
        _, end = parse_statement(lines, line - 1)
        return string_literal_at(lines, end + 1)

    def field_samples(self, finding: Finding, line: Optional[int]) -> Optional[List[str]]:
        lines = self.source_lines(finding.path)
        if not line or not 1 <= line <= len(lines):
            return None
        return field_samples_from_source(lines, line) or None
