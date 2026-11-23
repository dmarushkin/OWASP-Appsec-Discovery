import codecs
import re
from typing import List, Optional

from appsec_discovery.parsers.base_parser import Finding, ObjectCollector, SemgrepParser
from appsec_discovery.parsers.comments import trailing_comment

# the struct tag of a field line and its ``key:"value"`` pairs
STRUCT_TAG = re.compile(r'`([^`]*)`')
TAG_PAIR = re.compile(r'([\w.-]+):"((?:[^"\\]|\\.)*)"')
# swaggo tags with example values: ``enums`` is a comma separated list
SAMPLE_TAGS = ('example', 'enums', 'default')


def _code_part(source_line: str) -> str:
    """``source_line`` without a trailing ``// comment`` (a tag quoted in a comment is no tag)."""
    in_tag = in_string = False
    for i, char in enumerate(source_line):
        if char == '`' and not in_string:
            in_tag = not in_tag
        elif char == '"' and not in_tag and (i == 0 or source_line[i - 1] != '\\'):
            in_string = not in_string
        elif source_line.startswith('//', i) and not in_tag and not in_string:
            return source_line[:i]
    return source_line


def _unescape(value: str) -> str:
    try:
        return codecs.decode(value.encode('utf-8'), 'unicode_escape').encode('latin-1').decode('utf-8')
    except (UnicodeError, ValueError):
        return value


def struct_tag_samples(source_line: str) -> List[str]:
    """``example`` / ``enums`` / ``default`` values of the struct tag on ``source_line``."""
    match = STRUCT_TAG.search(_code_part(source_line or ''))
    if not match:
        return []
    tags = {}
    for key, value in TAG_PAIR.findall(match.group(1)):
        tags.setdefault(key, _unescape(value))
    samples: List[str] = []
    for key in SAMPLE_TAGS:
        value = tags.get(key)
        if not value:
            continue
        if key == 'enums':
            samples.extend(item.strip() for item in value.split(','))
        else:
            samples.append(value)
    return samples


# strings, raw strings / struct tags and rune literals: their braces are no code
_LITERAL = re.compile(r'`[^`]*`|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')
_FIRST_NAME = re.compile(r'^\s*(\w+)')


def _braces(source_line: str) -> str:
    """The ``{`` / ``}`` of the code of ``source_line`` (not in a comment, string or tag)."""
    code = _LITERAL.sub('', _code_part(source_line)).split('/*', 1)[0]
    return ''.join(char for char in code if char in '{}')


def nested_path(lines: List[str], object_line: int, field_line: int) -> Optional[List[str]]:
    """Names of the anonymous structs between the struct declared at ``object_line`` and the
    field at ``field_line`` (``Billing struct { CardPan string }`` -> ``['Billing']``, [] for a
    field of the struct itself); None when the field is not inside that struct."""
    stack: List[str] = []
    for index in range(object_line - 1, field_line - 1):
        name = _FIRST_NAME.match(lines[index])
        for brace in _braces(lines[index]):
            if brace == '{':
                stack.append(name.group(1) if name else '')
            elif stack:
                stack.pop()
                if not stack:
                    return None         # the struct is closed before the field
    if not stack:
        return None
    return stack[1:]


def in_nested_struct(lines: List[str], object_line: int) -> bool:
    """True when the ``Name struct {`` at ``object_line`` of a ``type ( ... )`` group is the
    anonymous struct of a field, not a type of the group."""
    if re.match(r'^\s*type\b', lines[object_line - 1]):
        return False
    depth = 0
    for index in range(object_line - 2, -1, -1):
        for brace in reversed(_braces(lines[index])):
            depth += 1 if brace == '}' else -1
        if depth < 0:
            return True                 # an unclosed ``{`` above: inside another struct
        if re.match(r'^\s*type\s*\(', lines[index]):
            return False
    return False


class GolangParser(SemgrepParser):

    name = 'golang'
    handlers = {'dto': 'handle_dto'}
    # the semgrep rules run on *.go only (``paths.include`` of scanner_rules/dto.yaml); comments are read from them
    file_patterns = ('*.go',)

    def handle_dto(self, finding: Finding, collector: ObjectCollector) -> None:
        field_name = finding.mv('$FIELD', strip_quotes=False)
        field_type = finding.mv('$TYPE', strip_quotes=False)
        names = self._declared_names(finding, field_name, field_type)
        if names is None:
            return          # ``$FIELD $TYPE`` inside a line that does not declare fields (func params, chan...)
        path = self._nested_path(finding)
        if path is None:
            return          # an anonymous struct of a field matched as a type, or a field outside $OBJECT
        prefix = ''.join(f'{part}.' for part in path)
        for name in names:
            name = prefix + name
            self.collect_dto(finding, collector, object_name=finding.mv('$OBJECT', strip_quotes=False),
                             field_name=name, field_type=field_type)

    def _nested_path(self, finding: Finding) -> Optional[List[str]]:
        """Path of the anonymous structs holding the field (``[]`` for a field of ``$OBJECT``
        itself, also when the source is not readable); None when the match is to be skipped."""
        lines = self.source_lines(finding.path)
        object_line = finding.mv_line('$OBJECT')
        field_line = finding.mv_line('$FIELD') or finding.line
        if not lines or not object_line or not field_line or not 1 <= object_line <= field_line <= len(lines):
            return []
        object_name = finding.mv('$OBJECT', strip_quotes=False)
        field_name = finding.mv('$FIELD', strip_quotes=False)
        if not re.search(rf'\b{re.escape(object_name)}\b', lines[object_line - 1]) or \
                not re.search(rf'\b{re.escape(field_name)}\b', lines[field_line - 1]):
            return []           # the lines are not the ones semgrep saw (source changed): trust the match
        if in_nested_struct(lines, object_line):
            return None
        if object_line == field_line:
            return []           # one-line struct
        return nested_path(lines, object_line, field_line)

    def _declared_names(self, finding: Finding, field_name: str, field_type: str) -> Optional[List[str]]:
        """The names a field line declares (``A, B string`` -> [A, B]); None when ``$FIELD $TYPE``
        is not the start of the line (a match inside ``func(a string)``, ``chan int``, a type
        name in the middle of a line). The source is not readable: trust the match."""
        lines = self.source_lines(finding.path)
        line = finding.mv_line('$FIELD') or finding.line
        if not lines or not line or not 1 <= line <= len(lines):
            return [field_name]
        text = lines[line - 1]
        if line == finding.mv_line('$OBJECT'):          # one-line struct: type T struct{ a, b string }
            text = text.split('{', 1)[-1]
            text = text.split(';')[-1] if f'{field_name} {field_type}' in text.split(';')[-1] else text
        if not re.search(rf'\b{re.escape(field_name)}\b', text):
            return [field_name]         # the line is not the one semgrep saw (source changed): trust it
        match = re.match(rf'^\s*((?:\w+\s*,\s*)*){re.escape(field_name)}\s+\*?{re.escape(field_type)}\b', text)
        if not match:
            return None
        return [n.strip() for n in match.group(1).split(',') if n.strip()] + [field_name]

    def field_comment(self, finding: Finding, line: Optional[int]) -> Optional[str]:
        # a field on the line of its struct (``type T struct{ a string }``): only a trailing comment
        if line and line == finding.mv_line('$OBJECT'):
            lines = self.source_lines(finding.path)
            return trailing_comment(lines[line - 1]) if 1 <= line <= len(lines) else None
        return super().field_comment(finding, line)

    def field_samples(self, finding: Finding, line: Optional[int]) -> Optional[List[str]]:
        lines = self.source_lines(finding.path)
        if not line or not 1 <= line <= len(lines):
            return None
        return struct_tag_samples(lines[line - 1]) or None
