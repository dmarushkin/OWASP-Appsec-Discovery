"""A light HCL (Terraform) scanner: blocks, attributes and their values, with line numbers.

Not a full HCL implementation: it tokenizes the file (strings with ``${...}`` interpolations,
heredocs, comments, numbers, identifiers, punctuation) and recovers the structure

    body      := (attribute | block)*
    attribute := IDENT "=" expression          (to the end of the line, brackets balanced)
    block     := IDENT (STRING | IDENT)* "{" body "}"

Expressions are kept as token lists and classified by ``classify``. Comments are not kept: the
parser reads them from the source lines (``comments.leading_comment``). A broken file never
raises: an unterminated string / comment / heredoc ends at the end of the line / file, an
unexpected token skips the line, and blocks still open at the end of the file are closed.
"""
import re
from dataclasses import dataclass, field
from typing import List, NamedTuple, Optional, Tuple, Union

__all__ = ["Token", "Attribute", "Block", "tokenize", "parse", "classify", "expression_text", "Value"]


class Token(NamedTuple):
    kind: str       # nl | str | istr | heredoc | num | ident | op
    value: str      # str: decoded text; istr: raw text between the quotes; heredoc: its content
    line: int


@dataclass
class Attribute:
    name: str
    line: int
    expr: List[Token]


@dataclass
class Block:
    type: str
    labels: List[str]
    line: int
    body: List[Union['Block', Attribute]] = field(default_factory=list)

    def attributes(self) -> List[Attribute]:
        return [item for item in self.body if isinstance(item, Attribute)]

    def blocks(self) -> List['Block']:
        return [item for item in self.body if isinstance(item, Block)]

    def attribute(self, name: str) -> Optional[Attribute]:
        for item in self.body:
            if isinstance(item, Attribute) and item.name == name:
                return item
        return None


TOKEN = re.compile(r'''
    (?P<ws>[ \t\r\f\v]+)
  | (?P<nl>\n)
  | (?P<lcomment>(?:\#|//)[^\n]*)
  | (?P<bcomment>/\*)
  | (?P<heredoc><<-?[ \t]*(?P<hid>[A-Za-z_][\w-]*)[ \t]*\r?\n)
  | (?P<string>")
  | (?P<num>\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)
  | (?P<ident>[A-Za-z_][\w-]*)
  | (?P<op>==|!=|<=|>=|&&|\|\||=>|\.\.\.|[{}\[\]()=,:?.!*/%+<>&|~-])
''', re.VERBOSE)

# the body of a quoted string up to its end, a newline or an interpolation
STRING_BODY = re.compile(r'(?:\$\$\{|%%\{|[^"\\\n$%]+|\\.|\$(?!\{)|%(?!\{))*')
ESCAPES = {'n': '\n', 't': '\t', 'r': '\r', '"': '"', '\\': '\\'}
ESCAPE = re.compile(r'\\(.)|\$\$\{|%%\{')


def _unescape(raw: str) -> str:
    def repl(match):
        if match.group(1) is not None:
            return ESCAPES.get(match.group(1), match.group(0))
        return match.group(0)[1:]
    return ESCAPE.sub(repl, raw) if ('\\' in raw or '{' in raw) else raw


def _scan_string(text: str, pos: int) -> Tuple[int, bool]:
    """End (after the closing quote) of the string whose body starts at ``pos`` and whether it has
    interpolations. An unterminated string ends at the end of the line."""
    n = len(text)
    interpolated = False
    while True:
        pos = STRING_BODY.match(text, pos).end()
        if pos >= n:
            return n, interpolated
        char = text[pos]
        if char == '"':
            return pos + 1, interpolated
        if char == '\n':
            return pos, interpolated
        if char in '$%' and text.startswith('{', pos + 1):
            interpolated = True
            pos = _scan_template(text, pos + 2)
            continue
        pos += 1        # a lone backslash at the end of the text


def _scan_template(text: str, pos: int) -> int:
    """Position after the ``}`` that closes the interpolation whose expression starts at ``pos``."""
    n, depth = len(text), 1
    while pos < n:
        char = text[pos]
        if char == '"':
            pos, _ = _scan_string(text, pos + 1)
            continue
        if char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                return pos + 1
        pos += 1
    return n


def tokenize(text: str) -> List[Token]:
    tokens: List[Token] = []
    append = tokens.append
    match = TOKEN.match
    pos, line, n = 0, 1, len(text)

    while pos < n:
        m = match(text, pos)
        if m is None:           # a character HCL does not know: skip it
            pos += 1
            continue
        kind = m.lastgroup
        if kind == 'hid':
            kind = 'heredoc'
        end = m.end()

        if kind == 'ws' or kind == 'lcomment':
            pos = end
        elif kind == 'nl':
            append(Token('nl', '\n', line))
            line += 1
            pos = end
        elif kind == 'bcomment':
            close = text.find('*/', end)
            close = n if close < 0 else close + 2
            line += text.count('\n', pos, close)
            pos = close
        elif kind == 'string':
            close, interpolated = _scan_string(text, end)
            terminated = close > end and text[close - 1] == '"'
            body_end = close - 1 if terminated else close
            raw = text[end:body_end]
            if interpolated:
                append(Token('istr', raw, line))
                line += raw.count('\n')
            else:
                append(Token('str', _unescape(raw), line))
            pos = close
        elif kind == 'heredoc':
            marker = re.compile(r'^[ \t]*' + re.escape(m.group('hid')) + r'[ \t]*\r?$', re.MULTILINE)
            found = marker.search(text, end)
            body = text[end:found.start()] if found else text[end:]
            append(Token('heredoc', body, line))
            close = found.end() if found else n
            line += text.count('\n', pos, close)
            pos = close
        else:
            append(Token(kind, m.group(kind), line))
            pos = end

    return tokens


OPEN = {'(', '[', '{'}
CLOSE = {')', ']', '}'}


def _expression_end(tokens: List[Token], i: int) -> int:
    """Index after the expression starting at ``i``: the end of its line (brackets balanced) or
    the ``}`` that closes the enclosing block."""
    depth, n = 0, len(tokens)
    while i < n:
        token = tokens[i]
        kind = token.kind
        if kind == 'nl':
            if depth == 0:
                break
        elif kind == 'op':
            value = token.value
            if value in OPEN:
                depth += 1
            elif value in CLOSE:
                if depth == 0:
                    break
                depth -= 1
        i += 1
    return i


def _skip_line(tokens: List[Token], i: int) -> int:
    end = _expression_end(tokens, i)
    return end + 1 if end == i else end


def _parse_body(tokens: List[Token], i: int, nested: bool) -> Tuple[list, int]:
    items: list = []
    n = len(tokens)
    while i < n:
        token = tokens[i]
        if token.kind == 'nl':
            i += 1
            continue
        if token.kind == 'op' and token.value == '}':
            if nested:
                return items, i + 1
            i += 1              # a stray brace at the top level
            continue
        if token.kind == 'ident':
            j = i + 1
            if j < n and tokens[j].kind == 'op' and tokens[j].value == '=':
                end = _expression_end(tokens, j + 1)
                items.append(Attribute(token.value, token.line, tokens[j + 1:end]))
                i = end
                continue
            labels = []
            while j < n and tokens[j].kind in ('str', 'ident'):
                labels.append(tokens[j].value)
                j += 1
            if j < n and tokens[j].kind == 'op' and tokens[j].value == '{':
                body, i = _parse_body(tokens, j + 1, True)
                items.append(Block(token.value, labels, token.line, body))
                continue
        i = _skip_line(tokens, i)
    return items, i


def parse(text: str) -> List[Block]:
    """Top-level blocks of an HCL file (top-level attributes, e.g. of ``*.tfvars``, are dropped)."""
    items, _ = _parse_body(tokenize(text), 0, False)
    return [item for item in items if isinstance(item, Block)]


# -- values -------------------------------------------------------------------------------------

class Value(NamedTuple):
    kind: str                   # string | number | bool | list | map | reference | expression
    samples: List[str]          # literal values (a string, a number, the literal items of a list)
    literal: Optional[str]      # the raw text of a quoted string (no unescaping), else None


REFERENCE_ROOTS = {'var', 'local', 'module', 'data', 'path', 'terraform', 'each', 'count', 'self'}
TEMPLATE_REFERENCE = re.compile(r'^\$\{\s*([A-Za-z_][\w-]*(?:\.[\w*-]+|\[[^\]]*\])*)\s*\}$')


def _is_reference(tokens: List[Token], roots=frozenset()) -> bool:
    """``var.x``, ``local.y[0]``, ``module.m.out``, ``data.t.n.id``, ``aws_instance.web.id``..."""
    first = tokens[0]
    if first.kind != 'ident' or first.value in ('true', 'false', 'null'):
        return False
    depth, dotted = 0, False
    for token in tokens[1:]:
        if token.kind == 'op':
            if token.value == '[':
                depth += 1
            elif token.value == ']':
                depth -= 1
            elif token.value == '.':
                dotted = dotted or depth == 0
            elif not (token.value == '*' or depth > 0):
                return False
        elif depth == 0 and token.kind not in ('ident', 'num'):
            return False
        elif token.kind == 'heredoc':
            return False
    if depth:
        return False
    return first.value in REFERENCE_ROOTS and (dotted or first.value in ('each', 'count', 'self')) or \
        dotted and ('_' in first.value or first.value in roots)


def _template_reference(raw: str) -> bool:
    match = TEMPLATE_REFERENCE.match(raw)
    if not match:
        return False
    root = match.group(1).split('.')[0].split('[')[0]
    return root in REFERENCE_ROOTS or ('_' in root and '.' in match.group(1))


def _literal(tokens: List[Token]) -> Optional[str]:
    """The sample of a literal value (one string / number / bool token, ``-`` number)."""
    if len(tokens) == 1:
        token = tokens[0]
        if token.kind in ('str', 'num'):
            return token.value
        if token.kind == 'ident' and token.value in ('true', 'false'):
            return token.value
    elif len(tokens) == 2 and tokens[0].kind == 'op' and tokens[0].value == '-' and tokens[1].kind == 'num':
        return '-' + tokens[1].value
    return None


def _closes_at_end(tokens: List[Token], opening: str, closing: str) -> bool:
    depth = 0
    for index, token in enumerate(tokens):
        if token.kind != 'op':
            continue
        if token.value == opening:
            depth += 1
        elif token.value == closing:
            depth -= 1
            if depth == 0:
                return index == len(tokens) - 1
    return False


def _list_items(tokens: List[Token]) -> List[List[Token]]:
    items, current, depth = [], [], 0
    for token in tokens[1:-1]:
        if token.kind == 'nl':
            continue
        if token.kind == 'op':
            if token.value in OPEN:
                depth += 1
            elif token.value in CLOSE:
                depth -= 1
            elif token.value == ',' and depth == 0:
                items.append(current)
                current = []
                continue
        current.append(token)
    if current:
        items.append(current)
    return items


def classify(tokens: List[Token], roots=frozenset()) -> Value:
    """Kind and samples of a value; ``roots`` are extra reference roots (``dynamic`` iterators)."""
    tokens = [token for token in tokens if token.kind != 'nl']
    if not tokens:
        return Value('expression', [], None)
    first = tokens[0]

    if len(tokens) == 1:
        if first.kind == 'str':
            return Value('string', [first.value], first.value)
        if first.kind == 'istr':
            return Value('reference' if _template_reference(first.value) else 'expression', [], first.value)
        if first.kind == 'heredoc':
            return Value('string', [], None)
        if first.kind == 'num':
            return Value('number', [first.value], None)
        if first.kind == 'ident' and first.value in ('true', 'false'):
            return Value('bool', [first.value], None)

    literal = _literal(tokens)
    if literal is not None:
        return Value('number', [literal], None)

    if first.kind == 'op' and first.value in ('[', '{'):
        closing = ']' if first.value == '[' else '}'
        comprehension = len(tokens) > 1 and tokens[1].kind == 'ident' and tokens[1].value == 'for'
        if _closes_at_end(tokens, first.value, closing) and not comprehension:
            if first.value == '{':
                return Value('map', [], None)
            samples = [value for value in (_literal(item) for item in _list_items(tokens)) if value is not None]
            return Value('list', samples, None)
        return Value('expression', [], None)

    if _is_reference(tokens, roots):
        return Value('reference', [], None)
    return Value('expression', [], None)


def expression_text(tokens: List[Token], limit: int = 200) -> str:
    """Compact source-like text of an expression (for type constraints such as ``list(string)``)."""
    out: List[str] = []
    previous = None
    for token in tokens:
        if token.kind == 'nl':
            continue
        text = {'str': f'"{token.value}"', 'istr': f'"{token.value}"', 'heredoc': '<<EOT'}.get(token.kind, token.value)
        word = token.kind != 'op'
        if previous is not None and (word and previous != 'op' or token.kind == 'op' and token.value in ('=', '?', ':')):
            out.append(' ')
        out.append(text)
        if token.kind == 'op' and token.value in (',', '=', '?', ':'):
            out.append(' ')
        previous = 'op' if not word else token.kind
        if sum(map(len, out)) > limit:
            break
    return ''.join(out).strip()
