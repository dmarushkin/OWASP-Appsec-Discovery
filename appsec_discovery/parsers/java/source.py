"""A small structural scanner of Java sources (no external parser).

It finds the type declarations of a file (classes, records, interfaces, enums, annotation
types; nested ones included, local and anonymous classes in method bodies are not), their
annotations and modifiers, record components, fields and methods (headers only: bodies are
skipped), plus the comments around them. That is all the java parser needs, and it is much
faster than a semgrep rule that has to parse every Java file.

Approach: comments and string / char / text-block literals are blanked out first (offsets and
line breaks are kept), brackets are matched once, then class bodies are split into members at
top-level ``;`` / ``{...}``. Unparsable pieces are skipped, never raised.
"""
import bisect
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from appsec_discovery.parsers.comments import is_documentation, unwrap_comment

__all__ = ["Annotation", "Member", "TypeDecl", "JavaSource", "unescape_java", "normalize_type"]

LEXEME = re.compile(
    r'//[^\n]*'
    r'|/\*.*?(?:\*/|\Z)'
    r'|"""(?:[^\\]|\\.)*?(?:"""|\Z)'
    r'|"(?:[^"\\\n]|\\.)*"?'
    r"|'(?:[^'\\\n]|\\.)*'?", re.S)
BRACKETS = re.compile(r'[(){}\[\]]')
OPEN_FOR = {')': '(', '}': '{', ']': '['}
IDENT = r'[A-Za-z_$][\w$]*'
QNAME = re.compile(IDENT + r'(?:\s*\.\s*' + IDENT + r')*')
ANNOTATION = re.compile(r'@\s*(' + IDENT + r'(?:\s*\.\s*' + IDENT + r')*)')
AT_INTERFACE = re.compile(r'@\s*interface\b')
WORD = re.compile(r'non-sealed|' + IDENT)
WS = re.compile(r'\s*')
MODIFIERS = frozenset({'public', 'protected', 'private', 'static', 'final', 'transient', 'volatile', 'abstract',
                       'native', 'synchronized', 'strictfp', 'default', 'sealed', 'non-sealed'})
# the first token that decides what a member is
SIGNIFICANT = re.compile(r'[;{=(@}]')
TYPE_KEYWORD = re.compile(r'(?:(?<![\w$.@])(class|interface|enum|record)|@\s*(interface))\s+(' + IDENT + r')')
STATEMENT_END = re.compile(r'[;({\[}]')
GENERIC_OPEN = re.compile(r'\s*[A-Z?>@]')
DECLARATOR = re.compile(r'\s*(' + IDENT + r')\s*((?:\[\s*\]\s*)*)(?:=(.*))?\Z', re.S)
METHOD_NAME = re.compile(r'(' + IDENT + r')\s*\Z')
TYPE_ANNOTATION = re.compile(r'@\s*' + IDENT + r'(?:\s*\.\s*' + IDENT + r')*(?:\s*\([^()]*\))?\s*')
JAVADOC_PARAM = re.compile(r'^@param\s+(' + IDENT + r')\s*(.*?)(?=^@\w|\Z)', re.S | re.M)
# IDE / tool directives that are not documentation (``// language=JSON``, ``//noinspection x``...)
JAVA_DIRECTIVE = re.compile(r'^\s*(?:language\s*=|noinspection\b|@formatter:|CHECKSTYLE[:.]|NOSONAR\b|NOPMD\b|'
                            r'spotless:|\$NON-NLS)', re.IGNORECASE)
ESCAPE = re.compile(r'\\(u+[0-9a-fA-F]{4}|[0-3][0-7]{0,2}|[4-7][0-7]?|.)', re.S)
ESCAPES = {'n': '\n', 't': '\t', 'b': '\b', 'r': '\r', 'f': '\f', 's': ' ', '"': '"', "'": "'", '\\': '\\',
           '\n': ''}


def unescape_java(text: str) -> str:
    """The value of the content of a Java string literal (``\\"`` -> ``"``, ``\\u0041`` -> ``A``...)."""
    def repl(match):
        esc = match.group(1)
        if esc[0] == 'u':
            return chr(int(esc[-4:], 16))
        if esc[0] in '01234567':
            return chr(int(esc, 8))
        return ESCAPES.get(esc, esc)
    return ESCAPE.sub(repl, text) if '\\' in text else text


def normalize_type(text: str) -> str:
    """Declared type without type-use annotations and with canonical spacing: ``Map<String, List<Long>>``."""
    text = TYPE_ANNOTATION.sub('', text)
    text = ' '.join(text.split())
    text = re.sub(r'\s*([<>\[\].?&])\s*', r'\1', text)
    text = re.sub(r'\s*,\s*', ', ', text)
    text = re.sub(r'\b(extends|super)(?=[A-Z_$])', r'\1 ', text)
    return text.replace('?extends', '? extends').replace('?super', '? super')


@dataclass
class Annotation:
    name: str                    # as written, dots kept: ``javax.persistence.Column``
    args: Optional[str]          # text between the parentheses (comments blanked), None without them
    start: int                   # offset of ``@``
    args_start: int = -1         # offset of the text in ``args``

    @property
    def simple(self) -> str:
        return self.name.rsplit('.', 1)[-1]

    @property
    def text(self) -> str:
        return f'@{self.name}' + (f'({self.args})' if self.args is not None else '')


@dataclass
class Member:
    kind: str                    # field | component | method | constructor
    name: str
    type: str                    # declared (return) type, normalised
    annotations: List[Annotation]
    modifiers: List[str]
    start: int                   # first annotation / modifier / type
    name_pos: int
    end: int                     # after ``;`` (field), the component, the header (method)
    init: Optional[str] = None   # initializer of a field (comments blanked)
    params: str = ''             # method parameters
    comment: Optional[str] = None
    owner: Optional['TypeDecl'] = None

    def annotated(self, names) -> List[Annotation]:
        return [a for a in self.annotations if a.simple in names]


@dataclass
class TypeDecl:
    kind: str                    # class | interface | enum | record | annotation
    name: str
    qualname: str                # ``Outer.Inner``
    annotations: List[Annotation]
    modifiers: List[str]
    start: int
    name_pos: int
    body_open: int
    body_close: int
    parent: Optional['TypeDecl'] = None
    components: List[Member] = field(default_factory=list)
    fields: List[Member] = field(default_factory=list)
    methods: List[Member] = field(default_factory=list)
    types: List['TypeDecl'] = field(default_factory=list)
    comment: Optional[str] = None
    param_docs: Dict[str, str] = field(default_factory=dict)  # javadoc ``@param`` of a record

    def annotated(self, names) -> List[Annotation]:
        return [a for a in self.annotations if a.simple in names]


@dataclass
class _Comment:
    start: int
    end: int
    text: str


class JavaSource:
    """The parsed structure of one Java file; ``types`` are the top-level declarations,
    ``all_types`` every declaration (pre-order)."""

    def __init__(self, text: str):
        self.text = text
        self._mask()
        self._match_brackets()
        self._newlines = [i for i, ch in enumerate(text) if ch == '\n']
        self._comment_starts = [c.start for c in self.comments]
        self.imports = re.findall(r'^\s*import\s+(?:static\s+)?([\w.]+(?:\.\*)?)\s*;', self.masked, re.M)
        self.types: List[TypeDecl] = []
        self.all_types: List[TypeDecl] = []
        self._parse_members(0, len(text), None, self.types)

    # -- lexing ---------------------------------------------------------------------

    def _mask(self) -> None:
        """``masked``: comments and literal contents blanked; ``clean``: only comments blanked."""
        text = self.text
        masked, clean, pos = [], [], 0
        self.comments: List[_Comment] = []
        for match in LEXEME.finditer(text):
            start, end = match.span()
            masked.append(text[pos:start])
            clean.append(text[pos:start])
            token = match.group()
            blank = re.sub(r'[^\n]', ' ', token)
            if token[0] == '/':
                self.comments.append(_Comment(start, end, token))
                masked.append(blank)
                clean.append(blank)
            else:
                quote = 3 if token.startswith('"""') else 1
                closed = len(token) >= 2 * quote and token.endswith(token[:quote])
                masked.append(token[:quote] + (blank[quote:-quote] + token[-quote:] if closed else blank[quote:]))
                clean.append(token)
            pos = end
        masked.append(text[pos:])
        clean.append(text[pos:])
        self.masked = ''.join(masked)
        self.clean = ''.join(clean)

    def _match_brackets(self) -> None:
        self.match: Dict[int, int] = {}
        stack: List[Tuple[str, int]] = []
        for found in BRACKETS.finditer(self.masked):
            ch, pos = found.group(), found.start()
            if ch in '({[':
                stack.append((ch, pos))
                continue
            opener = OPEN_FOR[ch]
            # tolerate broken code: close the nearest opener of the same kind
            for depth in range(len(stack) - 1, -1, -1):
                if stack[depth][0] == opener:
                    for _, unclosed in stack[depth + 1:]:
                        self.match[unclosed] = pos
                    self.match[stack[depth][1]] = pos
                    del stack[depth:]
                    break
        for _, unclosed in stack:
            self.match[unclosed] = len(self.masked)

    def line_of(self, pos: int) -> int:
        return bisect.bisect_left(self._newlines, pos) + 1

    def _skip_ws(self, pos: int) -> int:
        return WS.match(self.masked, pos).end()

    def _close(self, pos: int) -> int:
        return self.match.get(pos, len(self.masked))

    def _find_top(self, pos: int, end: int, stops: str) -> int:
        """Offset of the first top-level character of ``stops`` in [pos, end) (bracket groups skipped)."""
        masked = self.masked
        while pos < end:
            found = STATEMENT_END.search(masked, pos, end)
            if found is None:
                return end
            ch, pos = found.group(), found.start()
            if ch in stops:
                return pos
            if ch == '}':
                return pos
            pos = self._close(pos) + 1
        return end

    # -- members --------------------------------------------------------------------

    def _prefix(self, pos: int, end: int) -> Tuple[List[Annotation], List[str], int]:
        """Annotations and modifiers from ``pos`` (in any order)."""
        masked = self.masked
        annotations: List[Annotation] = []
        modifiers: List[str] = []
        while True:
            pos = self._skip_ws(pos)
            if pos >= end:
                break
            if masked[pos] == '@':
                if AT_INTERFACE.match(masked, pos):
                    break
                found = ANNOTATION.match(masked, pos)
                if not found:
                    break
                name = re.sub(r'\s+', '', found.group(1))
                after = self._skip_ws(found.end())
                if after < end and masked[after] == '(':
                    close = self._close(after)
                    annotations.append(Annotation(name, self.clean[after + 1:close], pos, after + 1))
                    pos = close + 1
                else:
                    annotations.append(Annotation(name, None, pos))
                    pos = found.end()
                continue
            word = WORD.match(masked, pos)
            if word and word.group() in MODIFIERS:
                modifiers.append(word.group())
                pos = word.end()
                continue
            break
        return annotations, modifiers, pos

    def _parse_members(self, start: int, end: int, owner: Optional[TypeDecl], types: List[TypeDecl]) -> None:
        masked = self.masked
        pos = start
        floor = start
        while True:
            pos = self._skip_ws(pos)
            if pos >= end:
                break
            ch = masked[pos]
            if ch == ';':
                pos += 1
                floor = pos
                continue
            if ch == '}':           # stray closer (broken code)
                pos += 1
                floor = pos
                continue
            member_start = pos
            annotations, modifiers, pos = self._prefix(pos, end)
            sig = pos
            while sig < end:
                found = SIGNIFICANT.search(masked, sig, end)
                if found is None:
                    sig = end
                    break
                sig = found.start()
                if found.group() == '@':
                    interface = AT_INTERFACE.match(masked, sig)
                    if interface:
                        sig = interface.end()
                        continue
                    ann = ANNOTATION.match(masked, sig)
                    after = self._skip_ws(ann.end()) if ann else sig + 1
                    sig = self._close(after) + 1 if after < end and masked[after] == '(' else after
                    continue
                break
            if sig >= end:
                break
            ch = masked[sig]
            header = masked[pos:sig]
            keyword = TYPE_KEYWORD.search(header)
            try:
                if keyword:
                    pos = self._type(keyword, pos, sig, end, member_start, annotations, modifiers, owner, types, floor)
                elif ch == '}':
                    pos = sig
                elif ch == '{':     # initializer block
                    pos = self._close(sig) + 1
                elif ch in ';=':
                    stop = sig if ch == ';' else self._find_top(sig, end, ';')
                    if owner is not None:
                        self._fields(owner, member_start, annotations, modifiers, pos, sig, stop, floor)
                    pos = stop + 1
                else:               # '(' : method or constructor
                    close = self._close(sig)
                    stop = self._find_top(close + 1, end, ';{')
                    if owner is not None:
                        self._method(owner, member_start, annotations, modifiers, pos, sig, close, stop, floor)
                    pos = self._close(stop) + 1 if stop < end and masked[stop] == '{' else stop + 1
            except (IndexError, ValueError):   # broken member: skip to the next statement
                pos = self._find_top(sig, end, ';') + 1
            floor = pos

    def _type(self, keyword, pos, sig, end, member_start, annotations, modifiers, owner, types, floor) -> int:
        masked = self.masked
        kind = keyword.group(1) or 'annotation'
        name = keyword.group(3)
        name_pos = pos + keyword.start(3)
        decl = TypeDecl(kind=kind, name=name, qualname=f'{owner.qualname}.{name}' if owner else name,
                        annotations=annotations, modifiers=modifiers, start=member_start, name_pos=name_pos,
                        body_open=-1, body_close=-1, parent=owner)
        brace = sig
        if masked[sig] == '(' and kind == 'record':
            close = self._close(sig)
            self._components(decl, sig + 1, close)
            brace = self._find_top(close + 1, end, '{;')
        elif masked[sig] != '{':
            brace = self._find_top(sig, end, '{;')
        if brace >= end or masked[brace] != '{':
            return brace + 1
        decl.body_open, decl.body_close = brace, self._close(brace)
        decl.comment = self._doc(member_start, floor, pos, brace + 1, self.line_of(brace))
        if kind == 'record':
            decl.param_docs = javadoc_params(self._leading_raw(member_start, floor))
        types.append(decl)
        self.all_types.append(decl)
        body = decl.body_open + 1
        if kind == 'enum':
            body = self._find_top(body, decl.body_close, ';') + 1
        if kind != 'annotation' and body < decl.body_close:
            self._parse_members(body, decl.body_close, decl, decl.types)
        return decl.body_close + 1

    def _skip_annotations(self, pos: int) -> int:
        """The offset after the (type-use) annotations at ``pos`` and the whitespace around them."""
        masked = self.masked
        pos = self._skip_ws(pos)
        while masked.startswith('@', pos) and not AT_INTERFACE.match(masked, pos):
            found = ANNOTATION.match(masked, pos)
            if not found:
                break
            after = self._skip_ws(found.end())
            pos = self._skip_ws(self._close(after) + 1 if masked.startswith('(', after) else after)
        return pos

    def _type_end(self, pos: int, end: int) -> int:
        """End of the type that starts at ``pos`` (qualified name, generics, array dims, varargs)."""
        masked = self.masked
        pos = self._skip_annotations(pos)        # type-use annotations
        head = QNAME.match(masked, pos)
        if not head:
            return -1
        pos = head.end()
        while True:
            nxt = self._skip_ws(pos)
            if nxt < end and masked[nxt] == '<':
                depth, i = 0, nxt
                while i < end:
                    c = masked[i]
                    if c == '<':
                        depth += 1
                    elif c == '>':
                        depth -= 1
                        if depth == 0:
                            break
                    elif c == '(':
                        i = self._close(i)
                    elif c in ';{=':
                        return -1
                    i += 1
                pos = i + 1
                continue
            if nxt < end and masked[nxt] == '.' and not masked.startswith('...', nxt):
                after = self._skip_annotations(nxt + 1)      # Outer<T>.Inner, Outer.@Nullable Inner
                head = QNAME.match(masked, after)
                if not head:
                    return -1
                pos = head.end()
                continue
            if nxt < end and masked[nxt] == '@':
                found = ANNOTATION.match(masked, nxt)
                if found:
                    after = self._skip_ws(found.end())
                    pos = self._close(after) + 1 if masked[after] == '(' else found.end()
                    continue
            if masked.startswith('[', nxt) and masked[self._skip_ws(nxt + 1):self._skip_ws(nxt + 1) + 1] == ']':
                pos = self._skip_ws(nxt + 1) + 1
                continue
            if masked.startswith('...', nxt):
                pos = nxt + 3
            return pos

    def _split_top(self, start: int, end: int, angles: bool) -> List[Tuple[int, int]]:
        """[start, end) split at top-level commas (bracket groups and generics kept). Without ``angles``
        (initializers) a ``<`` only opens generics when a type or ``>`` follows (``new HashMap<K, V>()``)."""
        masked = self.masked
        parts, pos, depth, i = [], start, 0, start
        while i < end:
            c = masked[i]
            if c in '({[':
                i = self._close(i)
            elif c == '<' and (angles or GENERIC_OPEN.match(masked, i + 1)):
                depth += 1
            elif c == '>' and depth:
                depth -= 1
            elif c == ',' and depth == 0:
                parts.append((pos, i))
                pos = i + 1
            i += 1
        parts.append((pos, end))
        return parts

    def _fields(self, owner, member_start, annotations, modifiers, pos, sig, stop, floor) -> None:
        type_end = self._type_end(pos, sig)
        if type_end < 0 or type_end > sig:
            return
        type_text = normalize_type(self.clean[pos:type_end])
        if not type_text or type_text in MODIFIERS:
            return
        comment = None
        first = True
        for part_start, part_end in self._split_top(type_end, stop, angles=False):
            found = DECLARATOR.match(self.masked[part_start:part_end])
            if not found:
                if first:
                    return
                continue
            name_pos = part_start + found.start(1)
            init = None
            if found.group(3) is not None:
                init = self.clean[part_start + found.start(3):part_end].strip()
            dims = re.sub(r'\s', '', found.group(2) or '')
            if first:   # the declarators of one declaration share its comment
                comment = self._doc(member_start, floor, pos, stop + 1, self.line_of(stop))
            member = Member('field', found.group(1), type_text + dims, annotations, modifiers, member_start,
                            name_pos, stop + 1, init=init, comment=comment, owner=owner)
            owner.fields.append(member)
            first = False

    def _components(self, decl: TypeDecl, start: int, end: int) -> None:
        parts = self._split_top(start, end, angles=True)
        for index, (part_start, part_end) in enumerate(parts):
            annotations, modifiers, pos = self._prefix(part_start, part_end)
            type_end = self._type_end(pos, part_end)
            if type_end < 0:
                continue
            found = re.match(r'\s*(' + IDENT + r')\s*\Z', self.masked[type_end:part_end])
            if not found:
                continue
            name_pos = type_end + found.start(1)
            name = found.group(1)
            first = self._skip_ws(part_start)
            # a comment right after the comma, on the line of the previous component, is its trailing one
            floor = part_start
            if index:
                prev_line = self.line_of(parts[index - 1][1])
                for comment in self._comments_in(part_start, first):
                    if self.line_of(comment.start) == prev_line:
                        floor = comment.end
            limit = self._skip_ws(parts[index + 1][0]) if index + 1 < len(parts) else end
            member = Member('component', name, normalize_type(self.clean[pos:type_end]), annotations, modifiers,
                            first, name_pos, name_pos + len(name), owner=decl)
            member.comment = self._doc(first, floor, pos, name_pos + len(name),
                                       self.line_of(name_pos), limit=limit)
            decl.components.append(member)

    def _method(self, owner, member_start, annotations, modifiers, pos, sig, close, stop, floor) -> None:
        header = self.masked[pos:sig]
        found = METHOD_NAME.search(header)
        if not found:
            return
        name = found.group(1)
        ret = re.sub(r'^\s*<.*?>\s*', '', self.clean[pos:pos + found.start(1)], flags=re.S).strip()
        name_pos = pos + found.start(1)
        member = Member('method' if ret else 'constructor', name, normalize_type(ret), annotations, modifiers,
                        member_start, name_pos,
                        close + 1, params=self.masked[sig + 1:close].strip(), owner=owner)
        member.comment = self._doc(member_start, floor, pos, stop + 1, self.line_of(stop))
        owner.methods.append(member)

    # -- comments -------------------------------------------------------------------

    def _comments_in(self, start: int, end: int) -> List[_Comment]:
        lo = bisect.bisect_left(self._comment_starts, start)
        hi = bisect.bisect_left(self._comment_starts, end)
        return self.comments[lo:hi]

    def _code_before_on_line(self, pos: int) -> bool:
        line_start = self.masked.rfind('\n', 0, pos) + 1
        return bool(self.masked[line_start:pos].strip())

    def _leading(self, start: int, floor: int) -> List[_Comment]:
        """The run of comments right above ``start`` (no blank line in between; a comment after
        code on its line belongs to that code)."""
        run: List[_Comment] = []
        limit = start
        for comment in reversed(self._comments_in(floor, start)):
            between = self.text[comment.end:limit]
            if between.strip() or between.count('\n') > 1:
                break
            if self._code_before_on_line(comment.start):
                break
            run.insert(0, comment)
            limit = comment.start
        return run

    def _leading_raw(self, start: int, floor: int) -> str:
        return '\n'.join(unwrap_comment(c.text) for c in self._leading(start, floor))

    def _doc(self, start: int, floor: int, span_end: int, trailing_from: int, trailing_line: int,
             limit: Optional[int] = None) -> Optional[str]:
        """Comment of a declaration: the comments right above ``start``, the ones between its
        annotations / modifiers (up to ``span_end``) and the trailing one on ``trailing_line``
        (comments inside the type or the initializer are not documentation)."""
        picked = self._leading(start, floor) + self._comments_in(start, span_end)
        lo = bisect.bisect_left(self._comment_starts, trailing_from)
        if lo < len(self.comments):
            comment = self.comments[lo]
            if (self.line_of(comment.start) == trailing_line and (limit is None or comment.start < limit)
                    and not self.masked[trailing_from:comment.start].strip(' \t,')
                    and comment not in picked):
                picked.append(comment)
        texts = [unwrap_comment(c.text) for c in picked]
        text = '\n'.join(t for t in texts if is_documentation(t) and not JAVA_DIRECTIVE.match(t))
        return text.strip() or None

    # -- lookups --------------------------------------------------------------------

    def innermost_type(self, pos: int) -> Optional[TypeDecl]:
        """The innermost declaration whose body contains ``pos``."""
        best = None
        for decl in self.all_types:
            if decl.body_open < pos < decl.body_close and (best is None or decl.body_open > best.body_open):
                best = decl
        return best

    def offset_of_line(self, line: int) -> int:
        if line <= 1:
            return 0
        if line - 2 >= len(self._newlines):
            return len(self.text)
        return self._newlines[line - 2] + 1


def javadoc_params(doc: str) -> Dict[str, str]:
    """``{name: text}`` of the ``@param`` tags of an unwrapped javadoc."""
    params = {}
    for name, text in JAVADOC_PARAM.findall(doc or ''):
        text = ' '.join(text.split())
        if text:
            params[name] = text
    return params
