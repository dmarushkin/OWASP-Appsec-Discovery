"""Code comments next to a source line, for the ``comment`` of objects and fields.

``leading_comment(lines, line)`` takes the comment block right above ``line`` (1-based; no
blank line in between) plus a trailing comment on the line itself. Line comment markers are
``//``, ``#`` and ``--``; ``/* ... */`` and javadoc blocks are unwrapped. Python docstrings and
GraphQL descriptions are read by their parsers, not here.
"""
import re
from typing import List, Optional, Sequence

__all__ = ["is_documentation", "leading_comment", "trailing_comment", "unwrap_comment"]

LINE_COMMENT = re.compile(r'^\s*(//+|#+|--+)\s?(.*)$')
BLOCK_END = re.compile(r'\*/\s*$')
# a trailing ``// x`` / ``# x`` / ``-- x`` outside of string literals (good enough for one line)
TRAILING = re.compile(r'''^(?:[^'"`/#-]|'[^']*'|"[^"]*"|`[^`]*`|/(?![/*])|-(?!-))*?(?:\s|(?<=[;{}\]]))(?://+|#+|--+)\s?(.*)$''')
# directives that are not documentation
DIRECTIVE = re.compile(r'^((?-i:go:\S)|\+goose|\+migrate|nolint|noqa|type:\s*ignore|eslint|@ts-|pylint|prettier|swagger:|'
                       r'nosec|lint:|lint-(disable|enable)|easyjson:)', re.IGNORECASE)
MIGRATION_DIRECTION = re.compile(r'\+(goose|migrate)\s+(up|down)\b', re.IGNORECASE)
# a line that ends a declaration is not an annotation line, even when it starts with ``@``
DECLARATION_END = re.compile(r'[;{}]\s*$')


def unwrap_comment(text: str) -> str:
    """The text of a ``/* ... */`` / ``/** ... */`` block or of ``//`` / ``#`` lines."""
    text = re.sub(r'^\s*/\*+', '', text.strip())
    # ``(?<!\*)``: a search must not re-scan a long ``****`` run from each of its stars (ReDoS)
    text = re.sub(r'(?<!\*)\*++/\s*$', '', text)
    lines = []
    for line in text.splitlines():
        line = re.sub(r'^\s*\*\s?', '', line)
        match = LINE_COMMENT.match(line)
        lines.append(match.group(2) if match else line)
    return '\n'.join(line.rstrip() for line in lines).strip()


def is_documentation(text: str) -> bool:
    """False for empty text and tool directives (``nolint``, ``eslint-disable``, ``+goose``...)."""
    return bool(text) and not DIRECTIVE.match(text.strip())


def trailing_comment(source_line: str) -> Optional[str]:
    if LINE_COMMENT.match(source_line):
        return None
    match = TRAILING.match(source_line)
    text = match.group(1).strip() if match else ''
    return text if is_documentation(text) else None


def _skip_annotations(lines: Sequence[str], i: int, max_lines: int = 30) -> int:
    """Index of the line above the annotations / decorators that end at ``lines[i]``; ``i`` itself
    when ``lines[i]`` is no annotation. A line counts only when it starts with ``@`` (and does not
    end a declaration: ``@Ann Type x;``) or lies inside the open parentheses of a multi-line one
    (``@Column(\n  name = "x")``): plain code above is never skipped."""
    while i >= 0:
        text = lines[i].strip()
        if text.startswith('@') and text.count('(') == text.count(')') and not DECLARATION_END.search(text):
            i -= 1
            continue
        depth = text.count(')') - text.count('(')
        if depth <= 0:
            return i
        # the last line of a multi-line annotation: climb while inside its parentheses
        start = i - 1
        while start >= 0 and i - start < max_lines and depth > 0:
            depth += lines[start].count(')') - lines[start].count('(')
            if depth > 0:
                start -= 1
        if start < 0 or depth != 0 or not lines[start].strip().startswith('@'):
            return i
        i = start - 1
    return i


def leading_comment(lines: Sequence[str], line: int, trailing: bool = True) -> Optional[str]:
    """Comment above ``lines[line - 1]`` (and after it on the same line); None when there is none.
    Annotation / decorator lines (``@...``) between the comment and the line are skipped."""
    if not 1 <= line <= len(lines):
        return None
    parts: List[str] = []
    i = _skip_annotations(lines, line - 2)
    if i >= 0 and BLOCK_END.search(lines[i]):
        end = i
        while i >= 0 and '/*' not in lines[i]:
            i -= 1
        # only a block that starts its line: ``x int /**/`` ends a declaration, it is no comment
        if i >= 0 and lines[i].lstrip().startswith('/*'):
            parts.append(unwrap_comment('\n'.join(lines[i:end + 1])))
    else:
        block = []
        while i >= 0:
            match = LINE_COMMENT.match(lines[i])
            if not match or MIGRATION_DIRECTION.match(match.group(2)):
                break               # a file header above ``-- +goose Up`` documents the file, not the line
            block.insert(0, match.group(2))
            i -= 1
        parts.append('\n'.join(text for text in block if is_documentation(text)))
    if trailing:
        parts.append(trailing_comment(lines[line - 1]) or '')
    text = '\n'.join(part for part in parts if part and part.strip())
    return text.strip() or None
