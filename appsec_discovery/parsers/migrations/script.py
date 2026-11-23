"""Migration files as text: the Up part of goose / sql-migrate files and statement splitting."""
import bisect
import re
from typing import List, Tuple

__all__ = ["has_directions", "up_section", "split_statements"]

# ``-- +goose Up`` / ``-- +goose Down`` (goose), ``-- +migrate Up`` / ``Down`` (sql-migrate)
DIRECTION = re.compile(r'^\s*--\s*\+(?:goose|migrate)\s+(up|down)\b', re.IGNORECASE)
# opening tag of a dollar-quoted string: ``$$`` or ``$body$`` (not a ``$1`` parameter)
DOLLAR_TAG = re.compile(r'\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$')


def has_directions(text: str) -> bool:
    """True for a goose / sql-migrate file (``-- +goose Up`` ...)."""
    return any(DIRECTION.match(line) for line in text.splitlines())


def up_section(text: str) -> str:
    """``text`` with only the Up part of an annotated migration; other lines are blanked so the
    line numbers stay. A file without ``+goose`` / ``+migrate`` annotations is returned as is."""
    if not has_directions(text):
        return text

    kept = []
    up = False
    for line in text.splitlines(keepends=True):
        match = DIRECTION.match(line)
        if match:
            up = match.group(1).lower() == 'up'
            kept.append('\n')
        else:
            kept.append(line if up else '\n')
    return ''.join(kept)


def split_statements(text: str) -> List[Tuple[int, str]]:
    """``[(line, statement)]``: the statements of ``text`` separated by ``;`` outside of
    comments, quoted strings / identifiers and dollar-quoted bodies (so a function body or a
    goose ``StatementBegin`` block with ``;`` inside stays whole). ``line`` (1-based) is the
    line of the first character of the statement; comments before it are not part of it."""
    line_starts = [0] + [m.end() for m in re.finditer('\n', text)]
    statements = []
    start = None
    i, n = 0, len(text)

    def close(end):
        statements.append((bisect.bisect_right(line_starts, start), text[start:end].strip()))

    while i < n:
        char = text[i]
        if text.startswith('--', i):
            newline = text.find('\n', i)
            i = n if newline < 0 else newline
            continue
        if text.startswith('/*', i):
            end = text.find('*/', i + 2)
            i = n if end < 0 else end + 2
            continue
        if char == ';':
            if start is not None:
                close(i)
                start = None
            i += 1
            continue
        if char.isspace():
            i += 1
            continue

        if start is None:
            start = i

        if char in ('"', "'"):
            i = _quoted_end(text, i)
            continue
        if char == '$':
            tag = DOLLAR_TAG.match(text, i)
            if tag:
                end = text.find(tag.group(), tag.end())
                i = n if end < 0 else end + len(tag.group())
                continue
        i += 1

    if start is not None:
        close(n)
    return statements


def _quoted_end(text: str, i: int) -> int:
    """Index after the string / identifier opened by the quote at ``i`` (a doubled quote is an
    escaped one)."""
    quote = text[i]
    i += 1
    while True:
        end = text.find(quote, i)
        if end < 0:
            return len(text)
        if text.startswith(quote * 2, end):
            i = end + 2
            continue
        return end + 1
