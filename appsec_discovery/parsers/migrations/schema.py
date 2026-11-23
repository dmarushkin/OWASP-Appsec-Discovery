"""Replay of DDL statements into the tables of one migration directory.

Every statement goes through sqlglot (dialect postgres) first; a statement it cannot parse
(or parses only as an opaque ``Command``) goes to a small regex fallback for the common
shapes (``CREATE TABLE``, ``ALTER TABLE`` column changes and ``ATTACH PARTITION``,
``DROP TABLE a, b``). Comments are stripped first. Both paths end in the same ``Schema`` mutators. A statement neither
path understands is counted in ``ReplayStats`` and skipped.
"""
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

from appsec_discovery.parsers.comments import leading_comment

logger = logging.getLogger(__name__)

# sqlglot logs a warning for every statement it falls back to parsing as ``Command``;
# such statements are counted (and logged at debug level) by ``Schema.apply`` instead
logging.getLogger('sqlglot').setLevel(logging.ERROR)

__all__ = ["Column", "Table", "ReplayStats", "Schema"]

DEFAULT_SCHEMA = 'public'

TableKey = Tuple[str, str]   # (schema, table)

# statements that change tables; everything else (indexes, functions, inserts, grants...) is skipped
TABLE_DDL = re.compile(r'(create\s+(unlogged\s+)?table|alter\s+table|drop\s+table|comment\s+on\s+(table|column))\b',
                       re.IGNORECASE)

# -- regex fallback ------------------------------------------------------------
# The patterns below run on untrusted text, so they must not backtrack catastrophically
# (ReDoS): every repetition is unambiguous or possessive (``*+`` / ``++``), and a ``\s+``
# that a search may enter mid-way is anchored to the start of the run with ``(?<!\s)``.
NAME = r'(?:"[^"]++"|[\w$]++)'
QNAME = rf'{NAME}(?:\s*\.\s*{NAME})?'
FALLBACK_CREATE = re.compile(
    rf'create\s+(?:unlogged\s+)?table\s+(if\s+not\s+exists\s+)?({QNAME})\s*(.*)\Z', re.IGNORECASE | re.DOTALL)
FALLBACK_ALTER = re.compile(
    rf'alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?({QNAME})\s+(.*)\Z', re.IGNORECASE | re.DOTALL)
FALLBACK_ADD_COLUMN = re.compile(
    rf'add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?(?!(?:constraint|primary|unique|check|foreign|exclude)\b)'
    rf'({NAME})\s+(.+)\Z', re.IGNORECASE | re.DOTALL)
FALLBACK_ATTACH = re.compile(rf'attach\s+partition\s+({QNAME})', re.IGNORECASE)
# ``DROP x`` in ALTER TABLE is a column (COLUMN is optional), unless it names another kind of element
FALLBACK_DROP_COLUMN = re.compile(
    rf'drop\s+(?:column\s+)?(?:if\s+exists\s+)?(?!(?:constraint|partition)\b)({NAME})(?:\s+(?:cascade|restrict))?\Z',
    re.IGNORECASE)
FALLBACK_RENAME_COLUMN = re.compile(
    rf'rename\s+(?:column\s+)?(?!(?:to|constraint)\b)({NAME})\s+to\s+({NAME})\Z', re.IGNORECASE)
FALLBACK_RENAME_TABLE = re.compile(rf'rename\s+to\s+({NAME})\Z', re.IGNORECASE)
FALLBACK_COLUMN_TYPE = re.compile(
    rf'alter\s+(?:column\s+)?({NAME})\s+(?:set\s+data\s+)?type\s+(.+?)(?:(?<!\s)\s++(?:using|collate)\b.*)?\Z',
    re.IGNORECASE | re.DOTALL)
# ALTER TABLE actions that do not change the columns (constraints, partitions, storage, owner...)
FALLBACK_NO_OP = re.compile(
    r'((add|drop|alter|validate|rename)\s+constraint|add\s+(primary|unique|check|foreign|exclude)|'
    r'detach\s+partition|alter\s+(column\s+)?\S+\s+(set|drop)\s|owner\s+to|set|reset|enable|disable|'
    r'replica|cluster|inherit|no\s+inherit)\b', re.IGNORECASE)
FALLBACK_DROP = re.compile(r'drop\s+table\s+(?:if\s+exists\s+)?(.*?)(?:(?<!\s)\s++(?:cascade|restrict))?\Z',
                           re.IGNORECASE | re.DOTALL)
# a quoted SQL string (``''`` is an escaped quote); possessive, so ``''`` is never re-split
# into the end of one literal and the start of the next (exponential backtracking)
STRING = r"'(?:[^']|'')*+'"
# ``COMMENT ON ... IS 'a' 'b'``: adjacent literals are one string (sqlglot rejects them)
FALLBACK_COMMENT = re.compile(rf"comment\s+on\s+(table|column)\s+({QNAME}(?:\s*\.\s*{NAME})?)\s+is\s+((?:{STRING}\s*+)++)\Z",
                              re.IGNORECASE | re.DOTALL)
# table elements that are not columns
TABLE_CONSTRAINT = re.compile(r'(constraint|primary|unique|check|foreign|exclude|like)\b', re.IGNORECASE)
COLUMN_DEF = re.compile(rf'({NAME})\s+(.+)\Z', re.DOTALL)
LIKE_OPTIONS = re.compile(r'\blike\s+\S+((?:\s+(?:including|excluding)\s+\w+)*)', re.IGNORECASE)
# ``int array`` / ``varchar(50) ARRAY`` is ``int[]`` (sqlglot drops the keyword); ``ARRAY[...]`` values stay
ARRAY_SUFFIX = re.compile(r'(?<=[\w)])\s++array\b(?!\s*\[)', re.IGNORECASE)
# where the type of a column definition ends
TYPE_END = re.compile(r'(?<!\s)\s++(not\s+null|null|default|primary\s+key|references|unique|check|constraint|collate|'
                      r'generated)\b.*\Z', re.IGNORECASE | re.DOTALL)


@dataclass
class Column:
    name: str
    type: str
    file: str
    line: int
    comment: Optional[str] = None          # COMMENT ON COLUMN
    code_comment: Optional[str] = None     # ``--`` / ``/* */`` comment next to the column definition
    default: Optional[str] = None          # the DEFAULT literal (None for none / an expression)
    checks: List[str] = field(default_factory=list)    # the values of CHECK (col IN (...)) constraints

    @property
    def samples(self) -> List[str]:
        return ([self.default] if self.default is not None else []) + [v for v in self.checks if v != self.default]


@dataclass
class Table:
    schema: str
    name: str
    # the file and line of the CREATE TABLE; None for a table only seen in ALTER TABLE ... ADD COLUMN
    file: Optional[str]
    line: Optional[int]
    columns: Dict[str, Column] = field(default_factory=dict)
    comment: Optional[str] = None          # COMMENT ON TABLE
    code_comment: Optional[str] = None     # the comment above the CREATE TABLE

    @property
    def qualified_name(self) -> str:
        return f"{self.schema}.{self.name}"


@dataclass
class ReplayStats:
    files: int = 0
    statements: int = 0          # table DDL statements seen
    parsed: int = 0              # understood by sqlglot
    fallback: int = 0            # understood by the regex fallback
    failed: int = 0              # understood by neither (skipped)
    reasons: Counter = field(default_factory=Counter)

    def summary(self) -> str:
        reasons = ', '.join(f"{reason} ({count})" for reason, count in self.reasons.most_common(3))
        return (f"{self.files} files, {self.statements} table statements: {self.parsed} parsed, "
                f"{self.fallback} by fallback, {self.failed} skipped" + (f" [{reasons}]" if reasons else ''))


# -- names and types -----------------------------------------------------------

def _ident(node: exp.Identifier) -> str:
    """Postgres identifier semantics: unquoted names fold to lower case."""
    return node.this if node.quoted else node.this.lower()


def _name_from_text(text: str) -> str:
    text = text.strip()
    return text[1:-1] if text.startswith('"') and text.endswith('"') else text.lower()


def _table_key(table: exp.Table) -> TableKey:
    db = table.args.get('db')
    return (_ident(db) if db else DEFAULT_SCHEMA, _ident(table.this))


def _key_from_text(text: str) -> TableKey:
    parts = re.findall(NAME, text)
    return (_name_from_text(parts[0]), _name_from_text(parts[1])) if len(parts) == 2 \
        else (DEFAULT_SCHEMA, _name_from_text(parts[0]))


def type_text(data_type: exp.DataType) -> str:
    """Lower-case postgres spelling: ``varchar(255)``, ``numeric(20,2)``, ``timestamptz``, ``text[]``
    (synonyms are unified by sqlglot: ``integer`` -> ``int``, ``timestamp with time zone`` -> ``timestamptz``)."""
    text = re.sub(r'(?<!\s)\s*+,\s*+', ',', data_type.sql(dialect='postgres').lower())
    return re.sub(r'^decimal\b', 'numeric', text)


def _type_from_text(text: str) -> str:
    text = re.sub(r'(?<!\s)\s++array\b', '[]', text, flags=re.IGNORECASE)      # ``bigint array`` is ``bigint[]``
    try:
        return type_text(exp.DataType.build(text, dialect='postgres', udt=True))
    except (SqlglotError, ValueError):
        return ' '.join(text.lower().split())


def strip_comments(sql: str) -> str:
    """``sql`` without ``--`` and ``/* */`` comments (quoted text kept): column comments must not
    become columns, and their commas must not split column definitions."""
    out, i, quote = [], 0, None
    while i < len(sql):
        char = sql[i]
        if quote:
            out.append(char)
            if char == quote:
                quote = None
            i += 1
        elif char in ('"', "'"):
            quote = char
            out.append(char)
            i += 1
        elif sql.startswith('--', i):
            end = sql.find('\n', i)
            i = len(sql) if end < 0 else end
        elif sql.startswith('/*', i):
            end = sql.find('*/', i + 2)
            out.append(' ')
            i = len(sql) if end < 0 else end + 2
        else:
            out.append(char)
            i += 1
    return ''.join(out).strip()


COLUMN_LINE = re.compile(rf'^\s*(?:alter\s+table\s+\S+\s+)?(?:add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?)?({NAME})\s+\S',
                         re.IGNORECASE)
NOT_A_COLUMN = re.compile(r'(constraint|primary|unique|check|foreign|exclude|like|create|alter|add|drop|partition)$',
                          re.IGNORECASE)
# one literal; every alternative ends deterministically (no digit run can be split in two numbers)
LITERAL = rf"{STRING}|-?\d++(?:\.\d++)?+|true\b|false\b"
DEFAULT_VALUE = re.compile(rf"\bdefault\s+({LITERAL})", re.IGNORECASE)
# ``col IN (v1, v2, ...)``: the list is ``literal (, literal)*`` (with an optional trailing comma);
# the name starts a word, so the search does not re-scan a long word from each of its characters
CHECK_IN = re.compile(rf"(?<![\w$])({NAME})(?:\s*+::\s*+\w++)?+\s++in\s*+\(\s*+"
                      rf"((?:{LITERAL})(?:\s*+,\s*+(?:{LITERAL}))*+)\s*+,?\s*+\)", re.IGNORECASE)


def column_code_comments(sql: str, source_lines: Sequence[str] = (), first_line: int = 1) -> Dict[str, str]:
    """``{column: comment}`` of the comments next to the column definitions of a raw statement
    (read from ``source_lines``, the file, when given: a comment after the ``;`` is not in ``sql``)."""
    lines = sql.splitlines()
    result = {}
    for number, text in enumerate(lines, 1):
        match = COLUMN_LINE.match(strip_comments(text))
        if not match or NOT_A_COLUMN.match(match.group(1)):
            continue
        absolute = first_line + number - 1
        in_file = 0 < absolute <= len(source_lines) and source_lines[absolute - 1].strip().startswith(text.strip()[:20])
        comment = leading_comment(source_lines, absolute) if in_file else leading_comment(lines, number)
        if comment:
            result.setdefault(_name_from_text(match.group(1)), comment)
    return result


def _literal(text: str) -> str:
    if text.startswith("'"):
        return text[1:-1].replace("''", "'")
    return text.lower() if text.lower() in ('true', 'false') else text


SET_DEFAULT = re.compile(rf"alter\s+(?:column\s+)?({NAME})\s+(?:set\s+default\s+(.+)|drop\s+default)\Z",
                         re.IGNORECASE | re.DOTALL)
LITERAL_ONLY = re.compile(rf"\A({LITERAL})(?:\s*::\s*[\w\s]+)?\Z", re.IGNORECASE)


def column_samples(definitions: Iterable[str]) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    """``({column: DEFAULT literal}, {column: CHECK (col IN (...)) values})`` of column / table
    definitions (comments already stripped)."""
    defaults: Dict[str, str] = {}
    checks: Dict[str, List[str]] = {}
    for definition in definitions:
        column = COLUMN_DEF.match(definition)
        own = _name_from_text(column.group(1)) if column and not TABLE_CONSTRAINT.match(definition) else None
        default = DEFAULT_VALUE.search(definition)
        if own and default:
            defaults[own] = _literal(default.group(1))
        for check in CHECK_IN.finditer(definition):
            values = [_literal(v) for v in re.findall(LITERAL, check.group(2), re.IGNORECASE)]
            checks.setdefault(_name_from_text(check.group(1)), []).extend(values)
    return defaults, checks


def outside_quotes(sql: str, pattern: re.Pattern, replacement: str) -> str:
    """``pattern.sub(replacement)`` applied to the text outside of '...' / "..." only."""
    parts = re.split(rf"({STRING}|\"[^\"]*+\")", sql)
    return ''.join(part if i % 2 else pattern.sub(replacement, part) for i, part in enumerate(parts))


def _definitions(sql: str) -> List[str]:
    """The column / table definitions of a CREATE TABLE body or the actions of an ALTER TABLE."""
    create = FALLBACK_CREATE.match(sql)
    if create:
        rest = create.group(3).strip()
        body = _parenthesised(rest) if rest.startswith('(') else None
        return _split_top_level(body) if body else []
    alter = FALLBACK_ALTER.match(sql)
    if alter:
        return [re.sub(r'^add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?', '', a, flags=re.IGNORECASE)
                for a in _split_top_level(alter.group(2))]
    return []


def _split_top_level(text: str) -> List[str]:
    """``text`` split on commas outside of parentheses and quotes."""
    parts, depth, quote, start = [], 0, None, 0
    for i, char in enumerate(text):
        if quote:
            if char == quote:
                quote = None
        elif char in ('"', "'"):
            quote = char
        elif char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
        elif char == ',' and depth == 0:
            parts.append(text[start:i].strip())
            start = i + 1
    parts.append(text[start:].strip())
    return [part for part in parts if part]


def _parenthesised(text: str) -> Optional[str]:
    """Content of the parentheses that ``text`` starts with (None if they are not closed)."""
    depth, quote = 0, None
    for i, char in enumerate(text):
        if quote:
            if char == quote:
                quote = None
        elif char in ('"', "'"):
            quote = char
        elif char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
            if depth == 0:
                return text[1:i]
    return None


class Schema:
    """Final tables of one migration directory, built by ``apply``-ing its statements in order."""

    def __init__(self, stats: ReplayStats):
        self.stats = stats
        self.tables: Dict[TableKey, Table] = {}
        self._statement_comment: Optional[str] = None
        self._column_comments: Dict[str, str] = {}
        self._column_defaults: Dict[str, str] = {}
        self._column_checks: Dict[str, List[str]] = {}
        self._like_including: set = set()
        # partitions (``PARTITION OF`` / ``ATTACH PARTITION``) are part of their parent, not tables
        self.partitions = set()

    def apply(self, sql: str, file: str, line: int, comment: Optional[str] = None,
              source_lines: Sequence[str] = ()) -> None:
        """``comment``: the code comment above the statement (the table comment of a CREATE TABLE);
        ``source_lines``: the lines of the file (for the comments of its columns)."""
        raw = sql
        sql = strip_comments(sql)
        if not TABLE_DDL.match(sql):
            return
        sql = outside_quotes(sql, ARRAY_SUFFIX, '[]')
        # documentation of the columns this statement defines, used by create_table / add_column
        self._statement_comment = comment
        self._column_comments = column_code_comments(raw, source_lines, line)
        if comment and FALLBACK_ALTER.match(sql):
            # the comment above an ALTER TABLE that adds one column documents that column
            added = [m.group(1) for m in map(FALLBACK_ADD_COLUMN.match, _split_top_level(FALLBACK_ALTER.match(sql).group(2)))
                     if m]
            if len(added) == 1:
                self._column_comments.setdefault(_name_from_text(added[0]), comment)
        self._column_defaults, self._column_checks = column_samples(_definitions(sql))
        like = LIKE_OPTIONS.search(sql) if FALLBACK_CREATE.match(sql) else None
        self._like_including = {o.lower() for o in re.findall(r'including\s+(\w+)', like.group(1), re.IGNORECASE)} \
            if like else set()
        self.stats.statements += 1

        try:
            node = sqlglot.parse_one(sql, dialect='postgres')
            reason = 'unsupported syntax'
        except SqlglotError as ex:
            node, reason = None, str(ex).split('. Line')[0].split('\n')[0]

        try:
            # an ALTER with an action sqlglot keeps as an opaque Command (``DROP x`` without
            # COLUMN, ``ALTER x TYPE ... USING``) goes to the fallback as a whole
            opaque = isinstance(node, exp.Command) or (
                isinstance(node, exp.Alter) and any(isinstance(a, exp.Command) for a in node.args.get('actions') or []))
            if node is not None and not opaque:
                self._apply_node(node, file, line)
                self.stats.parsed += 1
                self._alter_samples(sql)
                return
            if self._apply_fallback(sql, file, line):
                self.stats.fallback += 1
                self._alter_samples(sql)
                return
        except Exception as ex:      # a statement must never break the replay
            reason = f"{type(ex).__name__}: {ex}"

        self.stats.failed += 1
        self.stats.reasons[reason] += 1
        logger.debug(f"migrations: skipped statement at {file}:{line} ({reason}): {sql[:200]}")

    # -- mutators (shared by the sqlglot and the fallback paths) -------------------

    def create_table(self, key: TableKey, columns: Iterable[Tuple[str, str]], file: str, line: int,
                     if_not_exists: bool = False, like: Optional[TableKey] = None) -> None:
        if if_not_exists and key in self.tables:
            return
        table = Table(schema=key[0], name=key[1], file=file, line=line, code_comment=self._statement_comment)
        if like in self.tables:
            # LIKE copies comments / defaults / constraints only with INCLUDING ... (or ALL)
            including = self._like_including
            every = 'all' in including
            for column in self.tables[like].columns.values():
                table.columns[column.name] = Column(
                    column.name, column.type, file, line,
                    comment=column.comment if every or 'comments' in including else None,
                    code_comment=column.code_comment,
                    default=column.default if every or 'defaults' in including else None,
                    checks=list(column.checks) if every or 'constraints' in including else [])
        for name, column_type in columns:
            table.columns.setdefault(name, self._column(name, column_type, file, line))
        self.tables[key] = table
        self.partitions.discard(key)

    def mark_partition(self, key: TableKey) -> None:
        self.tables.pop(key, None)
        self.partitions.add(key)

    def add_column(self, key: TableKey, name: str, column_type: str, file: str, line: int) -> None:
        if key in self.partitions:
            return
        table = self.tables.get(key)
        if table is None:
            # created outside of this directory (or by a statement that was skipped)
            table = self.tables[key] = Table(schema=key[0], name=key[1], file=None, line=None)
        table.columns.setdefault(name, self._column(name, column_type, file, line))

    def _column(self, name: str, column_type: str, file: str, line: int) -> Column:
        return Column(name, column_type, file, line, code_comment=self._column_comments.get(name),
                      default=self._column_defaults.get(name), checks=list(self._column_checks.get(name, [])))

    def _alter_samples(self, sql: str) -> None:
        """ALTER TABLE changes of the samples of existing columns: ``ALTER col SET / DROP DEFAULT``
        and ``ADD CONSTRAINT ... CHECK (col IN (...))``."""
        alter = FALLBACK_ALTER.match(sql)
        table = self.tables.get(_key_from_text(alter.group(1))) if alter else None
        if table is None:
            return
        for action in _split_top_level(alter.group(2)):
            match = SET_DEFAULT.match(action.strip())
            if match and _name_from_text(match.group(1)) in table.columns:
                value = LITERAL_ONLY.match((match.group(2) or '').strip())
                table.columns[_name_from_text(match.group(1))].default = _literal(value.group(1)) if value else None
        for name, values in self._column_checks.items():
            column = table.columns.get(name)
            if column is not None:
                column.checks.extend(v for v in values if v not in column.checks)

    def drop_column(self, key: TableKey, name: str) -> None:
        if key in self.tables:
            self.tables[key].columns.pop(name, None)

    def rename_column(self, key: TableKey, old: str, new: str) -> None:
        table = self.tables.get(key)
        if table is None or old not in table.columns:
            return
        table.columns[old].name = new
        table.columns = {column.name: column for column in table.columns.values()}

    def set_column_type(self, key: TableKey, name: str, column_type: str) -> None:
        column = self.tables[key].columns.get(name) if key in self.tables else None
        if column is not None:
            column.type = column_type

    def rename_table(self, key: TableKey, new_key: TableKey) -> None:
        table = self.tables.pop(key, None)
        if table is not None:
            table.schema, table.name = new_key
            self.tables[new_key] = table

    def drop_table(self, key: TableKey) -> None:
        self.tables.pop(key, None)
        self.partitions.discard(key)

    def comment(self, key: TableKey, column: Optional[str], text: str) -> None:
        table = self.tables.get(key)
        if table is None:
            return
        if column is None:
            table.comment = text
        elif column in table.columns:
            table.columns[column].comment = text

    # -- sqlglot path --------------------------------------------------------------

    def _apply_node(self, node: exp.Expression, file: str, line: int) -> None:
        kind = str(node.args.get('kind') or '').upper()
        if isinstance(node, exp.Create) and kind == 'TABLE':
            self._create(node, file, line)
        elif isinstance(node, exp.Alter) and kind == 'TABLE':
            self._alter(node, file, line)
        elif isinstance(node, exp.Drop) and kind == 'TABLE':
            self.drop_table(_table_key(node.this))
        elif isinstance(node, exp.Comment) and kind == 'TABLE':
            self.comment(_table_key(node.this), None, node.expression.name)
        elif isinstance(node, exp.Comment) and kind == 'COLUMN':
            column = node.this
            db = column.args.get('db')
            key = (_ident(db) if db else DEFAULT_SCHEMA, _ident(column.args['table']))
            self.comment(key, _ident(column.this), node.expression.name)

    def _create(self, node: exp.Create, file: str, line: int) -> None:
        target = node.this
        elements = target.expressions if isinstance(target, exp.Schema) else []
        table = target.this if isinstance(target, exp.Schema) else target
        key = _table_key(table)

        properties = node.args.get('properties')
        if properties is not None and properties.find(exp.PartitionedOfProperty):
            self.mark_partition(key)
            return

        like = next((_table_key(el.this) for el in elements if isinstance(el, exp.LikeProperty)), None)
        columns = [(_ident(el.this), type_text(el.args['kind']) if el.args.get('kind') else '')
                   for el in elements if isinstance(el, exp.ColumnDef)]
        self.create_table(key, columns, file, line, if_not_exists=bool(node.args.get('exists')), like=like)

    def _alter(self, node: exp.Alter, file: str, line: int) -> None:
        key = _table_key(node.this)
        for action in node.args.get('actions') or []:
            if isinstance(action, exp.ColumnDef):
                column_type = type_text(action.args['kind']) if action.args.get('kind') else ''
                self.add_column(key, _ident(action.this), column_type, file, line)
            elif isinstance(action, exp.Drop) and str(action.args.get('kind')).upper() == 'COLUMN':
                self.drop_column(key, _ident(action.this.this))
            elif isinstance(action, exp.RenameColumn):
                self.rename_column(key, _ident(action.this.this), _ident(action.args['to'].this))
            elif isinstance(action, exp.AlterColumn) and action.args.get('dtype'):
                self.set_column_type(key, _ident(action.this), type_text(action.args['dtype']))
            elif isinstance(action, exp.AlterRename):
                renamed = action.this
                new_schema = _ident(renamed.args['db']) if renamed.args.get('db') else key[0]
                self.rename_table(key, (new_schema, _ident(renamed.this)))

    # -- regex fallback ------------------------------------------------------------

    def _apply_fallback(self, sql: str, file: str, line: int) -> bool:
        """True if the statement was understood by the regex fallback."""
        create = FALLBACK_CREATE.match(sql)
        if create:
            return self._fallback_create(_key_from_text(create.group(2)), create.group(3).strip(),
                                         bool(create.group(1)), file, line)

        comment = FALLBACK_COMMENT.match(sql)
        if comment:
            names = [_name_from_text(n) for n in re.findall(NAME, comment.group(2))]
            text = ''.join(part.replace("''", "'") for part in re.findall(r"'((?:[^']|'')*+)'", comment.group(3)))
            if comment.group(1).lower() == 'table':
                key = tuple(names) if len(names) == 2 else (DEFAULT_SCHEMA, names[0])
                self.comment(key, None, text)
            else:
                *table, column = names
                self.comment(tuple(table) if len(table) == 2 else (DEFAULT_SCHEMA, table[0]), column, text)
            return True

        drop = FALLBACK_DROP.match(sql)
        if drop:
            for name in _split_top_level(drop.group(1)):
                self.drop_table(_key_from_text(name))
            return True

        alter = FALLBACK_ALTER.match(sql)
        if alter:
            key = _key_from_text(alter.group(1))
            attach = FALLBACK_ATTACH.match(alter.group(2))
            if attach:
                self.mark_partition(_key_from_text(attach.group(1)))
                return True
            changes = [self._fallback_action(key, action.strip(), file, line)
                       for action in _split_top_level(alter.group(2))]
            if None in changes:
                return False
            for change in changes:
                change()
            return True

        return False

    def _fallback_action(self, key: TableKey, action: str, file: str, line: int):
        """The change of one ALTER TABLE action (a no-op for actions that keep the columns),
        None if the action is not understood. Checked before applying any of a statement's actions."""
        match = FALLBACK_COLUMN_TYPE.match(action)
        if match:
            return lambda: self.set_column_type(key, _name_from_text(match.group(1)), _type_from_text(match.group(2)))
        match = FALLBACK_ADD_COLUMN.match(action)
        if match:
            return lambda: self.add_column(key, _name_from_text(match.group(1)), _column_type(match.group(2)),
                                           file, line)
        match = FALLBACK_DROP_COLUMN.match(action)
        if match:
            return lambda: self.drop_column(key, _name_from_text(match.group(1)))
        match = FALLBACK_RENAME_TABLE.match(action)
        if match:
            return lambda: self.rename_table(key, (key[0], _name_from_text(match.group(1))))
        match = FALLBACK_RENAME_COLUMN.match(action)
        if match:
            return lambda: self.rename_column(key, _name_from_text(match.group(1)), _name_from_text(match.group(2)))
        if FALLBACK_NO_OP.match(action):
            return lambda: None
        return None

    def _fallback_create(self, key: TableKey, rest: str, if_not_exists: bool, file: str, line: int) -> bool:
        if re.match(r'partition\s+of\b', rest, re.IGNORECASE):
            self.mark_partition(key)
            return True
        if re.match(r'as\b', rest, re.IGNORECASE):
            self.create_table(key, [], file, line, if_not_exists)
            return True

        body = _parenthesised(rest) if rest.startswith('(') else None
        if body is None:
            return False

        columns, like = [], None
        for element in _split_top_level(body):
            like_match = re.match(rf'like\s+({QNAME})', element, re.IGNORECASE)
            if like_match:
                like = _key_from_text(like_match.group(1))
            elif not TABLE_CONSTRAINT.match(element):
                column = COLUMN_DEF.match(element)
                if column:
                    columns.append((_name_from_text(column.group(1)), _column_type(column.group(2))))
        self.create_table(key, columns, file, line, if_not_exists, like=like)
        return True


def _column_type(definition: str) -> str:
    """The type at the start of a column definition (constraints and defaults cut off)."""
    return _type_from_text(TYPE_END.sub('', definition.strip()))
