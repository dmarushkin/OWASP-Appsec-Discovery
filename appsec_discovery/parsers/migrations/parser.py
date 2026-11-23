import logging
import posixpath
import re
from collections import defaultdict
from pathlib import PurePosixPath
from typing import Dict, List, Optional, Tuple

from appsec_discovery.models import CodeObject, CodeObjectField, CodeObjectProp
from appsec_discovery.parsers.base_parser import FileParser
from appsec_discovery.parsers.comments import leading_comment
from appsec_discovery.parsers.common import DEFAULT_PRUNE_DIRS
from appsec_discovery.parsers.migrations.schema import ReplayStats, Schema, Table
from appsec_discovery.parsers.migrations.script import has_directions, split_statements, up_section

logger = logging.getLogger(__name__)

# directories whose .sql files are migrations / schema definitions
MIGRATION_DIR = re.compile(r'(migrat\w*|db|schemas?)', re.IGNORECASE)
CREATE_TABLE = re.compile(r'\bcreate\s+(?:unlogged\s+)?table\b', re.IGNORECASE)
# ClickHouse DDL (its migrations often sit next to the postgres ones): not postgres tables
CLICKHOUSE_DIR = re.compile(r'clickhouse|(^|[_-])ch($|[_-])', re.IGNORECASE)
CLICKHOUSE_ENGINE = re.compile(
    r'\bengine\s*=\s*(\w*MergeTree|Replicated\w*|Distributed|Kafka|Memory|Log|TinyLog|Null|Buffer|Dictionary)\b',
    re.IGNORECASE)
# leading version of a migration file name: 00001_x.sql, 20240101120000_x.up.sql, V3__x.sql
VERSION = re.compile(r'[Vv]?(\d+)')
# the files of a "one migration per directory" layout: Diesel / golang-migrate dirs
# ``<version>_name/{up.sql,down.sql}``, Prisma ``<timestamp>_name/migration.sql``
DIRECTORY_MIGRATION_FILES = frozenset({'up.sql', 'migration.sql'})
DOWN_FILE = re.compile(r'(^|\.)down\.sql$', re.IGNORECASE)


def _in_version_directory(path: str) -> bool:
    """True for ``.../<version>_name/up.sql`` (or ``migration.sql``): one migration of a history
    whose migrations are directories."""
    return (posixpath.basename(path).lower() in DIRECTORY_MIGRATION_FILES
            and VERSION.match(posixpath.basename(posixpath.dirname(path))) is not None)


def history_of(path: str) -> str:
    """The directory of the migration history ``path`` belongs to: its own directory, or the
    parent of its version directory (``migrations/<version>_name/up.sql`` -> ``migrations``)."""
    directory = posixpath.dirname(path)
    return posixpath.dirname(directory) if _in_version_directory(path) else directory


def migration_order(path: str) -> Tuple[bool, int, str]:
    """Sort key of a migration file: by its leading version number, ties (and files without a
    version, which go last) by name. In a version directory the directory name is the version."""
    name = posixpath.basename(posixpath.dirname(path)) if _in_version_directory(path) else posixpath.basename(path)
    version = VERSION.match(name)
    return (version is None, int(version.group(1)) if version else 0, name)


def _join(*parts) -> Optional[str]:
    """The COMMENT ON text and the code comment (when they differ) as one comment: COMMENT ON first,
    it is the authoritative one and survives the clipping of long comments."""
    texts = list(dict.fromkeys(part for part in parts if part))
    return '\n'.join(texts) or None


def _is_migration(path: str) -> bool:
    """A file of a migration history: versioned name, ``*.up.sql`` or a version directory's file."""
    name = posixpath.basename(path)
    return name.endswith('.up.sql') or VERSION.match(name) is not None or _in_version_directory(path)


class SqlParser(FileParser):
    """SQL schema migrations (PostgreSQL DDL) -> one ``table`` object per table of the final schema.

    The ``.sql`` files of one directory are one migration history (goose, golang-migrate,
    plain numbered scripts): they are replayed in version order and the tables left at the end
    become objects, with one field per column. Only the Up part of goose / sql-migrate files is
    read and ``*.down.sql`` / ``down.sql`` files are skipped. When every migration is a directory
    (Diesel / golang-migrate ``<version>_name/up.sql``, Prisma ``<timestamp>_name/migration.sql``)
    the sibling version directories are one history, replayed in the order of their names. A ``.sql`` file is read when it is a goose /
    sql-migrate / ``*.up.sql`` migration, lies under a directory named like ``migrations`` /
    ``migrate`` / ``db`` / ``schema``, or contains ``CREATE TABLE``. Different directories are
    different schemas. When a repository has migration histories (numbered or ``*.up.sql``
    files), directories without one (schema dumps such as ``structure.sql``) are skipped: they
    repeat the tables of the migrations. ClickHouse DDL, test data, seeds and data fixes are
    not read.
    """

    name = 'migrations'
    globs = ('*.sql',)
    prune_dirs = DEFAULT_PRUNE_DIRS | {'test', 'tests', 'testdata', 'fixtures', 'seeds', 'seed', 'datafixes',
                                       'benchmarks', 'examples', 'mocks'}
    # a table is the result of all the migrations of its directory
    objects_span_files = True

    stats: Optional[ReplayStats] = None    # counters of the last ``build_objects``

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._lines: Dict[str, List[str]] = {}     # source lines, for the comments above statements

    def accept_file(self, path, text):
        if DOWN_FILE.search(posixpath.basename(path)):
            return False
        directories = PurePosixPath(self.relpath(path)).parts[1:-1]
        if any(CLICKHOUSE_DIR.search(d) for d in directories) or CLICKHOUSE_ENGINE.search(text):
            return False
        return (path.endswith('.up.sql') or any(MIGRATION_DIR.fullmatch(d) for d in directories)
                or has_directions(text) or bool(CREATE_TABLE.search(text)))

    def parse_file(self, path, text):
        self._lines[self.relpath(path)] = text.splitlines()
        return split_statements(up_section(text))

    def build_objects(self, parsed) -> List[CodeObject]:

        by_directory = defaultdict(list)
        for file in parsed:
            by_directory[history_of(file)].append(file)
        histories = {d for d, files in by_directory.items() if any(_is_migration(f) for f in files)}
        if histories:
            by_directory = {d: files for d, files in by_directory.items() if d in histories}

        self.stats = ReplayStats(files=len(parsed))
        objects = []

        for directory, files in sorted(by_directory.items()):
            schema = Schema(self.stats)
            for file in sorted(files, key=migration_order):
                for line, sql in parsed[file]:
                    lines = self._lines.get(file, ())
                    schema.apply(sql, file, line, leading_comment(lines, line, trailing=False), lines)
            objects.extend(self._table_object(directory, table) for table in schema.tables.values())

        logger.info(f"migrations: {self.stats.summary()}; {len(objects)} tables")
        return objects

    def _table_object(self, directory: str, table: Table) -> CodeObject:
        properties = {'migrations': directory}
        if table.file:
            properties['created_in'] = table.file

        return CodeObject(
            hash=self.identity(directory, 'table', table.qualified_name),
            object_name=table.qualified_name,
            object_type='table',
            parser=self.parser,
            file=directory,
            line=table.line or 1,
            properties={name: CodeObjectProp(prop_name=name, prop_value=value) for name, value in properties.items()},
            fields={column.name: CodeObjectField(field_name=column.name, field_type=column.type,
                                                 file=column.file, line=column.line,
                                                 comment=_join(column.comment, column.code_comment),
                                                 samples=column.samples)
                    for column in table.columns.values()},
            comment=_join(table.comment, table.code_comment),
        )
