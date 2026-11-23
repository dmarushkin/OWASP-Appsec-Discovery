"""SQL migrations parser: replay of DDL into the final tables of each migration directory."""
from pathlib import Path

import pytest

from appsec_discovery.models import object_identity
from appsec_discovery.parsers import ParserFactory
from appsec_discovery.parsers.migrations.parser import SqlParser, migration_order
from appsec_discovery.parsers.migrations.script import split_statements, up_section

SAMPLES = Path(__file__).resolve().parent / 'migrations_samples'


def scan(folder):
    parser = ParserFactory.get_parser('migrations')(parser='migrations', source_folder=str(folder))
    return parser, {obj.object_name: obj for obj in parser.run_scan()}


def scan_files(tmp_path, files):
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return scan(tmp_path)


def columns(obj):
    return {name: field.field_type for name, field in obj.fields.items()}


@pytest.fixture(scope='module')
def samples():
    return scan(SAMPLES)


# --- registry -------------------------------------------------------------------

def test_registered_as_sql():
    assert ParserFactory.get_parser('migrations') is SqlParser


# --- the samples folder ------------------------------------------------------------

def test_samples_final_tables(samples):
    _, tables = samples
    assert set(tables) == {
        'public.clients', 'billing.accounts', 'public.payments', 'public.payment_imports',
        'public.reports',
    }
    for obj in tables.values():
        assert obj.object_type == 'table' and obj.parser == 'migrations'
        assert all(name == field.field_name for name, field in obj.fields.items())


def test_create_alter_rename_and_comments(samples):
    _, tables = samples
    clients = tables['public.clients']
    assert columns(clients) == {
        'id': 'bigserial', 'name': 'varchar(255)', 'email': 'varchar(320)', 'created_at': 'timestamptz',
        'phone': 'varchar(20)', 'passport_number': 'text',
    }
    assert clients.file == '/migrations/accounts'
    assert clients.line == 3
    assert clients.hash == object_identity('migrations', '/migrations/accounts', 'table', 'public.clients')
    props = {name: prop.prop_value for name, prop in clients.properties.items()}
    assert props == {
        'migrations': '/migrations/accounts',
        'created_in': '/migrations/accounts/00001_create_clients.sql',
    }
    # COMMENT ON TABLE / COLUMN go to the comments of the object and its fields
    assert clients.comment == 'Bank clients'
    assert clients.fields['passport_number'].comment == 'Identity document number'
    # a column keeps the file and line of the statement that added it
    phone = clients.fields['phone']
    assert (phone.file, phone.line) == ('/migrations/accounts/00003_alter_clients.sql', 2)


def test_schema_qualified_table_and_types(samples):
    _, tables = samples
    accounts = tables['billing.accounts']
    assert columns(accounts) == {'id': 'uuid', 'client_id': 'bigint', 'balance': 'numeric(20,2)', 'currency': 'char(3)'}
    assert accounts.line == 2


def test_partitions_are_part_of_the_parent(samples):
    _, tables = samples
    payments = tables['public.payments']
    # sqlglot rejects ``bigint array``: the regex fallback reads the statement
    assert columns(payments) == {'id': 'bigint', 'account_id': 'uuid', 'amount': 'numeric(20,2)',
                                 'card_pan': 'bigint[]', 'created_at': 'timestamptz'}
    assert not any('payments_20' in name for name in tables)


def test_rename_and_drop_table(samples):
    _, tables = samples
    assert columns(tables['public.payment_imports']) == {'id': 'int', 'payload': 'jsonb'}
    assert 'public.import_buffer' not in tables
    assert 'public.legacy_transfers' not in tables


def test_golang_migrate_up_files_only(samples):
    _, tables = samples
    reports = tables['public.reports']
    # quoted identifiers keep their case; DROP COLUMN of a later file applies
    assert columns(reports) == {'id': 'serial', 'Owner': 'varchar(64)', 'status': 'smallint'}
    assert reports.file == '/migrations/reporting'


def test_sql_outside_migration_dirs_needs_create_table(samples):
    parser, tables = samples
    # queries/schema_dump.sql is read (it has CREATE TABLE) but, next to migration histories,
    # a directory without one is a dump of the same schema: no objects. select_clients.sql is not read.
    assert parser.stats.files == 7
    assert not any(obj.file == '/queries' for obj in tables.values())


def test_broken_statement_is_counted_not_fatal(samples):
    parser, _ = samples
    assert parser.stats.failed == 1
    assert parser.stats.fallback >= 2          # ATTACH PARTITION, DROP TABLE a, b
    assert parser.stats.parsed > 10


# --- statement kinds and replay rules ----------------------------------------------

def test_goose_down_part_is_ignored(tmp_path):
    _, tables = scan_files(tmp_path, {'migrations/1_x.sql': (
        '-- +goose Up\nCREATE TABLE clients (id int);\n'
        '-- +goose Down\nDROP TABLE clients;\nCREATE TABLE down_only (id int);\n'
    )})
    assert set(tables) == {'public.clients'}


def test_statement_begin_end_block_with_several_statements(tmp_path):
    _, tables = scan_files(tmp_path, {'migrations/1_x.sql': (
        '-- +goose Up\n-- +goose StatementBegin\n'
        'CREATE TABLE a (id int);\n'
        "DO $body$ BEGIN PERFORM 1; RAISE NOTICE 'x;y'; END $body$;\n"
        'CREATE TABLE b (id int);\n'
        '-- +goose StatementEnd\n'
    )})
    assert set(tables) == {'public.a', 'public.b'}
    assert tables['public.b'].line == 5


def test_files_replayed_by_numeric_version(tmp_path):
    _, tables = scan_files(tmp_path, {
        'migrations/10_rename.sql': 'ALTER TABLE clients RENAME COLUMN login TO email;',
        'migrations/2_add.sql': 'ALTER TABLE clients ADD COLUMN login text;',
        'migrations/1_create.sql': 'CREATE TABLE clients (id int);',
    })
    assert columns(tables['public.clients']) == {'id': 'int', 'email': 'text'}


def test_migration_order():
    names = ['/m/20240101120000_b.sql', '/m/schema.sql', '/m/00002_a.sql', '/m/2_b.sql', '/m/V1__init.sql']
    assert sorted(names, key=migration_order) == [
        '/m/V1__init.sql', '/m/00002_a.sql', '/m/2_b.sql', '/m/20240101120000_b.sql', '/m/schema.sql']


def test_rename_and_drop_chains(tmp_path):
    _, tables = scan_files(tmp_path, {'db/1_x.sql': (
        'CREATE TABLE t1 (a int, b int, c int);\n'
        'ALTER TABLE t1 RENAME COLUMN a TO a2;\n'
        'ALTER TABLE t1 RENAME COLUMN a2 TO a3;\n'
        'ALTER TABLE t1 DROP COLUMN IF EXISTS b;\n'
        'ALTER TABLE t1 RENAME TO t2;\n'
        'ALTER TABLE t2 RENAME TO t3;\n'
        'ALTER TABLE t3 ALTER COLUMN c TYPE bigint;\n'
        'CREATE TABLE t1 (z int);\n'
        'DROP TABLE t1;\n'
    )})
    assert set(tables) == {'public.t3'}
    # column order is kept through renames
    assert list(columns(tables['public.t3']).items()) == [('a3', 'int'), ('c', 'bigint')]
    assert tables['public.t3'].line == 1


def test_create_if_not_exists_keeps_existing_table(tmp_path):
    _, tables = scan_files(tmp_path, {'migrations/1_x.sql': (
        'CREATE TABLE t (a int);\nCREATE TABLE IF NOT EXISTS t (b int);\n'
    )})
    assert columns(tables['public.t']) == {'a': 'int'}


def test_create_table_as_and_like(tmp_path):
    _, tables = scan_files(tmp_path, {'migrations/1_x.sql': (
        'CREATE TABLE clients (id bigint, email text);\n'
        'CREATE TABLE clients_copy AS SELECT * FROM clients;\n'
        'CREATE TABLE clients_archive (LIKE clients INCLUDING ALL, archived_at timestamptz);\n'
    )})
    assert columns(tables['public.clients_copy']) == {}
    assert columns(tables['public.clients_archive']) == {'id': 'bigint', 'email': 'text',
                                                               'archived_at': 'timestamptz'}


def test_add_column_to_table_created_elsewhere(tmp_path):
    _, tables = scan_files(tmp_path, {'migrations/1_x.sql': 'ALTER TABLE clients ADD COLUMN email text;'})
    obj = tables['public.clients']
    assert columns(obj) == {'email': 'text'}
    assert obj.line == 1 and 'created_in' not in obj.properties


def test_two_directories_are_two_schemas(tmp_path):
    parser, _ = scan_files(tmp_path, {
        'migrations/shard_a/1_x.sql': 'CREATE TABLE clients (id int);',
        'migrations/shard_b/1_x.sql': 'CREATE TABLE clients (id int, email text);',
    })
    by_dir = {obj.file: obj for obj in parser.run_scan()}
    assert set(by_dir) == {'/migrations/shard_a', '/migrations/shard_b'}
    assert {obj.object_name for obj in by_dir.values()} == {'public.clients'}
    assert by_dir['/migrations/shard_a'].hash != by_dir['/migrations/shard_b'].hash
    assert columns(by_dir['/migrations/shard_b']) == {'id': 'int', 'email': 'text'}


def test_unparsable_statements_fall_back_or_are_skipped(tmp_path):
    parser, tables = scan_files(tmp_path, {'migrations/1_x.sql': (
        'CREATE TABLE cards (id bigint, numbers bigint array NOT NULL, "Holder" text);\n'
        'ALTER TABLE cards ADD CONSTRAINT cards_pkey PRIMARY KEY USING INDEX cards_idx;\n'
        'ALTER TABLE cards WHATEVER;\n'
        'ALTER TABLE cards ADD COLUMN cvv_hash text;\n'
    )})
    assert columns(tables['public.cards']) == {'id': 'bigint', 'numbers': 'bigint[]', 'Holder': 'text',
                                                     'cvv_hash': 'text'}
    # ``bigint array`` is rewritten to ``bigint[]`` before sqlglot; USING INDEX goes to the fallback
    assert (parser.stats.parsed, parser.stats.fallback, parser.stats.failed) == (2, 1, 1)


def test_non_table_statements_are_not_counted(tmp_path):
    parser, _ = scan_files(tmp_path, {'migrations/1_x.sql': (
        'CREATE INDEX i ON t (a);\nGRANT SELECT ON t TO reader;\nINSERT INTO t VALUES (1);\n'
    )})
    assert parser.stats.statements == 0


# --- text helpers ------------------------------------------------------------------

def test_split_statements_respects_quotes_and_comments():
    text = ("-- leading; comment\nCREATE TABLE a (x text DEFAULT 'a;b');\n"
            "/* block; */ CREATE TABLE \"b;c\" (y int);\nSELECT $$;$$")
    assert split_statements(text) == [
        (2, "CREATE TABLE a (x text DEFAULT 'a;b')"),
        (3, 'CREATE TABLE "b;c" (y int)'),
        (4, 'SELECT $$;$$'),
    ]


def test_up_section_keeps_line_numbers():
    text = '-- +goose Down\nDROP TABLE a;\n-- +goose Up\nCREATE TABLE a (id int);\n'
    assert up_section(text).splitlines() == ['', '', '', 'CREATE TABLE a (id int);']
    assert up_section('CREATE TABLE a (id int);') == 'CREATE TABLE a (id int);'


# -- regressions found on real migration histories --------------------------------------------

def _tables(tmp_path, files):
    from appsec_discovery.parsers.migrations.parser import SqlParser
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return {o.object_name: o for o in SqlParser(parser='migrations', source_folder=str(tmp_path)).run_scan()}


def test_comments_inside_create_table_are_not_columns(tmp_path):
    tables = _tables(tmp_path, {'migrations/00001_jobs.sql': '''-- +goose Up
CREATE TABLE jobs (
    id      BIGSERIAL PRIMARY KEY,
    -- request_id: correlation id, used by the API, for polling
    request_id UUID NOT NULL UNIQUE,
    /* trigger: manual, scheduled */
    trigger TEXT NOT NULL CHECK (trigger IN ('manual', 'scheduled')),
    status  TEXT NOT NULL   -- queued, running, done
);
'''})
    assert list(tables['public.jobs'].fields) == ['id', 'request_id', 'trigger', 'status']


def test_alter_actions_without_column_keyword_and_mixed_actions(tmp_path):
    tables = _tables(tmp_path, {
        'migrations/00001_init.sql': 'CREATE TABLE counters (id bigint, kind text, legacy bigint, old_name text, ids int);',
        'migrations/00002_drop.sql': '-- +goose Up\n-- +goose StatementBegin\nALTER TABLE counters DROP legacy;\n-- +goose StatementEnd\n',
        'migrations/00003_mixed.sql': '''ALTER TABLE counters
    DROP CONSTRAINT counters_pkey,
    DROP COLUMN id,
    RENAME COLUMN old_name TO new_name,
    ADD CONSTRAINT counters_pkey PRIMARY KEY (kind);''',
        'migrations/00004_type.sql': '''ALTER TABLE counters
    ALTER COLUMN kind TYPE SMALLINT USING (CASE kind WHEN 'a' THEN 1 ELSE 2 END),
    ALTER COLUMN ids SET DATA TYPE int ARRAY;''',
        'migrations/00005_rename.sql': 'ALTER TABLE counters RENAME TO tariff_counters;',
    })
    fields = {k: f.field_type for k, f in tables['public.tariff_counters'].fields.items()}
    assert fields == {'kind': 'smallint', 'new_name': 'text', 'ids': 'int[]'}


def test_array_keyword_is_an_array_type(tmp_path):
    tables = _tables(tmp_path, {'migrations/00001_a.sql': '''CREATE TABLE docs (codes int array, ids VARCHAR(50) ARRAY,
    tags text[] DEFAULT ARRAY[]::text[]);
ALTER TABLE docs ADD COLUMN extra bigint ARRAY;'''})
    assert {k: f.field_type for k, f in tables['public.docs'].fields.items()} == {
        'codes': 'int[]', 'ids': 'varchar(50)[]', 'tags': 'text[]', 'extra': 'bigint[]'}


def test_comment_with_adjacent_literals(tmp_path):
    tables = _tables(tmp_path, {'migrations/00001_a.sql': '''CREATE TABLE members (method text);
COMMENT ON TABLE members IS
    'Registry of members; '
    'one active row per pair.';
COMMENT ON COLUMN public.members.method IS 'How it''s ' 'included';'''})
    members = tables['public.members']
    assert members.comment == 'Registry of members; one active row per pair.'
    assert members.fields['method'].comment == "How it's included"


def test_clickhouse_test_data_and_dumps_next_to_migrations_are_skipped(tmp_path):
    tables = _tables(tmp_path, {
        'migrations/00001_users.sql': 'CREATE TABLE users (id bigint);',
        'structure.sql': 'CREATE TABLE users (id bigint); CREATE TABLE schema_migrations (version bigint);',
        'db/clickhouse/00001_events.sql': 'CREATE TABLE events (id UInt64) ENGINE = MergeTree ORDER BY id;',
        'migrations_ch/00001_stats.sql': 'CREATE TABLE stats (id UInt64);',
        'db/migrations/00002_kafka.sql': "CREATE TABLE q (id UInt64) ENGINE = Kafka SETTINGS kafka_broker_list = 'x';",
        'internal/testdata/00001_fixture.sql': 'CREATE TABLE fixture (id int);',
        'datafixes/00001_fix.sql': 'CREATE TABLE tmp_fix (id int);',
    })
    assert set(tables) == {'public.users'} and tables['public.users'].file == '/migrations'


def test_a_dump_alone_is_read(tmp_path):
    tables = _tables(tmp_path, {'db/schema.sql': 'CREATE TABLE users (id bigint, email text);'})
    assert list(tables) == ['public.users']



def test_code_comments_and_samples(tmp_path):
    tables = _tables(tmp_path, {'migrations/00001_cards.sql': '''-- +goose Up
-- +goose StatementBegin
-- Payment cards of clients
CREATE TABLE cards (
    id      BIGSERIAL PRIMARY KEY,
    -- masked PAN, first 6 and last 4 digits
    pan     TEXT NOT NULL,
    status  TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'blocked', 'closed')),
    kind    SMALLINT NOT NULL DEFAULT 1, -- 1 debit, 2 credit
    CONSTRAINT kind_ck CHECK (kind IN (1, 2))
);
-- +goose StatementEnd
COMMENT ON COLUMN cards.pan IS 'card number';
ALTER TABLE cards ADD COLUMN holder TEXT; -- name on the card
-- the issue date
ALTER TABLE cards
    ADD COLUMN issued_at timestamptz;
-- +goose Down
DROP TABLE cards;
'''})
    cards = tables['public.cards']
    assert cards.comment == 'Payment cards of clients'        # goose directives are not comments
    docs = {name: (f.comment, f.samples) for name, f in cards.fields.items()}
    assert docs == {
        'id': (None, None),
        'pan': ('card number\nmasked PAN, first 6 and last 4 digits', None),   # COMMENT ON first
        'status': (None, ['active', 'blocked', 'closed']),
        'kind': ('1 debit, 2 credit', ['1', '2']),
        'holder': ('name on the card', None),           # after the ``;`` of a one-line ALTER
        'issued_at': ('the issue date', None),           # above an ALTER that adds one column
    }



def test_samples_from_alter_and_like_options(tmp_path):
    tables = _tables(tmp_path, {
        'migrations/00001_a.sql': '''-- Payments service schema, generated by a tool
-- +goose Up
CREATE TABLE orders (status text, flag boolean NOT NULL DEFAULT TRUE, n int, items jsonb);
COMMENT ON COLUMN orders.items IS 'JSONB array of items';
ALTER TABLE orders ADD CONSTRAINT status_ck CHECK (status IN ('new', 'done'));
ALTER TABLE orders ALTER COLUMN flag SET DEFAULT false, ALTER COLUMN n SET DEFAULT 0;
ALTER TABLE orders RENAME TO orders_old;
CREATE TABLE orders (LIKE orders_old INCLUDING DEFAULTS);
CREATE TABLE orders_copy (LIKE orders_old INCLUDING ALL);
'''})
    old = tables['public.orders_old']
    assert old.comment is None                       # the file header above ``+goose Up`` is not the table's
    assert {n: f.samples for n, f in old.fields.items()} == {
        'status': ['new', 'done'], 'flag': ['false'], 'n': ['0'], 'items': None}
    assert old.fields['items'].comment == 'JSONB array of items'     # ``array`` in a string is text
    new = tables['public.orders']
    assert new.fields['flag'].samples == ['false'] and new.fields['status'].samples is None   # defaults only
    assert new.fields['items'].comment is None                      # no INCLUDING COMMENTS
    copy = tables['public.orders_copy']
    assert copy.fields['status'].samples == ['new', 'done'] and copy.fields['items'].comment == 'JSONB array of items'


# --- one migration per directory (Diesel, golang-migrate dirs, Prisma) ----------------

def test_version_directories_are_one_history(tmp_path):
    parser, _ = scan_files(tmp_path, {
        'migrations/00000000000000_initial_setup/up.sql': 'CREATE TABLE settings (k text);',
        'migrations/00000000000000_initial_setup/down.sql': 'DROP TABLE settings;',
        'migrations/2024-01-01-000000_create_users/up.sql': 'CREATE TABLE users (id int, email text);',
        'migrations/2024-01-01-000000_create_users/down.sql': 'DROP TABLE users;',
        'migrations/2024-02-01-000000_add_document/up.sql': 'ALTER TABLE users ADD COLUMN document text;',
        'migrations/2024-02-01-000000_add_document/down.sql': 'ALTER TABLE users DROP COLUMN document;',
        'migrations/2024-03-01-000000_drop_settings/up.sql': 'DROP TABLE settings;',
        'migrations/2024-03-01-000000_drop_settings/down.sql': 'CREATE TABLE settings (k text);',
    })
    objects = parser.run_scan()
    assert [(obj.object_name, obj.file) for obj in objects] == [('public.users', '/migrations')]
    users = objects[0]
    assert columns(users) == {'id': 'int', 'email': 'text', 'document': 'text'}
    assert users.properties['created_in'].prop_value == '/migrations/2024-01-01-000000_create_users/up.sql'
    assert users.fields['document'].file == '/migrations/2024-02-01-000000_add_document/up.sql'


def test_prisma_migration_directories(tmp_path):
    _, tables = scan_files(tmp_path, {
        'prisma/migrations/20240101120000_init/migration.sql': 'CREATE TABLE "Account" ("id" int, "login" text);',
        'prisma/migrations/20240301120000_drop_login/migration.sql': 'ALTER TABLE "Account" DROP COLUMN "login";',
        'prisma/migrations/20240201120000_add_phone/migration.sql': 'ALTER TABLE "Account" ADD COLUMN "phone" text;',
        'prisma/migrations/migration_lock.toml': 'provider = "postgresql"',
    })
    assert set(tables) == {'public.Account'}
    assert tables['public.Account'].file == '/prisma/migrations'
    assert columns(tables['public.Account']) == {'id': 'int', 'phone': 'text'}


def test_down_sql_is_skipped(tmp_path):
    _, tables = scan_files(tmp_path, {
        'migrations/1_x.sql': 'CREATE TABLE a (id int);',
        'migrations/down.sql': 'DROP TABLE a;',
        'migrations/2_x.down.sql': 'DROP TABLE a;',
    })
    assert set(tables) == {'public.a'}


# --- ReDoS: adversarial statements must parse in linear time ------------------------

def _timed_scan(tmp_path, text):
    import time
    started = time.perf_counter()
    result = scan_files(tmp_path, {'migrations/001_x.sql': text})
    return result, time.perf_counter() - started


@pytest.mark.parametrize('text', [
    # ``-?\d+`` repeated: a digit run split into numbers in 2^n ways
    'CREATE TABLE users (id int, status int CHECK (status in (' + '1' * 60 + 'x)));',
    'ALTER TABLE users ADD CONSTRAINT c CHECK (status IN (' + '1' * 60 + 'x));',
    # ``''`` as an escaped quote or as the end + start of two adjacent literals
    "COMMENT ON TABLE users IS '" + "''" * 60 + " x;",
    "COMMENT ON TABLE users IS " + "'a'" * 60 + "x;",
    # quadratic: whitespace runs and long words entered by a search at every position
    'ALTER TABLE users ALTER COLUMN c TYPE int' + ' ' * 50_000 + 'y;',
    'DROP TABLE users' + ' ' * 50_000 + 'y;',
    'CREATE TABLE users (c int' + ' ' * 50_000 + 'x);',
    'CREATE TABLE users (c ' + 'a' * 50_000 + ');',
    'CREATE TABLE users (c int CHECK (c' + ' ' * 50_000 + 'x));',
    'CREATE TABLE users (c bigint' + ' ' * 50_000 + 'array);',
])
def test_adversarial_statements_are_fast(tmp_path, text):
    _, elapsed = _timed_scan(tmp_path, text)
    assert elapsed < 1.0


def test_check_in_and_comment_literals_still_parsed(tmp_path):
    _, tables = scan_files(tmp_path, {'migrations/1_x.sql': (
        "CREATE TABLE t (s text CHECK (s IN ('a', 'it''s', 'b',)), n int CHECK (n::int in (1, -2.5 ,3)), "
        "f boolean CHECK (f IN (true, false)));\n"
        "COMMENT ON TABLE t IS 'one' 'two''s';\n"
    )})
    table = tables['public.t']
    assert table.fields['s'].samples == ['a', "it's", 'b']
    assert table.fields['n'].samples == ['1', '-2.5', '3']
    assert table.fields['f'].samples == ['true', 'false']
    assert table.comment == "onetwo's"
