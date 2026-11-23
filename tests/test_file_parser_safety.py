"""``FileParser`` reading untrusted repositories: links, special files, size and encoding."""
import os
import time

import pytest

from appsec_discovery.parsers import ParserFactory
from appsec_discovery.parsers.base_parser import MAX_FILE_BYTES, read_text_file
from appsec_discovery.parsers.migrations.parser import SqlParser

CREATE = 'CREATE TABLE users (id int, email text);\n'


def tables(repo, **attrs):
    parser = ParserFactory.get_parser('migrations')(parser='migrations', source_folder=str(repo))
    for name, value in attrs.items():
        setattr(parser, name, value)
    return {obj.object_name: obj for obj in parser.run_scan()}


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / 'repo'
    (root / 'migrations').mkdir(parents=True)
    return root


def test_link_outside_of_the_repository_is_not_followed(tmp_path, repo):
    outside = tmp_path / 'outside.sql'
    outside.write_text('CREATE TABLE host_secrets (token text);')
    (repo / 'migrations' / '001_link.sql').symlink_to(outside)
    (repo / 'migrations' / '002_users.sql').write_text(CREATE)
    assert set(tables(repo)) == {'public.users'}


def test_link_inside_of_the_repository_is_read(repo):
    (repo / 'schema').mkdir()
    (repo / 'schema' / 'real.sql').write_text(CREATE)
    (repo / 'migrations' / '001_link.sql').symlink_to(repo / 'schema' / 'real.sql')
    assert 'public.users' in tables(repo)


@pytest.mark.skipif(not os.path.exists('/dev/zero'), reason='no /dev/zero')
def test_link_to_a_device_does_not_hang(repo):
    (repo / 'migrations' / '001_zero.sql').symlink_to('/dev/zero')
    (repo / 'migrations' / '002_users.sql').write_text(CREATE)
    started = time.perf_counter()
    assert set(tables(repo)) == {'public.users'}
    assert time.perf_counter() - started < 5


@pytest.mark.skipif(not hasattr(os, 'mkfifo'), reason='no FIFOs')
def test_fifo_is_not_read(repo):
    os.mkfifo(repo / 'migrations' / '001_pipe.sql')       # opening it would block forever
    (repo / 'migrations' / '002_users.sql').write_text(CREATE)
    assert set(tables(repo)) == {'public.users'}


def test_file_over_the_size_limit_is_skipped(repo):
    (repo / 'migrations' / '001_big.sql').write_text('CREATE TABLE big (id int);\n' + '-- x\n' * 100)
    (repo / 'migrations' / '002_users.sql').write_text(CREATE)
    assert set(tables(repo, max_file_bytes=200)) == {'public.users'}
    assert SqlParser.max_file_bytes == MAX_FILE_BYTES == 5 * 1024 * 1024


def test_non_utf8_file_is_read_with_replacement(repo):
    (repo / 'migrations' / '001_users.sql').write_bytes(
        '-- Clients: café, naïve, ß\nCREATE TABLE users (id int, document text);\n'.encode('cp1252'))
    (repo / 'migrations' / '002_add.sql').write_text('ALTER TABLE users ADD COLUMN phone text;\n')
    users = tables(repo)['public.users']
    assert list(users.fields) == ['id', 'document', 'phone']
    assert users.properties['created_in'].prop_value == '/migrations/001_users.sql'


def test_read_text_file_bom_and_line_ends(tmp_path):
    path = tmp_path / 'a.sql'
    path.write_bytes(b'\xef\xbb\xbfline1\r\nline2\rline3\n')
    assert read_text_file(path, tmp_path) == 'line1\nline2\nline3\n'


def test_read_text_file_outside_root(tmp_path):
    (tmp_path / 'root').mkdir()
    (tmp_path / 'other.txt').write_text('x')
    assert read_text_file(tmp_path / 'root' / '..' / 'other.txt', tmp_path / 'root') is None
    assert read_text_file(tmp_path / 'root' / 'missing.txt', tmp_path / 'root') is None


def test_semgrep_source_lines_do_not_follow_outside_links(tmp_path, repo):
    outside = tmp_path / 'outside.py'
    outside.write_text('# host secret\nTOKEN = 1\n')
    (repo / 'link.py').symlink_to(outside)
    (repo / 'own.py').write_text('# own\nX = 1\n')
    parser = ParserFactory.get_parser('python')(parser='python', source_folder=str(repo))
    assert parser.source_lines('/link.py') == []
    assert parser.source_lines('/own.py') == ['# own', 'X = 1']
