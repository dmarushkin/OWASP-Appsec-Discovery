"""Object identity (P1-8): ``CodeObject.hash`` depends only on parser, relative file,
object type and the object's logical name.

Shifting the code down by N lines and adding a field must keep every hash. This is
checked for every parser: hermetically on the recorded semgrep JSON for the semgrep
parsers, on real files for the file parsers, and (``semgrep`` marker) on real sources
run through the real rules.
"""
import copy
import json

import pytest

from appsec_discovery.models import object_identity
from appsec_discovery.parsers import ParserFactory
from appsec_discovery.parsers.base_parser import relative_source_path
from tests.golden_support import (ALL_PARSERS, FIXTURES_DIR, NATIVE_PARSERS, SEMGREP_PARSERS, load_semgrep_fixture,
                                  make_parser, parse_hermetic)

SHIFT = 17


def _hashes(objects):
    # names may repeat across object types / files (the type is not part of the name)
    return {(obj.object_type, obj.file, obj.object_name): obj.hash for obj in objects}


def _field_count(objects):
    return sum(len(obj.fields) for obj in objects)


def _lines(objects):
    return sorted(obj.line for obj in objects)


def _shift_lines(data, n):
    """Add ``n`` to every ``line`` in a semgrep result tree."""
    if isinstance(data, dict):
        return {k: (v + n if k == 'line' and isinstance(v, int) else _shift_lines(v, n)) for k, v in data.items()}
    if isinstance(data, list):
        return [_shift_lines(v, n) for v in data]
    return data


def _with_extra_field(results):
    """Clone the first DTO finding with a new field name (a field added to the structure)."""
    dto = next((r for r in results if r['extra'].get('metadata', {}).get('object_type') == 'dto'), None)
    if dto is None:
        return results
    extra = copy.deepcopy(dto)
    metavars = extra['extra']['metavars']
    field_var = '$DB_FIELD' if '$DB_FIELD' in metavars else '$FIELD'
    metavars[field_var]['abstract_content'] = 'added_field'
    extra['start']['line'] += 1
    return results + [extra]


# --- object_identity ---------------------------------------------------------

def test_object_identity_is_md5_of_its_parts():
    import hashlib
    assert object_identity('golang', '/a.go', 'dto', 'User') == hashlib.md5(b'golang#/a.go#dto#User').hexdigest()


@pytest.mark.parametrize('other', [
    ('python', '/a.go', 'dto', 'User'),
    ('golang', '/b.go', 'dto', 'User'),
    ('golang', '/a.go', 'route', 'User'),
    ('golang', '/a.go', 'dto', 'Users'),
])
def test_object_identity_depends_on_every_part(other):
    assert object_identity('golang', '/a.go', 'dto', 'User') != object_identity(*other)


# --- pinned identities of the golden samples -----------------------------------
#
# ``fixtures/identity_pins.json`` holds the hash of every golden sample object as computed
# before object names lost their type word (``legacy_name``: ``Rpc /pkg.S/Get``, ``Route /x
# (GET)``, ``Struct dto User``, ``Virtual machine vm.domain``...). The identity comes from the
# logical name, never from ``object_name``: renaming objects must not change any stored key.

IDENTITY_PINS = json.loads((FIXTURES_DIR / 'identity_pins.json').read_text())


def test_identity_pins_cover_every_parser():
    assert set(IDENTITY_PINS) == set(ALL_PARSERS)
    assert all(IDENTITY_PINS[name] for name in ALL_PARSERS)


@pytest.mark.parametrize('parser_name', sorted(ALL_PARSERS))
def test_golden_sample_identities_are_unchanged(parser_name):
    pins = IDENTITY_PINS[parser_name]
    objects = parse_hermetic(parser_name)
    assert sorted((o.object_type, o.file, o.object_name, o.hash) for o in objects) == \
        sorted((p['object_type'], p['file'], p['object_name'], p['hash']) for p in pins)


@pytest.mark.parametrize('parser_name', sorted(ALL_PARSERS))
def test_object_names_have_no_type_word(parser_name):
    for pin in IDENTITY_PINS[parser_name]:
        assert pin['object_name'] != pin['legacy_name'], pin
        assert not pin['object_name'].lower().startswith(pin['object_type'].replace('js-gql-', '') + ' '), pin


# --- hermetic: semgrep parsers on the recorded findings -----------------------

@pytest.mark.parametrize('parser_name', sorted(SEMGREP_PARSERS))
def test_semgrep_identity_ignores_line_shift_and_new_field(parser_name):
    parser = make_parser(parser_name)
    results = load_semgrep_fixture(parser_name)

    before = parser.parse_report(copy.deepcopy(results))
    after = parser.parse_report(_with_extra_field(_shift_lines(copy.deepcopy(results), SHIFT)))

    assert before
    assert _lines(after) == [line + SHIFT for line in _lines(before)]
    assert _hashes(after) == _hashes(before)
    if parser_name in ('golang', 'java', 'python'):
        assert _field_count(after) == _field_count(before) + 1


# --- file parsers on real files ------------------------------------------------

GRAPHQL_V1 = """type Money {
    units: Int
}

type Bank

extend type Query {
    bank: Bank!
}

extend type Bank {
    balance: Money
}
"""

GRAPHQL_V2 = "\n" * SHIFT + """# shifted
type Money {
    units: Int
    currency: String
}

type Bank

extend type Query {
    bank: Bank!
}

extend type Bank {
    balance(at: String): Money
}
"""

PROTO_V1 = """syntax = "proto3";
package demo.v1;
service Users {
  rpc Get (GetUserRequest) returns (User);
}
message GetUserRequest {
  int64 id = 1;
}
message User {
  int64 id = 1;
}
"""

PROTO_V2 = "\n" * SHIFT + """syntax = "proto3";
// shifted
package demo.v1;
service Users {
  rpc Get (GetUserRequest) returns (User);
}
message GetUserRequest {
  int64 id = 1;
  string tenant = 2;
}
message User {
  int64 id = 1;
  string email = 2;
}
"""

SWAGGER_V1 = """openapi: 3.0.0
info:
  title: Identity
  version: "1.0"
paths:
  /users:
    get:
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
      responses:
        "200":
          description: ok
"""

SWAGGER_V2 = "\n" * SHIFT + """# shifted
openapi: 3.0.0
info:
  title: Identity
  version: "1.0"
paths:
  /users:
    get:
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
        - name: email
          in: query
          schema:
            type: string
      responses:
        "200":
          description: ok
"""

FILE_SOURCES = {
    'graphql': ('schema.graphql', GRAPHQL_V1, GRAPHQL_V2),
    'protobuf': ('api/users.proto', PROTO_V1, PROTO_V2),
    'swagger': ('api/openapi.yaml', SWAGGER_V1, SWAGGER_V2),
    'migrations': ('migrations/00001_users.sql',
            'CREATE TABLE users (\n  id bigint,\n  name text\n);\n',
            '\n' * SHIFT + '-- shifted\nCREATE TABLE users (\n  id bigint,\n  name text,\n  email text\n);\n'),
    'javascript': ('src/query.js',
                   'const Q = gql`\n  query GetUser {\n    user {\n      id\n    }\n  }\n`;\n',
                   '\n' * SHIFT + '// shifted\nconst Q = gql`\n  query GetUser {\n    user {\n      id\n      email\n    }\n  }\n`;\n'),
    'terraform': ('main.tf',
                  'module "web" {\n  vm_name = "web"\n  vm_pool = "p1"\n}\n'
                  'resource "aws_s3_bucket" "logs" {\n  bucket = "logs"\n}\n',
                  '\n' * SHIFT + '# shifted\nmodule "web" {\n  vm_name = "web"\n  vm_pool = "p1"\n  vm_desc = "added"\n}\n'
                  'resource "aws_s3_bucket" "logs" {\n  bucket = "logs"\n  acl = "private"\n}\n'),
}


def _scan(parser_name, folder):
    cls = ParserFactory.get_parser(parser_name)
    return cls(parser=parser_name, source_folder=str(folder)).run_scan()


def _write(folder, rel, text):
    path = folder / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


@pytest.mark.parametrize('parser_name', sorted(NATIVE_PARSERS))
def test_file_parser_identity_ignores_line_shift_and_new_field(parser_name, tmp_path):
    rel, v1, v2 = FILE_SOURCES[parser_name]
    _write(tmp_path / 'v1', rel, v1)
    _write(tmp_path / 'v2', rel, v2)

    before = _scan(parser_name, tmp_path / 'v1')
    after = _scan(parser_name, tmp_path / 'v2')

    assert before
    assert _field_count(after) > _field_count(before)
    assert _hashes(after) == _hashes(before)
    # a sql table is the result of its whole migrations directory
    location = '/' + (rel.rsplit('/', 1)[0] if parser_name == 'migrations' else rel)
    assert all(obj.file == location for obj in after)


@pytest.mark.parametrize('parser_name', sorted(NATIVE_PARSERS))
def test_file_parser_identity_independent_of_source_folder_spelling(parser_name, tmp_path, monkeypatch):
    rel, v1, _ = FILE_SOURCES[parser_name]
    _write(tmp_path / 'proj', rel, v1)
    monkeypatch.chdir(tmp_path)

    spellings = [str(tmp_path / 'proj'), str(tmp_path / 'proj') + '/', 'proj', './proj', 'proj/']
    hashes = [_hashes(_scan(parser_name, s)) for s in spellings]
    assert all(h == hashes[0] for h in hashes)

    monkeypatch.chdir(tmp_path / 'proj')
    assert _hashes(_scan(parser_name, '.')) == hashes[0]  # '.' used to strip every dot of the path


def test_protobuf_object_file_is_the_service_file(tmp_path):
    _write(tmp_path, 'a_messages.proto', 'syntax = "proto3";\npackage demo;\nmessage Req { int64 id = 1; }\n')
    _write(tmp_path, 'b_service.proto', 'syntax = "proto3";\npackage demo;\nservice S { rpc Get (Req) returns (Req); }\n')

    [rpc] = _scan('protobuf', tmp_path)

    assert rpc.file == '/b_service.proto'
    assert rpc.hash == object_identity('protobuf', '/b_service.proto', 'rpc', '/demo.S/Get')
    assert rpc.fields['input.Req.id'].file == '/a_messages.proto'


def test_relative_source_path_dot_source(tmp_path, monkeypatch):
    (tmp_path / 'sub').mkdir()
    monkeypatch.chdir(tmp_path)
    assert relative_source_path(str(tmp_path / 'sub' / 'x.v1.proto'), '.') == '/sub/x.v1.proto'


# --- live semgrep: real rules over shifted sources -----------------------------

SEMGREP_SOURCES = {
    'golang': ('pkg/models.go',
               'package pkg\n\ntype User struct {\n    ID int\n    Name string\n}\n',
               '\n' * SHIFT + 'package pkg\n\n// shifted\ntype User struct {\n    ID int\n    Name string\n    Email string\n}\n'),
    'python': ('app.py',
               'import pydantic\nimport flask\n\nclass User(pydantic.BaseModel):\n    id: int\n\n'
               'app = flask.Flask(__name__)\n\n@app.route("/users", methods=["GET"])\ndef users():\n    return ""\n',
               '\n' * SHIFT + 'import pydantic\nimport flask\n\n\nclass User(pydantic.BaseModel):\n    id: int\n    email: str\n\n'
               'app = flask.Flask(__name__)\n\n\n@app.route("/users", methods=["GET"])\ndef users():\n    return ""\n'),
    'java': ('src/User.java',
             '@Table(name = "users")\npublic class User {\n    @Column(name = "id")\n    private Long id;\n}\n',
             '\n' * SHIFT + '@Table(name = "users")\npublic class User {\n    @Column(name = "id")\n    private Long id;\n\n'
             '    @Column(name = "email")\n    private String email;\n}\n'),
}


@pytest.mark.semgrep
@pytest.mark.parametrize('parser_name', sorted(SEMGREP_SOURCES))
def test_semgrep_identity_live(parser_name, tmp_path):
    rel, v1, v2 = SEMGREP_SOURCES[parser_name]
    _write(tmp_path / 'v1', rel, v1)
    _write(tmp_path / 'v2', rel, v2)

    before = _scan(parser_name, tmp_path / 'v1')
    after = _scan(parser_name, tmp_path / 'v2')

    assert before, json.dumps([o.dict() for o in before])
    assert _hashes(after) == _hashes(before)
    assert min(_lines(after)) > max(_lines(before))
    # the content did change (a field, property or the query text), only the identity did not
    def content(objects):
        return sorted(json.dumps(o.dict(exclude={'hash', 'line'}), sort_keys=True, default=str) for o in objects)
    assert content(after) != content(before)
