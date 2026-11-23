"""``comment`` / ``samples`` of the semgrep parsers (golang, java, python, terraform) and swagger.

Hermetic: semgrep findings are built by hand next to source files written into ``tmp_path``.
"""
import textwrap

from appsec_discovery.parsers.golang.parser import GolangParser, struct_tag_samples
from appsec_discovery.parsers.java.parser import JavaParser, annotation_samples
from appsec_discovery.parsers.python.parser import PythonParser, field_samples_from_source
from appsec_discovery.parsers.swagger.parser import SwaggerParser
from appsec_discovery.parsers.terraform.parser import TerraformParser


def finding(parser, object_type, path, line, metavars, end=None, **metadata):
    return {
        'check_id': f'appsec_discovery.parsers.{parser}.scanner_rules.rule-{object_type}',
        'path': path,
        'start': {'line': line},
        'end': {'line': end or line},
        'extra': {
            'metadata': {'parser': parser, 'object_type': object_type, **metadata},
            'metavars': {name: {'abstract_content': value, 'start': {'line': mv_line}}
                         for name, (value, mv_line) in metavars.items()},
        },
    }


def write(tmp_path, name, text):
    path = tmp_path / name.lstrip('/')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip('\n'))
    return name


def by_name(objects):
    return {obj.object_name: obj for obj in objects}


# --- golang -----------------------------------------------------------------------------------

GO_SOURCE = '''
package dto

// UserDTO is the public user profile.
// It is returned by GET /users.
type UserDTO struct {
    // ID of the user
    ID     int    `json:"id" example:"42"`
    Status string `json:"status" enums:"active,blocked" default:"active"` // account state
    //nolint:lll
    Email  string `json:"email"`
    /* Secret token,
       never logged */
    Token  string `json:"token" example:"tok_\\"x\\""`
}
'''


def go_findings(path):
    def f(field, line, type_='string'):
        return finding('golang', 'dto', path, line, {'$OBJECT': ('UserDTO', 5), '$FIELD': (field, line),
                                                     '$TYPE': (type_, line)}, framework='struct')
    return [f('ID', 7, 'int'), f('Status', 8), f('Email', 10), f('Token', 13)]


def test_golang_comments_and_samples(tmp_path):
    path = write(tmp_path, '/dto/user.go', GO_SOURCE)
    obj = GolangParser(source_folder=str(tmp_path)).parse_report(go_findings(path))[0]

    assert obj.comment == 'UserDTO is the public user profile.\nIt is returned by GET /users.'
    fields = obj.fields
    assert fields['ID'].comment == 'ID of the user'
    assert fields['ID'].samples == ['42']
    assert fields['Status'].comment == 'account state'
    assert fields['Status'].samples == ['active', 'blocked']  # enums, default deduplicated
    assert fields['Email'].comment is None  # directives are not documentation
    assert fields['Email'].samples is None
    assert fields['Token'].comment == 'Secret token,\nnever logged'
    assert fields['Token'].samples is None      # a secret-named field is never sampled (models.secrets)
    assert struct_tag_samples('Token string `example:"tok_\\"x\\""`') == ['tok_"x"']   # tag unescaped
    assert all(name == field.field_name for name, field in fields.items())


def test_struct_tag_samples():
    assert struct_tag_samples('X int `example:"1" default:"2"`') == ['1', '2']
    assert struct_tag_samples('X int `enums:"a, b,c"`') == ['a', 'b', 'c']
    assert struct_tag_samples('X int // example:"1"') == []
    assert struct_tag_samples('') == []


def test_missing_source_file_gives_no_docs(tmp_path):
    objects = GolangParser(source_folder=str(tmp_path)).parse_report(go_findings('/absent.go'))
    assert len(objects) == 1
    assert objects[0].comment is None
    assert all(f.comment is None and f.samples is None for f in objects[0].fields.values())


def test_unreadable_source_and_bad_lines_give_no_docs(tmp_path):
    (tmp_path / 'dir.go').mkdir()  # a directory where a file is expected
    write(tmp_path, '/short.go', 'package x\n')
    data = go_findings('/dir.go') + [
        finding('golang', 'dto', '/short.go', 99, {'$OBJECT': ('Short', 98), '$FIELD': ('A', 99),
                                                   '$TYPE': ('int', 99)}, framework='struct'),
    ]
    objects = GolangParser(source_folder=str(tmp_path)).parse_report(data)
    assert {o.object_name for o in objects} == {'UserDTO', 'Short'}
    assert all(o.comment is None for o in objects)


def test_source_file_is_read_once(tmp_path, monkeypatch):
    path = write(tmp_path, '/dto/user.go', GO_SOURCE)
    parser = GolangParser(source_folder=str(tmp_path))
    reads = []
    original = parser._read_source
    monkeypatch.setattr(parser, '_read_source', lambda p: reads.append(p) or original(p))
    parser.parse_report(go_findings(path))
    assert reads == [path]
    assert parser._source_cache == {}  # dropped after the parse


# --- java -------------------------------------------------------------------------------------

JAVA_SOURCE = '''
package models;

/**
 * Audio record of a call.
 */
@Entity
@Table(name = "audio")
public class AudioEntity {

    /** Sample rate in Hz */
    @Schema(description = "rate", example = "44100", allowableValues = {"8000", "44100"})
    @Column(name = "rate")
    public String getRate() { return rate; }

    @ApiModelProperty(allowableValues = "mono,stereo")
    @Column(name = "channels") // mono or stereo
    public String getChannels() { return channels; }

    @ApiModelProperty(allowableValues = "range[1, 5]", example = "2")
    @Column(name = "quality")
    public int getQuality() { return quality; }
}
'''


def java_finding(path, field, start, column_line, type_line, type_='String'):
    return finding('java', 'dto', path, start, {'$OBJECT': ('AudioEntity', 8), '$DB_NAME': ('"audio"', 7),
                                                '$DB_FIELD': (f'"{field}"', column_line),
                                                '$TYPE': (type_, type_line)},
                   end=type_line, framework='javax')


def test_java_comments_and_samples(tmp_path):
    path = write(tmp_path, '/models/Audio.java', JAVA_SOURCE)
    data = [java_finding(path, 'rate', 11, 12, 13), java_finding(path, 'channels', 15, 16, 17),
            java_finding(path, 'quality', 19, 20, 21, 'int')]
    obj = JavaParser(source_folder=str(tmp_path)).parse_report(data)[0]

    assert obj.comment == 'Audio record of a call.'
    assert obj.fields['rate'].comment == 'Sample rate in Hz'
    assert obj.fields['rate'].samples == ['44100', '8000']
    assert obj.fields['channels'].comment == 'mono or stereo'
    assert obj.fields['channels'].samples == ['mono', 'stereo']
    assert obj.fields['quality'].samples == ['2']  # a range is not a list of values
    assert obj.fields['rate'].line == 12  # the reported line is unchanged


def test_annotation_samples():
    assert annotation_samples('@Schema(example = "a\\"b")') == ['a\\"b']
    assert annotation_samples('@ApiParam(defaultValue = "10")') == ['10']
    assert annotation_samples('@Column(name = "x")') == []


# --- python -----------------------------------------------------------------------------------

PY_DTO = '''
from pydantic import BaseModel, Field


class User(BaseModel):
    """A registered user.

    Stored in the users table.
    """

    id: int = Field(..., example=42)
    # the login
    login: str = Field(examples=["alice", "bob"])
    role: str = Field("user", description="role")
    """Role of the user in the tenant."""
    age: int = 18
    token: str = Field(default=make_token())
    tags: list = Field(
        default=[],
        examples=[["a", "b"]],
    )
    """Free form labels."""


# Accounts table
class Account(Base):
    __tablename__ = "accounts"

    id = Column(Integer, primary_key=True, default=-1)
'''


def py_dto(path, obj, obj_line, field, field_line, start, framework='pydantic'):
    return finding('python', 'dto', path, start, {'$OBJECT': (obj, obj_line), '$FIELD': (field, field_line),
                                                  '$TYPE': ('str', field_line)}, framework=framework)


def test_python_dto_comments_and_samples(tmp_path):
    path = write(tmp_path, '/app/models.py', PY_DTO)
    data = [py_dto(path, 'User', 4, name, line, 4) for name, line in
            [('id', 10), ('login', 12), ('role', 13), ('age', 15), ('token', 16), ('tags', 17)]]
    data.append(py_dto(path, 'accounts', 25, 'id', 27, 27, framework='sqlalchemy'))
    objects = by_name(PythonParser(source_folder=str(tmp_path)).parse_report(data))

    user = objects['User']
    assert user.comment == 'A registered user.\nStored in the users table.'
    assert user.fields['id'].samples == ['42']
    assert user.fields['id'].line == 10  # the field's own line (a dataclass match starts at its decorator)
    assert user.fields['login'].comment == 'the login'
    assert user.fields['login'].samples == ['alice', 'bob']
    assert user.fields['role'].comment == 'Role of the user in the tenant.'
    assert user.fields['role'].samples == ['user']
    assert user.fields['age'].samples == ['18']
    assert user.fields['token'].samples is None  # a call is not a literal, nothing is executed
    assert user.fields['tags'].samples == ['a', 'b']
    assert user.fields['tags'].comment == 'Free form labels.'

    account = objects['accounts']
    assert account.comment == 'Accounts table'  # above the class, found from __tablename__
    assert account.fields['id'].samples == ['-1']


def test_python_field_samples_ignore_non_literals():
    assert field_samples_from_source(['x = Field(default=os.environ["X"])'], 1) == []
    assert field_samples_from_source(['x: int = compute()'], 1) == []
    assert field_samples_from_source(['x = Column(String, default="a")  # c'], 1) == ['a']
    assert field_samples_from_source(['    def broken(:'], 1) == []


PY_ROUTES = '''
from flask import Flask

app = Flask(__name__)

@app.route('/a')
def a():
    """Lists the accounts."""
    return 'a'

# Deletes everything
@app.route('/b', methods=['DELETE'])
@login_required
def b():
    return 'b'
'''


def test_python_route_comments(tmp_path):
    path = write(tmp_path, '/app/routes.py', PY_ROUTES)
    data = [
        finding('python', 'route', path, 3, {'$APP': ('app', 3), '$PATH': ('/a', 5), '$FUNC': ('a', 6)},
                framework='flask'),
        finding('python', 'route', path, 3, {'$APP': ('app', 3), '$PATH': ('/b', 11), '$FUNC': ('b', 13),
                                             '$METHOD': ('DELETE', 11)}, framework='flask'),
    ]
    objects = by_name(PythonParser(source_folder=str(tmp_path)).parse_report(data))
    assert objects['/a (a)'].comment == 'Lists the accounts.'
    assert objects['DELETE /b (b)'].comment == 'Deletes everything'


# --- terraform --------------------------------------------------------------------------------

TF_SOURCE = '''
# Keycloak node in dc1
module "kc01" {
  vm_name = "kc01"
  vm_pool = "app"
}

module "kc02" {
  vm_name = "kc02"
}
'''


def test_terraform_module_comment(tmp_path):
    write(tmp_path, '/main.tf', TF_SOURCE)
    objects = by_name(TerraformParser(source_folder=str(tmp_path)).run_scan())
    assert objects['kc01'].comment == 'Keycloak node in dc1'
    assert objects['kc01'].line == 3         # the vm_name line, as before
    assert objects['kc02'].comment is None


# --- swagger ----------------------------------------------------------------------------------

SWAGGER = '''
openapi: 3.0.3
info: {title: t, version: '1'}
paths:
  /users/{id}:
    parameters:
      - name: id
        in: path
        required: true
        description: User id
        example: 7
        schema: {type: integer}
    get:
      summary: Get a user
      description: Returns one user.
      parameters:
        - name: fields
          in: query
          examples:
            short: {value: id}
            long: {value: 'id,name'}
          schema: {type: string, title: Field list}
        - name: kind
          in: query
          x-example: admin
          schema: {type: string, enum: [admin, user], default: user}
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema: {$ref: '#/components/schemas/User'}
              examples:
                alice: {value: {name: alice, tags: [a, b]}}
components:
  schemas:
    User:
      type: object
      description: A user
      properties:
        name: {type: string, description: Login name, example: bob}
        state: {type: string, title: State, enum: [on, off]}
        tags:
          type: array
          description: Labels
          items: {type: string}
'''


def test_swagger_comments_and_samples(tmp_path):
    write(tmp_path, '/api.yaml', SWAGGER)
    obj = SwaggerParser(source_folder=str(tmp_path)).run_scan()[0]

    assert obj.object_name == 'GET /users/{id}'
    assert obj.comment == 'Get a user\nReturns one user.'
    fields = obj.fields
    assert fields['path.param.id'].comment == 'User id'
    assert fields['path.param.id'].samples == ['7']
    assert fields['query.param.fields'].comment == 'Field list'
    assert fields['query.param.fields'].samples == ['id', 'id,name']
    assert fields['query.param.kind'].samples == ['admin', 'user']
    assert fields['output.name'].comment == 'Login name'
    assert fields['output.name'].samples == ['bob', 'alice']
    assert fields['output.state'].comment == 'State'
    assert fields['output.state'].samples == ['on', 'off']
    assert fields['output.tags.'].comment == 'Labels'
    assert fields['output.tags.'].samples == ['a', 'b']
    assert all(name == field.field_name for name, field in fields.items())


def test_swagger_spec_without_raw_still_documents(tmp_path):
    """A spec parsed elsewhere (no raw dict): no parameter examples, the rest still filled."""
    from openapi_parser import parse

    path = tmp_path / 'api.yaml'
    path.write_text(textwrap.dedent(SWAGGER).lstrip('\n'))
    obj = SwaggerParser(source_folder=str(tmp_path)).parse_report({'/api.yaml': parse(str(path))})[0]
    assert obj.comment == 'Get a user\nReturns one user.'
    assert obj.fields['path.param.id'].samples is None
    assert obj.fields['query.param.kind'].samples == ['admin', 'user']
    assert obj.fields['output.name'].samples == ['bob', 'alice']

