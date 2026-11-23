"""``comment`` of objects / fields and ``samples`` of fields filled by the schema parsers."""

from appsec_discovery.models import CodeObject, CodeObjectField
from appsec_discovery.models.code_object import COMMENT_MAX, SAMPLES_MAX
from appsec_discovery.parsers.comments import leading_comment
from appsec_discovery.parsers.graphql.parser import GraphqlParser
from appsec_discovery.parsers.javascript.parser import JsGqlParser
from appsec_discovery.parsers.protobuf.parser import ProtobufParser


def _scan(cls, name, tmp_path, files):
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return cls(parser=name, source_folder=str(tmp_path)).run_scan()


def _docs(obj):
    return {name: (f.comment, f.samples) for name, f in obj.fields.items()}


def test_model_clips_and_drops_empty_values():
    field = CodeObjectField(field_name='a', field_type='t', comment='  x \n\n  y  ', samples=['1', 1, '', None, True])
    assert field.comment == 'x\ny' and field.samples == ['1', 'true']
    assert CodeObjectField(field_name='a', field_type='t', comment='  ', samples=[]).comment is None
    long = CodeObjectField(field_name='a', field_type='t', comment='c' * 5000, samples=[str(i) for i in range(20)])
    assert len(long.comment) == COMMENT_MAX and len(long.samples) == SAMPLES_MAX
    obj = CodeObject(hash='h', object_name='o', object_type='t', parser='p', file='/f', line=1,
                     properties={}, fields={}, comment=None)
    assert 'comment' not in obj.dict(exclude_none=True)          # snapshots without comments are unchanged


def test_leading_comment_styles():
    lines = ['// Client', '// of the bank', 'type C struct {', '\t// PAN', '\tPan string // masked',
             '', '\t//nolint:lll', '\tName string', '\t/**', '\t * Phone', '\t */', '\t@Json', '\tPhone string']
    assert leading_comment(lines, 3) == 'Client\nof the bank'
    assert leading_comment(lines, 5) == 'PAN\nmasked'
    assert leading_comment(lines, 8) is None                   # directives are not documentation
    assert leading_comment(lines, 13) == 'Phone'               # javadoc above an annotation
    assert leading_comment(lines, 99) is None


PROTO = '''syntax = "proto3";
package bank.v1;

service Cards {
  // Issue a card to a client.
  rpc Issue (IssueRequest) returns (Card) { option (google.api.http) = { post: "/v1/cards" }; }
}

message IssueRequest {
  // client id in CRM
  string client_id = 1 [json_name = "clientId"];
  Kind kind = 2; // card kind
  oneof doc {
    /* passport series and number */
    string passport = 3;
  }
  message Inner { int64 id = 1; } // inner id
  Inner inner = 5;
  enum Kind { KIND_UNSPECIFIED = 0; DEBIT = 1; CREDIT = 2; }
}
message Card { string pan = 1; Status status = 2; }
enum Status { STATUS_UNSPECIFIED = 0; ACTIVE = 1; BLOCKED = 2; }
'''


def test_protobuf_comments_lines_and_enum_samples(tmp_path):
    (rpc,) = _scan(ProtobufParser, 'protobuf', tmp_path, {'api/cards.proto': PROTO})
    assert (rpc.comment, rpc.line) == ('Issue a card to a client.', 6)
    assert _docs(rpc) == {
        'input.IssueRequest.client_id': ('client id in CRM', None),
        'input.IssueRequest.kind': ('card kind', ['DEBIT', 'CREDIT', 'KIND_UNSPECIFIED']),   # the 0 value last
        'input.IssueRequest.passport': ('passport series and number', None),
        'input.IssueRequest.inner.Inner.id': ('inner id', None),
        'output.Card.pan': (None, None),
        'output.Card.status': (None, ['ACTIVE', 'BLOCKED', 'STATUS_UNSPECIFIED']),
    }


GRAPHQL = '''
"Client card"
type Card {
  # masked PAN
  pan: String
  status: CardStatus # current status
}
enum CardStatus { ACTIVE BLOCKED }
input CardFilter {
  "status to filter by"
  status: CardStatus = ACTIVE
  limit: Int = 10
}
type Query {
  # list client cards
  """
  Cards of a client.
  """
  cards(
    "CRM client id"
    clientId: ID!
    filter: CardFilter
    kind: CardStatus = BLOCKED
  ): [Card]
}
'''


def test_graphql_descriptions_comments_defaults_and_enums(tmp_path):
    (op,) = _scan(GraphqlParser, 'graphql', tmp_path, {'schema.graphql': GRAPHQL})
    assert op.comment == 'list client cards\nCards of a client.'
    assert _docs(op) == {
        'clientId': ('CRM client id', None),
        'filter.status': ('status to filter by', ['ACTIVE', 'BLOCKED']),
        'filter.limit': (None, ['10']),
        'kind': (None, ['BLOCKED', 'ACTIVE']),                  # the default first
        'output.pan': ('masked PAN', None),
        'output.status': ('current status', ['ACTIVE', 'BLOCKED']),
    }


def test_javascript_comments_and_literal_samples(tmp_path):
    (op,) = _scan(JsGqlParser, 'javascript', tmp_path, {'src/cards.ts': '''import gql from 'graphql-tag';

// Loads the client cards for the profile page
export const Q = gql`
  query Cards($id: ID!, $limit: Int = 20) {
    # cards of the client
    cards(clientId: $id, limit: $limit, kind: DEBIT, tags: ["a", "b"]) {
      pan # masked
      # holder name
      holder
    }
  }
`;'''})
    assert op.comment == 'Loads the client cards for the profile page\ncards of the client'
    assert _docs(op) == {
        'input.clientId': (None, None),
        'input.limit': (None, ['20']),                          # the variable default
        'input.kind': (None, ['DEBIT']),
        'input.tags': (None, ['"a"', '"b"']),
        'output.pan': ('masked', None),
        'output.holder': ('holder name', None),                 # ``# masked`` belongs to pan only
    }


def test_graphql_comment_edge_cases(tmp_path):
    (first, second) = sorted(_scan(GraphqlParser, 'graphql', tmp_path, {'schema.graphql': '''
type Mutation {
  "Checks the operation"
  # one request a second: the answer reveals the recipient
  # lint-disable mask-directive
  check(id: ID!): Boolean

  # -- section header --

  "Opens an account"
  open(
    # lint-enable mask-directive
    pin: String
  ): Boolean
}'''}), key=lambda o: o.object_name)
    assert first.comment == 'Checks the operation\none request a second: the answer reveals the recipient'
    assert second.comment == 'Opens an account'          # the header above a blank line is no one's
    assert second.fields['pin'].comment is None            # tool directives are not documentation


def test_javascript_duplicated_selection_keeps_its_comment_and_list_variables(tmp_path):
    (op,) = _scan(JsGqlParser, 'javascript', tmp_path, {'q.ts': '''const F = gql`fragment UserF on User { id name # the name
}`;
const Q = gql`query Q($n: Int = 7) {
  users(ids: [1, 2, $n]) {
    id # the id
    ...UserF
    name
  }
}`;'''})
    assert op.fields['output.id'].comment == 'the id' and op.fields['output.name'].comment == 'the name'
    assert op.fields['input.ids'].samples == ['1', '2', '7']


def test_protobuf_nested_options_and_one_line_messages(tmp_path):
    (rpc,) = _scan(ProtobufParser, 'protobuf', tmp_path, {'a.proto': '''syntax = "proto3";
service S { rpc Get (Outer) returns (Doc); }
message Outer {
  message Inner {
    string a = 1 [(v.rules).string = {in: ["x", "y"]}];
    // inner b
    string b = 2;
  }
  // outer x
  string x = 3 [
    (v.rules).string = {min_len: 1}
  ];
  string d = 4;// YYYY-MM-DD
  Inner inner = 5;
}
// about the message
message Doc { string id = 1; string kind = 2; // the kind
}
'''})
    docs = {k: f.comment for k, f in rpc.fields.items()}
    assert docs == {'input.Outer.x': 'outer x', 'input.Outer.d': 'YYYY-MM-DD',
                    'input.Outer.inner.Inner.a': None, 'input.Outer.inner.Inner.b': 'inner b',
                    'output.Doc.id': None, 'output.Doc.kind': 'the kind'}


# --- ReDoS: the comment regexes run on every source line ------------------------------

import time  # noqa: E402

import pytest  # noqa: E402

from appsec_discovery.parsers.comments import trailing_comment, unwrap_comment  # noqa: E402

N = 100_000


@pytest.mark.parametrize('call', [
    lambda: unwrap_comment('*' * N + 'x'),
    lambda: unwrap_comment('/*' + ' *' * N),
    lambda: leading_comment(['/*', '*' * N + ' */', 'x int'], 3),
    lambda: leading_comment(['// ' + 'a' * N, 'x' + ' ' * N + 'y'], 2),
    lambda: trailing_comment('x' + ' ' * N + 'y'),
    lambda: trailing_comment('x' + '-' * N),
    lambda: trailing_comment("'a'" * N + "'"),
    lambda: trailing_comment('"' * N),
    lambda: trailing_comment('x;' * N),
    lambda: leading_comment(['@A(' * 1000, ')' * 1000 + ' x'], 2),
], ids=lambda call: '')
def test_comment_helpers_are_linear(call):
    started = time.perf_counter()
    call()
    assert time.perf_counter() - started < 1.0
