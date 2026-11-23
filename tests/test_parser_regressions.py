"""Regression tests for the parser correctness fixes (P0-6).

Hermetic tests use the native parsers or the recorded semgrep JSON
(``tests/fixtures``); ``semgrep``-marked tests run the real rules over
``tests/regression_samples``.
"""
from pathlib import Path

import graphql
import pytest
from openapi_parser import parse as parse_openapi

from appsec_discovery.models import object_identity
from appsec_discovery.parsers.golang.parser import GolangParser
from appsec_discovery.parsers.graphql.parser import GraphqlParser
from appsec_discovery.parsers.java.parser import JavaParser
from appsec_discovery.parsers.protobuf.parser import ProtobufParser
from appsec_discovery.parsers.python.parser import PythonParser
from appsec_discovery.parsers.swagger.parser import SwaggerParser
from tests.golden_support import parse_hermetic

REGRESSION_SAMPLES = Path(__file__).resolve().parent / 'regression_samples'


def _by_name(objects):
    return {obj.object_name: obj for obj in objects}


# --- python routes: $METHOD is bound and part of the identity ---------------

def test_python_routes_keep_http_method():
    routes = _by_name(o for o in parse_hermetic('python') if o.object_type == 'route')

    flask_get = routes['GET /submit (submit)']
    flask_post = routes['POST /submit (submit)']
    assert flask_get.properties['method'].prop_value == 'GET'
    assert flask_post.properties['method'].prop_value == 'POST'
    assert flask_get.hash != flask_post.hash

    bottle_get = routes['GET /get (hello)']
    assert bottle_get.properties['method'].prop_value == 'get'

    # @route without a method has no method property (not "route")
    bottle_route = routes['/hello (hello)']
    assert 'method' not in bottle_route.properties


def test_python_route_hash_includes_method_only_when_bound():
    parser = PythonParser(parser='python', source_folder='/src')

    def finding(method=None):
        metavars = {'$PATH': {'abstract_content': '/x'}, '$FUNC': {'abstract_content': 'h'}}
        if method:
            metavars['$METHOD'] = {'abstract_content': method}
        metadata = {'parser': 'python', 'object_type': 'route', 'framework': 'flask'}
        return {'check_id': 'rules.route-flask-object', 'path': '/app.py',
                'start': {'line': 3}, 'extra': {'metavars': metavars, 'metadata': metadata}}

    no_method, get, get_lower = (parser.parse_report([f])[0] for f in (finding(), finding('GET'), finding('get')))

    assert no_method.hash == object_identity('python', '/app.py', 'route', '/x')
    assert get.hash == object_identity('python', '/app.py', 'route', 'GET /x')
    assert get.hash == get_lower.hash != no_method.hash


# --- java: $TYPE is bound ---------------------------------------------------

def test_java_field_types_from_recorded_semgrep():
    [entity] = parse_hermetic('java')
    assert {name: f.field_type for name, f in entity.fields.items()} == {
        'counter': 'int', 'id': 'String', 'acSampleRate': 'String', 'acState': 'String',
    }
    # line still points at the @Column annotation
    assert entity.fields['counter'].line == 14


@pytest.mark.semgrep
def test_java_annotated_fields_and_getters_live():
    pr = JavaParser(parser='java', source_folder=str(REGRESSION_SAMPLES / 'java'))
    [entity] = pr.run_scan()

    assert entity.object_name == 'UserEntity'
    assert entity.properties['db_table'].prop_value == 'users'
    assert {name: f.field_type for name, f in entity.fields.items()} == {
        'user_id': 'Long', 'email': 'String', 'created': 'java time Instant', 'pwd': 'String',
        'status': 'Integer',      # field with an initializer
        'full_name': 'String',    # annotated getter
    }
    assert entity.fields['user_id'].line == 10  # the @Column line, not @Id


# --- golang: anchored type regex --------------------------------------------

@pytest.mark.semgrep
def test_golang_type_regex_is_anchored_live():
    pr = GolangParser(parser='golang', source_folder=str(REGRESSION_SAMPLES / 'golang'))
    [regress] = pr.run_scan()

    assert {name: f.field_type for name, f in regress.fields.items()} == {
        'Ok': 'bool', 'Count': 'uint32', 'Ratio': 'float64', 'When': 'time',
    }
    # interface{}, timeout, stringer, integer no longer pass by prefix


# --- graphql ----------------------------------------------------------------

def _graphql_objects():
    pr = GraphqlParser(parser='graphql', source_folder=str(REGRESSION_SAMPLES / 'graphql'))
    return _by_name(pr.run_scan())


def test_graphql_schema_without_arguments_does_not_crash():
    # used to raise UnboundLocalError (stale ``input_type`` from the arguments loop)
    assert set(_graphql_objects()) == {'Bank.account', 'Shop.account'}


def test_graphql_result_types_are_expanded_once():
    account = _graphql_objects()['Bank.account']
    assert {name: f.field_type for name, f in account.fields.items()} == {
        'output.id': 'ID',
        'output.owner.name': 'String',
        'output.owner.account': 'Account',  # cycle Account -> Person -> Account stops here
        'output.balance.units': 'Int',
        'output.balance.currency': 'String',
        'output.limit': 'Money',            # Money is expanded once, at output.balance
    }


def test_graphql_inputs_expand_repeated_types_everywhere(tmp_path):
    objects = _scan_schema(tmp_path, '''type Query { quote(input: QuoteInput!): Quote }
input QuoteInput { amount: MoneyInput  fee: MoneyInput }
input MoneyInput { units: Int  currency: String }
type Quote { id: ID }''')
    assert set(objects['quote'].fields) == {'input.amount.units', 'input.amount.currency', 'input.fee.units',
                                                  'input.fee.currency', 'output.id'}


def test_graphql_repeated_result_type_expanded_at_the_shallowest_place(tmp_path):
    objects = _scan_schema(tmp_path, '''type Query { order: Order }
type Order { deal: Deal  buyer: Person }
type Deal { seller: Person }
type Person { name: String  passport: String }''')
    assert {name: f.field_type for name, f in objects['order'].fields.items()} == {
        'output.deal.seller': 'Person', 'output.buyer.name': 'String', 'output.buyer.passport': 'String'}


def test_graphql_lines_are_source_lines():
    objects = _graphql_objects()
    bank = objects['Bank.account']
    assert bank.line == 28
    assert bank.fields['output.id'].line == 12
    assert bank.fields['output.balance.units'].line == 2
    assert objects['Shop.account'].line == 32


def test_graphql_hash_includes_type_name():
    objects = _graphql_objects()
    bank, shop = objects['Bank.account'], objects['Shop.account']

    assert bank.hash != shop.hash
    assert bank.hash == object_identity('graphql', '/schema.graphql', 'query', 'Bank.account')


def test_graphql_resolve_fields_is_bounded():
    pr = GraphqlParser(parser='graphql', source_folder='/src')
    pr.max_resolved_fields = 3
    doc = graphql.parse((REGRESSION_SAMPLES / 'graphql' / 'schema.graphql').read_text(), no_location=False)
    [bank, _] = pr.parse_report({'/schema.graphql': doc})
    # the cap counts every visited field (nested ones too), so at most 3 leaves remain
    assert 0 < len(bank.fields) <= 3


def test_graphql_resolve_fields_bounded_without_leaves():
    # 12 object types that all reference each other: no scalar leaves until depth 10,
    # so a leaf-only budget would walk ~11! paths; counting visited fields stops early
    names = [f"T{i}" for i in range(12)]
    sdl = "\n".join(
        "type %s { %s }" % (n, " ".join(f"f{m}: {m}" for m in names if m != n)) for n in names
    ) + "\ntype Query { root: T0 }\nextend type Query { root: T0 }\n"
    pr = GraphqlParser(parser='graphql', source_folder='/src')
    pr.max_resolved_fields = 200
    [obj] = pr.parse_report({'/deep.graphql': graphql.parse(sdl, no_location=False)})
    assert len(obj.fields) <= 200


# --- protobuf ---------------------------------------------------------------

def test_protobuf_file_without_package():
    pr = ProtobufParser(parser='protobuf', source_folder=str(REGRESSION_SAMPLES / 'protobuf'))
    objects = _by_name(pr.run_scan())

    # used to raise KeyError('') and drop every file
    assert set(objects) == {'/Echo/Say', '/demo.v1.Users/Get'}
    assert objects['/Echo/Say'].file == '/no_package.proto'
    assert objects['/demo.v1.Users/Get'].file == '/with_package.proto'


def test_protobuf_field_line_is_not_the_tag_number():
    pr = ProtobufParser(parser='protobuf', source_folder=str(REGRESSION_SAMPLES / 'protobuf'))
    echo = _by_name(pr.run_scan())['/Echo/Say']
    # ``string text = 7;`` used to give line=7
    assert echo.fields['input.EchoRequest.text'].line is None


def test_protobuf_broken_file_does_not_drop_others():
    pr = ProtobufParser(parser='protobuf', source_folder=str(REGRESSION_SAMPLES / 'protobuf'))
    good = pr.run_scan()

    class Broken:
        @property
        def file_elements(self):
            raise RuntimeError('boom')

    pr2 = ProtobufParser(parser='protobuf', source_folder='/src')
    import proto_schema_parser.parser as pb_parser
    data = {
        '/broken.proto': Broken(),
        '/with_package.proto': pb_parser.Parser().parse((REGRESSION_SAMPLES / 'protobuf' / 'with_package.proto').read_text()),
    }
    assert [o.object_name for o in pr2.parse_report(data)] == ['/demo.v1.Users/Get']
    assert len(good) == 2


# --- swagger ----------------------------------------------------------------

def _swagger_spec():
    path = REGRESSION_SAMPLES / 'swagger' / 'no_schema_param.yaml'
    return parse_openapi(str(path))


def test_swagger_parameter_without_schema():
    spec = _swagger_spec()
    search = next(p for p in spec.paths if p.url == '/search')
    search.operations[0].parameters[0].schema = None  # used to raise AttributeError

    objects = _by_name(SwaggerParser(parser='swagger', source_folder='/src').parse_report({'/api.yaml': spec}))

    assert set(objects) == {'GET /search', 'GET /items'}
    fields = objects['GET /search'].fields
    assert fields['query.param.filter'].field_type == ''
    assert fields['query.param.kind'].field_type == 'oneOf'
    assert fields['query.param.limit'].field_type == 'integer'


def test_swagger_broken_operation_does_not_drop_others():
    spec = _swagger_spec()
    search = next(p for p in spec.paths if p.url == '/search')
    search.operations[0].responses[0].content[0].schema = None  # resolve_fields fails

    objects = SwaggerParser(parser='swagger', source_folder='/src').parse_report({'/api.yaml': spec})

    assert [o.object_name for o in objects] == ['GET /items']


def test_swagger_regression_sample_scans():
    pr = SwaggerParser(parser='swagger', source_folder=str(REGRESSION_SAMPLES / 'swagger'))
    assert {o.object_name for o in pr.run_scan()} == {'GET /search', 'GET /items'}


# --- graphql: namespaces without `extend`, roots, depth, directives ------------------------------

NAMESPACED_SCHEMA = '''
schema { query: RootQuery mutation: Mutation subscription: Subscription }

type RootQuery { client(id: ID!): Client  me: Client }
type Mutation { wallet: WalletMutations! @requireAuth  ping: Boolean }
type Subscription { events(clientId: ID!): Event }

type WalletMutations {
    create(input: WalletCreateInput!): Issue! @skipAuthenticate
    cards: CardMutations!
}
type CardMutations { block(cardId: ID!, reason: String): Issue! }

input WalletCreateInput { passport: PassportInput!  phone: String! }
input PassportInput { series: String!  number: String! }

type Client { id: ID!  name: String  profile: Profile }
type Profile { address: Address }
type Address { city: City }
type City { region: Region }
type Region { name: String  country: Country }
type Country { code: String  capital: City }
type Issue { id: ID! }
type Event { id: ID! }
'''


def _scan_schema(tmp_path, text, name='schema.graphql'):
    (tmp_path / name).write_text(text)
    return _by_name(GraphqlParser(parser='graphql', source_folder=str(tmp_path)).run_scan())


def test_graphql_plain_namespace_types_are_expanded(tmp_path):
    objects = _scan_schema(tmp_path, NAMESPACED_SCHEMA)
    assert set(objects) == {
        'client', 'me', 'ping', 'events',
        'WalletMutations.create', 'CardMutations.block',   # nested namespace: still a mutation
    }
    create = objects['WalletMutations.create']
    assert {'input.passport.series', 'input.passport.number', 'input.phone', 'output.id'} == set(create.fields)
    assert create.properties['directives'].prop_value == '@requireAuth @skipAuthenticate'   # inherited + own
    assert objects['CardMutations.block'].properties['directives'].prop_value == '@requireAuth'
    assert create.object_type == 'mutation' and objects['events'].object_type == 'subscription'
    assert set(objects['CardMutations.block'].fields) == {'cardId', 'reason', 'output.id'}


def test_graphql_output_depth_is_limited(tmp_path):
    me = _scan_schema(tmp_path, NAMESPACED_SCHEMA)['me']
    # 5 levels below output: profile.address.city.region.country is a leaf, not expanded further
    assert me.fields['output.profile.address.city.region.name'].field_type == 'String'
    assert me.fields['output.profile.address.city.region.country'].field_type == 'Country'
    assert not any(name.startswith('output.profile.address.city.region.country.') for name in me.fields)


def test_graphql_plain_root_without_extend_and_empty_files(tmp_path, caplog):
    (tmp_path / 'empty.graphql').write_text('\n')
    objects = _scan_schema(tmp_path, 'type Query { account(id: ID!): Account }\ntype Account { iban: String }')
    assert set(objects) == {'account'} and set(objects['account'].fields) == {'id', 'output.iban'}
    assert 'Failed to parse' not in caplog.text


# --- protobuf: name resolution, oneof, map, cycles ------------------------------------------------

PROTO_COMMON = '''syntax = "proto3";
package common;
message Money { int64 units = 1; string currency = 2; }
'''

PROTO_API = '''syntax = "proto3";
package api.v1;
import "common.proto";

service Clients {
  rpc Check (CheckRequest) returns (.api.v1.CheckResponse);
}

message CheckRequest {
  message Doc { string number = 1; string issuer = 2; }
  oneof document {
    Doc passport = 1;
    string snils = 2;
  }
  map<string, string> labels = 3;
  common.Money limit = 4;
  Node tree = 5;
}

message Node { string name = 1; Node parent = 2; }

message CheckResponse {
  Result.Status status = 1;
}

message Result {
  message Status { bool ok = 1; }
}
'''


def test_protobuf_resolves_scopes_oneof_map_packages_and_cycles(tmp_path):
    from appsec_discovery.parsers.protobuf.parser import ProtobufParser
    (tmp_path / 'common.proto').write_text(PROTO_COMMON)
    (tmp_path / 'api.proto').write_text(PROTO_API)
    objects = _by_name(ProtobufParser(parser='protobuf', source_folder=str(tmp_path)).run_scan())
    check = objects['/api.v1.Clients/Check']
    assert {name: f.field_type for name, f in check.fields.items()} == {
        'input.CheckRequest.passport.Doc.number': 'string',      # oneof member, nested message
        'input.CheckRequest.passport.Doc.issuer': 'string',
        'input.CheckRequest.snils': 'string',                     # oneof scalar
        'input.CheckRequest.labels': 'map<string,string>',        # map field
        'input.CheckRequest.limit.Money.units': 'int64',          # message of another package
        'input.CheckRequest.limit.Money.currency': 'string',
        'input.CheckRequest.tree.Node.name': 'string',
        'input.CheckRequest.tree.Node.parent': 'Node',            # recursion stops on the path
        'output.CheckResponse.status.Status.ok': 'bool',          # Outer.Inner, absolute .pkg.Msg
    }



def test_protobuf_duplicate_messages_resolve_to_the_same_file(tmp_path):
    from appsec_discovery.parsers.protobuf.parser import ProtobufParser
    for name, extra in (('a', 'string bucket = 2;'), ('b', '')):
        (tmp_path / name).mkdir()
        (tmp_path / name / 'api.proto').write_text(f'''syntax = "proto3";
package storage;
service S{name.upper()} {{ rpc Resync (ResyncRequest) returns (ResyncRequest); }}
message ResyncRequest {{ int64 max_revision = 1; {extra} }}
''')
    objects = _by_name(ProtobufParser(parser='protobuf', source_folder=str(tmp_path)).run_scan())
    assert 'input.ResyncRequest.bucket' in objects['/storage.SA/Resync'].fields
    assert 'input.ResyncRequest.bucket' not in objects['/storage.SB/Resync'].fields



def test_every_parser_names_fields_by_their_full_path():
    """The service stores fields by ``field_name``: it must equal the dict key (the full path),
    else leaves with the same name in different branches of a message are merged."""
    from appsec_discovery.parsers.protobuf.parser import ProtobufParser
    objects = ProtobufParser(parser='protobuf', source_folder=str(REGRESSION_SAMPLES.parent / 'protobuf_samples')).run_scan()
    assert objects and all(f.field_name == key for o in objects for key, f in o.fields.items())



def test_protobuf_same_leaf_name_in_two_branches_stays_two_fields(tmp_path):
    from appsec_discovery.parsers.protobuf.parser import ProtobufParser
    (tmp_path / 'a.proto').write_text('''syntax = "proto3";
package p;
service S { rpc Check (Req) returns (Req); }
message Doc { string number = 1; }
message Req { Doc passport = 1; Doc license = 2; }
''')
    (check,) = ProtobufParser(parser='protobuf', source_folder=str(tmp_path)).run_scan()
    names = sorted(f.field_name for f in check.fields.values())
    assert names == ['input.Req.license.Doc.number', 'input.Req.passport.Doc.number',
                     'output.Req.license.Doc.number', 'output.Req.passport.Doc.number']


def test_graphql_business_type_named_subscription_is_not_a_root(tmp_path):
    # a product subscription of a client, referenced as a field type: an entity, not the root
    objects = _scan_schema(tmp_path, '''
type Query { client(id: ID!): Client }
type Client { id: ID!  subscription: Subscription }
type Subscription { id: ID!  plan: String  renew(auto: Boolean): Boolean }
''')
    assert set(objects) == {'client'}
    assert all(o.object_type != 'subscription' for o in objects.values())


def test_graphql_schema_block_declares_the_only_roots(tmp_path):
    objects = _scan_schema(tmp_path, '''
schema { query: Query }
type Query { me: User }
type User { id: ID! }
type Subscription { events(id: ID!): User }
''')
    assert set(objects) == {'me'}


def test_graphql_default_subscription_root_still_works(tmp_path):
    objects = _scan_schema(tmp_path, '''
type Query { me: User }
type User { id: ID! }
type Subscription { events(id: ID!): User }
''')
    assert objects['events'].object_type == 'subscription'
