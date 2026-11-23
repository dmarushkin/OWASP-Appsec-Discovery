from appsec_discovery.parsers import ParserFactory
from appsec_discovery.parsers.graphql.parser import GraphqlParser
import os
from pathlib import Path
import pytest

from tests.support import require_local_samples

def test_parser_graphql_get_parser():

    pf = ParserFactory()

    parser = pf.get_parser('graphql')
    assert parser.__qualname__ == "GraphqlParser"


def test_parser_graphql_parse_folder():

    pf = ParserFactory()

    parserCls = pf.get_parser('graphql')

    test_folder = str(Path(__file__).resolve().parent)
    samples_folder = os.path.join(test_folder, "graphql_samples")

    pr: GraphqlParser = parserCls(parser='graphql', source_folder=samples_folder)

    results = pr.run_scan()

    assert len(results) == 4
    by_name = {r.object_name: r for r in results}
    assert set(by_name) == {'BusinessLoungesMutations.createOrder', 'BusinessLoungesMutations.cancelOrder',
                            'MgmQueries.offer', 'MgmQueries.promoterInfo'}
    assert 'input.idempotencyKey' in by_name['BusinessLoungesMutations.cancelOrder'].fields.keys()


@pytest.mark.local_samples
def test_parser_graphql_local_debug():

    require_local_samples()

    pf = ParserFactory()

    parserCls = pf.get_parser('graphql')

    test_folder = str(Path(__file__).resolve().parent)
    samples_folder = os.path.join(test_folder, "local_samples")

    pr: GraphqlParser = parserCls(parser='graphql', source_folder=samples_folder)

    results = pr.run_scan()

    assert len(results) > 0


def _scan_gql(folder, files):
    for rel, text in files.items():
        path = folder / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return {(o.object_name, o.file): o for o in GraphqlParser(parser='graphql', source_folder=str(folder)).run_scan()}


def test_graphql_two_services_are_two_schemas(tmp_path):
    from appsec_discovery.models.code_object import object_identity
    objects = _scan_gql(tmp_path, {
        'svc-a/schema.graphql': 'type Query { user(id: ID!): User }\ntype User { name: String  paid: Money }\n',
        'svc-b/schema.graphql': 'type Query { user(passport: String!): User }\n'
                                'type User { passportNumber: String  cardPan: String }\n',
        'svc-b/extra.gql': 'extend type Query { other(at: Money): String }\n',
        # defined once in the repo: visible to both services
        'common/money.graphql': 'type Money { units: Int  currency: String }\n',
    })
    assert set(objects) == {('user', '/svc-a/schema.graphql'), ('user', '/svc-b/schema.graphql'),
                            ('other', '/svc-b/extra.gql')}
    a, b = objects['user', '/svc-a/schema.graphql'], objects['user', '/svc-b/schema.graphql']
    assert set(a.fields) == {'id', 'output.name', 'output.paid.units', 'output.paid.currency'}
    assert set(b.fields) == {'passport', 'output.passportNumber', 'output.cardPan'}
    assert a.hash == object_identity('graphql', '/svc-a/schema.graphql', 'query', 'Query.user')
    assert set(objects['other', '/svc-b/extra.gql'].fields) == {'at.units', 'at.currency', 'output'}


def test_graphql_schema_split_over_subdirectories_is_one_schema(tmp_path):
    objects = _scan_gql(tmp_path, {
        'api/schema.graphql': 'type Query { client(id: ID!): Client }\n',
        'api/types/client.graphql': 'type Client { id: ID  card: Card }\n',
        'api/types/more/card.graphql': 'type Card { pan: String }\n',
        'api/ext/accounts.graphql': 'extend type Query { accounts(first: Int): [Client] }\n',
    })
    assert set(objects) == {('client', '/api/schema.graphql'), ('accounts', '/api/ext/accounts.graphql')}
    assert set(objects['client', '/api/schema.graphql'].fields) == {'id', 'output.id', 'output.card.pan'}


def test_graphql_entity_field_identity_ignores_mutations_returning_it(tmp_path):
    entity = 'type Query { client(id: ID!): Client }\ntype Client { id: ID }\n' \
             'extend type Client { accounts(first: Int): [String] }\n'
    before = _scan_gql(tmp_path / 'v1', {'s.graphql': entity})
    after = _scan_gql(tmp_path / 'v2', {'s.graphql': entity + 'type Mutation { renameClient(id: ID!): Client }\n'})
    accounts = before['Client.accounts', '/s.graphql']
    assert accounts.object_type == 'query'
    assert after['Client.accounts', '/s.graphql'].hash == accounts.hash
    assert {k: o.hash for k, o in after.items() if k in before} == {k: o.hash for k, o in before.items()}
    assert ('renameClient', '/s.graphql') in after


def test_graphql_gql_files_and_argument_named_output(tmp_path):
    objects = _scan_gql(tmp_path, {
        's.gql': 'type Query {\n  export(output: String, cardPan: String): String\n'
                 '  dump(output: Target): Report\n}\n'
                 'input Target { path: String }\ntype Report { size: Int }\n'})
    assert {k: f.field_type for k, f in objects['export', '/s.gql'].fields.items()} == {
        'input.output': 'String', 'cardPan': 'String', 'output': 'String'}
    assert set(objects['dump', '/s.gql'].fields) == {'input.output.path', 'output.size'}
