"""GraphQL operations of JS / TS clients (gql`...` templates), parsed without semgrep."""

import os
from pathlib import Path

import pytest

from appsec_discovery.parsers import ParserFactory
from appsec_discovery.parsers.javascript.parser import JsGqlParser, gql_templates
from tests.support import require_local_samples


def _scan(tmp_path, files):
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return {o.object_name: o for o in JsGqlParser(parser='javascript', source_folder=str(tmp_path)).run_scan()}


def test_parser_javascript_get_parser():
    assert ParserFactory.get_parser('javascript').__qualname__ == "JsGqlParser"


def test_parser_javascript_parse_folder():
    samples = str(Path(__file__).resolve().parent / "javascript_samples")
    (obj,) = JsGqlParser(parser='javascript', source_folder=samples).run_scan()
    assert obj.object_name == 'ProfileLoginQuery.me'
    assert {k: f.field_type for k, f in obj.fields.items()} == {'output.login': 'selection'}


def test_templates_skip_interpolations_and_escapes():
    text = 'const a = gql`\n query A { a(id: "x\\`y") { ...F } }\n ${F}\n`;\nconst b = gql `{ b }`;'
    assert [(line, body.split()) for line, body in gql_templates(text)] == [
        (1, ['query', 'A', '{', 'a(id:', '"x\\`y")', '{', '...F', '}', '}']), (5, ['{', 'b', '}'])]


SOURCES = {
    'src/fragments.ts': '''export const PASSPORT = gql`
  fragment Passport on Document { series number issuedBy { code } }
`;''',
    'src/client.ts': '''import { PASSPORT } from './fragments';
export const GET = gql`
  query GetClient($id: ID!, $card: CardFilter) {
    client(id: $id) {
      id
      fullName
      documents(filter: {kind: PASSPORT, active: true}) { ...Passport }
      ... on Person { phone }
    }
    balance: accountBalance(clientId: $id, card: $card)
  }
  ${PASSPORT}
`;
export const OPEN = gql`
  mutation OpenAccount($input: OpenAccountInput!) {
    openAccount(input: $input, tags: [$input]) { account { iban } errors { code } }
  }
  fragment Unused on Account { iban }
`;
export const EVENTS = gql`subscription { events(limit: 10) { id kind } }`;
export const BROKEN = gql`query { oops (`;
''',
}


def test_operations_fields_and_fragments(tmp_path):
    objects = _scan(tmp_path, SOURCES)
    assert set(objects) == {
        'GetClient.client',
        'GetClient.balance: accountBalance',   # scalar root field, alias kept
        'OpenAccount.openAccount',          # a document with a fragment definition
        'anonymous.events',
    }
    client = objects['GetClient.client']
    assert {k: f.field_type for k, f in client.fields.items()} == {
        'input.id': 'ID!',
        'output.id': 'selection', 'output.fullName': 'selection',
        'output.documents.series': 'selection', 'output.documents.number': 'selection',   # fragment of another file
        'output.documents.issuedBy.code': 'selection',
        'output.phone': 'selection',                                                      # inline fragment
    }
    assert client.object_type == 'js-gql-query' and client.file == '/src/client.ts' and client.line == 2
    balance = objects['GetClient.balance: accountBalance']
    assert {k: f.field_type for k, f in balance.fields.items()} == {
        'input.clientId': 'ID!', 'input.card': 'CardFilter', 'output': 'selection'}
    open_account = objects['OpenAccount.openAccount']
    assert {k: f.field_type for k, f in open_account.fields.items()} == {
        'input.input': 'OpenAccountInput!', 'input.tags': 'OpenAccountInput!',
        'output.account.iban': 'selection', 'output.errors.code': 'selection'}
    events = objects['anonymous.events']
    assert events.object_type == 'js-gql-subscription' and events.fields['input.limit'].field_type == 'literal'
    assert all(f.field_name == key for o in objects.values() for key, f in o.fields.items())


def test_object_arguments_and_identity_stable_across_line_shifts(tmp_path):
    first = _scan(tmp_path / 'a', {'q.js': 'const Q = gql`query Q($n: String) { find(by: {name: $n, age: 3}) { id } }`;'})
    second = _scan(tmp_path / 'b', {'q.js': '\n\n// moved\nconst Q = gql`query Q($n: String) { find(by: {name: $n, age: 3}) { id } }`;'})
    (a,), (b,) = first.values(), second.values()
    assert {k: f.field_type for k, f in a.fields.items()} == {
        'input.by.name': 'String', 'input.by.age': 'literal', 'output.id': 'selection'}
    assert a.hash == b.hash and (a.line, b.line) == (1, 4)


def test_node_modules_and_files_without_gql_are_skipped(tmp_path):
    objects = _scan(tmp_path, {'node_modules/lib/q.js': 'gql`{ a }`', 'src/plain.ts': 'const x = `{ a }`;'})
    assert objects == {}


@pytest.mark.local_samples
def test_parser_javascript_local_debug():
    require_local_samples()
    samples_folder = os.path.join(str(Path(__file__).resolve().parent), "local_samples")
    assert JsGqlParser(parser='javascript', source_folder=samples_folder).run_scan()


def test_same_resolver_twice_in_a_file_merges_the_selections(tmp_path):
    # two anonymous operations with one root field: one object (the identity of the first),
    # the fields of both selections, nothing lost
    text = ('const A = gql`\n  query { me { id } }\n`;\n'
            'const B = gql`\n  query { me { passportNumber cardPan } }\n`;\n'
            'const C = gql`query Find($q: String = "x") { find(q: $q) { id } }`;\n'
            'const D = gql`query Find($q: String = "y") { find(q: $q) { email } }`;\n')
    objects = _scan(tmp_path, {'q.ts': text})
    assert set(objects) == {'anonymous.me', 'Find.find'}
    me = objects['anonymous.me']
    assert set(me.fields) == {'output.id', 'output.passportNumber', 'output.cardPan'}
    assert me.line == 1 and 'me { id }' in me.properties['request_text'].prop_value
    single = _scan(tmp_path / 'single', {'q.ts': 'const A = gql`\n  query { me { id } }\n`;\n'})
    assert single['anonymous.me'].hash == me.hash
    find = objects['Find.find']
    assert set(find.fields) == {'input.q', 'output.id', 'output.email'}
    assert find.fields['input.q'].samples == ['"x"', '"y"']
