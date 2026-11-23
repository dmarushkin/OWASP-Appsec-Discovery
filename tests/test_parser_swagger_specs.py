"""Swagger parser on real-world shaped specifications: Swagger 2.0 (protoc-gen-openapiv2 style),
file detection, lenient loading, ``$ref`` descriptions, lists, deep schemas, robustness."""
import logging
import textwrap
from pathlib import Path

from appsec_discovery.parsers.swagger import spec as specs
from appsec_discovery.parsers.swagger.parser import SwaggerParser

SAMPLES = Path(__file__).resolve().parent / 'swagger_samples'


def write(folder, name, text):
    path = folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip('\n'))
    return path


def scan(folder):
    return {obj.object_name: obj for obj in SwaggerParser(source_folder=str(folder)).run_scan()}


# --- B1: detection by the top-level key ---------------------------------------------------------

def test_swagger2_and_openapi3_files_are_accepted(tmp_path):
    write(tmp_path, 'v2.yaml', '''
        swagger: "2.0"
        info: {title: t, version: '1'}
        paths:
          /a: {get: {responses: {'200': {description: ok}}}}
    ''')
    write(tmp_path, 'v31.yaml', '''
        openapi: 3.1.0
        info: {title: t, version: '1'}
        paths:
          /b: {get: {responses: {'200': {description: ok}}}}
    ''')
    write(tmp_path, 'v2-min.json', '{"swagger":"2.0","info":{"title":"t","version":"1"},"paths":{"/c":{"get":{"responses":{"200":{"description":"ok"}}}}}}')
    assert set(scan(tmp_path)) == {'GET /a', 'GET /b', 'GET /c'}


def test_non_spec_files_are_skipped_silently(tmp_path, caplog):
    # code generator configs mentioning openapi, a nested key, broken YAML, a spec without paths
    write(tmp_path, 'buf.gen.yaml', '''
        version: v1
        plugins:
          - name: openapiv2
            out: api/openapi
            opt: [allow_merge=true, json_names_for_fields=false]
    ''')
    write(tmp_path, 'service.yaml', '''
        tools:
          openapi: 3.0.0
        paths:
          - /var/lib
    ''')
    write(tmp_path, 'broken.yaml', 'openapi: 3.0.0\npaths: [unclosed\n')
    write(tmp_path, 'nopaths.json', '{"swagger": "2.0", "info": {"title": "t", "version": "1"}}')
    write(tmp_path, 'swagger-ui.json', '{"swagger": "see https://swagger.io", "paths": {}}')

    with caplog.at_level(logging.DEBUG):
        assert scan(tmp_path) == {}
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_detect():
    assert specs.detect({'openapi': '3.0.3', 'paths': {}}) == 3
    assert specs.detect({'openapi': 3.0, 'paths': {}}) == 3
    assert specs.detect({'swagger': '2.0', 'paths': {}}) == 2
    assert specs.detect({'swagger': 2.0, 'paths': {}}) == 2
    assert specs.detect({'swagger': '1.2', 'paths': {}}) is None
    assert specs.detect({'openapi': '3.0.0'}) is None
    assert specs.detect(['openapi', 'paths']) is None


# --- B2: Swagger 2.0 -------------------------------------------------------------------------------

def test_swagger2_sample_objects_and_fields():
    objects = scan_sample()
    assert set(objects) == {'GET /v1/books', 'POST /v1/books',
                            'DELETE /v1/books/{isbn}', 'PUT /v1/books/{isbn}/cover'}

    listing = objects['GET /v1/books']
    assert listing.comment == 'List books\nBooks of the library, filtered by status.'
    # identity: METHOD + path as written (no basePath)
    assert listing.properties['path'].prop_value == '/v1/books'
    assert listing.properties['method'].prop_value == 'GET'
    fields = listing.fields
    assert fields['query.param.pageSize'].field_type == 'integer'
    assert fields['query.param.pageSize'].samples == ['20']
    assert fields['query.param.authorId'].comment == 'Author filter.'
    assert fields['query.param.authorId'].samples == ['42']
    assert fields['output.books.isbn'].samples == ['978-3-16-148410-0']  # response ``examples``
    assert fields['output.nextPageToken'].field_type == 'string'
    assert {'output.code', 'output.message', 'output.details.@type'} <= set(fields)

    create = objects['POST /v1/books'].fields
    assert create['input.isbn'].comment == 'ISBN of the book'
    assert create['input.author.name'].samples == ['Jane Doe']
    assert 'output.isbn' in create
    assert all(name == field.field_name for name, field in create.items())


def scan_sample():
    return {obj.object_name: obj
            for obj in SwaggerParser(source_folder=str(SAMPLES)).run_scan()
            if obj.file == '/swagger2-gateway.json'}


def test_swagger2_form_data_is_the_request_body():
    fields = scan_sample()['PUT /v1/books/{isbn}/cover'].fields
    assert set(fields) == {'path.param.isbn', 'input.image', 'input.caption'}
    assert fields['input.image'].comment == 'Cover image.'
    assert fields['input.image'].field_type == 'string'  # type: file
    assert fields['input.caption'].samples == ['First edition']


def test_operation_parameter_overrides_path_parameter():
    fields = scan_sample()['DELETE /v1/books/{isbn}'].fields
    assert fields['path.param.isbn'].comment == 'ISBN of the book to remove.'
    assert fields['header.param.X-Request-Id'].field_type == 'string'


def test_swagger2_conversion_shapes():
    converted = specs.swagger2_to_openapi3({
        'swagger': '2.0', 'produces': ['application/xml'],
        'paths': {'/x/{id}': {
            'parameters': [{'name': 'id', 'in': 'path', 'type': 'string', 'required': True}],
            'post': {
                'consumes': ['application/json'],
                'parameters': [
                    {'name': 'ids', 'in': 'query', 'type': 'array', 'items': {'type': 'integer'},
                     'collectionFormat': 'csv', 'description': 'Ids'},
                    {'name': 'body', 'in': 'body', 'schema': {'type': 'object'}, 'required': True},
                ],
                'responses': {'200': {'description': 'ok', 'schema': {'type': 'string'},
                                      'headers': {'X-Rate': {'type': 'integer'}}}},
            }}},
    })
    operation = converted['paths']['/x/{id}']['post']
    assert converted['openapi'].startswith('3.0')
    assert operation['parameters'] == [
        {'name': 'ids', 'in': 'query', 'description': 'Ids', 'schema': {'type': 'array', 'items': {'type': 'integer'}}},
        {'name': 'id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}},
    ]
    assert operation['requestBody'] == {'content': {'application/json': {'schema': {'type': 'object'}}}, 'required': True}
    assert operation['responses']['200']['content'] == {'application/xml': {'schema': {'type': 'string'}}}
    assert operation['responses']['200']['headers'] == {'X-Rate': {'schema': {'type': 'integer'}}}


# --- B3: lenient formats, recursive schemas ---------------------------------------------------------

LENIENT = '''
openapi: 3.0.3
info: {title: t, version: '1'}
paths:
  /nodes:
    get:
      parameters:
        - {name: id, in: query, schema: {type: string, format: int64}}
        - {name: at, in: query, schema: {type: number, format: decimal}}
      responses:
        200:
          description: ok
          content:
            application/vnd.custom+json:
              schema: {$ref: '#/components/schemas/Node'}
components:
  schemas:
    Node:
      type: object
      properties:
        name: {type: string, format: slug}
        parent: {$ref: '#/components/schemas/Node'}
        children: {type: array, items: {$ref: '#/components/schemas/Node'}}
'''


def test_unknown_formats_media_types_and_recursion_do_not_fail_the_file(tmp_path):
    write(tmp_path, 'api.yaml', LENIENT)
    fields = scan(tmp_path)['GET /nodes'].fields
    assert fields['query.param.id'].field_type == 'string'
    assert fields['query.param.at'].field_type == 'number'
    assert fields['output.name'].field_type == 'string'
    # a schema referring to itself is cut at the reference (no fields below it)
    assert not [name for name in fields if name.startswith(('output.parent.', 'output.children.'))]


def test_swagger2_recursive_definition():
    fields = scan_sample()['POST /v1/books'].fields
    assert fields['input.author.id'].comment == 'Author id.'
    assert not [name for name in fields if '.mentor.mentor.' in name]


# --- M1: the description next to a $ref ----------------------------------------------------------

REF_DOC = '''
openapi: 3.0.3
info: {title: t, version: '1'}
paths:
  /users:
    get:
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema: {$ref: '#/components/schemas/User'}
components:
  schemas:
    State:
      type: string
      description: Generic state
      enum: [on, off]
    User:
      type: object
      properties:
        state: {$ref: '#/components/schemas/State', description: State of the user}
        previous: {$ref: '#/components/schemas/State', title: Previous state}
        plain: {$ref: '#/components/schemas/State'}
'''


def test_description_next_to_ref_wins(tmp_path):
    write(tmp_path, 'api.yaml', REF_DOC)
    fields = scan(tmp_path)['GET /users'].fields
    assert fields['output.state'].comment == 'State of the user'
    assert fields['output.previous'].comment == 'Previous state'
    assert fields['output.plain'].comment == 'Generic state'
    # the referenced schema still gives type and samples (YAML 1.2: ``on`` stays a string)
    assert fields['output.state'].field_type == 'string'
    assert fields['output.state'].samples == ['on', 'off']


def test_swagger2_description_next_to_ref():
    fields = scan_sample()['POST /v1/books'].fields
    assert fields['input.status'].comment == 'Current status of this copy.'
    assert fields['input.previousStatus'].comment == 'Status before the last change'
    assert fields['input.status'].samples == ['AVAILABLE', 'BORROWED']


def test_prepare_keeps_parameter_refs():
    node = {'parameters': [{'$ref': '#/components/parameters/Id', 'description': 'x'}],
            'schema': {'$ref': '#/definitions/A', 'title': 'T'}, 200: {'description': 'ok'}}
    assert specs.prepare(node) == {
        'parameters': [{'$ref': '#/components/parameters/Id', 'description': 'x'}],
        'schema': {'allOf': [{'$ref': '#/definitions/A'}, {'description': 'T'}]},
        '200': {'description': 'ok'},
    }


# --- M2: lists of scalars ------------------------------------------------------------------------

def test_list_description_wins_over_items():
    fields = scan_sample()['POST /v1/books'].fields
    assert fields['input.tags.'].comment == 'Shelf tags.'       # the list's own description
    assert fields['input.readerIds.'].comment == 'Reader id.'   # no list description: the items'


# --- M3: deep schemas ----------------------------------------------------------------------------

def test_deep_schema_is_not_truncated(tmp_path):
    schema = 'type: string\ndescription: leaf'
    for level in reversed(range(15)):
        schema = f"type: object\nproperties:\n  l{level}:\n" + textwrap.indent(schema, '    ')
    body = textwrap.indent(schema, ' ' * 22)
    write(tmp_path, 'deep.yaml', f'''
        openapi: 3.0.3
        info: {{title: t, version: '1'}}
        paths:
          /deep:
            post:
              requestBody:
                content:
                  application/json:
                    schema:
''' + body + '''
              responses:
                '200': {description: ok}
''')
    fields = scan(tmp_path)['POST /deep'].fields
    name = 'input.' + '.'.join(f'l{level}' for level in range(15))
    assert fields[name].comment == 'leaf'


# --- M5: enum of the items of an array parameter -------------------------------------------------

def test_array_parameter_items_enum_are_samples(tmp_path):
    write(tmp_path, 'api.yaml', '''
        openapi: 3.0.3
        info: {title: t, version: '1'}
        paths:
          /search:
            get:
              parameters:
                - name: kind
                  in: query
                  schema: {type: array, items: {type: string, enum: [user, group]}}
              responses:
                '200': {description: ok}
    ''')
    assert scan(tmp_path)['GET /search'].fields['query.param.kind'].samples == ['user', 'group']
    assert scan_sample()['GET /v1/books'].fields['query.param.status'].samples == ['AVAILABLE', 'BORROWED']


# --- responses -----------------------------------------------------------------------------------

def test_first_response_defining_a_field_wins(tmp_path):
    write(tmp_path, 'api.yaml', '''
        openapi: 3.0.3
        info: {title: t, version: '1'}
        paths:
          /items:
            get:
              responses:
                '200':
                  description: ok
                  content:
                    application/json:
                      schema:
                        type: object
                        properties:
                          message: {type: string, description: Greeting}
                default:
                  description: error
                  content:
                    application/json:
                      schema:
                        type: object
                        properties:
                          message: {type: string, description: Error text}
                          code: {type: integer}
    ''')
    fields = scan(tmp_path)['GET /items'].fields
    assert fields['output.message'].comment == 'Greeting'
    assert fields['output.code'].field_type == 'integer'


# --- robustness ----------------------------------------------------------------------------------

def test_broken_spec_file_does_not_break_the_scan(tmp_path, caplog):
    write(tmp_path, 'a-broken.yaml', '''
        openapi: 3.0.3
        info: {title: t, version: '1'}
        paths:
          /x:
            get:
              responses:
                '200':
                  description: ok
                  content:
                    application/json:
                      schema: {$ref: '#/components/schemas/Missing'}
    ''')
    write(tmp_path, 'b-good.yaml', '''
        swagger: '2.0'
        info: {title: t, version: '1'}
        paths:
          /y: {get: {responses: {200: {description: ok, schema: {type: object, properties: {id: {type: string}}}}}}}
    ''')
    with caplog.at_level(logging.WARNING):
        objects = scan(tmp_path)
    assert set(objects) == {'GET /y'}
    assert 'output.id' in objects['GET /y'].fields
    assert any('a-broken.yaml' in r.getMessage() for r in caplog.records)


def test_rejected_operation_is_dropped_alone(tmp_path, caplog):
    write(tmp_path, 'api.yaml', '''
        openapi: 3.0.3
        info: {title: t, version: '1'}
        paths:
          /x:
            get:
              parameters:
                - {name: q, in: query, style: no-such-style, schema: {type: string}}
              responses:
                '200': {description: ok}
            post:
              responses:
                '200': {description: ok}
          /y:
            get:
              responses:
                '200': {description: ok}
    ''')
    with caplog.at_level(logging.WARNING):
        objects = scan(tmp_path)
    assert set(objects) == {'POST /x', 'GET /y'}
    assert any('GET /x' in r.getMessage() for r in caplog.records)


def test_untyped_and_odd_schemas_are_normalised():
    assert specs.normalize_schema({'properties': {'a': {'type': ['string', 'null']}}}) == \
        {'type': 'object', 'properties': {'a': {'type': 'string'}}}
    assert specs.normalize_schema({'type': 'array'}) == {'type': 'array', 'items': {}}
    assert specs.normalize_schema({'type': 'file'}) == {'type': 'string', 'format': 'binary'}
    assert specs.normalize_schema({'type': 'object', 'discriminator': 'kind'}) == \
        {'type': 'object', 'discriminator': {'propertyName': 'kind'}}
    assert specs.normalize_schema({'type': 'date', 'description': 'd'}) == {'description': 'd'}
    assert specs.normalize_schema(None) == {}
