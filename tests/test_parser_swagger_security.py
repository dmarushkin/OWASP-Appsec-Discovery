"""Swagger parser on untrusted specifications: ``$ref`` only reads regular files inside the scan
root, YAML aliases and ``$ref`` fan-out are bounded, the body fields are budgeted."""
import os
import sys
import textwrap
import time
import tomllib
from pathlib import Path

import pytest

from appsec_discovery.parsers.swagger import spec as specs
from appsec_discovery.parsers.swagger.parser import SwaggerParser

REPO_ROOT = Path(__file__).resolve().parent.parent

OUTSIDE_VALUE = 'value-from-outside-the-repo'


def write(folder, name, text):
    path = folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip('\n'))
    return path


def scan(folder):
    return {obj.object_name: obj for obj in SwaggerParser(source_folder=str(folder)).run_scan()}


def all_samples(objects):
    return [sample for obj in objects.values() for field in obj.fields.values() for sample in (field.samples or [])]


def all_text(objects):
    return repr([(obj.comment, [(f.field_name, f.comment, f.samples) for f in obj.fields.values()])
                 for obj in objects.values()])


@pytest.fixture
def layout(tmp_path):
    """``repo/`` (the scan root) next to ``outside/`` holding a file the scan must not read."""
    repo, outside = tmp_path / 'repo', tmp_path / 'outside'
    write(outside, 'shared.yaml', f'''
        region: {OUTSIDE_VALUE}
        settings:
          region: {OUTSIDE_VALUE}
        Schema:
          type: object
          description: {OUTSIDE_VALUE}
          properties:
            leaked_{OUTSIDE_VALUE.replace('-', '_')}: {{type: string}}
    ''')
    repo.mkdir()
    return repo, outside


def spec_with_refs(example_ref, enum_ref, schema_ref):
    return f'''
        openapi: 3.0.0
        info: {{title: t, version: '1'}}
        paths:
          /items:
            post:
              requestBody:
                content:
                  application/json:
                    schema:
                      type: object
                      properties:
                        region:
                          type: string
                          example: {{$ref: '{example_ref}'}}
                        zone:
                          type: string
                          enum: [{{$ref: '{enum_ref}'}}]
                        nested: {{$ref: '{schema_ref}'}}
                    example:
                      settings: {{$ref: '{example_ref.split('#')[0]}#/settings'}}
              responses:
                '200': {{description: ok}}
    '''


# --- $ref outside the scan root ----------------------------------------------------------------

def test_absolute_ref_outside_root_is_not_read(layout):
    repo, outside = layout
    target = outside / 'shared.yaml'
    write(repo, 'api.yaml', spec_with_refs(f'{target}#/region', f'{target}#/region', f'{target}#/Schema'))
    objects = scan(repo)
    route = objects['POST /items']
    assert {'input.region', 'input.zone'} <= set(route.fields)
    assert OUTSIDE_VALUE not in all_samples(objects)
    assert OUTSIDE_VALUE not in all_text(objects)
    assert 'leaked' not in all_text(objects)


def test_relative_ref_leaving_root_is_not_read(layout):
    repo, _ = layout
    ref = '../outside/shared.yaml'
    write(repo, 'api/v1/api.yaml', spec_with_refs(f'../../{ref}#/region', f'../../{ref}#/region',
                                                  f'../../{ref}#/Schema'))
    objects = scan(repo)
    assert 'POST /items' in objects
    assert OUTSIDE_VALUE not in all_text(objects)


@pytest.mark.skipif(sys.platform == 'win32', reason='symlinks')
def test_symlink_inside_root_to_outside_is_not_read(layout):
    repo, outside = layout
    os.symlink(outside / 'shared.yaml', repo / 'link.yaml')
    os.symlink(outside, repo / 'linked_dir')
    write(repo, 'api.yaml', spec_with_refs('./link.yaml#/region', 'linked_dir/shared.yaml#/region',
                                           'link.yaml#/Schema'))
    objects = scan(repo)
    assert 'POST /items' in objects
    assert OUTSIDE_VALUE not in all_text(objects)


@pytest.mark.skipif(sys.platform == 'win32', reason='symlinks')
def test_symlinked_spec_outside_root_is_not_scanned(tmp_path):
    repo, outside = tmp_path / 'repo', tmp_path / 'outside'
    write(outside, 'api.yaml', '''
        openapi: 3.0.0
        info: {title: t, version: '1'}
        paths:
          /outside: {get: {responses: {'200': {description: ok}}}}
    ''')
    repo.mkdir()
    os.symlink(outside / 'api.yaml', repo / 'api.yaml')
    assert scan(repo) == {}


def test_ref_inside_root_is_still_resolved(tmp_path):
    write(tmp_path, 'common/models.yaml', '''
        Item:
          type: object
          properties:
            colour:
              type: string
              description: Item colour
              example: green
            size: {$ref: '#/Size'}
        Size:
          type: integer
          example: 42
    ''')
    write(tmp_path, 'api/api.yaml', '''
        openapi: 3.0.0
        info: {title: t, version: '1'}
        paths:
          /items:
            get:
              responses:
                '200':
                  description: ok
                  content:
                    application/json:
                      schema: {$ref: '../common/models.yaml#/Item'}
    ''')
    route = scan(tmp_path)['GET /items']
    assert route.fields['output.colour'].samples == ['green']
    assert route.fields['output.colour'].comment == 'Item colour'
    assert route.fields['output.size'].samples == ['42']


@pytest.mark.skipif(not hasattr(os, 'mkfifo'), reason='fifo')
def test_ref_to_fifo_inside_root_does_not_block(tmp_path):
    os.mkfifo(tmp_path / 'pipe.yaml')
    write(tmp_path, 'api.yaml', spec_with_refs('pipe.yaml#/region', 'pipe.yaml#/region', 'pipe.yaml#/Schema'))
    started = time.monotonic()
    objects = scan(tmp_path)  # the fifo itself matches the globs: it must not be opened either
    assert time.monotonic() - started < 10
    assert 'POST /items' in objects


def test_ref_to_device_and_large_file_is_not_read(tmp_path, monkeypatch):
    monkeypatch.setattr(specs, 'MAX_SPEC_BYTES', 64)
    write(tmp_path, 'big.yaml', f'region: {OUTSIDE_VALUE}\n' + '# padding\n' * 20)
    write(tmp_path, 'api.yaml', spec_with_refs('big.yaml#/region', '/dev/zero#/region', 'big.yaml#/Schema'))
    # the spec itself is above the patched limit too: parse it directly
    parser = SwaggerParser(source_folder=str(tmp_path))
    path = str(tmp_path / 'api.yaml')
    text = Path(path).read_text()
    assert parser.accept_file(path, text)
    objects = {o.object_name: o for o in parser.build_objects({'/api.yaml': parser.parse_file(path, text)})}
    assert 'POST /items' in objects
    assert OUTSIDE_VALUE not in all_text(objects)
    # and the oversized scanned file is skipped before it is read
    assert scan(tmp_path) == {}


def test_other_ref_schemes_are_not_read(tmp_path):
    write(tmp_path, 'api.yaml', spec_with_refs('python://appsec_discovery/parsers/swagger/x.yaml#/region',
                                               '#/components/schemas/Zone/example',
                                               'python://appsec_discovery/parsers/swagger/x.yaml#/Schema') + '''
        components:
          schemas:
            Zone: {type: string, example: inner-zone}
    ''')
    route = scan(tmp_path)['POST /items']
    assert route.fields['input.zone'].samples == ['inner-zone']  # internal refs still work
    assert not route.fields['input.region'].samples


def test_read_spec_file_rules(tmp_path):
    inside = write(tmp_path / 'root', 'a.yaml', 'a: 1\n')
    outside = write(tmp_path, 'b.yaml', 'b: 1\n')
    root = str(tmp_path / 'root')
    assert specs.read_spec_file(str(inside), root) == 'a: 1\n'
    assert specs.read_spec_file(str(outside), root) is None
    assert specs.read_spec_file(str(tmp_path / 'root' / '..' / 'b.yaml'), root) is None
    assert specs.read_spec_file(str(tmp_path / 'root'), root) is None  # a directory
    assert specs.read_spec_file('/dev/zero', root) is None


# --- YAML alias bomb ---------------------------------------------------------------------------

BOMB = '''
openapi: 3.0.0
info: {title: t, version: '1'}
x-bomb:
  l0: &l0 [a,a,a,a,a,a,a,a,a,a]
  l1: &l1 [*l0,*l0,*l0,*l0,*l0,*l0,*l0,*l0,*l0,*l0]
  l2: &l2 [*l1,*l1,*l1,*l1,*l1,*l1,*l1,*l1,*l1,*l1]
  l3: &l3 [*l2,*l2,*l2,*l2,*l2,*l2,*l2,*l2,*l2,*l2]
  l4: &l4 [*l3,*l3,*l3,*l3,*l3,*l3,*l3,*l3,*l3,*l3]
  l5: &l5 [*l4,*l4,*l4,*l4,*l4,*l4,*l4,*l4,*l4,*l4]
  l6: &l6 [*l5,*l5,*l5,*l5,*l5,*l5,*l5,*l5,*l5,*l5]
  l7: &l7 [*l6,*l6,*l6,*l6,*l6,*l6,*l6,*l6,*l6,*l6]
  l8: &l8 [*l7,*l7,*l7,*l7,*l7,*l7,*l7,*l7,*l7,*l7]
paths:
  /a: {get: {responses: {'200': {description: ok}}}}
'''


def test_yaml_alias_bomb_is_refused_quickly(tmp_path):
    (tmp_path / 'bomb.yaml').write_text(BOMB)
    write(tmp_path, 'ok.yaml', '''
        openapi: 3.0.0
        info: {title: t, version: '1'}
        paths:
          /ok: {get: {responses: {'200': {description: ok}}}}
    ''')
    started = time.monotonic()
    objects = scan(tmp_path)
    assert time.monotonic() - started < 10
    assert set(objects) == {'GET /ok'}  # the bomb is skipped, the other file is scanned


def test_prepare_budget():
    shared = {'type': 'string', 'example': 'x'}
    node = {'a': shared, 'b': shared, 'c': [shared, shared]}
    assert specs.prepare(node) == {'a': shared, 'b': shared, 'c': [shared, shared]}
    with pytest.raises(specs.SpecTooLarge):
        specs.prepare(node, max_nodes=5)


def test_small_yaml_anchors_still_work(tmp_path):
    write(tmp_path, 'api.yaml', '''
        openapi: 3.0.0
        info: {title: t, version: '1'}
        x-param: &region
          name: region
          in: query
          schema: {type: string, example: north}
        paths:
          /a: {get: {parameters: [*region], responses: {'200': {description: ok}}}}
          /b: {get: {parameters: [*region], responses: {'200': {description: ok}}}}
    ''')
    objects = scan(tmp_path)
    assert objects['GET /a'].fields['query.param.region'].samples == ['north']
    assert objects['GET /b'].fields['query.param.region'].samples == ['north']


def test_external_file_alias_bomb_is_not_loaded(tmp_path):
    (tmp_path / 'models.yaml').write_text(BOMB.replace('openapi: 3.0.0\n', '').replace('x-bomb:', 'Bomb:'))
    write(tmp_path, 'api.yaml', '''
        openapi: 3.0.0
        info: {title: t, version: '1'}
        paths:
          /items:
            get:
              responses:
                '200':
                  description: ok
                  content:
                    application/json:
                      schema: {type: object, properties: {b: {$ref: 'models.yaml#/Bomb'}}}
    ''')
    started = time.monotonic()
    objects = SwaggerParser(source_folder=str(tmp_path)).run_scan()
    assert time.monotonic() - started < 10
    assert [o.object_name for o in objects if o.file == '/api.yaml'] == ['GET /items']


# --- $ref fan-out ------------------------------------------------------------------------------

def fanout_spec(levels, width):
    import json
    schemas = {}
    for level in range(levels):
        if level == levels - 1:
            schemas[f'S{level}'] = {'type': 'object', 'properties': {f'p{i}': {'type': 'string'} for i in range(width)}}
        else:
            schemas[f'S{level}'] = {'type': 'object', 'properties': {
                f'p{i}': {'$ref': f'#/components/schemas/S{level + 1}'} for i in range(width)}}
    return json.dumps({
        'openapi': '3.0.0', 'info': {'title': 't', 'version': '1'},
        'paths': {'/a': {'get': {'responses': {'200': {'description': 'ok', 'content': {
            'application/json': {'schema': {'$ref': '#/components/schemas/S0'}}}}}}}},
        'components': {'schemas': schemas},
    })


def test_ref_fanout_is_bounded(tmp_path):
    (tmp_path / 'api.json').write_text(fanout_spec(levels=10, width=4))  # 4^9 = 262144 leaves unbounded
    started = time.monotonic()
    route = scan(tmp_path)['GET /a']
    assert time.monotonic() - started < 10
    assert 0 < len(route.fields) <= SwaggerParser.max_output_fields


def test_small_fanout_is_complete(tmp_path):
    (tmp_path / 'api.json').write_text(fanout_spec(levels=3, width=3))
    route = scan(tmp_path)['GET /a']
    assert len(route.fields) == 27
    assert 'output.p0.p1.p2' in route.fields


def test_field_budget_per_body_schema(tmp_path):
    (tmp_path / 'api.json').write_text(fanout_spec(levels=3, width=3))

    class Small(SwaggerParser):
        max_output_fields = 5

    objects = Small(source_folder=str(tmp_path)).run_scan()
    assert 0 < len(objects[0].fields) <= 5


# --- dependencies ------------------------------------------------------------------------------

def test_prance_is_a_declared_dependency():
    project = tomllib.loads((REPO_ROOT / 'pyproject.toml').read_text())
    assert any(dep.split('>')[0].split('=')[0].strip() == 'prance' for dep in project['project']['dependencies'])
