"""Report renderers (P2-2) and the ReportService wrapper, checked structurally.

Reports are written under tmp_path only.
"""
import io
import json

import pytest
import yaml

import appsec_discovery
from appsec_discovery.pipeline import ScanPipeline
from appsec_discovery.reports import REPORT_FORMATS, render_json, render_report, render_sarif, render_yaml
from appsec_discovery.services import ReportService
from tests.support import build_object


@pytest.fixture
def objects():
    return [
        build_object(hash='a', object_name='POST /user', fields=['input.passport', 'input.color'],
                     properties={'path': '/user'}, file='/api/swagger.yaml', line=10),
        build_object(hash='b', object_name='GET /orders', fields=['output.id'],
                     properties={'path': '/orders'}, file='/api/swagger.yaml', line=42),
        build_object(hash='c', object_name='Contact', parser='golang', object_type='dto',
                     fields=['Email'], file='/dto/contact.go', line=3),
    ]


@pytest.fixture
def scored(objects):
    return ScanPipeline(use_config_ai=False).score(objects)


def render(objects, report_type, tmp_path):
    out = tmp_path / f'report.{report_type}'
    with open(out, 'w') as report_file:
        ReportService(code_objects=objects, report_type=report_type, report_file=report_file).save_report_to_disk()
    return out.read_text()


def test_json_report(scored, tmp_path):
    data = json.loads(render(scored, 'json', tmp_path))

    assert [o['hash'] for o in data] == ['a', 'b', 'c']
    assert data[0]['severity'] == 'high'
    assert data[0]['fields']['input.passport']['tags'] == ['pii']
    # exclude_none: unscored values are omitted
    assert 'severity' not in data[1]
    assert 'severity' not in data[0]['fields']['input.color']


def test_yaml_report(scored, tmp_path):
    data = yaml.safe_load(render(scored, 'yaml', tmp_path))

    assert [o['object_name'] for o in data] == ['POST /user', 'GET /orders', 'Contact']
    assert data[2]['severity'] == 'medium'
    assert data[2]['tags'] == ['pii', 'auth']
    # key order of CodeObject is kept (sort_keys=False)
    assert list(data[0])[:4] == ['hash', 'object_name', 'object_type', 'parser']


def test_json_and_get_json_report_agree(scored, tmp_path):
    service = ReportService(code_objects=scored, report_type='json', report_file=None)
    assert json.loads(service.get_json_report()) == json.loads(render(scored, 'json', tmp_path))


def test_sarif_report(scored, tmp_path):
    sarif = json.loads(render(scored, 'sarif', tmp_path))

    assert sarif['$schema'] == 'https://json.schemastore.org/sarif-2.1.0.json'
    assert sarif['version'] == '2.1.0'

    [run] = sarif['runs']
    assert run['tool']['driver']['name'] == 'appsec-discovery'
    assert run['tool']['driver']['semanticVersion'] == appsec_discovery.__version__
    rules = {r['id']: r for r in run['tool']['driver']['rules']}
    assert sorted(rules) == ['golang.dto', 'swagger.route']
    # every rule has its own description
    assert rules['golang.dto']['shortDescription'] != rules['swagger.route']['shortDescription']

    results = run['results']
    # 'a': one result for its scored field input.passport (input.color is unscored);
    # 'b': unscored -> one result for the object; 'c': one result for Email
    assert len(results) == 3
    assert [r['ruleId'] for r in results] == ['swagger.route', 'swagger.route', 'golang.dto']
    # high -> error, unscored -> note, medium -> warning (the SARIF default, so omitted)
    assert results[0]['level'] == 'error'
    assert results[0]['properties'] == {
        'tags': ['pii'], 'security-severity': '8.0',
        'hits': [{'rule': 'score_tags/pii/high', 'type': 'keyword', 'severity': 'high', 'tags': ['pii'],
                  'status': 'match'}],
    }
    assert 'kind' not in results[0]                     # default 'fail'
    assert results[0]['message']['text'] == '[swagger.route] POST /user: field input.passport (pii)'
    assert results[1]['level'] == 'note'
    assert results[1]['properties'] == {}
    assert results[1]['message']['text'] == '[swagger.route] GET /orders'
    assert results[2].get('level', 'warning') == 'warning'
    assert results[2]['properties']['security-severity'] == '5.5'

    # fingerprints: the object hash, plus a per-field hash on field results
    assert results[0]['partialFingerprints']['discoveryHash'] == 'a'
    assert results[1]['partialFingerprints'] == {'discoveryHash': 'b'}
    fingerprints = [tuple(sorted(r['partialFingerprints'].items())) for r in results]
    assert len(set(fingerprints)) == len(fingerprints)

    location = results[0]['locations'][0]['physicalLocation']
    # relative to %SRCROOT%: no leading '/'
    assert location['artifactLocation'] == {'uri': 'api/swagger.yaml', 'uriBaseId': '%SRCROOT%'}
    assert location['region']['startLine'] == 10
    snippet = yaml.safe_load(location['contextRegion']['snippet']['text'])
    assert snippet['hash'] == 'a'


def sarif_results(objects):
    return json.loads(render_sarif(objects))['runs'][0]['results']


def test_sarif_one_result_per_scored_field():
    obj = build_object(hash='h', fields=['email', 'phone', 'color'])
    ScanPipeline(use_config_ai=False).score([obj])
    results = sarif_results([obj])
    assert sorted(r['message']['text'].split('field ')[1].split(' ')[0] for r in results) == ['email', 'phone']
    assert len({r['partialFingerprints']['discoveryFieldHash'] for r in results}) == 2


def test_sarif_object_result_for_property_scoring():
    # scored only through a property -> one result for the object
    obj = build_object(hash='h', properties={'path': '/api/passport'}, fields=['color'])
    ScanPipeline(use_config_ai=False).score([obj])
    assert obj.severity
    [result] = sarif_results([obj])
    assert result['partialFingerprints'] == {'discoveryHash': 'h'}
    assert result['level'] == 'error'


def test_sarif_object_and_field_results_when_both_scored():
    obj = build_object(hash='h', properties={'path': '/api/passport'}, fields=['email'])
    ScanPipeline(use_config_ai=False).score([obj])
    results = sarif_results([obj])
    assert len(results) == 2
    assert 'discoveryFieldHash' not in results[0]['partialFingerprints']
    assert 'discoveryFieldHash' in results[1]['partialFingerprints']


@pytest.mark.parametrize('line, expected', [(0, 1), (-3, 1), (7, 7)])
def test_sarif_start_line_at_least_1(line, expected):
    [result] = sarif_results([build_object(line=line)])
    assert result['locations'][0]['physicalLocation']['region']['startLine'] == expected


def test_sarif_field_location():
    obj = build_object(hash='h', fields=['email'], file='/a.go', line=3)
    obj.fields['email'].file = '/b.go'
    obj.fields['email'].line = 0
    ScanPipeline(use_config_ai=False).score([obj])
    [result] = sarif_results([obj])
    location = result['locations'][0]['physicalLocation']
    assert location['artifactLocation']['uri'] == 'b.go'
    assert location['region']['startLine'] == 1


@pytest.mark.parametrize('file, uri', [
    ('/api/swagger.yaml', 'api/swagger.yaml'),
    ('api/swagger.yaml', 'api/swagger.yaml'),
    ('/dir with space/a#b.go', 'dir%20with%20space/a%23b.go'),
    ('\\win\\path.go', 'win/path.go'),
])
def test_sarif_uri(file, uri):
    [result] = sarif_results([build_object(file=file)])
    assert result['locations'][0]['physicalLocation']['artifactLocation']['uri'] == uri


def test_render_report_dispatch(scored):
    assert set(REPORT_FORMATS) == {'yaml', 'json', 'sarif'}
    assert render_report(scored, 'json') == render_json(scored)
    assert render_report(scored, 'YAML') == render_yaml(scored)
    assert render_report(scored, 'sarif') == render_sarif(scored)
    assert render_report(scored, 'json') == ReportService(scored, 'json', None).render()


def test_render_report_unknown_format(scored):
    with pytest.raises(ValueError, match='unknown report format'):
        render_report(scored, 'xml')
    with pytest.raises(ValueError):
        ReportService(code_objects=scored, report_type='xml', report_file=None).save_report_to_disk()


def test_render_empty():
    assert json.loads(render_json([])) == []
    assert yaml.safe_load(render_yaml([])) == []
    assert sarif_results([]) == []


def test_report_to_stdout(scored, capsys):
    ReportService(code_objects=scored, report_type='json', report_file=None).save_report_to_disk()
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 3


def test_report_leaves_report_file_open(scored):
    # P2-2: the caller owns the file, ReportService no longer closes it
    report_file = io.StringIO()
    ReportService(code_objects=scored, report_type='yaml', report_file=report_file).save_report_to_disk()
    assert not report_file.closed
    assert yaml.safe_load(report_file.getvalue())[0]['hash'] == 'a'


def test_report_of_scanned_samples(samples_dir, load_config, tmp_path):
    """End-to-end without semgrep: swagger samples scanned with conf.yaml -> every format."""
    config = load_config('conf.yaml')
    config.parsers = ['swagger']
    objects = appsec_discovery.scan(samples_dir('swagger'), config).objects
    assert objects

    assert len(json.loads(render(objects, 'json', tmp_path))) == len(objects)
    assert len(yaml.safe_load(render(objects, 'yaml', tmp_path))) == len(objects)
    expected = sum(max(1, len([f for f in o.fields.values() if f.severity])) for o in objects
                   if not any(p.severity for p in o.properties.values()))
    expected += sum(1 + len([f for f in o.fields.values() if f.severity]) for o in objects
                    if any(p.severity for p in o.properties.values()))
    assert len(json.loads(render(objects, 'sarif', tmp_path))['runs'][0]['results']) == expected
