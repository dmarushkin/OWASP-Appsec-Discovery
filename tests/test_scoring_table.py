"""Table tests of ``ScanService.filter_objects`` / ``score_objects`` on the CURRENT behaviour.

They pin the matching semantics (``re.match`` OR case-insensitive substring,
AND of all set criteria, max severity, tag accumulation) before the matcher is
extracted into ``ExcludeFilter`` / ``RuleScorer`` (P1-1, P1-3). Known defects are
``xfail(strict=True)`` so a fix shows up as XPASS.
"""
import io

import pytest

from appsec_discovery.services import ScanService
from tests.support import build_object


def service(config_yaml: str = '') -> ScanService:
    if not config_yaml:
        return ScanService(source_folder='some')
    return ScanService(source_folder='some', conf_file=io.StringIO(config_yaml))


# --------------------------------------------------------------------------- filter_objects

FILTER_OBJECTS = [
    build_object(hash='1', parser='golang', file='/internal/dto/user.go', object_name='User', object_type='dto'),
    build_object(hash='2', parser='golang', file='/internal/dto/order.go', object_name='Order', object_type='dto'),
    build_object(hash='3', parser='swagger', file='/api/swagger.yaml', object_name='GET /user', object_type='route'),
    build_object(hash='4', parser='terraform', file='/infra/main.tf', object_name='keycloak01-dc2', object_type='vm'),
]


@pytest.mark.parametrize('exclude, kept', [
    pytest.param('[]', ['1', '2', '3', '4'], id='no-excludes'),
    pytest.param('[{}]', ['1', '2', '3', '4'], id='empty-rule-matches-nothing'),
    pytest.param('[{parser: golang}]', ['3', '4'], id='parser'),
    pytest.param('[{parser: GoLang}]', ['3', '4'], id='parser-case-insensitive'),
    pytest.param('[{parser: go}]', ['1', '2', '3', '4'], id='parser-is-exact-not-substring'),
    pytest.param("[{file: '/internal/.*'}]", ['3', '4'], id='file-regex-from-start'),
    pytest.param("[{file: 'ORDER.GO'}]", ['1', '3', '4'], id='file-substring-case-insensitive'),
    pytest.param("[{object_name: 'keycloak01'}]", ['1', '2', '3'], id='object-name-substring'),
    pytest.param("[{object_name: '(User|Order)$'}]", ['3', '4'], id='object-name-regex'),
    pytest.param("[{object_type: dto}]", ['3', '4'], id='object-type'),
    pytest.param("[{parser: golang, object_name: Order}]", ['1', '3', '4'], id='criteria-are-anded'),
    pytest.param("[{parser: swagger, object_name: Order}]", ['1', '2', '3', '4'], id='anded-no-match'),
    pytest.param("[{parser: golang, object_name: Order}, {object_type: vm}]", ['1', '3'], id='rules-are-ored'),
])
def test_filter_objects(exclude, kept):
    svc = service(f'exclude_scan: {exclude}\n')
    result = svc.filter_objects(list(FILTER_OBJECTS))
    assert [o.hash for o in result] == kept


# --------------------------------------------------------------------------- score_objects: matching

TAGS = """
score_tags:
  pii:
    high: ['passport', 'phone']
    medium: ['email']
  auth:
    high: ['token']
    medium: ['phone', 'email']
"""


@pytest.mark.parametrize('field_name, severity, tags', [
    pytest.param('input.passport', 'high', ['pii'], id='substring'),
    pytest.param('input.PassPort', 'high', ['pii'], id='substring-case-insensitive'),
    pytest.param('input.city', None, None, id='no-match'),
    pytest.param('input.phone', 'high', ['pii', 'auth'], id='max-severity-tags-accumulate'),
    pytest.param('input.email', 'medium', ['pii', 'auth'], id='same-severity-two-tags'),
    pytest.param('accessToken', 'high', ['auth'], id='camel-case'),
])
def test_score_field_keyword_matching(field_name, severity, tags):
    [obj] = service(TAGS).score_objects([build_object(fields=[field_name])])
    field = obj.fields[field_name]
    assert field.severity == severity
    assert field.tags == tags
    assert obj.severity == severity
    assert obj.tags == tags


@pytest.mark.parametrize('keyword, field_name, matched', [
    pytest.param('^input\\.secret', 'input.secret', True, id='regex-anchored'),
    pytest.param('input\\.(cvv|cvc)', 'input.cvc', True, id='regex-alternation'),
    pytest.param('secret$', 'input.secret', False, id='re-match-is-anchored-at-start'),
    pytest.param('.*secret$', 'input.secret', True, id='regex-full'),
    pytest.param('SECRET', 'input.secret', True, id='literal-case-insensitive'),
])
def test_score_regex_vs_substring(keyword, field_name, matched):
    config = f"score_tags:\n  custom:\n    high: ['{keyword}']\n"
    [obj] = service(config).score_objects([build_object(fields=[field_name])])
    assert (obj.fields[field_name].severity == 'high') is matched


def test_score_properties_match_on_value_not_name():
    [obj] = service(TAGS).score_objects([build_object(properties={'passport': '/orders', 'path': '/user/phone'})])
    assert obj.properties['passport'].severity is None
    assert obj.properties['path'].severity == 'high'
    assert obj.properties['path'].tags == ['pii', 'auth']
    assert obj.severity == 'high'


def test_score_object_severity_is_max_of_fields_and_props():
    obj = build_object(fields=['input.email'], properties={'path': '/token'})
    [scored] = service(TAGS).score_objects([obj])
    assert scored.fields['input.email'].severity == 'medium'
    assert scored.properties['path'].severity == 'high'
    assert scored.severity == 'high'
    assert set(scored.tags) == {'pii', 'auth'}


def test_score_unscored_object_unchanged():
    [obj] = service(TAGS).score_objects([build_object(fields=['input.city'], properties={'path': '/orders'})])
    assert obj.severity is None and obj.tags is None
    assert obj.fields['input.city'].severity is None


def test_score_default_rules_substring_noise():
    # current behaviour: default 'pan' keyword matches as a substring (release-note item of P0-1)
    [obj] = service().score_objects([build_object(fields=['input.company'])])
    assert obj.fields['input.company'].severity == 'high'
    assert obj.fields['input.company'].tags == ['finance']


def test_score_keeps_field_order():
    names = ['z.token', 'a.city', 'm.email']
    [obj] = service(TAGS).score_objects([build_object(fields=names)])
    assert list(obj.fields) == names


def test_score_invalid_regex_keyword_does_not_crash():
    # P1-3: a keyword that is not a valid regex falls back to re.escape with a warning
    config = "score_tags:\n  custom:\n    high: ['card(']\n"
    [obj] = service(config).score_objects([build_object(fields=['input.card(number)'])])
    assert obj.fields['input.card(number)'].severity == 'high'


# --------------------------------------------------------------------------- score_objects: exclude_scoring

SCORE_OBJ = dict(
    parser='swagger', file='/api/user.yaml', object_name='POST /user', object_type='route',
    fields={'input.passport': 'string', 'input.email': 'string'},
    properties={'path': '/user/token'},
)


@pytest.mark.parametrize('exclude, field_sev, prop_sev', [
    pytest.param("{}", {'input.passport': 'high', 'input.email': 'medium'}, 'high', id='empty-rule-no-effect'),
    pytest.param("{parser: swagger}", {'input.passport': None, 'input.email': None}, None, id='parser'),
    pytest.param("{parser: golang}", {'input.passport': 'high', 'input.email': 'medium'}, 'high', id='parser-mismatch'),
    pytest.param("{file: '/api/.*'}", {'input.passport': None, 'input.email': None}, None, id='file-regex'),
    pytest.param("{object_name: 'POST /user'}", {'input.passport': None, 'input.email': None}, None, id='object-name-substring'),
    pytest.param("{object_type: route}", {'input.passport': None, 'input.email': None}, None, id='object-type'),
    pytest.param("{field_name: passport}", {'input.passport': None, 'input.email': 'medium'}, 'high', id='field-name-not-props'),
    pytest.param("{field_type: string}", {'input.passport': None, 'input.email': None}, 'high', id='field-type-not-props'),
    pytest.param("{prop_name: path}", {'input.passport': 'high', 'input.email': 'medium'}, None, id='prop-name-not-fields'),
    pytest.param("{tag: pii}", {'input.passport': 'medium', 'input.email': 'medium'}, 'high', id='tag-pii-auth-remains'),
    pytest.param("{tag: auth}", {'input.passport': 'high', 'input.email': 'medium'}, None, id='tag-auth'),
    pytest.param("{keyword: email}", {'input.passport': 'high', 'input.email': None}, 'high', id='keyword'),
    pytest.param("{tag: pii, keyword: email}", {'input.passport': 'high', 'input.email': 'medium'}, 'high',
                 id='tag-and-keyword-anded'),
])
def test_exclude_scoring(exclude, field_sev, prop_sev):
    config = """
score_tags:
  pii:
    high: ['passport']
    medium: ['email']
  auth:
    high: ['token']
    medium: ['email', 'passport']
exclude_scoring:
  - """ + exclude + "\n"
    [obj] = service(config).score_objects([build_object(**SCORE_OBJ)])
    assert {name: f.severity for name, f in obj.fields.items()} == field_sev
    assert obj.properties['path'].severity == prop_sev


def test_exclude_scoring_by_tag_keeps_other_tags():
    config = TAGS + "exclude_scoring:\n  - tag: pii\n"
    [obj] = service(config).score_objects([build_object(fields=['input.phone'])])
    assert obj.fields['input.phone'].severity == 'medium'
    assert obj.fields['input.phone'].tags == ['auth']


# --------------------------------------------------------------------------- scan_folder end-to-end (no semgrep)


def test_scan_folder_only_scored_objects(samples_dir):
    swagger = str(samples_dir('swagger'))
    all_objects = ScanService(source_folder=swagger, conf_file=io.StringIO('parsers: [swagger]\n')).scan_folder()
    scored_only = ScanService(source_folder=swagger, conf_file=io.StringIO('parsers: [swagger]\n'),
                              only_scored_objects=True).scan_folder()

    assert scored_only
    assert len(scored_only) < len(all_objects)
    assert all(o.severity for o in scored_only)
    assert {o.hash for o in scored_only} == {o.hash for o in all_objects if o.severity}


def test_scan_folder_applies_exclude_scan(samples_dir):
    swagger = str(samples_dir('swagger'))
    conf = "parsers: [swagger]\nexclude_scan:\n  - file: 'swagger2'\n"
    objects = ScanService(source_folder=swagger, conf_file=io.StringIO(conf)).scan_folder()
    assert objects
    assert not any('swagger2' in o.file for o in objects)
