"""Rules engine (stage 5b): keyword rule modes, score_rules (P1-6), LLM rules, hits with status, reports."""
import json
import logging

import pytest
import yaml

import appsec_discovery
from appsec_discovery.ai import FakeLlmBackend
from appsec_discovery.errors import ConfigError
from appsec_discovery.hits import apply_hit_statuses, has_open_hits
from appsec_discovery.models import HitStatus, LlmRule, ScoreConfig, ScoreRule
from appsec_discovery.pipeline import ScanPipeline, ai_scorer_from_config
from appsec_discovery.models import CodeObject, CodeObjectField
from appsec_discovery.scoring import RuleScorer
from appsec_discovery.reports import render_json, render_sarif, render_yaml
from appsec_discovery.services.ai_service import AiService
from tests.support import build_object, config_from

TAGS = {'pii': {'high': ['passport']}}


def keyword_pipeline(**config) -> ScanPipeline:
    return ScanPipeline(ScoreConfig(**{'score_tags': TAGS, **config}), use_config_ai=False)


def statuses(obj):
    return [(h.rule_type, h.subject, h.field_name or h.prop_name, h.tags, h.status) for h in obj.hits or []]


# --------------------------------------------------------------------------- config: backward compatibility


def test_legacy_config_maps_to_auto_keyword_rules_and_one_implicit_llm_rule():
    config = config_from('ai_conf_deepseek.yaml')
    assert config.score_tags_mode == 'auto'
    assert config.score_rules == []
    assert config.llm_rules is None
    [rule] = config.effective_llm_rules()
    assert rule.name == 'llm-default' and rule.is_classifier
    assert (rule.mode, rule.severity, rule.target) == ('auto', 'medium', 'field')
    assert rule.system_prompt == config.ai_api.system_prompt


def test_no_ai_api_no_llm_rules():
    assert ScoreConfig().effective_llm_rules() == []
    assert ai_scorer_from_config(ScoreConfig()) is None


def test_explicit_empty_llm_rules_disable_the_implicit_rule():
    config = ScoreConfig(ai_api={'base_url': 'http://x', 'model': 'm'}, llm_rules=[])
    assert config.effective_llm_rules() == []


def test_keyword_hits_are_confirmed_and_score_like_before():
    obj = build_object(fields=['input.passport'], properties={'path': '/passport'})
    keyword_pipeline().score([obj])
    assert obj.severity == 'high' and obj.fields['input.passport'].tags == ['pii']
    assert statuses(obj) == [('keyword', 'prop', 'path', ['pii'], 'match'),
                             ('keyword', 'field', 'input.passport', ['pii'], 'match')]
    assert obj.hits[1].keyword == 'passport' and obj.hits[1].rule == 'score_tags/pii/high'


def test_unscored_object_has_no_hits_key():
    obj = build_object(fields=['input.color'])
    keyword_pipeline().score([obj])
    assert obj.hits is None
    assert 'hits' not in obj.dict(exclude_none=True)


@pytest.mark.parametrize('bad', [
    {'score_tags_mode': 'sometimes'},
    {'score_rules': [{'tag': 't'}]},                                  # no matcher
    {'score_rules': [{'field': 'card'}]},                             # score without tag
    {'score_rules': [{'field': 'card', 'tag': 't', 'mode': 'x'}]},
    {'score_rules': [{'field': 'card', 'tag': 't', 'severity': 'urgent'}]},
    {'score_rules': [{'field': 'card', 'tag': 't', 'action': 'mark'}]},
    {'llm_rules': [{'name': 'r', 'target': 'object'}]},               # object rule needs a category
    {'llm_rules': [{'name': 'r', 'target': 'table'}]},
])
def test_invalid_rules_are_config_errors(bad):
    with pytest.raises(ConfigError):
        appsec_discovery.api.to_config(bad)


# --------------------------------------------------------------------------- keyword rule mode review


def test_review_mode_hits_are_pending_and_do_not_score():
    obj = build_object(fields=['input.passport'])
    keyword_pipeline(score_tags_mode='review').score([obj])
    assert obj.severity is None and obj.fields['input.passport'].severity is None
    assert statuses(obj) == [('keyword', 'field', 'input.passport', ['pii'], 'pending_review')]
    assert has_open_hits(obj)


def test_only_scored_keeps_objects_with_pending_hits():
    pending, plain = build_object(hash='1', fields=['input.passport']), build_object(hash='2', fields=['color'])
    pipeline = ScanPipeline(ScoreConfig(score_tags=TAGS, score_tags_mode='review'), only_scored=True,
                            use_config_ai=False)
    assert [o.hash for o in pipeline.process([pending, plain])] == ['1']


def test_apply_hit_statuses_confirms_and_rejects():
    obj = build_object(fields=['input.passport', 'input.email'])
    ScanPipeline(ScoreConfig(score_tags={'pii': {'high': ['passport'], 'medium': ['email']}},
                             score_tags_mode='review'), use_config_ai=False).score([obj])
    passport, email = obj.hits
    apply_hit_statuses([obj], {passport.key(obj.hash): 'match', email.key(obj.hash): 'no_match'})
    assert obj.severity == 'high' and obj.tags == ['pii']
    assert obj.fields['input.passport'].severity == 'high'
    assert obj.fields['input.email'].severity is None
    assert not has_open_hits(obj)

    # rejecting the matched hit later removes its score again
    apply_hit_statuses([obj], {passport.key(obj.hash): HitStatus.no_match})
    assert obj.severity is None and obj.fields['input.passport'].severity is None


def test_apply_hit_statuses_accepts_legacy_statuses(caplog):
    obj = build_object(fields=['input.passport', 'input.email'])
    ScanPipeline(ScoreConfig(score_tags={'pii': {'high': ['passport'], 'medium': ['email']}},
                             score_tags_mode='review'), use_config_ai=False).score([obj])
    passport, email = obj.hits
    with caplog.at_level('WARNING'):
        apply_hit_statuses([obj], {passport.key(obj.hash): 'confirmed', email.key(obj.hash): 'REJECTED'})
    assert [h.status for h in obj.hits] == ['match', 'no_match']
    assert obj.severity == 'high' and obj.fields['input.email'].severity is None
    with pytest.raises(ValueError):
        apply_hit_statuses([obj], {passport.key(obj.hash): 'approved'})


def test_hit_key_is_stable_and_distinct():
    a, b = build_object(hash='h', fields=['passport']), build_object(hash='h', fields=['passport'])
    keyword_pipeline().score([a, b])
    assert a.hits[0].key('h') == b.hits[0].key('h')
    assert a.hits[0].key('h') != a.hits[0].key('other')


# --------------------------------------------------------------------------- score_rules (P1-6)


def test_score_rule_scoped_by_object_hits_fields():
    config = ScoreConfig(score_tags={}, score_rules=[
        {'object_type': 'dto', 'field': 'card', 'severity': 'critical', 'tag': 'pci', 'name': 'cards'},
    ])
    dto = build_object(hash='1', object_type='dto', fields=['cardNumber', 'color'])
    route = build_object(hash='2', object_type='route', fields=['cardNumber'])
    ScanPipeline(config, use_config_ai=False).score([dto, route])
    assert dto.fields['cardNumber'].severity == 'critical' and dto.severity == 'critical'
    assert dto.fields['color'].severity is None
    assert statuses(dto) == [('keyword', 'field', 'cardNumber', ['pci'], 'match')]
    assert dto.hits[0].rule == 'cards' and dto.hits[0].keyword is None
    assert route.severity is None


def test_score_rule_without_field_matcher_hits_the_object():
    config = ScoreConfig(score_tags={}, score_rules=[
        ScoreRule(object='Payment', severity='high', tag='payments', id=7, mode='review'),
    ])
    obj = build_object(object_name='PaymentRequest', fields=['amount'])
    ScanPipeline(config, use_config_ai=False).score([obj])
    [hit] = obj.hits
    assert (hit.subject, hit.rule_id, hit.status, hit.field_name) == ('object', '7', 'pending_review', None)
    assert obj.severity is None


def test_deprecated_alert_action_is_treated_as_score_and_warned_once(caplog, monkeypatch):
    from appsec_discovery.models import rules as rules_module
    monkeypatch.setattr(rules_module, '_alert_action_warned', False)
    with caplog.at_level(logging.WARNING, logger='appsec_discovery.models.rules'):
        config = ScoreConfig(score_tags={}, score_rules=[{'field': 'token', 'tag': 'secret', 'action': 'alert'},
                                                         {'field': 'name', 'tag': 'pii', 'action': 'ALERT'}])
    assert [r.action for r in config.score_rules] == ['score', 'score']
    assert sum("action 'alert' is deprecated" in r.getMessage() for r in caplog.records) == 1
    obj = build_object(fields=['token', 'name'])
    ScanPipeline(config, use_config_ai=False).score([obj])
    assert sorted(h.field_name for h in obj.hits) == ['name', 'token']
    assert obj.fields['token'].severity == 'medium'
    assert all('alert' not in h.dict() for h in obj.hits)


def test_score_rule_exclude_action_suppresses_hits():
    config = ScoreConfig(score_tags=TAGS, score_rules=[
        {'object': 'Legacy', 'action': 'exclude'},
        {'parser': 'swagger', 'field': 'passport', 'tag': 'pii', 'action': 'exclude'},
    ])
    legacy = build_object(hash='1', object_name='LegacyUser', parser='golang', fields=['passport'])
    swagger = build_object(hash='2', parser='swagger', fields=['passport'])
    other = build_object(hash='3', parser='golang', fields=['passport'])
    ScanPipeline(config, use_config_ai=False).score([legacy, swagger, other])
    assert legacy.hits is None and swagger.hits is None
    assert other.severity == 'high'
    assert len(config.effective_exclude_scoring()) == 2


def test_disabled_score_rule_is_ignored():
    config = ScoreConfig(score_tags={}, score_rules=[{'field': 'token', 'tag': 'secret', 'enabled': False}])
    obj = build_object(fields=['token'])
    ScanPipeline(config, use_config_ai=False).score([obj])
    assert obj.hits is None


def test_score_rules_per_project():
    config = ScoreConfig(score_tags={}, score_rules=[
        {'field': 'token', 'tag': 'a', 'project': 'group/*'},
        {'field': 'token', 'tag': 'b', 'project': 'other/repo'},
        {'field': 'token', 'tag': 'c'},
    ])
    assert [r.tag for r in config.for_project('group/svc').score_rules] == ['a', 'c']
    assert [r.tag for r in config.for_project(None).score_rules] == ['c']

    obj = build_object(fields=['token'])
    ScanPipeline(config, project='GROUP/svc', use_config_ai=False).score([obj])
    assert obj.fields['token'].tags == ['a', 'c']

    # without a project the config is used as is (the caller built it for the project)
    obj = build_object(fields=['token'])
    ScanPipeline(config, use_config_ai=False).score([obj])
    assert obj.fields['token'].tags == ['a', 'b', 'c']


def test_score_rules_from_yaml():
    config = config_from("score_tags: {}\nscore_rules:\n  - object: User\n    field: passport\n    severity: HIGH\n"
                         "    tag: pii\n")
    [rule] = config.score_rules
    assert (rule.object_name, rule.field_name, rule.severity) == ('User', 'passport', 'high')


# --------------------------------------------------------------------------- LLM rules


def field_answer(*items):
    return json.dumps({'fields': [dict(zip(('name', 'verdict', 'reason'), item)) for item in items]})


PCI = {'name': 'pci', 'category': 'pci', 'severity': 'high', 'system_prompt': 'Find card data.',
       'prompt_version': 3}


def llm_pipeline(rules, backend, **config):
    return ScanPipeline(ScoreConfig(score_tags={}, llm_rules=rules, **config), llm_backend=backend)


def test_llm_field_rule_review_mode():
    backend = FakeLlmBackend(field_answer(('cardNumber', 'match', 'PAN'), ('cvv', 'need_more_info', 'maybe')))
    obj = build_object(object_name='Payment', fields={'input.cardNumber': 'string', 'input.cvv': 'string',
                                                      'input.id': 'string'})
    llm_pipeline([{**PCI, 'mode': 'review'}], backend).score([obj])

    card, cvv = obj.hits
    assert (card.subject, card.field_name, card.tags, card.status) == ('field', 'input.cardNumber', ['llm-pci'],
                                                                       'pending_review')
    assert (card.rule, card.rule_type, card.rule_version, card.model, card.reason) == \
        ('pci', 'llm', '3.3', 'fake-model', 'PAN')
    assert (cvv.field_name, cvv.status) == ('input.cvv', 'need_more_info')
    assert obj.severity is None

    [(system, user, schema)] = backend.calls
    assert system == 'Find card data.'
    assert 'Rule: pci' in user and '- input.cardNumber' in user and 'input.id' not in user
    assert schema['properties']['fields']['items']['properties']['name']['enum'] == ['input.cardNumber',
                                                                                     'input.cvv']


def test_llm_field_rule_auto_mode_scores():
    backend = FakeLlmBackend(field_answer(('input.cardNumber', 'match')))
    obj = build_object(fields=['input.cardNumber'])
    llm_pipeline([PCI], backend).score([obj])
    assert obj.fields['input.cardNumber'].severity == 'high'
    assert obj.fields['input.cardNumber'].tags == ['llm-pci']
    assert obj.hits[0].status == 'match'


def test_llm_object_rule_sends_the_whole_object():
    backend = FakeLlmBackend(json.dumps({'verdict': 'match', 'reason': 'admin route without auth'}))
    rule = {'name': 'admin', 'category': 'privileged', 'tag': 'admin-route', 'target': 'object', 'severity': 'critical'}
    obj = build_object(object_name='POST /admin', fields={'input.id': 'int', 'input.flag': 'bool'},
                       properties={'path': '/admin'})
    llm_pipeline([rule], backend).score([obj])

    [hit] = obj.hits
    assert (hit.subject, hit.tags, hit.status, hit.reason) == ('object', ['admin-route'], 'match',
                                                               'admin route without auth')
    assert obj.severity == 'critical' and obj.tags == ['admin-route']
    [(_, user, schema)] = backend.calls
    # every field (ids and bools too) and the properties are context
    assert '"input.id"' in user and '"input.flag"' in user and '"/admin"' in user
    assert schema['required'] == ['verdict']


@pytest.mark.parametrize('answer, status', [
    ({'verdict': 'no_match'}, None),
    ({'verdict': 'need_more_info'}, 'need_more_info'),
    ({'verdict': 'yes'}, 'pending_review'),
])
def test_llm_object_rule_verdicts(answer, status):
    rule = {'name': 'r', 'category': 'c', 'target': 'object', 'mode': 'review'}
    obj = build_object(fields=['a'])
    llm_pipeline([rule], FakeLlmBackend(json.dumps(answer))).score([obj])
    assert [h.status for h in obj.hits or []] == ([status] if status else [])
    assert obj.severity is None


def test_llm_rule_scope_filters():
    backend = FakeLlmBackend(json.dumps({'verdict': 'match'}))
    rules = [
        {'name': 'dto-only', 'category': 'c', 'target': 'object', 'object_types': ['DTO']},
        {'name': 'golang-only', 'category': 'c', 'target': 'object', 'parsers': ['golang']},
        {'name': 'proj', 'category': 'c', 'target': 'object', 'projects': ['team/*']},
        {'name': 'off', 'category': 'c', 'target': 'object', 'enabled': False},
    ]
    obj = build_object(object_type='dto', parser='swagger', fields=['a'])
    llm_pipeline(rules, backend, ).score([obj])
    assert [h.rule for h in obj.hits] == ['dto-only', 'proj']        # no project given: scope not checked

    obj = build_object(object_type='dto', parser='swagger', fields=['a'])
    ScanPipeline(ScoreConfig(score_tags={}, llm_rules=rules), llm_backend=backend, project='x/y').score([obj])
    assert [h.rule for h in obj.hits] == ['dto-only']


def test_llm_rule_error_is_isolated_per_rule():
    def answer(system, user, schema):
        if system == 'boom':
            raise RuntimeError('down')
        return json.dumps({'verdict': 'match'})

    rules = [{'name': 'bad', 'category': 'c', 'target': 'object', 'system_prompt': 'boom'},
             {'name': 'good', 'category': 'c', 'target': 'object'}]
    obj = build_object(fields=['a'])
    llm_pipeline(rules, FakeLlmBackend(answer)).score([obj])
    assert [h.rule for h in obj.hits] == ['good']


def test_llm_rule_honours_exclude_scoring():
    backend = FakeLlmBackend(field_answer(('card', 'match')))
    obj = build_object(fields=['card'])
    llm_pipeline([PCI], backend, exclude_scoring=[{'tag': 'llm-pci'}]).score([obj])
    assert obj.hits is None


def test_implicit_rule_records_classifier_hits(fake_llm):
    fake_llm(category='pii, finance', fields=['passport'])
    config = config_from('ai_conf_local_server.yaml')
    service = AiService(exclude_scoring=[], ai_api=config.ai_api)
    [obj] = service.ai_score_objects([build_object(fields=['input.passport'])])
    [hit] = obj.hits
    assert (hit.rule, hit.rule_type, hit.rule_version, hit.tags, hit.status) == \
        ('llm-default', 'llm', '3', ['llm-pii', 'llm-finance'], 'match')


def test_llm_rules_without_endpoint_are_skipped(caplog):
    config = ScoreConfig(llm_rules=[{'name': 'r', 'category': 'c'}])
    with caplog.at_level(logging.WARNING, logger='appsec_discovery.pipeline'):
        assert ai_scorer_from_config(config) is None
    assert any('no \'ai_api\'' in r.getMessage() for r in caplog.records)


def test_scan_api_takes_project_and_backend(tmp_path):
    (tmp_path / 'api.yaml').write_text('openapi: 3.0.0\ninfo: {title: t, version: "1"}\npaths: {}\n')
    result = appsec_discovery.scan(tmp_path, {'parsers': ['swagger'], 'llm_rules': [{'name': 'r', 'category': 'c'}]},
                                   project='g/p', llm_backend=FakeLlmBackend('{"fields": []}'))
    assert result.errors == {}


# --------------------------------------------------------------------------- reports


@pytest.fixture
def triaged():
    """One confirmed keyword hit on a field, one pending LLM hit on another field, one pending object hit."""
    backend = FakeLlmBackend(lambda system, user, schema: (
        json.dumps({'verdict': 'match'}) if 'verdict' in schema['properties']
        else field_answer(('email', 'match', 'contact'))))
    rules = [{'name': 'contacts', 'category': 'contact', 'mode': 'review'},
             {'name': 'obj', 'category': 'sensitive', 'target': 'object', 'mode': 'review'}]
    obj = build_object(hash='h', fields=['passport', 'email', 'color'])
    ScanPipeline(ScoreConfig(score_tags=TAGS, llm_rules=rules), llm_backend=backend).score([obj])
    return obj


def test_yaml_and_json_reports_include_hits_with_status(triaged):
    for data in (yaml.safe_load(render_yaml([triaged])), json.loads(render_json([triaged]))):
        hits = data[0]['hits']
        assert [(h['rule'], h['subject'], h['status']) for h in hits] == [
            ('score_tags/pii/high', 'field', 'match'),
            ('contacts', 'field', 'pending_review'),
            ('obj', 'object', 'pending_review'),
        ]
        assert hits[1]['reason'] == 'contact' and hits[1]['field_name'] == 'email'


def test_sarif_reports_hits_and_review_results(triaged):
    results = json.loads(render_sarif([triaged]))['runs'][0]['results']
    by_text = {r['message']['text']: r for r in results}
    assert sorted(by_text) == [
        '[swagger.route] Obj',
        '[swagger.route] Obj: field email (review: llm-contact)',
        '[swagger.route] Obj: field passport (pii)',
    ]
    passport = by_text['[swagger.route] Obj: field passport (pii)']
    assert 'kind' not in passport and passport['properties']['hits'][0]['status'] == 'match'

    email = by_text['[swagger.route] Obj: field email (review: llm-contact)']
    assert email['kind'] == 'review' and email['level'] == 'none'   # SARIF: kind != fail -> level none
    assert email['properties']['hits'] == [{'rule': 'contacts', 'type': 'llm', 'severity': 'medium',
                                            'tags': ['llm-contact'], 'status': 'pending_review',
                                            'reason': 'contact'}]
    assert 'security-severity' not in email['properties']

    obj_result = by_text['[swagger.route] Obj']
    assert [h['rule'] for h in obj_result['properties']['hits']] == ['obj']


def test_sarif_rejected_hits_create_no_result(triaged):
    apply_hit_statuses([triaged], {h.key('h'): 'no_match' for h in triaged.hits if h.rule_type == 'llm'})
    results = json.loads(render_sarif([triaged]))['runs'][0]['results']
    assert [r['message']['text'] for r in results] == ['[swagger.route] Obj: field passport (pii)']


def test_rules_config_sample():
    config = config_from('rules_conf.yaml')
    assert config.score_tags_mode == 'review'
    assert [r.action for r in config.score_rules] == ['score', 'score', 'exclude']
    assert [r.name for r in config.effective_llm_rules()] == ['pci-fields', 'privileged-object']
    assert [r.name for r in config.for_project('web/site').effective_llm_rules()] == ['pci-fields']
    assert config.effective_llm_rules()[0].prompt_version == '1'



# ---- field combinations ------------------------------------------------------------------------

def _person(*names):
    return CodeObject(hash='h-' + '-'.join(names), object_name='Req', object_type='rpc', parser='protobuf',
                      file='/a.proto', line=1, properties={},
                      fields={n: CodeObjectField(field_name=n, field_type='string', file='/a.proto', line=2)
                              for n in names})


PERSON_CONTACT = dict(name='pii-person-contact', tag='pii', severity='high',
                      fields_all=['last_?name|fio|full_?name|surname', 'phone|msisdn'])


@pytest.mark.parametrize('names, matched', [
    (('FirstName',), None),
    (('FirstName', 'Phone'), None),                                       # a first name alone is not enough
    (('Req.client.LastName', 'Req.client.Phone', 'Req.id'), ['Req.client.LastName', 'Req.client.Phone']),
    (('Fio', 'ReceiverPhone', 'Amount'), ['Fio', 'ReceiverPhone']),
])
def test_combination_rule_hits_the_object_with_the_matched_fields(names, matched):
    scorer = RuleScorer({}, score_rules=[ScoreRule(**PERSON_CONTACT)])
    obj = scorer.score(_person(*names))
    if matched is None:
        assert not obj.hits and obj.severity is None
        return
    (hit,) = obj.hits
    assert (hit.subject, hit.fields, hit.status, obj.severity) == ('object', matched, 'match', 'high')


def test_combination_rule_min_groups_and_fields_none():
    rule = ScoreRule(name='id-docs', tag='pii', fields_all=['last_?name', 'passport', 'birth'], min_groups=2,
                     fields_none=['masked'], mode='review')
    assert rule.combination_fields(_person('LastName', 'BirthDate')) == ['LastName', 'BirthDate']
    assert rule.combination_fields(_person('LastName', 'Phone')) is None
    assert rule.combination_fields(_person('LastName', 'BirthDate', 'MaskedPan')) is None
    hit, = RuleScorer({}, score_rules=[rule]).score(_person('PassportNumber', 'BirthDate')).hits
    assert hit.status == 'pending_review' and hit.fields == ['PassportNumber', 'BirthDate']


@pytest.mark.parametrize('extra, error', [
    ({'fields_all': ['a'], 'field': 'b'}, 'cannot be combined'),
    ({'fields_all': ['a', 'b'], 'min_groups': 3}, 'min_groups must be between'),
    ({'object': 'X', 'min_groups': 1}, 'min_groups needs fields_all'),
    ({'object': 'X', 'fields_none': ['a']}, 'fields_none needs fields_all'),
])
def test_combination_rule_validation(extra, error):
    with pytest.raises(ValueError, match=error):
        ScoreRule(name='r', tag='t', **extra)


def test_llm_object_rule_names_the_matching_fields():
    from appsec_discovery.ai.rules import parse_object_rule_answer, run_object_rule
    obj = _person('Req.client.FirstName', 'Req.client.LastName', 'Req.client.Phone')
    backend = FakeLlmBackend(json.dumps({'verdict': 'match', 'reason': 'name + phone',
                                         'fields': ['lastname', 'Req.client.Phone', 'Unknown']}))
    rule = LlmRule(name='person', category='pii', target='object', system_prompt='last name + phone')
    verdict, reason, fields = run_object_rule(rule, obj, backend)
    assert (verdict, reason, fields) == ('match', 'name + phone', ['Req.client.LastName', 'Req.client.Phone'])
    system, user, schema = backend.calls[0]
    assert 'combination of fields' in user and schema['properties']['fields']['items']['enum'][0] == 'Req.client.FirstName'
    assert parse_object_rule_answer('{"verdict": "no_match", "fields": ["Phone"]}', ['Phone']) == ('no_match', None, [])
    assert parse_object_rule_answer('{"verdict": "match"}', ['Phone']) == ('match', None, [])



@pytest.mark.parametrize('mode, status', [('auto', 'match'), ('review', 'pending_review')])
def test_llm_object_rule_mark_fields_hits_the_object_and_the_named_fields(mode, status):
    backend = FakeLlmBackend(json.dumps({'verdict': 'match', 'reason': 'name + phone',
                                         'fields': ['LastName', 'Phone', 'Unknown']}))
    rule = {'name': 'person', 'category': 'pii', 'target': 'object', 'mode': mode, 'severity': 'high',
            'mark_fields': True, 'tags': ['personal-data']}
    obj = _person('FirstName', 'LastName', 'Phone')
    llm_pipeline([rule], backend).score([obj])

    assert len(backend.calls) == 1                                     # one model call per object
    assert [(h.subject, h.field_name, h.tags, h.status, h.severity, h.reason, h.fields) for h in obj.hits] == [
        ('object', None, ['llm-pii'], status, 'high', 'name + phone', ['LastName', 'Phone']),
        ('field', 'LastName', ['llm-pii'], status, 'high', 'name + phone', None),
        ('field', 'Phone', ['llm-pii'], status, 'high', 'name + phone', None),
    ]
    assert len({h.key(obj.hash) for h in obj.hits}) == 3
    if mode == 'auto':
        assert obj.fields['LastName'].tags == ['llm-pii'] and obj.fields['Phone'].severity == 'high'
        assert obj.fields['FirstName'].tags is None and 'personal-data' in obj.tags
    else:
        assert obj.fields['LastName'].tags is None and obj.severity is None
        # a decision on the object hit does not decide its field hits
        apply_hit_statuses([obj], {obj.hits[0].key(obj.hash): 'match'})
        assert [h.status for h in obj.hits] == ['match', 'pending_review', 'pending_review']
        assert obj.fields['LastName'].tags is None


def test_llm_object_rule_mark_fields_on_need_more_info_and_no_match():
    rule = {'name': 'person', 'category': 'pii', 'target': 'object', 'mark_fields': True}
    obj = _person('LastName', 'Phone')
    llm_pipeline([rule], FakeLlmBackend(json.dumps({'verdict': 'need_more_info', 'fields': ['Phone']}))).score([obj])
    assert [(h.subject, h.field_name, h.status) for h in obj.hits] == [
        ('object', None, 'need_more_info'), ('field', 'Phone', 'need_more_info')]

    obj = _person('LastName', 'Phone')
    llm_pipeline([rule], FakeLlmBackend(json.dumps({'verdict': 'no_match', 'fields': ['Phone']}))).score([obj])
    assert not obj.hits

    # without mark_fields: the object hit only (the default)
    obj = _person('LastName', 'Phone')
    llm_pipeline([{**rule, 'mark_fields': False}],
                 FakeLlmBackend(json.dumps({'verdict': 'match', 'fields': ['Phone']}))).score([obj])
    assert [(h.subject, h.fields) for h in obj.hits] == [('object', ['Phone'])]


def test_llm_mark_fields_needs_target_object():
    with pytest.raises(ValueError, match='mark_fields'):
        LlmRule(name='r', category='c', target='field', mark_fields=True)
    assert LlmRule(name='r', category='c', target='object').mark_fields is False


def test_llm_mark_fields_reports_list_field_hits():
    backend = FakeLlmBackend(json.dumps({'verdict': 'match', 'fields': ['Phone']}))
    obj = _person('LastName', 'Phone')
    llm_pipeline([{'name': 'person', 'category': 'pii', 'target': 'object', 'mode': 'review',
                   'mark_fields': True}], backend).score([obj])
    hits = json.loads(render_json([obj]))[0]['hits']
    assert [(h['subject'], h.get('field_name')) for h in hits] == [('object', None), ('field', 'Phone')]
    texts = sorted(r['message']['text'] for r in json.loads(render_sarif([obj]))['runs'][0]['results'])
    assert texts == ['[protobuf.rpc] Req', '[protobuf.rpc] Req: field Phone (review: llm-pii)']


def test_rule_tags_are_set_on_the_object_of_confirmed_hits():
    rule = ScoreRule(name='pc', tag='pii', tags='personal-data, gdpr,', fields_all=['last_?name', 'phone'])
    obj = RuleScorer({}, score_rules=[rule]).score(_person('LastName', 'Phone'))
    assert obj.tags == ['pii', 'personal-data', 'gdpr'] and obj.hits[0].object_tags == ['personal-data', 'gdpr']

    field_rule = ScoreRule(name='cards', tag='pci', field='card', tags=['payments'], mode='review')
    obj = RuleScorer({}, score_rules=[field_rule]).score(_person('CardNumber'))
    assert obj.tags is None                                               # review: not confirmed yet
    apply_hit_statuses([obj], {obj.hits[0].key(obj.hash): 'match'})
    assert obj.tags == ['pci', 'payments'] and obj.fields['CardNumber'].tags == ['pci']   # object only

    backend = FakeLlmBackend(json.dumps({'verdict': 'match', 'fields': ['Phone']}))
    llm = LlmRule(name='person', category='pii', target='object', tags=['personal-data'])
    obj = _person('LastName', 'Phone')
    ScanPipeline(ScoreConfig(score_tags={}, llm_rules=[llm]), llm_backend=backend).score([obj])
    assert 'personal-data' in obj.tags


def test_combination_rule_with_catastrophic_regex_does_not_hang():
    import time
    rule = ScoreRule(name='redos', tag='pii', severity='high', fields_all=['(a|aa)+$', 'phone'])
    scorer = RuleScorer({}, score_rules=[rule])
    started = time.monotonic()
    obj = scorer.score(_person('a' * 40 + '!', 'Phone'))
    assert time.monotonic() - started < 2
    assert not obj.hits
