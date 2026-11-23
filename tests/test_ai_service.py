"""AiService / LLM layer tests.

The default run is hermetic: ``fake_llm`` replaces the OpenAI-compatible
backend. Tests against real models are opt-in: ``-m llm_local`` needs a local
OpenAI-compatible server (``LLM_BASE_URL``, default ``http://localhost:8080/v1``,
e.g. ``llama-server -hf Qwen/Qwen2.5-0.5B-Instruct-GGUF:Q4_K_M``), ``-m llm_api``
needs ``AI_API_KEY``.
"""
import json
import logging
import os

import pytest

from appsec_discovery.ai import FakeLlmBackend, LlmError, OpenAICompatibleBackend, classify, select_candidate_fields
from appsec_discovery.ai.classifier import parse_answer
from appsec_discovery.models import AiApi
from appsec_discovery.services import ScanService
from appsec_discovery.services.ai_service import AiService
from tests.support import TESTS_DIR, build_object, config_from, require_api_key, require_llm_server

AI_SAMPLES = str(TESTS_DIR / 'ai_samples' / 'code_objects')
USER_POST = 'POST /user'


def scan_service(config_name: str, source_folder: str = 'some') -> ScanService:
    with open(TESTS_DIR / 'config_samples' / config_name) as conf_file:
        return ScanService(source_folder=source_folder, conf_file=conf_file)


def by_name(objects, name):
    [obj] = [o for o in objects if o.object_name == name]
    return obj


# --------------------------------------------------------------------------- config


@pytest.mark.parametrize('name, model_id', [
    ('ai_conf_llama.yaml', 'mradermacher/Llama-3.2-3B-Instruct-uncensored-GGUF'),
    ('ai_conf_llama_8b.yaml', 'QuantFactory/DarkIdol-Llama-3.1-8B-Instruct-1.2-Uncensored-GGUF'),
    ('ai_conf_vikhr_7b.yaml', 'Neurogen/Vikhr-Llama3.1-8B-Instruct-R-21-09-24-Q4_K_M-GGUF'),
])
def test_deprecated_ai_local_maps_to_local_server(name, model_id, caplog):
    with caplog.at_level(logging.WARNING, logger='appsec_discovery.models.config'):
        config = config_from(name)
    assert config.ai_local.model_id == model_id                     # still loads
    assert config.ai_api.base_url == 'http://localhost:8080/v1'     # mapped to a local server
    assert config.ai_api.model == model_id
    assert 'security bot' in config.ai_api.system_prompt
    assert config.ai_api.api_key is None
    assert any("'ai_local' is deprecated" in r.getMessage() for r in caplog.records)


def test_ai_local_custom_base_url():
    config = config_from("ai_local:\n  base_url: http://llm:9000/v1\n  model_id: m\n")
    assert config.ai_api.base_url == 'http://llm:9000/v1'


def test_ai_local_ignored_when_ai_api_set(caplog):
    with caplog.at_level(logging.WARNING, logger='appsec_discovery.models.config'):
        config = config_from("ai_local:\n  model_id: local\nai_api:\n  base_url: http://api\n  model: remote\n")
    assert config.ai_api.model == 'remote'
    assert any('ignored' in r.getMessage() for r in caplog.records)


def test_ai_api_config_sample():
    config = config_from('ai_conf_deepseek.yaml')
    assert config.ai_local is None
    assert config.ai_api.model == 'deepseek-chat'
    assert config.ai_api.base_url == 'https://api.deepseek.com'
    assert (config.ai_api.timeout, config.ai_api.max_retries, config.ai_api.structured) == (120.0, 2, 'auto')


def test_local_server_config_sample():
    config = config_from('ai_conf_local_server.yaml')
    assert config.ai_api.base_url == 'http://localhost:8080/v1'
    assert config.ai_api.api_key is None


# --------------------------------------------------------------------------- classifier


def test_select_candidate_fields():
    fields = [('input.email', 'string'), ('input.id', 'string'), ('input.user_id', 'int'), ('input.flag', 'bool'),
              ('input.userId', 'string'), ('input.page', 'int'), ('input.age', 'integer')]
    assert select_candidate_fields(fields) == ['input.email', 'input.age']


def test_parse_answer_exact_names():
    names = ['input.username', 'input.name', 'input.card']
    answer = '```json\n{"fields": [{"name": "name", "category": "PII"}, {"name": "input.card", "category": "money"},' \
             ' {"name": "unknown", "category": "pii"}]}\n```'
    # 'name' does not match inside 'username'; unknown categories become 'other'
    assert parse_answer(answer, names) == {'input.name': ['pii'], 'input.card': ['other']}


def test_parse_answer_text_around_json():
    assert parse_answer('Sure: {"fields": [{"name": "email", "category": "pii"}]} done', ['email']) == {'email': ['pii']}


def test_parse_answer_not_json():
    with pytest.raises(LlmError):
        parse_answer('yes, email', ['email'])


def test_classify_sends_schema_and_system_prompt():
    backend = FakeLlmBackend('{"fields": []}')
    assert classify('User', ['input.email'], backend, 'sys') == {}
    [(system, user, schema)] = backend.calls
    assert system == 'sys'
    assert 'Object: User' in user and '- input.email' in user
    assert schema['properties']['fields']['items']['properties']['name']['enum'] == ['input.email']


# --------------------------------------------------------------------------- OpenAI-compatible backend


class _Response:
    def __init__(self, content):
        message = type('Message', (), {'content': content})()
        self.choices = [type('Choice', (), {'message': message})()]


class _RecordingClient:
    def __init__(self, reject=()):
        self.calls = []
        self.reject = set(reject)
        self.chat = type('Chat', (), {'completions': self})()

    def create(self, **kwargs):
        import httpx
        import openai

        self.calls.append(kwargs)
        mode = (kwargs.get('response_format') or {}).get('type')
        if mode in self.reject:
            request = httpx.Request('POST', 'http://x/chat/completions')
            raise openai.BadRequestError('unsupported response_format', response=httpx.Response(400, request=request),
                                         body=None)
        return _Response('{"fields": []}')


def test_backend_falls_back_from_json_schema_once():
    client = _RecordingClient(reject={'json_schema'})
    backend = OpenAICompatibleBackend(base_url='http://x', model='m', client=client, max_tokens=64)
    assert backend.complete('s', 'u', json_schema={'type': 'object'}) == '{"fields": []}'
    assert backend.complete('s', 'u', json_schema={'type': 'object'}) == '{"fields": []}'
    modes = [c.get('response_format', {}).get('type') for c in client.calls]
    assert modes == ['json_schema', 'json_object', 'json_object']
    assert all(c['model'] == 'm' and c['max_tokens'] == 64 and c['temperature'] == 0.0 for c in client.calls)


def test_backend_request_error_does_not_downgrade_structured_mode():
    import openai

    # a 400 that every mode gets (e.g. prompt over the context size) is raised and keeps json_schema
    client = _RecordingClient(reject={'json_schema', 'json_object', None})
    backend = OpenAICompatibleBackend(base_url='http://x', model='m', client=client)
    with pytest.raises(openai.BadRequestError):
        backend.complete('s', 'u', json_schema={'type': 'object'})
    client.reject = set()
    backend.complete('s', 'u', json_schema={'type': 'object'})
    modes = [(c.get('response_format') or {}).get('type') for c in client.calls]
    assert modes == ['json_schema', 'json_object', None, 'json_schema']


def test_backend_plain_completion_has_no_response_format():
    client = _RecordingClient()
    OpenAICompatibleBackend(base_url='http://x', model='m', client=client).complete(None, 'u')
    assert 'response_format' not in client.calls[0]
    assert client.calls[0]['messages'] == [{'role': 'user', 'content': 'u'}]


def test_backend_builds_one_client_with_timeout_and_retries():
    backend = OpenAICompatibleBackend(base_url='http://localhost:8080/v1', model='m', timeout=7, max_retries=5)
    client = backend.client
    assert backend.client is client
    assert client.timeout == 7 and client.max_retries == 5
    assert client.api_key == 'none'                     # a local server needs no key


# --------------------------------------------------------------------------- AiService (hermetic)


def ai_service(config_name='ai_conf_local_server.yaml', exclude_scoring=None):
    config = config_from(config_name)
    return AiService(exclude_scoring=exclude_scoring or [], ai_api=config.ai_api)


def test_ai_scores_selected_fields(fake_llm):
    fake = fake_llm(fields=['email'])
    obj = build_object(object_name='User', fields={'input.id': 'string', 'input.email': 'string',
                                                   'input.age': 'integer', 'input.flag': 'bool'})

    [scored] = ai_service().ai_score_objects([obj])

    assert scored.fields['input.email'].severity == 'medium'
    assert scored.fields['input.email'].tags == ['llm-pii']
    assert scored.fields['input.age'].severity is None
    assert scored.severity == 'medium'
    assert scored.tags == ['llm-pii']

    # one structured request per object, with the configured system prompt
    [(system, question, schema)] = fake.calls
    assert 'security bot' in system
    assert 'input.email' in question and 'input.age' in question
    # ids and non str/int fields are never sent to the LLM
    assert 'input.id' not in question and 'input.flag' not in question
    assert schema is not None


def test_ai_one_backend_per_service(fake_llm):
    fake = fake_llm(fields=['email'])
    service = ai_service()
    service.ai_score_objects([build_object(hash='1', fields=['input.email']), build_object(hash='2', fields=['input.email'])])
    assert len(fake.loads) == 1 and len(fake.calls) == 2


def test_ai_empty_answer_scores_nothing(fake_llm):
    fake_llm(fields=[])
    [scored] = ai_service().ai_score_objects([build_object(fields=['input.email'])])
    assert scored.severity is None
    assert scored.fields['input.email'].severity is None


def test_ai_multiple_categories(fake_llm):
    fake_llm(category='pii, finance', fields=['passport'])
    [scored] = ai_service().ai_score_objects([build_object(fields=['input.passport'])])
    assert scored.fields['input.passport'].tags == ['llm-pii', 'llm-finance']


def test_ai_categories_per_field(fake_llm):
    fake_llm(raw=json.dumps({'fields': [{'name': 'input.password', 'category': 'auth'},
                                        {'name': 'input.email', 'category': 'pii'}]}))
    [scored] = ai_service().ai_score_objects([build_object(fields=['input.password', 'input.email', 'input.username'])])
    assert scored.fields['input.password'].tags == ['llm-auth']
    assert scored.fields['input.email'].tags == ['llm-pii']
    assert scored.fields['input.username'].tags is None


def test_ai_keeps_higher_keyword_severity(fake_llm):
    fake_llm(fields=['passport'])
    obj = build_object(fields=['input.passport'])
    keyword_scored = ScanService(source_folder='some').score_objects([obj])

    [scored] = ai_service().ai_score_objects(keyword_scored)

    assert scored.fields['input.passport'].severity == 'high'
    assert scored.fields['input.passport'].tags == ['pii', 'llm-pii']
    assert scored.severity == 'high'


def test_ai_object_without_candidate_fields_not_asked(fake_llm):
    fake = fake_llm(fields=['id'])
    [scored] = ai_service().ai_score_objects([build_object(fields=['input.id', 'input.user_id'])])
    assert fake.calls == []
    assert scored.severity is None


@pytest.mark.parametrize('exclude, excluded', [
    ({'tag': 'llm-pii'}, True),
    ({'field_name': 'email'}, True),
    ({'parser': 'swagger'}, True),
    ({'parser': 'golang'}, False),
    # intentional: keyword excludes never apply to LLM scoring (rejected idea in the report)
    ({'keyword': 'email'}, False),
    ({'prop_name': 'path'}, False),
])
def test_ai_exclude_scoring(fake_llm, exclude, excluded):
    from appsec_discovery.models import ExcludeScoring

    fake_llm(fields=['email'])
    service = ai_service(exclude_scoring=[ExcludeScoring(**exclude)])
    [scored] = service.ai_score_objects([build_object(fields=['input.email'])])
    assert (scored.fields['input.email'].severity is None) is excluded


def test_ai_api_backend_from_config(fake_llm):
    fake = fake_llm(category='auth', fields=['password'])
    [scored] = ai_service('ai_conf_deepseek.yaml').ai_score_objects([build_object(fields=['input.password'])])
    assert scored.fields['input.password'].tags == ['llm-auth']
    [ai_api] = fake.loads
    assert (ai_api.base_url, ai_api.api_key, ai_api.model) == ('https://api.deepseek.com', 'test', 'deepseek-chat')


def test_ai_service_accepts_deprecated_ai_local(fake_llm):
    fake = fake_llm(fields=['email'])
    local = config_from('ai_conf_llama.yaml').ai_local
    AiService(exclude_scoring=[], ai_local=local).ai_score_objects([build_object(fields=['input.email'])])
    assert fake.loads[0].base_url == 'http://localhost:8080/v1'


def test_ai_error_is_isolated_per_object(fake_llm):
    def flaky(system, user, schema):
        if 'input.email' in user:
            raise RuntimeError('model crashed')
        return json.dumps({'fields': [{'name': 'phone', 'category': 'pii'}]})

    fake_llm(answer=flaky)
    objects = [build_object(hash='1', fields=['input.email']), build_object(hash='2', fields=['input.phone'])]
    result = ai_service().ai_score_objects(objects)
    assert result is objects
    assert objects[0].severity is None and objects[0].fields['input.email'].tags is None
    assert objects[1].fields['input.phone'].tags == ['llm-pii']


def test_ai_bad_answer_leaves_object_unscored(fake_llm):
    fake_llm(raw='I think email is private')
    [scored] = ai_service().ai_score_objects([build_object(fields=['input.email'])])
    assert scored.severity is None


def test_scan_folder_with_ai_config(fake_llm):
    fake_llm(fields=['username'])
    service = scan_service('ai_conf_vikhr_7b.yaml', source_folder=AI_SAMPLES)
    objects = service.scan_folder()

    field = by_name(objects, USER_POST).fields['input.username']
    assert field.severity == 'medium'
    assert 'llm-pii' in field.tags
    assert 'auth' in field.tags  # keyword scoring ran first


# --------------------------------------------------------------------------- real models (opt-in)


@pytest.mark.llm_local
def test_ai_local_server_scan():
    base_url = require_llm_server()
    service = scan_service('ai_conf_local_server.yaml', source_folder=AI_SAMPLES)
    service.config.ai_api.base_url = base_url

    objects = service.scan_folder()

    obj = by_name(objects, USER_POST)
    llm_tags = [t for f in obj.fields.values() for t in (f.tags or []) if t.startswith('llm-')]
    assert llm_tags, 'the model did not flag any field of the user route'


@pytest.mark.llm_local
def test_ai_local_server_classifies_passport():
    base_url = require_llm_server()
    backend = OpenAICompatibleBackend(base_url=base_url, model=os.getenv('LLM_MODEL', 'local-model'))
    result = classify('Client', ['passport_number', 'created_at_page'], backend)
    assert 'passport_number' in result


@pytest.mark.llm_api
def test_ai_api_scan():
    api_key = require_api_key()
    service = scan_service('ai_conf_deepseek.yaml', source_folder=AI_SAMPLES)
    service.config.ai_api.api_key = api_key

    objects = service.scan_folder()

    assert service.config.ai_api.model == 'deepseek-chat'
    field = by_name(objects, USER_POST).fields['input.username']
    assert field.severity == 'medium'
    assert 'llm-pii' in field.tags


@pytest.mark.llm_api
def test_ai_api_classifies_passport():
    api_key = require_api_key()
    ai_api = config_from('ai_conf_deepseek.yaml').ai_api
    backend = OpenAICompatibleBackend(base_url=ai_api.base_url, model=ai_api.model, api_key=api_key)
    assert 'passport_number' in classify('Client', ['passport_number'], backend, ai_api.system_prompt)


def test_ai_api_model_requires_base_url():
    with pytest.raises(Exception):
        AiApi(model='m')


def test_backend_names_a_truncated_answer():
    from appsec_discovery.ai.backends import LlmError

    class _Cut:
        def __init__(self):
            message = type('Message', (), {'content': '{"fields": [{"name": "LastName", "verdict": "ma'})()
            self.choices = [type('Choice', (), {'message': message, 'finish_reason': 'length'})()]

    class _Client:
        def __init__(self):
            self.chat = type('Chat', (), {'completions': self})()

        def create(self, **kwargs):
            return _Cut()

    backend = OpenAICompatibleBackend(base_url='http://x', model='m', client=_Client(), max_tokens=32)
    with pytest.raises(LlmError, match='truncated at max_tokens=32'):
        backend.complete('s', 'u', json_schema={'type': 'object'})


def test_backend_default_max_tokens_fits_long_answers():
    assert OpenAICompatibleBackend(base_url='http://x', model='m').max_tokens == 8192
