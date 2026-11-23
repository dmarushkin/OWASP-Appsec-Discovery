"""Public API (P1-1): ``appsec_discovery.scan``, ``ScanPipeline`` and the ``ScanService`` wrapper."""
import io
import warnings

import pytest

import appsec_discovery
from appsec_discovery import ConfigError, ScanPipeline, ScanResult, scan
from appsec_discovery.errors import SemgrepError, UnknownParserError
from appsec_discovery.models import CodeObject, ScoreConfig
from appsec_discovery.parsers import Parser, ParserFactory
from appsec_discovery.pipeline import ai_scorer_from_config
from appsec_discovery.services import ScanService
from tests.support import build_object

EXCLUDE_CONF = """
parsers: [good, bad]
exclude_scan:
  - object_name: skip-me
exclude_scoring:
  - keyword: phone
"""


class GoodParser(Parser):
    def run_scan(self):
        return [
            build_object(hash='1', object_name='keep-me', parser='good', fields=['email', 'phone', 'color']),
            build_object(hash='2', object_name='skip-me', parser='good', fields=['email']),
            build_object(hash='3', object_name='plain', parser='good', fields=['color']),
        ]

    def parse_report(self, data):
        return []


class BadParser(Parser):
    def run_scan(self):
        raise SemgrepError('semgrep exploded')

    def parse_report(self, data):
        return []


@pytest.fixture
def fake_parsers(monkeypatch):
    registry = {'good': GoodParser, 'bad': BadParser}

    def get_parser(name):
        if name not in registry:
            raise UnknownParserError(name)
        return registry[name]

    monkeypatch.setattr(ParserFactory, 'get_parser', staticmethod(get_parser))
    monkeypatch.setattr(ParserFactory, 'get_parser_types', staticmethod(lambda: list(registry)))


def names(objects):
    return [o.object_name for o in objects]


def test_public_exports():
    for name in ('scan', 'load_config', 'load_config_file', 'run_parsers', 'render_report',
                 'ScanPipeline', 'ScanResult', 'ConfigError', '__version__'):
        assert hasattr(appsec_discovery, name), name


def test_scan_applies_exclude_scan_scoring_and_excludes(fake_parsers):
    config = appsec_discovery.load_config(io.StringIO(EXCLUDE_CONF))
    result = scan('src', config)

    assert isinstance(result, ScanResult)
    assert names(result.objects) == ['keep-me', 'plain']
    assert result.parsers == ['good', 'bad']
    assert list(result.errors) == ['bad']
    assert result.failed and not result.all_failed

    keep = result.objects[0]
    assert keep.severity == 'medium'
    assert keep.fields['email'].severity == 'medium'
    assert keep.fields['phone'].severity is None  # exclude_scoring keyword
    assert result.objects[1].severity is None


def test_scan_only_scored(fake_parsers):
    result = scan('src', {'parsers': ['good']}, only_scored=True)
    assert names(result.objects) == ['keep-me', 'skip-me']


@pytest.mark.parametrize('kind', ['none', 'mapping', 'path', 'str', 'model'])
def test_scan_config_kinds(fake_parsers, tmp_path, kind):
    path = tmp_path / 'conf.yaml'
    path.write_text('parsers: [good]\n')
    config = {
        'none': None,
        'mapping': {'parsers': ['good']},
        'path': path,
        'str': str(path),
        'model': ScoreConfig(parsers=['good']),
    }[kind]
    result = scan('src', config)
    assert names(result.objects) == ['keep-me', 'skip-me', 'plain']


@pytest.mark.parametrize('config', [{'exclude_scan': 5}, {'score_tags': {'pii': {'hgh': ['x']}}}])
def test_scan_invalid_config_raises(config):
    with pytest.raises(ConfigError):
        scan('src', config)


def test_scan_missing_config_file_raises(tmp_path):
    with pytest.raises(ConfigError):
        scan('src', tmp_path / 'nope.yaml')


def test_scan_rejects_unknown_config_type():
    with pytest.raises(TypeError):
        scan('src', 42)


def test_scan_does_not_mutate_config(fake_parsers):
    config = ScoreConfig(parsers=['good'])
    before = config.dict()
    scan('src', config, only_scored=True)
    assert config.dict() == before


class RecordingAi:
    def __init__(self):
        self.seen = []

    def ai_score_objects(self, code_objects):
        self.seen = list(code_objects)
        for obj in code_objects:
            obj.apply_score('low', ['llm'])
        return code_objects


def test_scan_explicit_ai_scorer_runs_after_rules(fake_parsers):
    ai = RecordingAi()
    result = scan('src', {'parsers': ['good'], 'exclude_scan': [{'object_name': 'skip-me'}]}, ai=ai, only_scored=True)
    # the AI sees the filtered, keyword-scored objects
    assert names(ai.seen) == ['keep-me', 'plain']
    assert ai.seen[0].severity == 'high'  # keyword scoring ran first (phone)
    # 'plain' is scored only by the AI and survives only_scored
    assert names(result.objects) == ['keep-me', 'plain']
    assert result.objects[1].tags == ['llm']


def test_ai_scorer_from_config_disabled_by_default():
    assert ai_scorer_from_config(ScoreConfig()) is None
    assert ScanPipeline().ai is None


def test_pipeline_can_ignore_config_ai():
    config = ScoreConfig(ai_api={'base_url': 'http://x', 'api_key': 'k', 'model': 'm', 'system_prompt': 's'})
    assert ScanPipeline(config, use_config_ai=False).ai is None
    assert ScanPipeline(config).ai is not None


def test_pipeline_reusable_across_sources(fake_parsers):
    pipeline = ScanPipeline(ScoreConfig(parsers=['good']))
    first, second = pipeline.run('a'), pipeline.run('b')
    assert names(first.objects) == names(second.objects)
    assert first.objects[0] is not second.objects[0]


def test_pipeline_process_result_keeps_errors():
    parsed = ScanResult(objects=[build_object(object_name='x', fields=['email'])], errors={'bad': 'boom'},
                        parsers=['good', 'bad'])
    result = ScanPipeline(only_scored=True).process_result(parsed)
    assert names(result.objects) == ['x']
    assert result.errors == {'bad': 'boom'} and result.parsers == ['good', 'bad']
    assert result.errors is not parsed.errors


# --------------------------------------------------------------------------- ScanService wrapper


def test_scan_service_is_deprecated():
    with pytest.warns(DeprecationWarning, match='appsec_discovery.scan'):
        ScanService(source_folder='src')


def test_scan_service_matches_scan(fake_parsers):
    conf = EXCLUDE_CONF
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        service = ScanService(source_folder='src', conf_file=io.StringIO(conf), only_scored_objects=True)
    legacy = service.scan_folder()

    result = scan('src', appsec_discovery.load_config(io.StringIO(conf)), only_scored=True)

    assert [o.dict() for o in legacy] == [o.dict() for o in result.objects]
    # scan_result keeps the raw parser output (before filtering) and the errors
    assert names(service.scan_result.objects) == ['keep-me', 'skip-me', 'plain']
    assert service.scan_result.errors == result.errors


def test_scan_service_uses_config_set_after_init(fake_parsers):
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        service = ScanService(source_folder='src')
    service.config = ScoreConfig(parsers=['good'], exclude_scan=[{'object_name': 'plain'}])
    assert names(service.scan_folder()) == ['keep-me', 'skip-me']
    assert all(isinstance(o, CodeObject) for o in service.filter_objects(service.scan_result.objects))
