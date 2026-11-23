import pytest

from appsec_discovery.errors import SemgrepError, UnknownParserError
from appsec_discovery.models import CodeObject
from appsec_discovery.parsers import ParserFactory, Parser
from appsec_discovery.runner import ScanResult, resolve_parser_names, run_parsers
from appsec_discovery.services import ScanService


def make_object(name):
    return CodeObject(hash=name, object_name=name, object_type='route', parser='good',
                      file='/f', line=1, properties={}, fields={})


class GoodParser(Parser):
    def run_scan(self):
        return [make_object(f'{self.parser}-obj')]

    def parse_report(self, data):
        return []


class BadParser(Parser):
    def run_scan(self):
        raise SemgrepError('semgrep exploded')

    def parse_report(self, data):
        return []


class NoneParser(Parser):
    def run_scan(self):
        return None

    def parse_report(self, data):
        return []


@pytest.fixture
def fake_parsers(monkeypatch):
    registry = {'good': GoodParser, 'bad': BadParser, 'none': NoneParser}

    def get_parser(name):
        if name not in registry:
            raise UnknownParserError(name)
        return registry[name]

    monkeypatch.setattr(ParserFactory, 'get_parser', staticmethod(get_parser))
    monkeypatch.setattr(ParserFactory, 'get_parser_types', staticmethod(lambda: list(registry)))
    return registry


def test_get_parser_unknown_raises():
    with pytest.raises(UnknownParserError):
        ParserFactory.get_parser('no_such_parser')
    with pytest.raises(UnknownParserError):
        ParserFactory.get_parser('../graphql')
    with pytest.raises(UnknownParserError):
        ParserFactory.get_parser('__pycache__')


def test_resolve_parser_names_all(fake_parsers):
    assert resolve_parser_names(['all']) == ['good', 'bad', 'none']
    assert resolve_parser_names(None) == ['good', 'bad', 'none']
    assert resolve_parser_names(['good', 'good', 'bad']) == ['good', 'bad']


def test_resolve_parser_names_real_has_no_duplicates():
    names = resolve_parser_names(['all'])
    assert len(names) == len(set(names))
    assert 'swagger' in names


def test_run_parsers_isolates_failures(fake_parsers):
    result = run_parsers('src', ['good', 'bad', 'none'])

    assert isinstance(result, ScanResult)
    assert [o.object_name for o in result.objects] == ['good-obj']
    assert list(result.errors) == ['bad']
    assert 'semgrep exploded' in result.errors['bad']
    assert result.parsers == ['good', 'bad', 'none']
    assert result.failed and not result.all_failed


def test_run_parsers_unknown_parser_is_recorded(fake_parsers):
    result = run_parsers('src', ['good', 'nope'])
    assert [o.object_name for o in result.objects] == ['good-obj']
    assert 'UnknownParserError' in result.errors['nope']


def test_run_parsers_all_failed(fake_parsers):
    result = run_parsers('src', ['bad', 'nope'])
    assert result.objects == []
    assert result.all_failed


def test_run_parsers_nothing_to_run():
    result = run_parsers('src', [])
    assert not result.failed and not result.all_failed


def test_scan_service_survives_failing_parser(fake_parsers):
    service = ScanService(source_folder='src')
    objects = service.scan_folder()

    assert [o.object_name for o in objects] == ['good-obj']
    assert list(service.scan_result.errors) == ['bad']
