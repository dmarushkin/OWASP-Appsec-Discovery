"""A built-in parser whose module fails to import must fail the scan, not vanish from it."""
import pytest

from appsec_discovery.parsers import ParserFactory, parser_factory
from appsec_discovery.parsers.base_parser import REGISTRY
from appsec_discovery.runner import resolve_parser_names, run_parsers


@pytest.fixture
def broken_swagger(monkeypatch):
    parser_factory.load_builtin_parsers()
    monkeypatch.delitem(REGISTRY, 'swagger')
    monkeypatch.setitem(parser_factory._import_errors, 'swagger',
                        ImportError("cannot import name '_create_parser' from 'openapi_parser.parser'"))


def test_broken_builtin_parser_stays_known(broken_swagger):
    assert 'swagger' in ParserFactory.get_parser_types()
    assert 'swagger' in ParserFactory.import_errors()
    assert 'swagger' in resolve_parser_names(['all'])
    with pytest.raises(ImportError):
        ParserFactory.get_parser('swagger')


@pytest.mark.parametrize('names', [['all'], ['swagger', 'graphql']])
def test_broken_builtin_parser_makes_the_scan_partial(broken_swagger, tmp_path, names):
    (tmp_path / 'schema.graphql').write_text('type Query { me: String }\n')
    result = run_parsers(str(tmp_path), names)
    assert 'swagger' in result.parsers
    assert result.failed and 'ImportError' in result.errors['swagger']
    assert 'graphql' not in result.errors


def test_scan_api_reports_the_broken_parser(broken_swagger, tmp_path):
    import appsec_discovery
    from appsec_discovery.models import ScoreConfig
    result = appsec_discovery.scan(str(tmp_path), ScoreConfig(parsers=['swagger']))
    assert set(result.errors) == {'swagger'}
