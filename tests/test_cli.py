import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from appsec_discovery.cli import main
from appsec_discovery.errors import SemgrepError, UnknownParserError
from appsec_discovery.models import CodeObject
from appsec_discovery.parsers import ParserFactory, Parser

TESTS = Path(__file__).resolve().parent
SWAGGER_SAMPLES = str(TESTS / 'swagger_samples')


def write_config(tmp_path, text):
    path = tmp_path / 'conf.yaml'
    path.write_text(text)
    return str(path)


class GoodParser(Parser):
    def run_scan(self):
        return [CodeObject(hash='h', object_name='good-obj', object_type='route', parser='good',
                           file='/f', line=1, properties={}, fields={})]

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


def test_cli_swagger_json_report(tmp_path):
    conf = write_config(tmp_path, "parsers: [swagger]\n")
    out = tmp_path / 'report.json'
    result = CliRunner().invoke(main, ['--source', SWAGGER_SAMPLES, '--config', conf,
                                       '--output', str(out), '--output-type', 'json'])
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    assert data


@pytest.mark.parametrize('text', ["parsers: [unclosed\n", "- a\n- b\n", "exclude_scan: 5\n"])
def test_cli_invalid_config_exits_2(tmp_path, text):
    conf = write_config(tmp_path, text)
    result = CliRunner().invoke(main, ['--source', SWAGGER_SAMPLES, '--config', conf])
    assert result.exit_code == 2
    assert '--config' in result.output


def test_cli_empty_config_uses_defaults(tmp_path, fake_parsers):
    conf = write_config(tmp_path, "")
    result = CliRunner().invoke(main, ['--source', str(tmp_path), '--config', conf])
    # 'bad' fails but 'good' succeeds -> exit 0 without --fail-on-error
    assert result.exit_code == 0
    assert 'good-obj' in result.output


def test_cli_partial_failure_exit_codes(tmp_path, fake_parsers):
    conf = write_config(tmp_path, "parsers: [good, bad]\n")
    out = tmp_path / 'r.yaml'

    result = CliRunner().invoke(main, ['--source', str(tmp_path), '--config', conf, '--output', str(out)])
    assert result.exit_code == 0
    assert 'good-obj' in out.read_text()

    result = CliRunner().invoke(main, ['--source', str(tmp_path), '--config', conf, '--output', str(out),
                                       '--fail-on-error'])
    assert result.exit_code == 1
    assert 'good-obj' in out.read_text()


def test_cli_all_parsers_failed_exits_1(tmp_path, fake_parsers):
    conf = write_config(tmp_path, "parsers: [bad]\n")
    result = CliRunner().invoke(main, ['--source', str(tmp_path), '--config', conf])
    assert result.exit_code == 1


def test_cli_unknown_parser_only_exits_1(tmp_path, fake_parsers):
    conf = write_config(tmp_path, "parsers: [nope]\n")
    result = CliRunner().invoke(main, ['--source', str(tmp_path), '--config', conf])
    assert result.exit_code == 1


@pytest.mark.parametrize('output_type, load', [
    ('yaml', yaml.safe_load),
    ('json', json.loads),
    ('sarif', lambda text: json.loads(text)['runs'][0]['results']),
])
def test_cli_each_output_type(tmp_path, output_type, load):
    conf = write_config(tmp_path, "parsers: [swagger]\n")
    out = tmp_path / f'report.{output_type}'
    result = CliRunner().invoke(main, ['--source', SWAGGER_SAMPLES, '--config', conf,
                                       '--output', str(out), '--output-type', output_type])
    assert result.exit_code == 0, result.output
    items = load(out.read_text())
    assert isinstance(items, list) and len(items) > 0


def test_cli_output_type_case_insensitive_and_default_stdout(tmp_path):
    conf = write_config(tmp_path, "parsers: [swagger]\n")
    result = CliRunner().invoke(main, ['--source', SWAGGER_SAMPLES, '--config', conf, '--output-type', 'JSON'])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)


def test_cli_default_output_is_yaml_to_stdout(tmp_path):
    conf = write_config(tmp_path, "parsers: [swagger]\n")
    result = CliRunner().invoke(main, ['--source', SWAGGER_SAMPLES, '--config', conf])
    assert result.exit_code == 0, result.output
    data = yaml.safe_load(result.output)
    assert data and all('hash' in o for o in data)


def test_cli_only_scored_objects(tmp_path):
    conf = write_config(tmp_path, "parsers: [swagger]\n")
    args = ['--source', SWAGGER_SAMPLES, '--config', conf, '--output-type', 'json']
    everything = json.loads(CliRunner().invoke(main, args).output)
    scored = json.loads(CliRunner().invoke(main, args + ['--only-scored-objects']).output)
    assert 0 < len(scored) < len(everything)
    assert all(o.get('severity') for o in scored)


def test_cli_missing_source_exits_2(tmp_path):
    result = CliRunner().invoke(main, ['--source', str(tmp_path / 'nope')])
    assert result.exit_code == 2


# --------------------------------------------------------------------------- P2-3: log levels, CI gate

from appsec_discovery import cli as cli_module  # noqa: E402
import logging  # noqa: E402


@pytest.mark.parametrize('verbosity, level', [(0, logging.WARNING), (1, logging.INFO), (2, logging.DEBUG), (5, logging.DEBUG)])
def test_cli_log_level(verbosity, level):
    assert cli_module.log_level(verbosity) == level


@pytest.mark.parametrize('flags, level', [([], logging.WARNING), (['-v'], logging.INFO), (['-vv'], logging.DEBUG)])
def test_cli_verbose_flag_sets_root_level(tmp_path, fake_parsers, flags, level):
    conf = write_config(tmp_path, "parsers: [good]\n")
    root = logging.getLogger()
    before = root.level
    try:
        result = CliRunner().invoke(main, ['--source', str(tmp_path), '--config', conf] + flags)
        assert result.exit_code == 0, result.output
        assert root.level == level
    finally:
        root.setLevel(before)


SEVERITY_GATE_CONF = "parsers: [swagger]\n"


def test_cli_fail_on_severity_hit(tmp_path):
    conf = write_config(tmp_path, SEVERITY_GATE_CONF)
    out = tmp_path / 'r.json'
    result = CliRunner().invoke(main, ['--source', SWAGGER_SAMPLES, '--config', conf, '--output', str(out),
                                       '--output-type', 'json', '--fail-on-severity', 'HIGH'])
    assert result.exit_code == 1
    assert '--fail-on-severity high' in result.output
    # the report is still written
    assert json.loads(out.read_text())


def test_cli_fail_on_severity_not_reached(tmp_path):
    conf = write_config(tmp_path, SEVERITY_GATE_CONF)
    result = CliRunner().invoke(main, ['--source', SWAGGER_SAMPLES, '--config', conf, '--output',
                                       str(tmp_path / 'r.yaml'), '--fail-on-severity', 'critical'])
    assert result.exit_code == 0, result.output


def test_cli_fail_on_severity_rejects_unknown(tmp_path):
    result = CliRunner().invoke(main, ['--source', SWAGGER_SAMPLES, '--fail-on-severity', 'info'])
    assert result.exit_code == 2


def test_severity_gate_helper():
    objs = [CodeObject(hash='h', object_name='o', object_type='t', parser='p', file='/f', line=1,
                       properties={}, fields={}, severity=sev) for sev in (None, 'medium')]
    assert cli_module.severity_gate_hit(objs, None) is None
    assert cli_module.severity_gate_hit(objs, 'medium') == 'medium'
    assert cli_module.severity_gate_hit(objs, 'high') is None
