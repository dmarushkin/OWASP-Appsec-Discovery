import json
import os
import subprocess
from pathlib import Path

import pytest

from appsec_discovery.errors import SemgrepError
from appsec_discovery.parsers.base_parser import DEFAULT_SEMGREP_TIMEOUT, relative_source_path
from appsec_discovery.parsers.golang.parser import GolangParser


def fake_run(returncode=0, stdout='', stderr='', calls=None):
    def _run(cmd, **kwargs):
        if calls is not None:
            calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)
    return _run


def make_parser(source):
    return GolangParser(parser='golang', source_folder=str(source))


def test_run_semgrep_returns_results_with_relative_paths(tmp_path, monkeypatch):
    src = tmp_path / 'src'
    (src / 'pkg').mkdir(parents=True)
    out = {'results': [{'path': str(src / 'pkg' / 'main.go'), 'check_id': 'x'}], 'errors': []}
    calls = []
    monkeypatch.setattr(subprocess, 'run', fake_run(stdout=json.dumps(out), calls=calls))

    results = make_parser(src).run_semgrep(source_folder=str(src), rules_folder='rules')

    assert results == [{'path': '/pkg/main.go', 'check_id': 'x'}]
    cmd, kwargs = calls[0]
    assert cmd[0] == 'semgrep'
    assert kwargs['timeout'] == DEFAULT_SEMGREP_TIMEOUT


def test_run_semgrep_relative_source_folder(tmp_path, monkeypatch):
    (tmp_path / 'code' / 'proj').mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    out = {'results': [{'path': 'code/proj/a/b.go'}]}
    monkeypatch.setattr(subprocess, 'run', fake_run(stdout=json.dumps(out)))

    results = make_parser('code/proj').run_semgrep(source_folder='code/proj', rules_folder='rules')

    assert results[0]['path'] == '/a/b.go'


@pytest.mark.parametrize('source', ['code/proj', 'code/proj/', './code/proj'])
def test_relative_source_path_variants(tmp_path, monkeypatch, source):
    (tmp_path / 'code' / 'proj').mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    assert relative_source_path('code/proj/x.go', source) == '/x.go'


def test_relative_source_path_outside_folder_falls_back():
    assert relative_source_path('/other/x.go', '/src') == '/other/x.go'


def test_run_semgrep_empty_results(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, 'run', fake_run(stdout=json.dumps({'results': [], 'errors': []})))
    assert make_parser(tmp_path).run_semgrep(str(tmp_path), 'rules') == []


def test_run_semgrep_logs_errors(tmp_path, monkeypatch, caplog):
    out = {'results': [], 'errors': [{'message': 'boom in file'}]}
    monkeypatch.setattr(subprocess, 'run', fake_run(stdout=json.dumps(out)))
    with caplog.at_level('WARNING'):
        assert make_parser(tmp_path).run_semgrep(str(tmp_path), 'rules') == []
    assert 'boom in file' in caplog.text


def test_run_semgrep_fatal_exit_code_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, 'run', fake_run(returncode=2, stdout='{"results": []}', stderr='fatal'))
    with pytest.raises(SemgrepError, match='fatal'):
        make_parser(tmp_path).run_semgrep(str(tmp_path), 'rules')


def test_run_semgrep_invalid_json_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, 'run', fake_run(stdout='not json', stderr='oops'))
    with pytest.raises(SemgrepError):
        make_parser(tmp_path).run_semgrep(str(tmp_path), 'rules')


def test_run_semgrep_missing_binary_raises(tmp_path, monkeypatch):
    def _run(cmd, **kwargs):
        raise FileNotFoundError('semgrep')
    monkeypatch.setattr(subprocess, 'run', _run)
    with pytest.raises(SemgrepError, match='not found'):
        make_parser(tmp_path).run_semgrep(str(tmp_path), 'rules')


def test_run_semgrep_timeout_raises(tmp_path, monkeypatch):
    def _run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs['timeout'])
    monkeypatch.setattr(subprocess, 'run', _run)
    parser = GolangParser(parser='golang', source_folder=str(tmp_path), semgrep_timeout=5)
    with pytest.raises(SemgrepError, match='timed out'):
        parser.run_semgrep(str(tmp_path), 'rules')


def test_semgrep_parser_run_scan_propagates_error(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, 'run', fake_run(returncode=2, stderr='fatal'))
    with pytest.raises(SemgrepError):
        make_parser(tmp_path).run_scan()


@pytest.mark.parametrize('parser_name', ['golang', 'java', 'python', 'db', 'client'])
def test_semgrep_parsers_parse_none_report(parser_name):
    from appsec_discovery.parsers import ParserFactory
    cls = ParserFactory.get_parser(parser_name)
    assert cls(parser=parser_name, source_folder='some').parse_report(None) == []


@pytest.mark.parametrize('parser_name', ['graphql', 'javascript', 'protobuf', 'swagger', 'terraform'])
def test_native_parsers_parse_none_report(parser_name):
    from appsec_discovery.parsers import ParserFactory
    cls = ParserFactory.get_parser(parser_name)
    assert cls(parser=parser_name, source_folder='some').parse_report(None) == []


@pytest.mark.semgrep
def test_run_semgrep_real_binary_keeps_relative_paths():
    """Integration: the real semgrep keeps paths relative to the scanned folder."""
    import shutil
    if not shutil.which('semgrep'):
        pytest.skip('semgrep not installed')
    samples = os.path.join(str(Path(__file__).resolve().parent), 'golang_samples')
    parser = make_parser(samples)
    rules = os.path.join(str(Path(__file__).resolve().parent.parent), 'appsec_discovery', 'parsers', 'golang', 'scanner_rules')
    results = parser.run_semgrep(samples, rules)
    assert results
    assert all(r['path'] == '/main.go' for r in results)
