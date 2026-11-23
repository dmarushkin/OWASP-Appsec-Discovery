"""Parser framework (P1-5): registry, Finding, ObjectCollector, walker, single semgrep run."""
import json
import subprocess
import warnings

import pytest

from appsec_discovery.errors import UnknownParserError
from appsec_discovery.models import ExcludeScan
from appsec_discovery.parsers import REGISTRY, Finding, ObjectCollector, ParserFactory, SemgrepParser, SemgrepRunner
from appsec_discovery.parsers.common import walk_files
from appsec_discovery.runner import resolve_parser_names, run_parsers
from tests.golden_support import SEMGREP_PARSERS, load_golden, load_semgrep_fixture, normalize

BUILTIN = ['client', 'db', 'golang', 'graphql', 'java', 'javascript', 'migrations', 'protobuf', 'python', 'swagger', 'terraform']


# --- registry / factory -------------------------------------------------------

def test_registry_has_every_builtin_parser_sorted():
    assert ParserFactory.get_parser_types() == BUILTIN
    for name in BUILTIN:
        assert REGISTRY[name].name == name


def test_get_parser_returns_registered_class():
    assert ParserFactory.get_parser('javascript').__qualname__ == 'JsGqlParser'
    with pytest.raises(UnknownParserError):
        ParserFactory.get_parser('Parser')


@pytest.mark.parametrize('name', ['db', 'client'])
def test_deprecated_parsers_still_accepted_with_warning(name, caplog):
    with pytest.warns(DeprecationWarning, match='deprecated'):
        cls = ParserFactory.get_parser(name)
    assert cls(parser=name, source_folder='.').run_scan() == []
    assert 'deprecated' in caplog.text


def test_all_excludes_deprecated_parsers():
    names = resolve_parser_names(['all'])
    assert 'db' not in names and 'client' not in names
    assert names == sorted(set(BUILTIN) - {'db', 'client'})
    # named explicitly they still run
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        assert resolve_parser_names(['db', 'golang']) == ['db', 'golang']


def test_subclass_without_name_is_not_registered():
    before = dict(REGISTRY)

    class Anonymous(SemgrepParser):
        pass

    assert REGISTRY == before


# --- Finding ------------------------------------------------------------------

def test_finding_accessors():
    f = Finding({
        'check_id': 'a.b.route-flask-object', 'path': '/app.py', 'start': {'line': 4},
        'extra': {'metadata': {'parser': 'python', 'object_type': 'route', 'framework': 'flask'},
                  'metavars': {'$PATH': {'abstract_content': '"/x"', 'start': {'line': 5}}}},
    })
    assert (f.rule_id, f.path, f.line) == ('route-flask-object', '/app.py', 4)
    assert (f.parser, f.object_type, f.framework) == ('python', 'route', 'flask')
    assert f.mv('$PATH') == '/x'
    assert f.mv('$PATH', strip_quotes=False) == '"/x"'
    assert f.mv('$MISSING') == ''
    assert f.mv_line('$PATH') == 5 and f.mv_line('$MISSING') is None


def test_finding_tolerates_missing_extra():
    f = Finding({'check_id': 'x'})
    assert f.mv('$A') == '' and f.metadata == {} and f.line == 0 and f.path == ''


# --- ObjectCollector -----------------------------------------------------------

def test_object_collector_merges_by_identity_first_wins():
    parser = ParserFactory.get_parser('golang')(parser='golang', source_folder='.')
    acc = ObjectCollector(parser)

    a = acc.get_or_create(object_type='dto', logical_name='User', file='/a.go', object_name='first', line=3,
                          properties={'framework': 'struct'})
    b = acc.get_or_create(object_type='dto', logical_name='User', file='/a.go', object_name='second', line=9)
    acc.add_field(a, 'id', 'int', line=4)
    acc.add_field(b, 'id', 'string', line=10)

    assert a is b and len(acc.objects()) == 1
    assert (a.object_name, a.line, a.fields['id'].field_type) == ('first', 3, 'int')
    assert a.hash == parser.identity('/a.go', 'dto', 'User')


def test_unhandled_rule_is_logged_and_skipped(caplog):
    parser = ParserFactory.get_parser('golang')(parser='golang', source_folder='.')
    finding = {'check_id': 'x.unknown-rule', 'path': '/a.go', 'start': {'line': 1},
               'extra': {'metadata': {'parser': 'golang', 'object_type': 'nope'}, 'metavars': {}}}
    with caplog.at_level('WARNING'):
        assert parser.parse_report([finding, finding]) == []
    assert caplog.text.count('unknown-rule') == 1


def test_rule_id_prefix_alone_is_not_dispatched():
    """Dispatch is by metadata, not by the rule id."""
    parser = ParserFactory.get_parser('golang')(parser='golang', source_folder='.')
    [finding] = load_semgrep_fixture('golang')[:1]
    finding = dict(finding, extra=dict(finding['extra'], metadata={}))
    assert parser.parse_report([finding]) == []


# --- walker -------------------------------------------------------------------

def test_walk_files_prunes_vendor_dirs_and_applies_exclude(tmp_path):
    for rel in ('a.proto', 'node_modules/x/b.proto', 'vendor/c.proto', 'sub/d.proto', 'sub/e.txt', 'gen/f.proto'):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('')

    found = walk_files(str(tmp_path), ['*.proto'], exclude=lambda rel: rel.startswith('/gen/'))
    assert [p[len(str(tmp_path)):] for p in found] == ['/a.proto', '/sub/d.proto']


def test_exclude_scan_file_rules_skip_files_before_parsing(tmp_path, monkeypatch):
    (tmp_path / 'gen').mkdir()
    (tmp_path / 'gen' / 'broken.yaml').write_text('openapi: 3.0.0\npaths: {\n')  # would be logged as a parse failure
    (tmp_path / 'ok.yaml').write_text(
        'openapi: 3.0.0\ninfo: {title: t, version: "1"}\n'
        'paths:\n  /bank:\n    get:\n      responses:\n        "200": {description: ok}\n'
    )

    seen = []
    from appsec_discovery.parsers.swagger.parser import SwaggerParser
    original = SwaggerParser.parse_file
    monkeypatch.setattr(SwaggerParser, 'parse_file', lambda self, path, text: seen.append(path) or original(self, path, text))

    result = run_parsers(str(tmp_path), ['swagger'], exclude_scan=[ExcludeScan(file='^/gen/')])

    assert result.errors == {}
    assert [o.file for o in result.objects] == ['/ok.yaml']
    assert [p[len(str(tmp_path)):] for p in seen] == ['/ok.yaml']


def test_exclude_scan_file_rules_keep_cross_file_content(tmp_path):
    """graphql/protobuf resolve types across files: an excluded file is still read, so the
    objects of the other files keep their fields (only the excluded file's objects go)."""
    (tmp_path / 'gen').mkdir()
    (tmp_path / 'gen' / 'msgs.proto').write_text(
        'syntax = "proto3";\npackage bank;\nmessage Req { string passport = 1; }\nmessage Resp { string id = 1; }\n'
    )
    (tmp_path / 'svc.proto').write_text(
        'syntax = "proto3";\npackage bank;\nservice Bank { rpc Get(Req) returns (Resp); }\n'
    )

    plain = run_parsers(str(tmp_path), ['protobuf'])
    excluded = run_parsers(str(tmp_path), ['protobuf'], exclude_scan=[ExcludeScan(file='^/gen/')])

    assert normalize(excluded.objects) == normalize(plain.objects)
    (obj,) = excluded.objects
    assert 'input.Req.passport' in obj.fields
    assert obj.fields['input.Req.passport'].file == '/gen/msgs.proto'


# --- single semgrep run ---------------------------------------------------------

def test_semgrep_runner_command_has_every_config_timeout_and_excludes():
    cmd = SemgrepRunner(rule_timeout=30).command('/src', ['/r1', '/r2'])
    assert cmd[:2] == ['semgrep', 'scan']
    assert cmd[cmd.index('--config') + 1] == '/r1'
    assert [cmd[i + 1] for i, a in enumerate(cmd) if a == '--config'] == ['/r1', '/r2']
    assert cmd[cmd.index('--timeout') + 1] == '30'
    assert {cmd[i + 1] for i, a in enumerate(cmd) if a == '--exclude'} == {'node_modules', 'vendor'}
    assert '--no-git-ignore' in cmd and cmd[-1] == '/src'


def _configs(cmd):
    return [cmd[i + 1] for i, a in enumerate(cmd) if a == '--config']


def _parser_of(rules_dir):
    return rules_dir.rstrip('/').split('/')[-2]


def _fake_semgrep(calls, fail_combined=False, fail_parser=None):
    def _run(cmd, **kwargs):
        configs = _configs(cmd)
        calls.append(configs)
        parsers = [_parser_of(c) for c in configs]
        if (fail_combined and len(configs) > 1) or fail_parser in parsers:
            return subprocess.CompletedProcess(cmd, 2, stdout='', stderr='fatal')
        results = [r for p in parsers for r in load_semgrep_fixture(p)]
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({'results': results, 'errors': []}), stderr='')
    return _run


def _without_docs(objects):
    """Snapshots without ``comment`` / ``samples``: they are read from the source files, which
    do not exist under the fake ``/src`` folder of these runs."""
    for obj in objects:
        obj.pop('comment', None)
        for field in obj.get('fields', {}).values():
            field.pop('comment', None)
            field.pop('samples', None)
    return objects


def _by_parser(objects):
    out = {}
    for obj in objects:
        out.setdefault(obj.parser, []).append(obj)
    return out


def test_run_parsers_runs_semgrep_once_for_all_semgrep_parsers(monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, 'run', _fake_semgrep(calls))

    names = sorted(SEMGREP_PARSERS)
    result = run_parsers('/src', names)

    assert len(calls) == 1 and sorted(_parser_of(c) for c in calls[0]) == names
    assert not result.errors
    by_parser = _by_parser(result.objects)
    for name in names:
        assert normalize(by_parser[name]) == _without_docs(load_golden(name, 'parsed')), name


def test_run_parsers_falls_back_to_per_parser_runs(monkeypatch, caplog):
    calls = []
    monkeypatch.setattr(subprocess, 'run', _fake_semgrep(calls, fail_combined=True, fail_parser='java'))

    names = sorted(SEMGREP_PARSERS)
    with caplog.at_level('WARNING'):
        result = run_parsers('/src', names)

    assert 'falling back' in caplog.text
    assert len(calls) == 1 + len(names)
    assert list(result.errors) == ['java']  # isolation kept: only the broken parser fails
    by_parser = _by_parser(result.objects)
    for name in names:
        if name != 'java':
            assert normalize(by_parser[name]) == _without_docs(load_golden(name, 'parsed')), name


def test_single_semgrep_parser_is_not_combined(monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, 'run', _fake_semgrep(calls))
    result = run_parsers('/src', ['golang', 'graphql'])
    assert [[_parser_of(c) for c in call] for call in calls] == [['golang']]
    assert not result.errors


@pytest.mark.semgrep
def test_combined_live_run_matches_per_parser_runs(tests_dir, tmp_path):
    """The real semgrep with all rule folders gives what the per-parser runs give."""
    import shutil
    for name in SEMGREP_PARSERS:
        shutil.copytree(tests_dir / f'{name}_samples', tmp_path / name)

    combined = run_parsers(str(tmp_path), sorted(SEMGREP_PARSERS))
    assert not combined.errors

    separate = []
    for name in sorted(SEMGREP_PARSERS):
        separate.extend(ParserFactory.get_parser(name)(parser=name, source_folder=str(tmp_path)).run_scan())

    assert normalize(combined.objects) == normalize(separate)
