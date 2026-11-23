"""Static consistency of the semgrep rules and the parsers that read them (P0-6, P1-5).

Every rule declares ``metadata: {parser, object_type, ...}``; the parser dispatches a
finding to ``handlers[object_type]``. Every metavariable a handler reads must be bound
by the rules of that family, every rule must bind the metavariables the handler needs,
and the rules must not bind a "data" metavariable the handler never reads (that is how
``$TYPE`` instead of ``$METHOD`` went unnoticed in the python route rules).
"""
import inspect
import re
from pathlib import Path

import pytest
import yaml

from appsec_discovery.parsers import ParserFactory

PARSERS_DIR = Path(__file__).resolve().parent.parent / 'appsec_discovery' / 'parsers'

METAVAR_RE = re.compile(r'\$(?:\.\.\.)?[A-Z_][A-Z0-9_]*')
READ_RE = re.compile(r"""['"](\$(?:\.\.\.)?[A-Z_][A-Z0-9_]*)['"]""")

# metavariables a rule may leave unbound (the parser falls back to '')
OPTIONAL = {
    ('python', 'route'): {'$METHOD'},      # django / starlette have no method in the pattern
    ('java', 'dto'): {'$DB_NAME'},         # optional db_table property
}

# helper metavariables bound only to anchor a pattern
HELPERS = {'$APP', '$URLPATTERNS', '$ROUTES', '$CLASS', '$SOME', '$DOCTYPE', '$_'}   # $_: semgrep's anonymous metavariable
PARSER_HELPERS = {'java': {'$FIELD', '$GETTER'}}  # java reports the @Column name ($DB_FIELD)

SEMGREP_PARSERS = sorted(p.parent.name for p in PARSERS_DIR.glob('*/scanner_rules'))


def _rules(parser_name):
    rules = []
    for path in sorted((PARSERS_DIR / parser_name / 'scanner_rules').glob('*.y*ml')):
        rules.extend(yaml.safe_load(path.read_text())['rules'])
    return rules


def _bound(rule) -> set:
    """Metavariables in the matching part of a rule (not ``message``/``id``/``metadata``)."""
    matching = {k: v for k, v in rule.items() if k not in ('id', 'message', 'severity', 'languages', 'metadata', 'paths')}
    return set(METAVAR_RE.findall(yaml.safe_dump(matching)))


def _reads_by_object_type(parser_name) -> dict:
    """``{object_type: metavariables read by its handler}``."""
    cls = ParserFactory.get_parser(parser_name)
    return {
        object_type: set(READ_RE.findall(inspect.getsource(getattr(cls, method))))
        for object_type, method in cls.handlers.items()
    }


def _families(parser_name):
    rules = _rules(parser_name)
    for object_type, reads in _reads_by_object_type(parser_name).items():
        family = [r for r in rules if r['metadata']['object_type'] == object_type]
        yield object_type, reads, family


@pytest.mark.parametrize('parser_name', SEMGREP_PARSERS)
def test_every_rule_declares_a_handled_object_type(parser_name):
    handled = _reads_by_object_type(parser_name)
    for rule in _rules(parser_name):
        metadata = rule.get('metadata') or {}
        assert metadata.get('parser') == parser_name, f"{parser_name}: rule {rule['id']} metadata.parser"
        assert metadata.get('object_type') in handled, f"{parser_name}: rule {rule['id']} is never parsed"


@pytest.mark.parametrize('parser_name', SEMGREP_PARSERS)
def test_metavariables_read_by_parser_are_bound(parser_name):
    for object_type, reads, family in _families(parser_name):
        assert family, f'{parser_name}: no rules for object_type {object_type!r}'
        bound_somewhere = set().union(*(_bound(r) for r in family))
        assert reads <= bound_somewhere, f'{parser_name}/{object_type}: never bound: {sorted(reads - bound_somewhere)}'

        optional = OPTIONAL.get((parser_name, object_type), set())
        if optional is None:
            continue
        for rule in family:
            missing = reads - optional - _bound(rule)
            assert not missing, f"{parser_name}: rule {rule['id']} does not bind {sorted(missing)}"


@pytest.mark.parametrize('parser_name', SEMGREP_PARSERS)
def test_rules_do_not_bind_unread_metavariables(parser_name):
    for object_type, reads, family in _families(parser_name):
        for rule in family:
            unread = _bound(rule) - reads - HELPERS - PARSER_HELPERS.get(parser_name, set())
            assert not unread, f"{parser_name}: rule {rule['id']} binds {sorted(unread)} which the parser never reads"


def test_python_route_rules_bind_method():
    rules = {r['id']: r for r in _rules('python')}
    for rule_id in ('route-fastapi-object', 'route-flask-object', 'route-bottle-object'):
        assert '$METHOD' in _bound(rules[rule_id]), rule_id
        assert '$TYPE' not in _bound(rules[rule_id]), rule_id


def test_java_dto_rule_binds_type_in_every_branch():
    [rule] = _rules('java')
    field_patterns = rule['patterns'][-1]['pattern-either']
    assert field_patterns
    for branch in field_patterns:
        assert '$TYPE' in branch['pattern'] and '$DB_FIELD' in branch['pattern']


def test_golang_type_regex_is_anchored():
    [rule] = _rules('golang')
    [regex] = [p['metavariable-regex']['regex'] for p in rule['patterns'] if 'metavariable-regex' in p]
    compiled = re.compile(regex)
    for ok in ('bool', 'string', 'int', 'int64', 'uint', 'uint8', 'float32', 'float64', 'byte', 'time'):
        assert compiled.search(ok), ok
    for bad in ('interface', 'timeout', 'stringer', 'integer', 'float', 'int128', 'mystring'):
        assert not compiled.search(bad), bad
