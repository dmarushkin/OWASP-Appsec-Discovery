"""Unit tests of the shared matcher, severity and merge helper (P1-3)."""
import io
import logging

import pytest

from appsec_discovery.config_loader import ConfigError, load_config
from appsec_discovery.errors import ConfigError as CoreConfigError
from appsec_discovery.matching import RANK, Pattern, Severity, max_severity, merge_score, severity_rank
from appsec_discovery.models import CodeObjectField, ExcludeScan, ExcludeScoring, ScoreConfig
from appsec_discovery.scoring import ExcludeFilter, RuleScorer, compile_rules
from tests.support import build_object


# --------------------------------------------------------------------------- Severity


def test_severity_is_str_enum_with_rank_table():
    assert Severity.high == 'high'
    assert str(Severity.critical) == 'critical'
    assert [s.value for s in sorted(Severity, key=RANK.get)] == ['info', 'low', 'medium', 'high', 'critical']
    assert severity_rank(None) == -1
    assert severity_rank('high') > severity_rank('medium')
    with pytest.raises(ValueError):
        severity_rank('hihg')


def test_max_severity():
    assert max_severity([None, 'low', 'high', 'medium']) is Severity.high
    assert max_severity([None]) is None
    assert max_severity([]) is None


# --------------------------------------------------------------------------- Pattern


@pytest.mark.parametrize('raw, value, matched', [
    ('passport', 'input.passport', True),           # substring
    ('PASSPORT', 'input.passport', True),           # case-insensitive substring
    ('^input\\.', 'input.passport', True),          # regex from start
    ('secret$', 'input.secret', False),             # re.match is anchored at the start
    ('.*secret$', 'input.secret', True),
    ('c++', 'lang_c++', True),                      # invalid regex -> literal
    ('card(', 'input.card(number)', True),
    ('card(', 'input.cardnumber', False),
    ('x', None, False),
    ('', 'anything', True),                          # empty pattern matches everything (as before)
])
def test_pattern_matches(raw, value, matched):
    assert Pattern.of(raw).matches(value) is matched


def test_pattern_invalid_regex_warns_once(caplog):
    raw = 'unique-invalid-((regex'
    with caplog.at_level(logging.WARNING, logger='appsec_discovery.matching'):
        Pattern.of(raw)
        Pattern.of(raw)
    assert [r.levelno for r in caplog.records if raw in r.getMessage()] == [logging.WARNING]


# --------------------------------------------------------------------------- merge_score / Scorable


def test_merge_score_first_hit_copies_tags():
    field = CodeObjectField(field_name='f', field_type='string')
    tags = ['llm-pii']
    field.apply_score('medium', tags)
    assert field.severity == 'medium' and field.tags == ['llm-pii']
    assert field.tags is not tags
    assert type(field.severity) is str


def test_merge_score_max_severity_and_tag_union():
    field = CodeObjectField(field_name='f', field_type='string', severity='medium', tags=['pii'])
    field.apply_score(Severity.low, ['pii', 'auth'])
    assert field.severity == 'medium'
    assert field.tags == ['pii', 'auth']
    field.apply_score(Severity.critical, ['x'])
    assert field.severity == 'critical'
    assert field.tags == ['pii', 'auth', 'x']


def test_merge_score_scored_without_tags():
    field = CodeObjectField(field_name='f', field_type='string', severity='low', tags=None)
    merge_score(field, 'high', ['pii'])
    assert (field.severity, field.tags) == ('high', ['pii'])


def test_llm_tags_not_shared_between_field_and_object():
    obj = build_object(fields=['input.email'])
    tags = ['llm-pii']
    obj.fields['input.email'].apply_score('medium', tags)
    obj.apply_score('medium', tags)
    obj.apply_score('medium', ['llm-auth'])
    assert obj.tags == ['llm-pii', 'llm-auth']
    assert obj.fields['input.email'].tags == ['llm-pii']
    assert tags == ['llm-pii']


# --------------------------------------------------------------------------- config validation


def test_unknown_severity_is_config_error():
    with pytest.raises(ConfigError, match='hihg'):
        load_config(io.StringIO("score_tags:\n  pii:\n    hihg: ['passport']\n"))


def test_severity_keys_are_normalised():
    config = load_config(io.StringIO("score_tags:\n  pii:\n    High: ['passport']\n    high: ['ssn']\n"))
    assert config.score_tags == {'pii': {'high': ['passport', 'ssn']}}


def test_compile_rules_unknown_severity_is_config_error():
    with pytest.raises(CoreConfigError):
        compile_rules({'pii': {'urgent': ['x']}})


def test_invalid_regex_in_excludes_loads():
    config = load_config(io.StringIO("exclude_scan:\n  - file: 'c++'\nexclude_scoring:\n  - field_name: 'card('\n"))
    assert config.exclude_scan[0].matches(build_object(file='/src/c++/main.go'))


# --------------------------------------------------------------------------- ExcludeScan / ExcludeScoring


def test_exclude_scan_empty_rule_never_matches():
    assert not ExcludeScan().matches(build_object())
    assert not ExcludeScan(file='').matches(build_object())


def test_exclude_scoring_contexts():
    obj = build_object(parser='swagger', fields={'input.email': 'string'}, properties={'path': '/x'})
    field = obj.fields['input.email']

    rule = ExcludeScoring(field_name='email')
    assert rule.matches(obj, field=field, tag='pii', keyword='email')
    assert not rule.matches(obj, prop_name='path', tag='pii', keyword='email')

    rule = ExcludeScoring(prop_name='path')
    assert rule.matches(obj, prop_name='path', tag='pii', keyword='x')
    assert not rule.matches(obj, field=field, tag='pii', keyword='x')

    # tag: one value (keyword scoring) or a list (LLM tags)
    assert ExcludeScoring(tag='llm-pii').matches(obj, field=field, tag=['llm-auth', 'llm-pii'])
    assert not ExcludeScoring(tag='pii').matches(obj, field=field, tag='auth', keyword='x')

    # keyword rules never apply to LLM scoring (keyword=None)
    assert ExcludeScoring(keyword='email').matches(obj, field=field, tag='pii', keyword='email')
    assert not ExcludeScoring(keyword='email').matches(obj, field=field, tag=['llm-pii'], keyword=None)

    assert ExcludeScoring(parser='SWAGGER').matches(obj, field=field, tag='pii')
    assert not ExcludeScoring(parser='swag').matches(obj, field=field, tag='pii')


# --------------------------------------------------------------------------- RuleScorer / ExcludeFilter


def test_rule_scorer_from_config():
    config = ScoreConfig(score_tags={'pii': {'high': ['passport']}, 'auth': {'medium': ['passport']}})
    [obj] = RuleScorer.from_config(config).score_all([build_object(fields=['input.passport'])])
    assert obj.fields['input.passport'].severity == 'high'
    assert obj.fields['input.passport'].tags == ['pii', 'auth']
    assert obj.tags == ['pii', 'auth']
    assert obj.tags is not obj.fields['input.passport'].tags


def test_exclude_filter_object_types():
    objects = [build_object(hash='1', object_type='route'), build_object(hash='2', object_type='dto')]
    assert [o.hash for o in ExcludeFilter.from_config(ScoreConfig()).filter(objects)] == ['1', '2']
    config = ScoreConfig(object_types=['DTO'])
    assert [o.hash for o in ExcludeFilter.from_config(config).filter(objects)] == ['2']
