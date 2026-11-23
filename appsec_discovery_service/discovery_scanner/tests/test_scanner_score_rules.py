"""DB keyword rules -> core ``ScoreRule`` (P1-6): matchers use the core ``Pattern``
(substring or regex from the start, case-insensitive, invalid regex = literal)."""
from types import SimpleNamespace

from appsec_discovery.models import CodeObjectField


def db_rule(**scope):
    return SimpleNamespace(id=1, name="r", kind="keyword", mode="auto", enabled=True, severity="high",
                           category="pii", scope=scope, version=1, deleted_at=None)


def test_db_rule_maps_to_core_rule_with_core_patterns(scanner):
    scan_service = scanner.load("services.scan_service")

    def matches(field_name='input.email', **scope):
        core_rule = scan_service.to_core_score_rule(db_rule(**scope))
        return core_rule.field_matches(CodeObjectField(field_name=field_name, field_type='string', file='f', line=1))

    assert matches(field_re='email')                         # substring
    assert matches(field_re='EMAIL')                         # case-insensitive
    assert matches(field_re='^input\\.')                     # regex
    assert not matches(field_re='phone')
    assert not matches(field_re='card(')                     # invalid regex does not raise
    assert matches(field_re='card(', field_name='card(number)')
    assert scan_service.to_core_score_rule(db_rule(project_re='grp/')) is None    # no matcher: not a core rule
