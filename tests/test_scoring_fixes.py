import io

from appsec_discovery.models import CodeObject, CodeObjectField, CodeObjectProp
from appsec_discovery.services import ScanService


def make_object(field_names=(), prop_values=None):
    return CodeObject(
        hash='h',
        object_name='Obj',
        object_type='route',
        parser='swagger',
        file='/api.yaml',
        line=1,
        properties={
            name: CodeObjectProp(prop_name=name, prop_value=value)
            for name, value in (prop_values or {}).items()
        },
        fields={
            name: CodeObjectField(field_name=name, field_type='string')
            for name in field_names
        },
    )


def make_service(config_yaml):
    return ScanService(source_folder="some", conf_file=io.StringIO(config_yaml))


SCORE_TAGS = """
score_tags:
  pii:
    high: ['passport']
    medium: ['email']
"""


def test_exclude_scoring_by_keyword_only_on_field():
    service = make_service(SCORE_TAGS + "exclude_scoring:\n  - keyword: 'passport'\n")
    obj = make_object(field_names=['input.passport', 'input.email'])

    [scored] = service.score_objects([obj])

    assert scored.fields['input.passport'].severity is None
    assert scored.fields['input.email'].severity == 'medium'
    assert scored.severity == 'medium'


def test_exclude_scoring_by_keyword_only_on_property():
    service = make_service(SCORE_TAGS + "exclude_scoring:\n  - keyword: 'passport'\n")
    obj = make_object(prop_values={'path': '/passport', 'other': '/email'})

    [scored] = service.score_objects([obj])

    assert scored.properties['path'].severity is None
    assert scored.properties['other'].severity == 'medium'
    assert scored.severity == 'medium'


def test_exclude_scoring_keyword_does_not_match_other_keywords():
    service = make_service(SCORE_TAGS + "exclude_scoring:\n  - keyword: 'email'\n")
    obj = make_object(field_names=['input.passport'])

    [scored] = service.score_objects([obj])

    assert scored.fields['input.passport'].severity == 'high'


def test_exclude_scoring_tag_and_keyword():
    # tag matches but keyword does not -> not excluded
    service = make_service(SCORE_TAGS + "exclude_scoring:\n  - tag: 'pii'\n    keyword: 'email'\n")
    obj = make_object(field_names=['input.passport', 'input.email'])

    [scored] = service.score_objects([obj])

    assert scored.fields['input.passport'].severity == 'high'
    assert scored.fields['input.email'].severity is None


def test_default_rules_score_cardnumber_field():
    service = ScanService(source_folder="some")
    obj = make_object(field_names=['input.cardNumber', 'input.card_number'])

    [scored] = service.score_objects([obj])

    assert scored.fields['input.cardNumber'].severity == 'high'
    assert 'finance' in scored.fields['input.cardNumber'].tags
    assert scored.fields['input.card_number'].severity == 'high'
