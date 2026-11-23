import io

import pytest

from appsec_discovery.config_loader import ConfigError, load_config
from appsec_discovery.models import ScoreConfig
from appsec_discovery.models.config import default_rules
from appsec_discovery.services import ScanService


def test_default_rules_card_number_keys_are_separate():
    finance_high = default_rules['finance']['high']
    assert 'card_number' in finance_high
    assert 'cardnumber' in finance_high
    assert 'card_numbercardnumber' not in finance_high


@pytest.mark.parametrize("text", ["", "   \n", "# only a comment\n"])
def test_load_config_empty_document_gives_defaults(text):
    config = load_config(io.StringIO(text))
    assert isinstance(config, ScoreConfig)
    assert config.parsers == ['all']
    assert config.score_tags == default_rules


def test_load_config_valid():
    config = load_config(io.StringIO("parsers: [swagger]\nexclude_scan:\n  - parser: swagger\n"))
    assert config.parsers == ['swagger']
    assert config.exclude_scan[0].parser == 'swagger'


@pytest.mark.parametrize("text", [
    "parsers: [unclosed\n",          # YAML syntax error
    "- just\n- a list\n",            # not a mapping
    "plain string\n",                # not a mapping
    "parsers: {a: 1}\n",             # wrong type for a field
    "exclude_scan: 5\n",             # wrong type for a field
    "ai_api:\n  model: x\n",        # missing required sub-fields (base_url)
    "ai_api:\n  base_url: u\n  model: m\n  structured: xml\n",  # unknown structured mode
])
def test_load_config_invalid_raises_config_error(text):
    with pytest.raises(ConfigError):
        load_config(io.StringIO(text))


def test_config_error_is_value_error():
    assert issubclass(ConfigError, ValueError)


def test_scan_service_invalid_config_raises():
    with pytest.raises(ConfigError):
        ScanService(source_folder="some", conf_file=io.StringIO("parsers: [unclosed\n"))
