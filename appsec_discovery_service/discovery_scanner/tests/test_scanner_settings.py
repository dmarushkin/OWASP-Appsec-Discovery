"""ScannerSettings (P1-7): typed env parsing, no env access at import."""

import base64
import importlib
import pickle
import sys

import pytest
from pydantic import ValidationError


def test_config_imports_without_any_env(scanner, monkeypatch):
    for name in list(scanner.config.ScannerSettings.__fields__):
        monkeypatch.delenv(name.upper(), raising=False)
    for name in ("GITLAB_PRIVATE_TOKEN", "GITLAB_PROJECTS_PREFIX", "GITLAB_SCAN_TYPES", "PARSERS"):
        monkeypatch.delenv(name, raising=False)

    sys.modules.pop("config", None)
    config = importlib.import_module("config")

    with pytest.raises(ValidationError) as exc:
        config.get_settings()

    missing = {err["loc"][0] for err in exc.value.errors()}
    assert {"database_url", "gitlab_url", "gitlab_token", "projects_prefix_csv", "scan_types_csv"} <= missing


def test_settings_from_env(scanner):
    scanner.setenv(
        GITLAB_PROJECTS_PREFIX="backend/, frontend/,,",
        GITLAB_SCAN_TYPES="mains,mrs",
        PARSERS="golang, swagger",
        CACHE_SIZE_GB="2",          # removed setting: still accepted (ignored)
        MAX_WORKERS="5",
        LLM_API_KEY="sk-123",
    )
    s = scanner.settings()

    assert s.projects_prefixes == ["backend/", "frontend/"]
    assert s.scan_types == ["mains", "mrs"]
    assert s.parsers == ["golang", "swagger"]
    assert s.max_workers == 5
    assert not hasattr(s, "cache_size_gb")
    assert s.gitlab_base_url == "https://gitlab.example"
    assert s.gitlab_token.get_secret_value() == "glpat-test-token"
    assert s.llm_api_key.get_secret_value() == "sk-123"
    for removed in ("mr_alerts", "tg_alert_token", "tg_chat_id", "alert_timeout_s"):   # alerting was removed
        assert not hasattr(s, removed)


def test_settings_cached_per_process(scanner):
    assert scanner.settings() is scanner.config.get_settings()


def test_defaults_and_empty_values_are_unset(scanner):
    # docker compose passes an unset ${VAR} as an empty string
    scanner.setenv(PARSERS="", MAX_WORKERS="", LLM_API_URL="", LLM_API_MODEL="")
    s = scanner.settings()

    assert s.parsers == ["all"]
    assert s.max_workers == 2
    assert s.llm_api_url is None                 # LLM rule disabled
    assert s.llm_api_model == "local-model"
    assert (s.llm_timeout_s, s.llm_max_retries, s.llm_structured) == (120.0, 2, "auto")


def test_empty_required_value_is_reported_missing(scanner):
    scanner.setenv(GITLAB_PRIVATE_TOKEN="")
    with pytest.raises(ValidationError, match="gitlab_token"):
        scanner.settings()


def test_removed_alert_settings_in_an_old_env_are_ignored(scanner):
    # an .env of a release with MR / Telegram alerts still starts the scanner
    scanner.setenv(MR_ALERTS="1", TG_ALERT_TOKEN="tg-secret", TG_CHAT_ID="chat", ALERT_TIMEOUT_S="10")
    s = scanner.settings()
    assert not hasattr(s, "mr_alerts") and "tg-secret" not in repr(s)


def test_invalid_values_fail_with_readable_error(scanner):
    scanner.setenv(MAX_WORKERS="many", GITLAB_URL="not a url")
    with pytest.raises(ValidationError) as exc:
        scanner.settings()
    assert {err["loc"][0] for err in exc.value.errors()} == {"max_workers", "gitlab_url"}


def test_secrets_are_not_printed(scanner):
    scanner.setenv(LLM_API_KEY="sk-secret")
    text = repr(scanner.settings()) + str(scanner.settings())
    for secret in ("glpat-test-token", "db-secret", "sk-secret"):
        assert secret not in text


def test_settings_pickle_for_worker_processes(scanner):
    s = scanner.settings()
    clone = pickle.loads(pickle.dumps(s))
    assert clone == s
    assert clone.gitlab_base_url == s.gitlab_base_url


def test_git_auth_env_uses_scoped_basic_header(scanner):
    env = scanner.config.git_auth_env(scanner.settings(), base_env={"PATH": "/bin"})

    assert env["PATH"] == "/bin"
    assert env["GIT_CONFIG_COUNT"] == "1"
    assert env["GIT_CONFIG_KEY_0"] == "http.https://gitlab.example/.extraHeader"
    scheme, value = env["GIT_CONFIG_VALUE_0"].split(": ", 1)[1].split(" ", 1)
    assert scheme == "Basic"
    assert base64.b64decode(value).decode() == "git:glpat-test-token"
    assert env["GIT_TERMINAL_PROMPT"] == "0"


def test_git_auth_env_appends_to_existing_git_config_env(scanner):
    base = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.askPass", "GIT_CONFIG_VALUE_0": ""}
    env = scanner.config.git_auth_env(scanner.settings(), base_env=base)

    assert env["GIT_CONFIG_COUNT"] == "2"
    assert env["GIT_CONFIG_KEY_0"] == "core.askPass"
    assert env["GIT_CONFIG_KEY_1"].endswith(".extraHeader")


def test_format_settings_error_uses_env_names(scanner):
    scanner.setenv(GITLAB_PRIVATE_TOKEN=None, MAX_WORKERS="many")
    with pytest.raises(ValidationError) as exc:
        scanner.settings()

    text = scanner.config.format_settings_error(exc.value)
    assert "GITLAB_PRIVATE_TOKEN: field required" in text
    assert "MAX_WORKERS: value is not a valid integer" in text


def test_unknown_llm_structured_mode_is_rejected(scanner):
    scanner.setenv(LLM_STRUCTURED="xml")
    with pytest.raises(ValidationError, match="LLM_STRUCTURED"):
        scanner.settings()
