"""ApiSettings (P1-7). The API's FastAPI deps are not installed in the core dev env, so only
config.py is loaded (by path, under a unique module name: the scanner also has `config`)."""

import importlib.util
from pathlib import Path

import pytest

CONFIG_PATH = Path(__file__).resolve().parents[1] / "config.py"

JWT_KEY = "k" * 32


@pytest.fixture
def config():
    spec = importlib.util.spec_from_file_location("discovery_api_config", CONFIG_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # no env access at import
    return module


def env(**overrides):
    base = {
        "DATABASE_URL": "postgresql://u:p@db/x",
        "UI_ADMIN_EMAIL": "admin@example.com",
        "UI_JWT_KEY": JWT_KEY,
        "UI_ADMIN_PASSWORD_HASH": "$2b$12$abcdefghijklmnopqrstuuK0Y3r7W1Kqk1Q2c3d4e5f6g7h8i9j0k",
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not None}


def test_valid_settings(config):
    s = config.ApiSettings.from_env(env())
    assert s.ui_admin_email == "admin@example.com"
    assert s.ui_admin_password_hash.startswith("$2b$")
    assert s.token_ttl_minutes == 30
    assert JWT_KEY not in repr(s) and "u:p" not in repr(s) and "$2b$" not in repr(s)


def test_plain_password_is_refused(config):
    # P3-2: review decisions are recorded under the user, a bcrypt hash is required
    with pytest.raises(config.ConfigError, match="no longer accepted"):
        config.ApiSettings.from_env(env(UI_ADMIN_PASSWORD_HASH=None, UI_ADMIN_PASSWORD="admin"))


@pytest.mark.parametrize("overrides, message", [
    ({"DATABASE_URL": None}, "DATABASE_URL is required"),
    ({"UI_ADMIN_EMAIL": ""}, "UI_ADMIN_EMAIL is required"),
    ({"UI_JWT_KEY": None}, "UI_JWT_KEY is required"),
    ({"UI_JWT_KEY": "short"}, "at least 32"),
    ({"UI_ADMIN_PASSWORD_HASH": None}, "UI_ADMIN_PASSWORD_HASH is required"),
    ({"UI_JWT_KEY": "change_me_to_a_random_string_of_32_chars_or_more"}, "example value"),
    ({"UI_TOKEN_TTL_MINUTES": "0"}, "UI_TOKEN_TTL_MINUTES"),
    ({"UI_TOKEN_TTL_MINUTES": "soon"}, "UI_TOKEN_TTL_MINUTES"),
])
def test_invalid_settings(config, overrides, message):
    with pytest.raises(config.ConfigError, match=message):
        config.ApiSettings.from_env(env(**overrides))


def test_token_ttl(config):
    assert config.ApiSettings.from_env(env(UI_TOKEN_TTL_MINUTES="480")).token_ttl_minutes == 480


def test_get_settings_reads_env_lazily_and_caches(config, monkeypatch):
    for k, v in env().items():
        monkeypatch.setenv(k, v)
    s = config.get_settings()
    assert config.get_settings() is s
    config.set_settings(None)
    assert config.get_settings() is not s


def test_weak_password_allowed_only_with_the_local_flag():
    pytest.importorskip("fastapi")       # auth.py needs the API deps (not in the core dev env)
    import auth
    from config import ApiSettings, ConfigError
    weak_hash = auth.pwd_context.hash("admin")
    base = {"DATABASE_URL": "postgresql://u:p@h/d", "UI_ADMIN_EMAIL": "admin@example.com",
            "UI_JWT_KEY": "k" * 40, "UI_ADMIN_PASSWORD_HASH": weak_hash}
    with pytest.raises(ConfigError, match="well-known"):
        auth.check_settings(ApiSettings.from_env(base))
    auth.check_settings(ApiSettings.from_env({**base, "UI_ALLOW_WEAK_PASSWORD": "true"}))
