"""Validated API settings (P1-7, P3-2).

Nothing is read from the environment at import time: `get_settings()` builds `ApiSettings`
on first use (at application startup) and caches it.

Plain dataclass on purpose: no dependency on the pydantic major version.

Admin password (P3-2): only UI_ADMIN_PASSWORD_HASH (a bcrypt hash, checked with the API's
`pwd_context`) is accepted. The plain-text UI_ADMIN_PASSWORD is refused since review
decisions (REST, UI and MCP) are recorded under the authenticated user: set the hash
instead (see `.env.example`). Well-known passwords (admin, password, ...) and the example
JWT key of `.env.example` are refused at startup (`auth.check_settings`).
"""

import os
from dataclasses import dataclass, field
from typing import Mapping, Optional

ALGORITHM = "HS256"

JWT_KEY_MIN_LENGTH = 32
DEFAULT_TOKEN_TTL_MINUTES = 30
MAX_TOKEN_TTL_MINUTES = 7 * 24 * 60
DEFAULT_TRIAL_MAX_SUBJECTS = 200
DEFAULT_TRIAL_DAILY_CALLS = 2000
DEFAULT_QA_AGREEMENT_MIN = 0.9
# scale: the scanner's stats_refresh interval (snapshots are fresh for 2x this), the MCP response cap and the
# per-client MCP rate limit
DEFAULT_STATS_REFRESH_S = 60
DEFAULT_MCP_MAX_RESPONSE_BYTES = 200_000
DEFAULT_MCP_RATE_LIMIT_PER_MINUTE = 600

# The placeholder of .env.example: refused, every deployment needs its own key.
EXAMPLE_JWT_KEY = "change_me_to_a_random_string_of_32_chars_or_more"

HASH_HELP = ("set UI_ADMIN_PASSWORD_HASH to a bcrypt hash, e.g. python -c \"from passlib.context import "
             "CryptContext; print(CryptContext(schemes=['bcrypt']).hash('<password>'))\"")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class ApiSettings:
    database_url: str = field(repr=False)
    ui_admin_email: str
    ui_jwt_key: str = field(repr=False)
    ui_admin_password_hash: str = field(repr=False)
    token_ttl_minutes: int = DEFAULT_TOKEN_TTL_MINUTES
    # UI_ALLOW_WEAK_PASSWORD=true: accept a well-known admin password (local stands only)
    allow_weak_password: bool = False
    # prompt trials (``services.trials_service``): subjects per trial (targets + controls) and model calls of
    # all trials per UTC day (LLM_TRIAL_MAX_SUBJECTS, LLM_TRIAL_DAILY_CALLS; 0 disables trials)
    llm_trial_max_subjects: int = DEFAULT_TRIAL_MAX_SUBJECTS
    llm_trial_daily_calls: int = DEFAULT_TRIAL_DAILY_CALLS
    # tiered workflow (``services.quality_service``): a rule whose service/harness agreement on the QA sample is below
    # this (with at least QA_MIN_SAMPLES samples of the last 30 days) is flagged "needs improvement"
    llm_qa_agreement_min: float = DEFAULT_QA_AGREEMENT_MIN
    # LLM rule lifecycle (``discovery_common.lifecycle``): the rollout a prompt / scope edit makes (LLM_ROLLOUT_DEFAULT:
    # immediate - running at once; canary | staged - planned, a human starts it)
    llm_rollout_default: str = "canary"
    # precomputed statistics (``services.stats_service``): STATS_REFRESH_S is the scanner's refresh interval - a
    # snapshot older than twice that is stale and the API computes live; 0 disables the snapshots in the API
    stats_refresh_s: int = DEFAULT_STATS_REFRESH_S
    # MCP (``mcp_server``): the byte cap of one tool result (lists are cut, ``truncated`` + a hint), 0 = no cap;
    # tool calls per minute per client (token / user), 0 = no limit
    mcp_max_response_bytes: int = DEFAULT_MCP_MAX_RESPONSE_BYTES
    mcp_rate_limit_per_minute: int = DEFAULT_MCP_RATE_LIMIT_PER_MINUTE
    # UI_BASE_URL: the base of the ``ui_url`` deep links in MCP answers (e.g. https://discovery.example.com);
    # empty: paths only
    ui_base_url: str = ""

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "ApiSettings":
        env = os.environ if env is None else env

        def get(name):
            value = env.get(name)
            return value if value and value.strip() else None

        errors = []

        for name in ("DATABASE_URL", "UI_ADMIN_EMAIL", "UI_JWT_KEY"):
            if get(name) is None:
                errors.append(f"{name} is required")

        jwt_key = get("UI_JWT_KEY")
        if jwt_key is not None and len(jwt_key) < JWT_KEY_MIN_LENGTH:
            errors.append(f"UI_JWT_KEY must be at least {JWT_KEY_MIN_LENGTH} characters long")
        if jwt_key == EXAMPLE_JWT_KEY:
            errors.append("UI_JWT_KEY is the example value of .env.example, generate one (openssl rand -hex 32)")

        password_hash = get("UI_ADMIN_PASSWORD_HASH")
        if password_hash is None:
            if get("UI_ADMIN_PASSWORD") is not None:
                errors.append("UI_ADMIN_PASSWORD (plain text) is no longer accepted: " + HASH_HELP)
            else:
                errors.append("UI_ADMIN_PASSWORD_HASH is required: " + HASH_HELP)

        ttl = DEFAULT_TOKEN_TTL_MINUTES
        raw_ttl = get("UI_TOKEN_TTL_MINUTES")
        if raw_ttl is not None:
            try:
                ttl = int(raw_ttl)
            except ValueError:
                errors.append("UI_TOKEN_TTL_MINUTES must be an integer")
            else:
                if not 1 <= ttl <= MAX_TOKEN_TTL_MINUTES:
                    errors.append(f"UI_TOKEN_TTL_MINUTES must be between 1 and {MAX_TOKEN_TTL_MINUTES}")

        def non_negative(name, default):
            raw = get(name)
            if raw is None:
                return default
            try:
                value = int(raw)
            except ValueError:
                errors.append(f"{name} must be an integer")
                return default
            if value < 0:
                errors.append(f"{name} must be >= 0")
            return value

        trial_subjects = non_negative("LLM_TRIAL_MAX_SUBJECTS", DEFAULT_TRIAL_MAX_SUBJECTS)
        trial_calls = non_negative("LLM_TRIAL_DAILY_CALLS", DEFAULT_TRIAL_DAILY_CALLS)

        agreement_min = DEFAULT_QA_AGREEMENT_MIN
        raw_agreement = get("LLM_QA_AGREEMENT_MIN")
        if raw_agreement is not None:
            try:
                agreement_min = float(raw_agreement)
            except ValueError:
                errors.append("LLM_QA_AGREEMENT_MIN must be a number")
            else:
                if not 0 <= agreement_min <= 1:
                    errors.append("LLM_QA_AGREEMENT_MIN must be between 0 and 1")

        stats_refresh_s = non_negative("STATS_REFRESH_S", DEFAULT_STATS_REFRESH_S)
        mcp_max_bytes = non_negative("MCP_MAX_RESPONSE_BYTES", DEFAULT_MCP_MAX_RESPONSE_BYTES)
        mcp_rate = non_negative("MCP_RATE_LIMIT_PER_MINUTE", DEFAULT_MCP_RATE_LIMIT_PER_MINUTE)
        ui_base_url = (get("UI_BASE_URL") or "").rstrip("/")

        rollout_default = (get("LLM_ROLLOUT_DEFAULT") or "canary").strip().lower()
        if rollout_default not in ("immediate", "canary", "staged"):
            errors.append("LLM_ROLLOUT_DEFAULT must be immediate, canary or staged")

        if errors:
            raise ConfigError("Invalid API configuration: " + "; ".join(errors))

        return cls(
            database_url=get("DATABASE_URL"),
            ui_admin_email=get("UI_ADMIN_EMAIL"),
            ui_jwt_key=jwt_key,
            ui_admin_password_hash=password_hash,
            token_ttl_minutes=ttl,
            allow_weak_password=(get("UI_ALLOW_WEAK_PASSWORD") or "").lower() in ("1", "true", "yes"),
            llm_trial_max_subjects=trial_subjects,
            llm_trial_daily_calls=trial_calls,
            llm_qa_agreement_min=agreement_min,
            llm_rollout_default=rollout_default,
            stats_refresh_s=stats_refresh_s,
            mcp_max_response_bytes=mcp_max_bytes,
            mcp_rate_limit_per_minute=mcp_rate,
            ui_base_url=ui_base_url,
        )


_settings: Optional[ApiSettings] = None


def get_settings() -> ApiSettings:
    global _settings
    if _settings is None:
        _settings = ApiSettings.from_env()
    return _settings


def set_settings(settings: Optional[ApiSettings]) -> None:
    global _settings
    _settings = settings
