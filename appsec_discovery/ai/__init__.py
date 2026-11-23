"""LLM layer (P1-4): one OpenAI-compatible backend, structured field classification.

Local models run out of process (e.g. the llama.cpp server, see README); the
package itself never loads a model.
"""
from appsec_discovery.ai.backends import (
    DEFAULT_LOCAL_BASE_URL,
    FakeLlmBackend,
    LlmBackend,
    LlmError,
    OpenAICompatibleBackend,
)
from appsec_discovery.ai.classifier import (
    CATEGORIES,
    DEFAULT_SYSTEM_PROMPT,
    PROMPT_VERSION,
    classify,
    is_candidate_field,
    select_candidate_fields,
)

__all__ = [
    "LlmBackend", "OpenAICompatibleBackend", "FakeLlmBackend", "LlmError", "DEFAULT_LOCAL_BASE_URL",
    "classify", "is_candidate_field", "select_candidate_fields", "CATEGORIES", "PROMPT_VERSION",
    "DEFAULT_SYSTEM_PROMPT", "backend_from_config",
]


def backend_from_config(ai_api) -> OpenAICompatibleBackend:
    """The backend for an ``AiApi`` config block (one per run)."""
    return OpenAICompatibleBackend(
        base_url=ai_api.base_url, model=ai_api.model, api_key=ai_api.api_key,
        timeout=ai_api.timeout, max_retries=ai_api.max_retries, max_tokens=ai_api.max_tokens,
        structured=ai_api.structured,
    )
