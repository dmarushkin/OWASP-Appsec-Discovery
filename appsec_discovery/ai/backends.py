"""LLM backends (P1-4).

Everything talks to an LLM through ``LlmBackend``. There is exactly one real
implementation, ``OpenAICompatibleBackend``: any server that speaks the OpenAI
chat-completions API (OpenAI, DeepSeek, a local ``llama.cpp`` server, vLLM,
Ollama, ...). Local models run out of process; nothing is loaded in-process.

``FakeLlmBackend`` is a deterministic stand-in for tests.
"""
import logging
from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable

logger = logging.getLogger(__name__)

__all__ = [
    "LlmBackend", "OpenAICompatibleBackend", "FakeLlmBackend", "LlmError",
    "STRUCTURED_MODES", "DEFAULT_LOCAL_BASE_URL",
]

# Default endpoint of a local llama.cpp server (`llama-server --port 8080`).
DEFAULT_LOCAL_BASE_URL = "http://localhost:8080/v1"

# How to ask for a structured answer: "auto" tries json_schema, then json_object, then plain text,
# remembering the first mode the server accepts.
STRUCTURED_MODES = ("auto", "json_schema", "json_object", "none")


class LlmError(Exception):
    """The LLM call failed or the answer could not be used."""


@runtime_checkable
class LlmBackend(Protocol):
    """``complete(system, user, json_schema=None) -> str``: one chat completion.

    ``json_schema`` (a JSON schema dict) asks for a JSON answer that follows it,
    where the backend supports structured output; callers must still parse and
    validate the text.
    """

    model: str

    def complete(self, system: Optional[str], user: str, *, json_schema: Optional[Dict[str, Any]] = None) -> str:
        ...


def _messages(system: Optional[str], user: str) -> List[Dict[str, str]]:
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": user})
    return messages


class OpenAICompatibleBackend:
    """One OpenAI client per backend instance (create one backend per run / worker).

    ``timeout`` (seconds) and ``max_retries`` go to the client: the ``openai``
    client retries connection errors, 408/409/429 and 5xx with backoff.
    """

    def __init__(self, *, base_url: str, model: str, api_key: Optional[str] = None,
                 timeout: float = 120.0, max_retries: int = 2, max_tokens: Optional[int] = 8192,
                 temperature: Optional[float] = 0.0, structured: str = "auto", client: Any = None):
        if structured not in STRUCTURED_MODES:
            raise ValueError(f"structured must be one of {STRUCTURED_MODES}, got {structured!r}")
        self.base_url = base_url
        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.structured = structured
        self._api_key = api_key
        self._client = client
        # modes still to try for structured answers, best first
        self._modes = {"auto": ["json_schema", "json_object", "none"]}.get(structured, [structured])

    @property
    def client(self):
        if self._client is None:
            from openai import OpenAI  # lazy: only needed when AI scoring is enabled

            # A local server needs no key, but the client refuses an empty one.
            self._client = OpenAI(api_key=self._api_key or "none", base_url=self.base_url,
                                  timeout=self.timeout, max_retries=self.max_retries)
        return self._client

    @staticmethod
    def _response_format(mode: str, json_schema: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if mode == "json_schema":
            return {"type": "json_schema", "json_schema": {"name": "answer", "schema": json_schema}}
        if mode == "json_object":
            return {"type": "json_object"}
        return None

    def _create(self, messages, response_format):
        kwargs: Dict[str, Any] = {"model": self.model, "messages": messages, "stream": False}
        if self.max_tokens:
            kwargs["max_tokens"] = self.max_tokens
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        if response_format is not None:
            kwargs["response_format"] = response_format
        response = self.client.chat.completions.create(**kwargs)
        if not response.choices:
            return ""
        choice = response.choices[0]
        if getattr(choice, "finish_reason", None) == "length":
            # a cut answer is not valid JSON: name the cause instead of a parse error
            raise LlmError(f"LLM answer truncated at max_tokens={self.max_tokens} (raise LLM_MAX_TOKENS / "
                           f"ai_api.max_tokens); answer starts {(choice.message.content or '')[:120]!r}")
        return choice.message.content or ""

    def complete(self, system: Optional[str], user: str, *, json_schema: Optional[Dict[str, Any]] = None) -> str:
        messages = _messages(system, user)
        if json_schema is None:
            return self._create(messages, None)

        import openai

        # Try the remaining modes in order. A mode is dropped for good only when a weaker one then
        # succeeds: a 400 caused by the request itself (e.g. a prompt over the context size) fails in
        # every mode and must not downgrade structured answers for the rest of the run.
        for i, mode in enumerate(self._modes):
            try:
                answer = self._create(messages, self._response_format(mode, json_schema))
            except (openai.BadRequestError, openai.UnprocessableEntityError) as e:
                if i == len(self._modes) - 1:
                    raise
                logger.info(f"LLM server at {self.base_url} rejected response_format {mode!r} ({e}); "
                            f"trying {self._modes[i + 1]!r}")
                continue
            if i:
                logger.info(f"LLM server at {self.base_url}: using response_format {mode!r} from now on")
                self._modes = self._modes[i:]
            return answer
        raise AssertionError("unreachable: at least one mode is always configured")


class FakeLlmBackend:
    """Deterministic backend for tests: no network, no model.

    ``answer`` is a string, or a callable ``(system, user, json_schema) -> str``
    (it may raise to simulate a failure). Every call is recorded in ``calls`` as
    ``(system, user, json_schema)``.
    """

    def __init__(self, answer: Any = "", model: str = "fake-model"):
        self.model = model
        self._answer = answer
        self.calls: List[Tuple[Optional[str], str, Optional[Dict[str, Any]]]] = []

    def complete(self, system: Optional[str], user: str, *, json_schema: Optional[Dict[str, Any]] = None) -> str:
        self.calls.append((system, user, json_schema))
        if callable(self._answer):
            return self._answer(system, user, json_schema)
        return self._answer
