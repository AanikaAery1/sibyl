"""Provider-neutral request / response model and errors of the LLM adapter (D52).

Errors never carry the API key, the request body or the upstream response body: only the
provider, an HTTP status and the provider's own error *type* string (e.g. ``rate_limit_error``),
which is safe to log and audit.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Literal

Provider = Literal["anthropic", "openai", "gemini"]
PROVIDERS: Final[tuple[Provider, ...]] = ("anthropic", "openai", "gemini")
Role = Literal["user", "assistant"]

DEFAULT_MODELS: Final[Mapping[str, str]] = {"anthropic": "claude-fable-5-1"}
"""Only Anthropic has a default; OpenAI and Gemini need an explicit model id."""
DEFAULT_BASE_URLS: Final[Mapping[str, str]] = {
    "anthropic": "https://api.anthropic.com",
    "openai": "https://api.openai.com",
    "gemini": "https://generativelanguage.googleapis.com",
}
MODEL_ID_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ERROR_TYPE_RE: Final = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


@dataclass(frozen=True)
class Message:
    role: Role
    content: str


@dataclass(frozen=True)
class LlmRequest:
    system: str
    messages: tuple[Message, ...]
    max_tokens: int = 4096
    temperature: float | None = None
    json_schema: Mapping[str, Any] | None = None
    schema_name: str = "sentinel_output"

    def __post_init__(self) -> None:
        if not self.messages or self.messages[0].role != "user":
            raise ValueError("a request needs at least one message, starting with the user")
        if not 1 <= self.max_tokens <= 128_000:
            raise ValueError("max_tokens must be 1..128000")
        if self.temperature is not None and not 0 <= self.temperature <= 2:
            raise ValueError("temperature must be 0..2")

    def with_messages(self, *extra: Message) -> LlmRequest:
        return LlmRequest(
            self.system,
            self.messages + extra,
            self.max_tokens,
            self.temperature,
            self.json_schema,
            self.schema_name,
        )


@dataclass(frozen=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            self.input_tokens + other.input_tokens, self.output_tokens + other.output_tokens
        )


@dataclass(frozen=True)
class LlmResponse:
    provider: Provider
    model: str  # the model the provider says served the call (falls back to the requested one)
    text: str
    usage: Usage
    stop_reason: str | None = None
    structured: bool = False  # True when the provider enforced the JSON schema itself
    attempts: int = 1


@dataclass(frozen=True)
class Structured:
    """A validated structured answer plus everything spent getting it (repairs included)."""

    value: Any
    response: LlmResponse
    usage: Usage
    calls: int
    repaired: bool = False
    extra: Mapping[str, Any] = field(default_factory=dict)


def safe_error_type(value: Any) -> str | None:
    """The provider's error type string when it is a plain identifier, else ``None``."""
    return value if isinstance(value, str) and _ERROR_TYPE_RE.fullmatch(value) else None


class LlmError(Exception):
    """Base error. ``retryable`` errors are retried by the client; ``code`` is stable."""

    code = "llm_error"
    retryable = False

    def __init__(self, provider: str, detail: str, *, status: int = 0) -> None:
        super().__init__(f"{provider}: {detail}")
        self.provider = provider
        self.status = status
        self.detail = detail


class LlmConfigError(LlmError):
    code = "config"


class EgressRefused(LlmError):
    code = "egress_refused"


class LlmHttpError(LlmError):
    code = "http_error"

    def __init__(
        self,
        provider: str,
        status: int,
        error_type: str | None = None,
        *,
        retryable: bool,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(provider, f"HTTP {status} {error_type or ''}".strip(), status=status)
        self.error_type = error_type
        self.retryable = retryable
        self.retry_after = retry_after


class LlmTransportError(LlmError):
    code = "transport"
    retryable = True


class LlmTimeout(LlmError):
    code = "timeout"
    retryable = True


class LlmRefused(LlmError):
    """The provider declined (safety stop); not retried, recorded as a skipped finding."""

    code = "refused"


class LlmBadOutput(LlmError):
    """The answer was not valid JSON for the schema, even after one repair attempt."""

    code = "bad_output"

    def __init__(self, provider: str, detail: str, usage: Usage, calls: int) -> None:
        super().__init__(provider, detail)
        self.usage = usage
        self.calls = calls


class LlmMalformedResponse(LlmError):
    code = "malformed_response"
