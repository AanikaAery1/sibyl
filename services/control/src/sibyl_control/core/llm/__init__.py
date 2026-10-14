"""Provider-neutral LLM adapter (D52, Sibyl Sentinel): Anthropic Messages, OpenAI Chat
Completions and Gemini ``generateContent`` over ``httpx``, no vendor SDK.

Never used in an enforcement or detection path: only Sentinel's advisory findings call it.
"""

from __future__ import annotations

from .client import LlmClient, extract_json, resolve_model
from .egress import EgressPolicy, guarded_transport
from .pricing import FALLBACK, PRICES, Price, cost_usd, estimate_tokens, price_for
from .types import (
    DEFAULT_BASE_URLS,
    DEFAULT_MODELS,
    PROVIDERS,
    EgressRefused,
    LlmBadOutput,
    LlmConfigError,
    LlmError,
    LlmHttpError,
    LlmMalformedResponse,
    LlmRefused,
    LlmRequest,
    LlmResponse,
    LlmTimeout,
    LlmTransportError,
    Message,
    Provider,
    Structured,
    Usage,
)

__all__ = [
    "DEFAULT_BASE_URLS",
    "DEFAULT_MODELS",
    "FALLBACK",
    "PRICES",
    "PROVIDERS",
    "EgressPolicy",
    "EgressRefused",
    "LlmBadOutput",
    "LlmClient",
    "LlmConfigError",
    "LlmError",
    "LlmHttpError",
    "LlmMalformedResponse",
    "LlmRefused",
    "LlmRequest",
    "LlmResponse",
    "LlmTimeout",
    "LlmTransportError",
    "Message",
    "Price",
    "Provider",
    "Structured",
    "Usage",
    "cost_usd",
    "estimate_tokens",
    "extract_json",
    "guarded_transport",
    "price_for",
    "resolve_model",
]
