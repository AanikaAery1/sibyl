"""The three wire protocols the data plane speaks (D50): OpenAI-compatible, Anthropic Messages
and Gemini ``generateContent``. A ``WireProtocol`` owns everything protocol-specific on the
request side: where the Sibyl key and the caller's provider credential arrive, which header a
credential is forwarded in, the upstream URL, the tool fields degraded mode strips, and the
error envelope. Calls are only ever served by targets of the same dialect: there is no
cross-protocol translation, so inline fallback and failover stay inside the protocol.

Credentials (never logged, never forwarded to the wrong place):
- a value containing ``sbl_`` is a Sibyl key and is never sent upstream;
- OpenAI: ``Authorization: Bearer`` (``Bearer sbl_...`` alone = a Sibyl-only call, R23);
- Anthropic: ``x-api-key`` (or ``Authorization: Bearer`` for OAuth tokens); ``x-api-key: sbl_...``
  alone makes a Sibyl-only call, so an SDK only changes its base URL and API key;
- Gemini: ``x-goog-api-key`` or the ``key`` query parameter (moved into the header, never kept
  in a URL), or ``Authorization: Bearer``; ``sbl_...`` in either key slot is a Sibyl-only call.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Literal
from urllib.parse import parse_qsl

from ..policy.view import Dialect, Operation
from .http import ErrorStyle

ProtocolName = Literal["openai", "anthropic", "gemini"]
Header = tuple[str, str]
GEMINI_MODEL: Final = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_-]|\.(?!\.)){0,127}$")
_GEMINI_PATH: Final = re.compile(
    r"^/v1beta/models/([^/:]+):(generateContent|streamGenerateContent)$"
)


@dataclass(frozen=True)
class Credentials:
    sibyl_key: str | None
    provider: Header | None  # the caller's provider credential, as forwarded upstream
    has_provider_credential: bool


@dataclass(frozen=True)
class Route:
    """One data-plane route: protocol, operation, upstream path and the model in the path."""

    protocol: WireProtocol
    operation: Operation
    path_suffix: str
    path_model: str | None = None  # Gemini: the model is part of the URL
    stream: bool = False  # Gemini ``streamGenerateContent`` (SSE or a JSON array)


def _bearer(value: str | None) -> str | None:
    if value and value[:7].lower() == "bearer ":
        return value[7:].strip()
    return None


def _not_sibyl(value: str | None) -> str | None:
    return value if value and "sbl_" not in value else None


@dataclass(frozen=True)
class WireProtocol:
    name: ProtocolName
    dialect: Dialect
    error_style: ErrorStyle
    tool_keys: tuple[str, ...]
    model_in_body: bool = True
    gated_operations: frozenset[str] = frozenset()

    # -- caller side ---------------------------------------------------------------------

    def credentials(self, headers: dict[str, str], query: str) -> Credentials:
        if self.name == "openai":
            return _openai_credentials(headers)
        key = headers.get("x-sibyl-key")
        auth = headers.get("authorization")
        if self.name == "anthropic":
            slot_name, slot = "x-api-key", headers.get("x-api-key")
        else:
            slot_name, slot = "x-goog-api-key", headers.get("x-goog-api-key") or _query_key(query)
        if key is None and slot and slot.startswith("sbl_"):
            key, slot = slot, None
        bearer = _bearer(auth)
        if key is None and bearer and bearer.startswith("sbl_"):
            key, auth = bearer, None
        provider: Header | None = None
        if _not_sibyl(slot):
            provider = (slot_name, slot)  # type: ignore[assignment]
        elif _not_sibyl(auth):
            provider = ("authorization", auth)  # type: ignore[assignment]
        return Credentials(key, provider, provider is not None)

    def upstream_query(self, query: str) -> str:
        """Only Gemini's ``alt`` survives (``alt=sse``); ``key`` and anything else are dropped."""
        if self.name != "gemini":
            return ""
        alt = [v for k, v in parse_qsl(query, keep_blank_values=True) if k == "alt"]
        return "alt=sse" if alt and alt[-1] == "sse" else ""

    # -- upstream side -------------------------------------------------------------------

    def url(self, base_url: str, route: Route, model: str, query: str) -> str | None:
        """The upstream URL, or None when the target cannot be addressed safely."""
        base = base_url.rstrip("/")
        if self.name == "openai":
            return base + route.path_suffix
        if self.name == "anthropic":
            return base.removesuffix("/v1") + route.path_suffix
        if not GEMINI_MODEL.match(model):
            return None
        root = base.removesuffix("/v1beta")
        url = f"{root}/v1beta/models/{model}{route.path_suffix}"
        return f"{url}?{query}" if query else url

    def vaulted(self, secret: str) -> Header:
        if self.name == "anthropic":
            return ("x-api-key", secret)
        if self.name == "gemini":
            return ("x-goog-api-key", secret)
        return ("authorization", f"Bearer {secret}")


def _openai_credentials(headers: dict[str, str]) -> Credentials:
    auth = headers.get("authorization")
    key = headers.get("x-sibyl-key")
    provider_auth: str | None = auth
    if key is None and auth and auth.lower().startswith("bearer sbl_"):
        key, provider_auth = auth[7:].strip(), None  # Sibyl-only call (R23)
    if provider_auth and "sbl_" in provider_auth:
        provider_auth = None  # never forward a Sibyl key upstream
    has_cred = bool(provider_auth) or bool(headers.get("x-api-key"))
    provider = ("authorization", provider_auth) if provider_auth else None
    return Credentials(key, provider, has_cred)


def _query_key(query: str) -> str | None:
    found = [v for k, v in parse_qsl(query, keep_blank_values=True) if k == "key"]
    return found[-1] if found else None


OPENAI: Final = WireProtocol(
    name="openai",
    dialect="openai_compatible",
    error_style="openai",
    tool_keys=("tools", "tool_choice", "parallel_tool_calls", "functions", "function_call"),
    gated_operations=frozenset({"chat.completions"}),
)
ANTHROPIC: Final = WireProtocol(
    name="anthropic",
    dialect="anthropic",
    error_style="anthropic",
    tool_keys=("tools", "tool_choice"),
    gated_operations=frozenset({"anthropic.messages"}),
)
GEMINI: Final = WireProtocol(
    name="gemini",
    dialect="gemini",
    error_style="gemini",
    tool_keys=("tools", "toolConfig", "tool_config"),
    model_in_body=False,
    gated_operations=frozenset({"gemini.generate_content"}),
)

ROUTES: Final[dict[str, Route]] = {
    "/v1/chat/completions": Route(OPENAI, "chat.completions", "/chat/completions"),
    "/v1/embeddings": Route(OPENAI, "embeddings", "/embeddings"),
    "/v1/messages": Route(ANTHROPIC, "anthropic.messages", "/v1/messages"),
    "/v1/messages/count_tokens": Route(
        ANTHROPIC, "anthropic.count_tokens", "/v1/messages/count_tokens"
    ),
}


def gemini_route(path: str) -> Route | None:
    """``/v1beta/models/{model}:generateContent|streamGenerateContent`` with a safe model id."""
    match = _GEMINI_PATH.match(path)
    if match is None or not GEMINI_MODEL.match(match.group(1)):
        return None
    method = match.group(2)
    return Route(
        GEMINI,
        "gemini.generate_content",
        f":{method}",
        path_model=match.group(1),
        stream=method == "streamGenerateContent",
    )


def route_for(path: str) -> Route | None:
    return ROUTES.get(path) or (gemini_route(path) if path.startswith("/v1beta/") else None)
