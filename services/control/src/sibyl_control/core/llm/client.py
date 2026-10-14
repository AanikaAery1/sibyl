"""``LlmClient``: one provider, one key, one model; async over ``httpx`` (no vendor SDK).

* ``complete`` sends one request with retries: 408/409/425/429/5xx, timeouts and transport
  errors are retried with exponential backoff (honouring a numeric ``Retry-After`` up to
  ``MAX_RETRY_AFTER_S``); other 4xx fail at once. An egress refusal is never retried.
* ``complete_structured`` asks for JSON against a schema (natively where the provider supports
  it), parses and validates it, and on failure makes **one** repair call that quotes the
  validation error (never the model's own text back as instructions). Usage of every call is
  summed so the caller can charge the budget for all of it.

The key lives in a private attribute, never in ``repr``, an exception or a log line.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import re
from collections.abc import Awaitable, Callable
from typing import Any, Final, TypeVar

import httpx

from . import providers
from .egress import EgressPolicy, guarded_transport, host_of
from .types import (
    DEFAULT_BASE_URLS,
    DEFAULT_MODELS,
    MODEL_ID_RE,
    PROVIDERS,
    EgressRefused,
    LlmBadOutput,
    LlmConfigError,
    LlmError,
    LlmHttpError,
    LlmMalformedResponse,
    LlmRequest,
    LlmResponse,
    LlmTimeout,
    LlmTransportError,
    Message,
    Provider,
    Structured,
    Usage,
    safe_error_type,
)

log = logging.getLogger("sibyl.llm")
T = TypeVar("T")
RETRY_STATUSES: Final = frozenset({408, 409, 425, 429, 500, 502, 503, 504, 529})
MAX_RETRY_AFTER_S: Final = 30.0
MAX_RESPONSE_BYTES: Final = 2 * 1024 * 1024
_FENCE: Final = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.DOTALL)
REPAIR_PROMPT: Final = (
    "Your previous reply could not be used: {error}. Reply again with exactly one JSON object"
    " that matches the required schema, and nothing else."
)
Sleep = Callable[[float], Awaitable[None]]


def resolve_model(provider: str, model: str | None) -> str:
    chosen = model or DEFAULT_MODELS.get(provider)
    if chosen and provider == "gemini":
        chosen = chosen.removeprefix("models/")
    if not chosen:
        raise LlmConfigError(provider, "an explicit model is required for this provider")
    if not MODEL_ID_RE.fullmatch(chosen):
        raise LlmConfigError(provider, "the model id has an invalid format")
    return chosen


def extract_json(text: str) -> Any:
    """The JSON value in ``text`` (a fenced block is unwrapped); ``ValueError`` otherwise."""
    match = _FENCE.match(text)
    raw = match.group(1) if match else text.strip()
    return json.loads(raw)


class LlmClient:
    def __init__(
        self,
        provider: str,
        api_key: str,
        model: str | None = None,
        *,
        base_url: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        policy: EgressPolicy | None = None,
        timeout_s: float = 60.0,
        connect_timeout_s: float = 5.0,
        max_retries: int = 2,
        backoff_base_s: float = 0.5,
        backoff_max_s: float = 8.0,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        if provider not in PROVIDERS:
            raise LlmConfigError(provider, "unknown provider")
        if not api_key:
            raise LlmConfigError(provider, "no API key")
        self.provider: Provider = provider
        self.model = resolve_model(provider, model)
        self.base_url = (base_url or DEFAULT_BASE_URLS[provider]).rstrip("/")
        base_policy = policy or EgressPolicy()
        self.policy = base_policy.allowing(host_of(self.base_url))
        self.policy.check(self.base_url + "/")
        if transport is None:
            transport = guarded_transport(self.policy)
        elif not hasattr(transport, "policy"):
            transport = guarded_transport(self.policy, transport)
        self._transport = transport
        self.__key = api_key
        self.timeout = httpx.Timeout(timeout_s, connect=min(connect_timeout_s, timeout_s))
        self.overall_s = timeout_s
        self.max_retries = max(0, max_retries)
        self.backoff_base_s = backoff_base_s
        self.backoff_max_s = backoff_max_s
        self._sleep = sleep

    def __repr__(self) -> str:
        return f"LlmClient(provider={self.provider!r}, model={self.model!r}, key=<redacted>)"

    # --- one call ---------------------------------------------------------------------------

    async def complete(self, req: LlmRequest) -> LlmResponse:
        wire = providers.build(self.provider, self.base_url, self.model, self.__key, req)
        attempt = 0
        while True:
            attempt += 1
            try:
                body = await self._send(wire)
                response = providers.parse(self.provider, self.model, body, wire.native_schema)
                return _with_attempts(response, attempt)
            except LlmError as exc:
                if not exc.retryable or attempt > self.max_retries:
                    raise
                retry_after = exc.retry_after if isinstance(exc, LlmHttpError) else None
                delay = self._delay(attempt, retry_after)
                log.info(
                    "llm %s retry %d after %s (%.2fs)", self.provider, attempt, exc.code, delay
                )
                await self._sleep(delay)

    def _delay(self, attempt: int, retry_after: float | None) -> float:
        if retry_after is not None:
            return min(max(retry_after, 0.0), MAX_RETRY_AFTER_S)
        base = min(self.backoff_base_s * float(2 ** (attempt - 1)), self.backoff_max_s)
        return base * (0.5 + random.random() / 2)  # noqa: S311 (jitter, not crypto)

    async def _send(self, wire: providers.WireRequest) -> Any:
        client = httpx.AsyncClient(
            transport=self._transport,
            timeout=self.timeout,
            follow_redirects=False,
            trust_env=False,
        )
        try:
            async with client, asyncio.timeout(self.overall_s):
                response = await client.post(wire.url, headers=dict(wire.headers), json=wire.body)
                raw = response.content[: MAX_RESPONSE_BYTES + 1]
        except EgressRefused:
            raise
        except (TimeoutError, httpx.TimeoutException):
            raise LlmTimeout(self.provider, "the request timed out") from None
        except httpx.HTTPError as exc:
            if isinstance(exc.__cause__, EgressRefused):
                raise exc.__cause__ from None
            from ...worker.jobs.net import is_ssrf_refusal

            if is_ssrf_refusal(exc):
                raise EgressRefused(self.provider, "the upstream address is not public") from None
            raise LlmTransportError(self.provider, type(exc).__name__) from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise LlmMalformedResponse(self.provider, "response body too large")
        try:
            body = json.loads(raw) if raw else None
        except ValueError:
            body = None
        if response.status_code >= 300:
            raise LlmHttpError(
                self.provider,
                response.status_code,
                safe_error_type(providers.error_type(self.provider, body)),
                retryable=response.status_code in RETRY_STATUSES,
                retry_after=_retry_after(response.headers.get("retry-after")),
            )
        if body is None:
            raise LlmMalformedResponse(self.provider, "response is not JSON")
        return body

    # --- structured -------------------------------------------------------------------------

    async def complete_structured(
        self, req: LlmRequest, validate: Callable[[Any], T]
    ) -> Structured:
        if req.json_schema is None:
            raise LlmConfigError(self.provider, "complete_structured needs a json_schema")
        first = await self.complete(req)
        usage, calls = first.usage, 1
        try:
            return Structured(validate(extract_json(first.text)), first, usage, calls)
        except (ValueError, TypeError) as exc:
            error = _short_error(exc)
        repair = req.with_messages(
            Message("assistant", first.text or "{}"),
            Message("user", REPAIR_PROMPT.format(error=error)),
        )
        try:
            second = await self.complete(repair)
        except LlmError as exc:
            raise LlmBadOutput(self.provider, f"repair failed: {exc.code}", usage, calls) from None
        usage, calls = usage + second.usage, calls + 1
        try:
            value = validate(extract_json(second.text))
        except (ValueError, TypeError) as exc:
            raise LlmBadOutput(self.provider, _short_error(exc), usage, calls) from None
        return Structured(value, second, usage, calls, repaired=True)


def _with_attempts(response: LlmResponse, attempts: int) -> LlmResponse:
    if attempts == 1:
        return response
    return LlmResponse(
        response.provider,
        response.model,
        response.text,
        response.usage,
        response.stop_reason,
        response.structured,
        attempts,
    )


def _retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _short_error(exc: BaseException) -> str:
    """A bounded, content-free description of why the output was rejected."""
    if isinstance(exc, json.JSONDecodeError):
        return "the reply was not valid JSON"
    errors = getattr(exc, "errors", None)
    if callable(errors):
        try:
            parts = [
                f"{'/'.join(str(p) for p in e.get('loc', ()))}: {e.get('type', 'invalid')}"
                for e in errors()[:5]
            ]
            return "schema violations: " + "; ".join(parts)
        except (TypeError, AttributeError, KeyError):
            log.debug("could not summarise a validation error")
    return "the reply did not match the schema"


def usage_of(exc: BaseException) -> Usage:
    return exc.usage if isinstance(exc, LlmBadOutput) else Usage()
