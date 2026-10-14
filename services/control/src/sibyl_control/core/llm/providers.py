"""Wire dialects: build one provider request and parse its answer (pure functions, no I/O).

* **Anthropic Messages** (``POST /v1/messages``, ``x-api-key``, ``anthropic-version``):
  JSON-schema structured output through ``output_config.format``. Current Claude models reject
  sampling parameters, so ``temperature`` is only sent to older models that accept it.
* **OpenAI Chat Completions** (``POST /v1/chat/completions``, bearer key):
  ``response_format: json_schema`` (strict).
* **Gemini** (``POST /v1beta/models/{model}:generateContent``, ``x-goog-api-key``): JSON mode
  (``responseMimeType: application/json``) with the schema stated in the system instruction;
  the client validates and repairs once.

A safety stop (Anthropic ``refusal``, OpenAI ``refusal`` / ``content_filter``, Gemini block
reasons) raises ``LlmRefused``. Anything that is not the documented shape raises
``LlmMalformedResponse`` without echoing the body.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from .types import (
    LlmConfigError,
    LlmMalformedResponse,
    LlmRefused,
    LlmRequest,
    LlmResponse,
    Provider,
    Usage,
)

ANTHROPIC_VERSION: Final = "2023-06-01"
_ANTHROPIC_SAMPLING_OK: Final = re.compile(r"^claude-(3|opus-4-[0-6]|sonnet-4|haiku-4)")
_GEMINI_BLOCKED: Final = frozenset(
    {"SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII", "RECITATION", "IMAGE_SAFETY"}
)


@dataclass(frozen=True)
class WireRequest:
    url: str
    headers: Mapping[str, str]
    body: Mapping[str, Any]
    native_schema: bool  # the provider enforces the JSON schema itself


def build(
    provider: Provider, base_url: str, model: str, api_key: str, req: LlmRequest
) -> WireRequest:
    base = base_url.rstrip("/")
    if provider == "anthropic":
        return _anthropic(base, model, api_key, req)
    if provider == "openai":
        return _openai(base, model, api_key, req)
    if provider == "gemini":
        return _gemini(base, model, api_key, req)
    raise LlmConfigError(str(provider), "unknown provider")


def parse(provider: Provider, requested_model: str, body: Any, native: bool) -> LlmResponse:
    if not isinstance(body, Mapping):
        raise LlmMalformedResponse(provider, "response is not a JSON object")
    try:
        if provider == "anthropic":
            return _parse_anthropic(requested_model, body, native)
        if provider == "openai":
            return _parse_openai(requested_model, body, native)
        return _parse_gemini(requested_model, body)
    except (KeyError, IndexError, TypeError, ValueError):
        raise LlmMalformedResponse(provider, "response does not have the expected shape") from None


def _json_headers(**extra: str) -> dict[str, str]:
    return {"content-type": "application/json", "accept": "application/json", **extra}


# --- Anthropic ------------------------------------------------------------------------------


def _anthropic(base: str, model: str, key: str, req: LlmRequest) -> WireRequest:
    body: dict[str, Any] = {
        "model": model,
        "max_tokens": req.max_tokens,
        "system": req.system,
        "messages": [{"role": m.role, "content": m.content} for m in req.messages],
    }
    if req.temperature is not None and _ANTHROPIC_SAMPLING_OK.match(model):
        body["temperature"] = req.temperature
    if req.json_schema is not None:
        body["output_config"] = {"format": {"type": "json_schema", "schema": req.json_schema}}
    headers = _json_headers(**{"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION})
    return WireRequest(base + "/v1/messages", headers, body, req.json_schema is not None)


def _parse_anthropic(model: str, body: Mapping[str, Any], native: bool) -> LlmResponse:
    stop = body.get("stop_reason")
    if stop == "refusal":
        raise LlmRefused("anthropic", "the model declined the request")
    texts = [b["text"] for b in body["content"] if b.get("type") == "text"]
    usage = body.get("usage") or {}
    return LlmResponse(
        provider="anthropic",
        model=str(body.get("model") or model),
        text="".join(texts),
        usage=Usage(int(usage.get("input_tokens", 0)), int(usage.get("output_tokens", 0))),
        stop_reason=str(stop) if stop is not None else None,
        structured=native,
    )


# --- OpenAI ---------------------------------------------------------------------------------


def _openai(base: str, model: str, key: str, req: LlmRequest) -> WireRequest:
    messages = [{"role": "system", "content": req.system}]
    messages += [{"role": m.role, "content": m.content} for m in req.messages]
    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_completion_tokens": req.max_tokens,
    }
    if req.temperature is not None:
        body["temperature"] = req.temperature
    if req.json_schema is not None:
        body["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": req.schema_name, "schema": req.json_schema, "strict": True},
        }
    headers = _json_headers(authorization=f"Bearer {key}")
    return WireRequest(base + "/v1/chat/completions", headers, body, req.json_schema is not None)


def _parse_openai(model: str, body: Mapping[str, Any], native: bool) -> LlmResponse:
    choice = body["choices"][0]
    message = choice["message"]
    finish = choice.get("finish_reason")
    if message.get("refusal") or finish == "content_filter":
        raise LlmRefused("openai", "the model declined the request")
    content = message.get("content")
    if not isinstance(content, str):
        raise ValueError("no content")
    usage = body.get("usage") or {}
    return LlmResponse(
        provider="openai",
        model=str(body.get("model") or model),
        text=content,
        usage=Usage(int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0))),
        stop_reason=str(finish) if finish is not None else None,
        structured=native,
    )


# --- Gemini ---------------------------------------------------------------------------------


def _gemini(base: str, model: str, key: str, req: LlmRequest) -> WireRequest:
    name = model.removeprefix("models/")
    system = req.system
    config: dict[str, Any] = {"maxOutputTokens": req.max_tokens}
    if req.temperature is not None:
        config["temperature"] = req.temperature
    if req.json_schema is not None:
        config["responseMimeType"] = "application/json"
        system += (
            "\n\nAnswer with one JSON object only, matching this JSON Schema exactly:\n"
            + json.dumps(req.json_schema, sort_keys=True)
        )
    body: dict[str, Any] = {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [
            {"role": "user" if m.role == "user" else "model", "parts": [{"text": m.content}]}
            for m in req.messages
        ],
        "generationConfig": config,
    }
    headers = _json_headers(**{"x-goog-api-key": key})
    url = f"{base}/v1beta/models/{name}:generateContent"
    return WireRequest(url, headers, body, False)


def _parse_gemini(model: str, body: Mapping[str, Any]) -> LlmResponse:
    feedback = body.get("promptFeedback") or {}
    if feedback.get("blockReason"):
        raise LlmRefused("gemini", "the prompt was blocked")
    candidate = body["candidates"][0]
    finish = candidate.get("finishReason")
    if finish in _GEMINI_BLOCKED:
        raise LlmRefused("gemini", "the model declined the request")
    parts = (candidate.get("content") or {}).get("parts") or []
    text = "".join(p["text"] for p in parts if "text" in p and not p.get("thought"))
    usage = body.get("usageMetadata") or {}
    return LlmResponse(
        provider="gemini",
        model=str(body.get("modelVersion") or model),
        text=text,
        usage=Usage(
            int(usage.get("promptTokenCount", 0)), int(usage.get("candidatesTokenCount", 0))
        ),
        stop_reason=str(finish) if finish is not None else None,
        structured=False,
    )


def error_type(provider: Provider, body: Any) -> Any:
    """The provider's error type field (validated by the caller before use)."""
    if not isinstance(body, Mapping):
        return None
    err = body.get("error")
    if not isinstance(err, Mapping):
        return None
    if provider == "gemini":
        return err.get("status")
    return err.get("type") or err.get("code")
