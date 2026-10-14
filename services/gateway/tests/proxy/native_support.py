"""Snapshot mutations and request helpers for the native Anthropic / Gemini surfaces."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import UUID

from sibyl_schemas import jsonschema as sj

from ..support import ANTHROPIC, CRED, GATEWAY_KEY, OPENAI, QUOTE, set_agent

GEMINI = UUID("0192f0a1-7b2c-7e3d-9a4b-5c6d7e8f9a14")
ANTHROPIC_KEY = "sk-ant-api03-clientcredential0123456789abcdefABCDEF"
GOOGLE_KEY = "AIzaSyClientCredential0123456789abcdefXY"
MESSAGES = "/v1/messages"
GEN = "/v1beta/models/gemini-2.5-pro:generateContent"
STREAM = "/v1beta/models/gemini-2.5-pro:streamGenerateContent"


def native(
    url: str, protocol: str, *, inline: bool = False, **agent: Any
) -> Callable[[dict[str, Any]], None]:
    """QUOTE's primary becomes the Anthropic or Gemini provider of the fake upstream. With
    ``inline``, the chain is: OpenAI (other protocol, vaulted), a same-provider alt model."""

    def mutate(block: dict[str, Any]) -> None:
        block["providers"][str(ANTHROPIC)]["base_url"] = f"{url}/anthropic"
        block["providers"][str(GEMINI)] = {
            "slug": "gemini",
            "provider_kind": "custom",
            "dialect": "gemini",
            "base_url": f"{url}/gemini",
            "is_enabled": True,
        }
        provider = ANTHROPIC if protocol == "anthropic" else GEMINI
        model = "claude-sonnet-5" if protocol == "anthropic" else "gemini-2.5-pro"
        alt = "claude-haiku-5" if protocol == "anthropic" else "gemini-2.5-flash"
        steps = [
            {
                "position": 1,
                "kind": "alt_provider",
                "provider_id": str(OPENAI),
                "model": "gpt-5.4",
                "credential_id": str(CRED),
                "viable": True,
            },
            {
                "position": 2,
                "kind": "alt_model_same_provider",
                "provider_id": str(provider),
                "model": alt,
                "viable": True,
            },
        ]
        set_agent(
            block,
            QUOTE,
            primary={"provider_id": str(provider), "model": model},
            inline_fallback=inline,
            fallback_chain={
                "chain_id": "0192f0b2-0000-7000-8000-0000000000c9",
                "version": 1,
                "steps": steps,
            },
            identity={"allowed_models": None},
            **agent,
        )

    return mutate


def anthropic_headers(**extra: str) -> dict[str, str]:
    return {
        "X-Sibyl-Key": GATEWAY_KEY,
        "X-Sibyl-Agent": "quote-assistant",
        "x-api-key": ANTHROPIC_KEY,
        "anthropic-version": "2023-06-01",
        "anthropic-beta": "tools-2026-01-01",
        **extra,
    }


def gemini_headers(**extra: str) -> dict[str, str]:
    return {
        "X-Sibyl-Key": GATEWAY_KEY,
        "X-Sibyl-Agent": "quote-assistant",
        "x-goog-api-key": GOOGLE_KEY,
        **extra,
    }


def messages(**extra: Any) -> dict[str, Any]:
    return {
        "model": "claude-sonnet-5",
        "max_tokens": 256,
        "messages": [{"role": "user", "content": "hi"}],
        **extra,
    }


def contents(**extra: Any) -> dict[str, Any]:
    return {"contents": [{"role": "user", "parts": [{"text": "hi"}]}], **extra}


def assert_wire_valid(event: dict[str, Any]) -> None:
    """Strict ``sibyl-event-wire/1`` validation, including the frozen ``system_fingerprint``
    attr (WAVE3) that lane PLUG added to the event schema."""
    errors = list(sj.iter_errors("sibyl-event-wire/1", event))
    assert not errors, errors
