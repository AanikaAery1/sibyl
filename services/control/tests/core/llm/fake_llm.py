"""Fake LLM providers for tests (no network): an ``httpx.MockTransport`` that answers in each
provider's wire dialect, records every request and can be scripted with failures.

Loaded by other suites as ``sibyl_fake_llm`` (``importlib``), so one module object is shared.
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx


def anthropic_body(text: str, *, tin: int = 120, tout: int = 40, stop: str = "end_turn") -> Any:
    return {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "model": "claude-fable-5-1",
        "content": [{"type": "thinking", "thinking": ""}, {"type": "text", "text": text}],
        "stop_reason": stop,
        "usage": {"input_tokens": tin, "output_tokens": tout},
    }


def openai_body(
    text: str | None, *, tin: int = 120, tout: int = 40, refusal: str | None = None
) -> Any:
    return {
        "id": "chatcmpl-test",
        "model": "gpt-test-1",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text, "refusal": refusal},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": tin, "completion_tokens": tout},
    }


def gemini_body(text: str, *, tin: int = 120, tout: int = 40, finish: str = "STOP") -> Any:
    return {
        "candidates": [
            {
                "content": {
                    "role": "model",
                    "parts": [{"text": "plan", "thought": True}, {"text": text}],
                },
                "finishReason": finish,
            }
        ],
        "usageMetadata": {"promptTokenCount": tin, "candidatesTokenCount": tout},
        "modelVersion": "gemini-test-1",
    }


BODIES: dict[str, Callable[..., Any]] = {
    "anthropic": anthropic_body,
    "openai": openai_body,
    "gemini": gemini_body,
}


@dataclass
class Scripted:
    status: int = 200
    body: Any = None
    headers: dict[str, str] = field(default_factory=dict)
    raise_exc: Exception | None = None


@dataclass
class FakeLlm:
    """Answers every call with ``default_text`` in the provider's dialect unless scripted."""

    provider: str = "anthropic"
    default_text: str = "{}"
    script: deque[Scripted] = field(default_factory=deque)
    requests: list[httpx.Request] = field(default_factory=list)
    responder: Callable[[httpx.Request], str] | None = None

    def push(self, *items: Scripted) -> None:
        self.script.extend(items)

    def text(self, text: str) -> Scripted:
        return Scripted(body=BODIES[self.provider](text))

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.script:
            item = self.script.popleft()
            if item.raise_exc is not None:
                raise item.raise_exc
            return httpx.Response(item.status, json=item.body, headers=item.headers)
        text = self.responder(request) if self.responder else self.default_text
        return httpx.Response(200, json=BODIES[self.provider](text))

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def bodies(self) -> list[Any]:
        return [json.loads(r.content) for r in self.requests]

    def last_body(self) -> Any:
        return json.loads(self.requests[-1].content)

    def prompt_text(self, index: int = -1) -> str:
        """Everything the provider was sent as text in one request (system + messages)."""
        return json.dumps(json.loads(self.requests[index].content))
