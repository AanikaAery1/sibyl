"""Model clients through `sibyl.instrument()`: served model, fingerprint, usage, finish
reasons, refusals and proposed tool calls, sync/async/streaming, capture modes, headers."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable
from typing import Any

import pytest
import sibyl
from sibyl.testing import AGENT_UUID, Ingest, attrs

USER = "0192767f-0000-7000-8000-0000000000aa"


def model_spans(ingest: Ingest) -> list[dict[str, Any]]:
    assert sibyl.flush(2)
    return [
        attrs(s)
        for s in ingest.spans()
        if attrs(s).get("gen_ai.operation.name") in ("chat", "generate_content", "embeddings")
    ]


def _cls(module: str, name: str) -> Any:
    return getattr(sys.modules[module], name)


CHAT = {
    "id": "chatcmpl-1",
    "model": "gpt-5-mini-2026-08-01",
    "system_fingerprint": "fp_abc123",
    "usage": {"prompt_tokens": 11, "completion_tokens": 7},
    "choices": [
        {
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {"id": "call_1", "function": {"name": "lookup_order", "arguments": "{}"}},
                    {"id": "call_2", "function": {"name": "quote", "arguments": "{}"}},
                ],
            },
        }
    ],
}


def test_instrument_detects_and_wraps_every_installed_client(
    start: Callable[..., sibyl.Client],
    fake_openai: dict[str, Any],
    fake_anthropic: Any,
    fake_google: Any,
) -> None:
    start(instrument=())
    names = sibyl.instrument()
    assert {"openai", "anthropic", "google"} <= set(names)
    for module, cls, method in (
        ("openai.resources.chat.completions", "Completions", "create"),
        ("openai.resources.responses", "AsyncResponses", "create"),
        ("anthropic.resources.messages", "Messages", "create"),
        ("google.genai.models", "AsyncModels", "generate_content_stream"),
    ):
        assert getattr(getattr(_cls(module, cls), method), "__sibyl_wrapped__", False)
    assert set(sibyl.instrument()) >= {"openai", "anthropic", "google"}  # idempotent


def test_instrument_skips_libraries_that_are_not_installed(
    start: Callable[..., sibyl.Client], fake_openai: dict[str, Any]
) -> None:
    start(instrument=())
    assert sibyl.instrument(libraries=["openai", "crewai"]) == ["openai"]


def test_openai_chat_records_fingerprint_served_model_and_proposed_tools(
    start: Callable[..., sibyl.Client], ingest: Ingest, fake_openai: dict[str, Any]
) -> None:
    start()
    fake_openai["chat"].responses.append(CHAT)
    client = _cls("openai.resources.chat.completions", "Completions")()
    with sibyl.on_behalf_of(user=USER):
        client.create(model="gpt-5-mini", messages=[{"role": "user", "content": "hi"}])
    sent = fake_openai["chat"].calls[0]["extra_headers"]
    assert sent["X-Sibyl-On-Behalf-Of"] == f"user:{USER}"
    (a,) = model_spans(ingest)
    assert a["gen_ai.request.model"] == "gpt-5-mini"
    assert a["gen_ai.response.model"] == "gpt-5-mini-2026-08-01"
    assert a["sibyl.system_fingerprint"] == "fp_abc123"
    assert a["gen_ai.usage.input_tokens"] == 11 and a["gen_ai.usage.output_tokens"] == 7
    assert a["gen_ai.response.finish_reasons"] == ["tool_calls"]
    assert a["sibyl.tool_calls.names"] == ["lookup_order", "quote"]
    assert a["sibyl.tool_calls.ids"] == ["call_1", "call_2"]
    assert "sibyl.refusal" not in a


def test_openai_refusal_is_flagged(
    start: Callable[..., sibyl.Client], ingest: Ingest, fake_openai: dict[str, Any]
) -> None:
    start()
    fake_openai["chat"].responses.append(
        {"choices": [{"finish_reason": "stop", "message": {"refusal": "I can't help"}}]}
    )
    _cls("openai.resources.chat.completions", "Completions")().create(model="m", messages=[])
    (a,) = model_spans(ingest)
    assert a["sibyl.refusal"] is True and a["gen_ai.response.finish_reasons"] == ["stop"]


def test_openai_stream_reassembles_tool_calls_fingerprint_and_refusal(
    start: Callable[..., sibyl.Client], ingest: Ingest, fake_openai: dict[str, Any]
) -> None:
    start()
    fake_openai["chat"].responses.append(
        [
            {"id": "c", "model": "gpt-x", "system_fingerprint": "fp_9", "choices": []},
            {
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {"index": 0, "id": "call_a", "function": {"name": "search"}}
                            ]
                        }
                    }
                ]
            },
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {}}]}}]},
            {"choices": [{"delta": {"refusal": "no"}, "finish_reason": "tool_calls"}]},
            {"choices": [], "usage": {"prompt_tokens": 3, "completion_tokens": 4}},
        ]
    )
    stream = _cls("openai.resources.chat.completions", "Completions")().create(
        model="gpt-x", stream=True, messages=[]
    )
    assert len(list(stream)) == 5
    (a,) = model_spans(ingest)
    assert a["sibyl.system_fingerprint"] == "fp_9" and a["sibyl.streamed"] is True
    assert a["sibyl.tool_calls.names"] == ["search"] and a["sibyl.refusal"] is True
    assert a["gen_ai.usage.output_tokens"] == 4 and "sibyl.ttfb_ms" in a


def test_openai_responses_api_sync_and_async_stream(
    start: Callable[..., sibyl.Client], ingest: Ingest, fake_openai: dict[str, Any]
) -> None:
    start()
    done = {
        "id": "resp_1",
        "model": "gpt-5-2026",
        "status": "completed",
        "usage": {"input_tokens": 5, "output_tokens": 6},
        "output": [
            {"type": "function_call", "call_id": "fc_1", "name": "send_email"},
            {"type": "message", "content": [{"type": "refusal", "refusal": "nope"}]},
        ],
    }
    fake_openai["responses"].responses += [
        done,
        [
            {"type": "response.created", "response": {"id": "resp_2", "model": "gpt-5"}},
            {"type": "response.output_text.delta", "delta": "Hel"},
            {
                "type": "response.incomplete",
                "response": {
                    "id": "resp_2",
                    "model": "gpt-5-2026",
                    "status": "incomplete",
                    "incomplete_details": {"reason": "max_output_tokens"},
                    "usage": {"input_tokens": 1, "output_tokens": 9},
                    "output": [],
                },
            },
        ],
    ]
    _cls("openai.resources.responses", "Responses")().create(
        model="gpt-5", input="hi", instructions="be brief"
    )

    async def consume() -> int:
        stream = await _cls("openai.resources.responses", "AsyncResponses")().create(
            model="gpt-5", input="hi", stream=True
        )
        return len([chunk async for chunk in stream])

    assert asyncio.run(consume()) == 3
    plain, streamed = model_spans(ingest)
    assert plain["gen_ai.response.model"] == "gpt-5-2026"
    assert plain["gen_ai.response.finish_reasons"] == ["tool_calls"]
    assert plain["sibyl.tool_calls.names"] == ["send_email"] and plain["sibyl.refusal"] is True
    assert plain["gen_ai.system_instructions"] == "be brief"
    assert streamed["gen_ai.response.finish_reasons"] == ["length"]
    assert streamed["gen_ai.usage.output_tokens"] == 9


def test_anthropic_tool_use_refusal_and_stream(
    start: Callable[..., sibyl.Client], ingest: Ingest, fake_anthropic: Any
) -> None:
    start()
    fake_anthropic.responses += [
        {
            "id": "msg_1",
            "model": "claude-x-2026",
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 8, "output_tokens": 2},
            "content": [{"type": "tool_use", "id": "tu_1", "name": "refund"}],
        },
        {"model": "claude-x", "stop_reason": "refusal", "content": []},
        [
            {"type": "message_start", "message": {"id": "m", "model": "claude-x", "usage": {}}},
            {
                "type": "content_block_start",
                "content_block": {"type": "tool_use", "id": "tu_2", "name": "lookup"},
            },
            {"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {}},
        ],
    ]
    messages = _cls("anthropic.resources.messages", "Messages")()
    messages.create(model="claude-x", messages=[])
    messages.create(model="claude-x", messages=[])
    list(messages.create(model="claude-x", stream=True, messages=[]))
    tool, refused, streamed = model_spans(ingest)
    assert tool["gen_ai.provider.name"] == "anthropic"
    assert tool["sibyl.tool_calls.names"] == ["refund"] and tool["sibyl.tool_calls.ids"] == ["tu_1"]
    assert refused["sibyl.refusal"] is True
    assert refused["gen_ai.response.finish_reasons"] == ["refusal"]
    assert streamed["sibyl.tool_calls.names"] == ["lookup"]


class FinishReason:
    def __init__(self, name: str) -> None:
        self.name = name


def test_google_generate_content_sync_async_and_stream(
    start: Callable[..., sibyl.Client], ingest: Ingest, fake_google: Any
) -> None:
    start()
    fake_google.responses += [
        {
            "response_id": "g1",
            "model_version": "gemini-2.5-flash-001",
            "usage_metadata": {"prompt_token_count": 4, "candidates_token_count": 3},
            "candidates": [
                {
                    "finish_reason": FinishReason("STOP"),
                    "content": {"parts": [{"text": "hi"}, {"function_call": {"name": "geo"}}]},
                }
            ],
        },
        {"candidates": [{"finish_reason": "SAFETY", "content": {"parts": []}}]},
        [
            {
                "model_version": "gemini-2.5",
                "candidates": [{"content": {"parts": [{"text": "a"}]}}],
            },
            {
                "candidates": [{"finish_reason": "MAX_TOKENS", "content": {"parts": []}}],
                "usage_metadata": {"prompt_token_count": 1, "candidates_token_count": 2},
            },
        ],
    ]
    models = _cls("google.genai.models", "Models")()
    models.generate_content(
        model="gemini-2.5-flash",
        contents="hello",
        config={"temperature": 0.1, "system_instruction": "terse", "http_options": {"timeout": 3}},
    )

    async def run_async() -> None:
        await _cls("google.genai.models", "AsyncModels")().generate_content(
            model="gemini-2.5-flash", contents="x"
        )

    asyncio.run(run_async())
    list(models.generate_content_stream(model="gemini-2.5", contents="y"))
    first, safety, streamed = model_spans(ingest)
    config = fake_google.calls[0]["config"]
    assert config["http_options"]["timeout"] == 3
    assert config["http_options"]["headers"]["X-Sibyl-Agent"] == "quote-assistant"
    assert first["gen_ai.provider.name"] == "gcp.gen_ai"
    assert first["gen_ai.operation.name"] == "generate_content"
    assert first["gen_ai.response.model"] == "gemini-2.5-flash-001"
    assert first["gen_ai.response.finish_reasons"] == ["stop"]
    assert first["gen_ai.request.temperature"] == 0.1
    assert first["gen_ai.system_instructions"] == "terse"
    assert first["sibyl.tool_calls.names"] == ["geo"]
    assert safety["sibyl.refusal"] is True
    assert streamed["gen_ai.response.finish_reasons"] == ["length"] and streamed["sibyl.streamed"]


def test_google_typed_config_is_left_untouched(
    start: Callable[..., sibyl.Client], fake_google: Any
) -> None:
    class Config:
        temperature = 0.5
        http_options = None

    start()
    config = Config()
    _cls("google.genai.models", "Models")().generate_content(model="g", contents="x", config=config)
    assert fake_google.calls[0]["config"] is config


def test_metadata_capture_keeps_fingerprint_and_tool_names_but_no_content(
    start: Callable[..., sibyl.Client], ingest: Ingest, fake_openai: dict[str, Any]
) -> None:
    start(capture_mode="metadata")
    fake_openai["chat"].responses.append(CHAT)
    _cls("openai.resources.chat.completions", "Completions")().create(
        model="m", messages=[{"role": "user", "content": "private plan"}]
    )
    (a,) = model_spans(ingest)
    assert "gen_ai.input.messages" not in a and "gen_ai.output.messages" not in a
    assert a["sibyl.system_fingerprint"] == "fp_abc123"
    assert a["sibyl.tool_calls.names"] == ["lookup_order", "quote"]
    assert len(a["sibyl.content_hash.input"]) == 64


def test_model_call_inside_a_run_records_the_run_tree(
    start: Callable[..., sibyl.Client], ingest: Ingest, fake_openai: dict[str, Any]
) -> None:
    start()
    fake_openai["chat"].responses += [CHAT, CHAT]
    client = _cls("openai.resources.chat.completions", "Completions")()
    with sibyl.agent("planner") as run:
        client.create(model="m", messages=[])
        client.create(model="m", messages=[])
    first, second = model_spans(ingest)
    assert first["sibyl.parent_run_id"] == str(run.task_id) == second["sibyl.parent_run_id"]
    assert (first["sibyl.step_index"], second["sibyl.step_index"]) == (0, 1)


def test_provider_errors_and_unreadable_responses_never_break_the_call(
    start: Callable[..., sibyl.Client], ingest: Ingest, fake_openai: dict[str, Any]
) -> None:
    class Boom(Exception):
        code = 503

    start()
    fake_openai["chat"].responses.append(object())  # nothing extractable
    client = _cls("openai.resources.chat.completions", "Completions")()
    client.create(model="m", messages=[])
    fake_openai["chat"].error = Boom("down")
    with pytest.raises(Boom):
        client.create(model="m", messages=[])
    ok, failed = model_spans(ingest)
    assert ok["gen_ai.request.model"] == "m"
    assert failed["error.type"] == "Boom" and failed["http.response.status_code"] == 503


def test_explicit_google_client_instance_is_wrapped(
    start: Callable[..., sibyl.Client], ingest: Ingest
) -> None:
    calls: list[dict[str, Any]] = []

    class Models:
        def generate_content(self, **kwargs: Any) -> Any:
            calls.append(kwargs)
            return {"candidates": []}

        def generate_content_stream(self, **kwargs: Any) -> Any:
            return iter([])

    class Aio:
        models = Models()

    class Client:
        models = Models()
        aio = Aio()

    start(instrument=())
    client = sibyl.instrument(Client())
    client.models.generate_content(model="gemini", contents="x")
    (a,) = model_spans(ingest)
    assert a["gen_ai.provider.name"] == "gcp.gen_ai" and calls


def test_embeddings_capture_usage_only(
    start: Callable[..., sibyl.Client], ingest: Ingest, fake_openai: dict[str, Any]
) -> None:
    start()
    fake_openai["embeddings"].responses.append({"usage": {"prompt_tokens": 2}, "data": []})
    _cls("openai.resources.embeddings", "Embeddings")().create(model="e", input="x")
    (a,) = model_spans(ingest)
    assert a["gen_ai.usage.input_tokens"] == 2 and "gen_ai.output.messages" not in a
    assert a["gen_ai.input.messages"] == "x"


def test_without_init_wrapped_clients_pass_through(fake_openai: dict[str, Any]) -> None:
    from sibyl._instrument import auto_instrument

    auto_instrument(("openai",))
    fake_openai["chat"].responses.append({"choices": []})
    result = _cls("openai.resources.chat.completions", "Completions")().create(model="m")
    assert result == {"choices": []} and "extra_headers" not in fake_openai["chat"].calls[0]
    assert AGENT_UUID  # the fixture key's agent is never contacted without init()
