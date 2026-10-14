"""OpenAI Agents SDK: tracing processor → run tree (agents, tools, handoffs, generations) and
the Action Gate on `FunctionTool.on_invoke_tool`."""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pytest
import sibyl
from sibyl.integrations import openai_agents
from sibyl.testing import Ingest, attrs


@dataclass
class Data:
    type: str
    name: str | None = None
    input: Any = None
    output: Any = None
    from_agent: str | None = None
    to_agent: str | None = None
    model: str | None = None
    usage: dict[str, Any] = field(default_factory=dict)
    response: Any = None


@dataclass
class FakeSpan:
    span_id: str
    trace_id: str
    parent_id: str | None
    span_data: Data
    error: dict[str, Any] | None = None


@dataclass
class Trace:
    trace_id: str
    name: str


def by_op(ingest: Ingest, op: str) -> list[dict[str, Any]]:
    assert sibyl.flush(2)
    return [attrs(s) for s in ingest.spans() if attrs(s).get("gen_ai.operation.name") == op]


@pytest.fixture
def processor(start: Callable[..., sibyl.Client], fake_agents: Any) -> Any:
    start(instrument=())
    assert sibyl.instrument(libraries=["openai-agents"]) == ["openai_agents"]
    assert sibyl.instrument(libraries=["openai_agents"]) == ["openai_agents"]
    (proc,) = fake_agents.processors
    assert proc is openai_agents.processor()
    return proc


def test_trace_maps_agents_tools_handoffs_and_generations(processor: Any, ingest: Ingest) -> None:
    trace = Trace("trace_1", "Support workflow")
    processor.on_trace_start(trace)
    triage = FakeSpan("s1", "trace_1", None, Data("agent", name="triage"))
    processor.on_span_start(triage)
    gen = FakeSpan(
        "s2",
        "trace_1",
        "s1",
        Data("generation", model="gpt-5", usage={"input_tokens": 7, "output_tokens": 3}),
    )
    processor.on_span_start(gen)
    processor.on_span_end(gen)
    tool = FakeSpan("s3", "trace_1", "s1", Data("function", name="lookup", input='{"id": 1}'))
    processor.on_span_start(tool)
    tool.span_data.output = "found"
    processor.on_span_end(tool)
    hand = FakeSpan("s4", "trace_1", "s1", Data("handoff", from_agent="triage", to_agent="billing"))
    processor.on_span_start(hand)
    processor.on_span_end(hand)
    processor.on_span_end(triage)
    billing = FakeSpan("s5", "trace_1", None, Data("agent", name="billing"))
    processor.on_span_start(billing)
    response = {"id": "r", "model": "gpt-5-2026", "status": "completed", "output": []}
    resp = FakeSpan("s6", "trace_1", "s5", Data("response", response=response))
    processor.on_span_start(resp)
    processor.on_span_end(resp)
    billing.error = {"message": "card declined", "data": {}}
    processor.on_span_end(billing)
    processor.on_trace_end(trace)
    processor.force_flush()

    runs = {a["gen_ai.agent.name"]: a for a in by_op(ingest, "invoke_agent")}
    root = runs["Support workflow"]
    assert runs["triage"]["sibyl.parent_run_id"] == root["sibyl.task_id"]
    assert runs["triage"]["sibyl.handoff_to_agent"] == "billing"
    assert runs["billing"]["error.type"] == "card declined"
    (fn,) = by_op(ingest, "execute_tool")
    assert fn["gen_ai.tool.name"] == "lookup"
    assert fn["sibyl.parent_run_id"] == runs["triage"]["sibyl.task_id"]
    first, second = by_op(ingest, "chat")
    assert first["gen_ai.usage.input_tokens"] == 7 and first["gen_ai.request.model"] == "gpt-5"
    assert second["gen_ai.response.model"] == "gpt-5-2026"
    assert second["gen_ai.response.finish_reasons"] == ["stop"]
    assert sibyl.current_run() is None


def test_generations_are_left_to_the_instrumented_openai_client(
    start: Callable[..., sibyl.Client], fake_agents: Any, fake_openai: Any, ingest: Ingest
) -> None:
    start(instrument=())
    sibyl.instrument(libraries=["openai", "openai_agents"])
    (proc,) = fake_agents.processors
    proc.on_trace_start(Trace("t", "wf"))
    agent = FakeSpan("a", "t", None, Data("agent", name="writer"))
    proc.on_span_start(agent)
    gen = FakeSpan("g", "t", "a", Data("generation", model="gpt-5"))
    proc.on_span_start(gen)
    fake_openai["responses"].responses.append({"model": "gpt-5", "status": "completed"})
    sys.modules["openai.resources.responses"].Responses().create(model="gpt-5", input="x")
    proc.on_span_end(gen)
    proc.on_span_end(agent)
    proc.on_trace_end(Trace("t", "wf"))
    (chat,) = by_op(ingest, "chat")
    writer = next(a for a in by_op(ingest, "invoke_agent") if a["gen_ai.agent.name"] == "writer")
    assert chat["sibyl.parent_run_id"] == writer["sibyl.task_id"]


def test_function_tools_are_gated_before_they_run(
    processor: Any, fake_agents: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SIBYL_SENSITIVE_TOOLS", "wire_money")
    ran: list[Any] = []

    async def invoke(ctx: Any, raw: str) -> str:
        ran.append(json.loads(raw))
        return "ok"

    agents = sys.modules["agents"]
    safe_tool = agents.FunctionTool(name="lookup", on_invoke_tool=invoke)
    money = agents.FunctionTool(name="wire_money", on_invoke_tool=invoke)
    ctx = type("Ctx", (), {"tool_call_id": "call_abc"})()
    assert asyncio.run(safe_tool.on_invoke_tool(ctx, '{"q": 1}')) == "ok"
    with pytest.raises(sibyl.SibylActionBlocked):
        asyncio.run(money.on_invoke_tool(ctx, '{"amount": 5}'))
    assert ran == [{"q": 1}]
    assert openai_agents.gate_tool(money) is money  # idempotent
    assert openai_agents.gate_tool(object()) is not None  # not a tool: untouched


def test_processor_ignores_unknown_spans_and_bad_input(processor: Any) -> None:
    processor.on_span_start(FakeSpan("x", "nope", None, Data("guardrail")))
    processor.on_span_end(FakeSpan("x", "nope", None, Data("guardrail")))
    processor.on_span_end(FakeSpan("unknown", "nope", None, Data("agent")))
    processor.on_span_start(None)
    processor.on_trace_end(Trace("never-started", "x"))
    processor.shutdown()
