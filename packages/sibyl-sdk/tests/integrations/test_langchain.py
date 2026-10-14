"""LangChain / LangGraph callback handler: run tree, handoffs, models, Action Gate, capture.

A tiny driver replays the callback sequence LangChain emits (chain → node → runnable →
model/tool) and honours `raise_error` like LangChain's callback manager: an exception from
`on_tool_start` propagates and the tool function never runs."""

from __future__ import annotations

import copy
import sys
from collections.abc import Callable
from typing import Any
from uuid import UUID, uuid4

import pytest
import sibyl
from sibyl.testing import FakeActionApi, Ingest, SnapshotServer, attrs, wait_for
from sibyl_schemas.golden import load_fixture

PAYMENTS = load_fixture("action_gate", "vectors.json")["policies"]["payments"]
SECRET = "sk-proj-" + "a1B2c3D4e5F6g7H8i9J0" * 3


class Command:
    def __init__(self, goto: Any) -> None:
        self.goto = goto


class ParentCommand(Exception):
    pass


class GraphInterrupt(Exception):
    pass


def run_tool(
    handler: Any, name: str, inputs: dict[str, Any], fn: Callable[..., Any], parent: UUID
) -> Any:
    run_id = uuid4()
    if handler.raise_error:
        handler.on_tool_start(
            {"name": name}, str(inputs), run_id=run_id, parent_run_id=parent, inputs=inputs
        )
    try:
        result = fn(**inputs)
    except Exception as exc:
        handler.on_tool_error(exc, run_id=run_id)
        raise
    handler.on_tool_end(result, run_id=run_id)
    return result


def chain(handler: Any, name: str, parent: UUID | None = None, **meta: Any) -> UUID:
    run_id = uuid4()
    handler.on_chain_start(None, {}, run_id=run_id, parent_run_id=parent, name=name, metadata=meta)
    return run_id


def spans_by_op(ingest: Ingest, op: str) -> list[dict[str, Any]]:
    assert sibyl.flush(2)
    return [attrs(s) for s in ingest.spans() if attrs(s).get("gen_ai.operation.name") == op]


LLM_RESULT = {
    "llm_output": {
        "token_usage": {"prompt_tokens": 12, "completion_tokens": 4},
        "model_name": "qwen3:32b",
        "system_fingerprint": "fp_local",
    },
    "generations": [
        [
            {
                "text": "routing",
                "generation_info": {"finish_reason": "STOP"},
                "message": {
                    "tool_calls": [{"id": "t1", "name": "transfer_to_researcher"}],
                    "additional_kwargs": {},
                },
            }
        ]
    ],
}


@pytest.fixture
def handler(start: Callable[..., sibyl.Client], fake_langchain: Any) -> Any:
    start(instrument=())
    assert sibyl.instrument(libraries=["langchain"]) == ["langchain"]
    assert sibyl.instrument(libraries=["langgraph"]) == ["langchain"]  # alias, idempotent
    h = fake_langchain.handler()
    assert h.raise_error is True and h.run_inline is True
    assert len(fake_langchain.hooks) == 1
    return h


def test_langgraph_supervisor_maps_to_a_run_tree(handler: Any, ingest: Ingest) -> None:
    root = chain(handler, "LangGraph")
    node = chain(handler, "supervisor", root, langgraph_node="supervisor", langgraph_step=1)
    inner = chain(handler, "RunnableSequence", node, langgraph_node="supervisor")
    llm = uuid4()
    handler.on_chat_model_start(
        {"id": ["langchain_ollama", "chat_models", "ChatOllama"]},
        [[{"role": "user", "content": "hi"}]],
        run_id=llm,
        parent_run_id=inner,
        invocation_params={"model": "qwen3:32b", "_type": "ollama-chat"},
    )
    handler.on_llm_end(LLM_RESULT, run_id=llm)
    assert run_tool(handler, "transfer_to_researcher", {}, lambda: "ok", inner) == "ok"
    handler.on_chain_end({}, run_id=inner)
    handler.on_chain_error(ParentCommand(Command(goto="researcher")), run_id=node)
    worker = chain(handler, "researcher", root, langgraph_node="researcher", langgraph_step=2)
    handler.on_chain_error(GraphInterrupt("wait for human"), run_id=worker)
    handler.on_chain_end({}, run_id=root)

    runs = {a["gen_ai.agent.name"]: a for a in spans_by_op(ingest, "invoke_agent")}
    graph, sup, res = runs["LangGraph"], runs["supervisor"], runs["researcher"]
    assert "RunnableSequence" not in runs  # transparent
    assert sup["sibyl.parent_run_id"] == graph["sibyl.task_id"] and sup["sibyl.step_index"] == 1
    assert res["sibyl.step_index"] == 2 and "error.type" not in res  # interrupt is control flow
    assert sup["sibyl.handoff_to_agent"] == "researcher" and "error.type" not in sup
    (model,) = spans_by_op(ingest, "chat")
    assert model["gen_ai.provider.name"] == "ollama"
    assert model["gen_ai.request.model"] == "qwen3:32b"
    assert model["sibyl.parent_run_id"] == sup["sibyl.task_id"]
    assert (
        model["gen_ai.usage.input_tokens"] == 12 and model["sibyl.system_fingerprint"] == "fp_local"
    )
    assert model["sibyl.tool_calls.names"] == ["transfer_to_researcher"]
    assert model["gen_ai.response.finish_reasons"] == ["stop"]
    (tool,) = spans_by_op(ingest, "execute_tool")
    assert tool["sibyl.handoff_to_agent"] == "researcher"
    assert tool["sibyl.parent_run_id"] == sup["sibyl.task_id"]


def test_chain_errors_close_runs_with_the_error(handler: Any, ingest: Ingest) -> None:
    root = chain(handler, "agent_executor")
    llm = uuid4()
    handler.on_llm_start({"id": ["x", "LLM"]}, ["p"], run_id=llm, parent_run_id=root)
    handler.on_llm_error(TimeoutError("slow"), run_id=llm)
    with pytest.raises(ValueError):
        run_tool(handler, "parse", {"text": "x"}, lambda text: int(text), root)
    handler.on_chain_error(RuntimeError("bad"), run_id=root)
    (run,) = spans_by_op(ingest, "invoke_agent")
    assert run["error.type"] == "RuntimeError"
    (model,) = spans_by_op(ingest, "chat")
    assert model["error.type"] == "TimeoutError" and model["gen_ai.request.model"] == "unknown"
    (tool,) = spans_by_op(ingest, "execute_tool")
    assert tool["error.type"] == "ValueError"


def test_openai_models_are_left_to_the_client_wrapper_and_nest_under_the_node(
    start: Callable[..., sibyl.Client], fake_langchain: Any, fake_openai: Any, ingest: Ingest
) -> None:
    start(instrument=())
    sibyl.instrument(libraries=["openai", "langchain"])
    h = fake_langchain.handler()
    root = chain(h, "graph")
    node = chain(h, "agent", root, langgraph_node="agent", langgraph_step=0)
    llm = uuid4()
    h.on_chat_model_start(
        {"id": ["langchain_openai", "chat_models", "ChatOpenAI"]},
        [[]],
        run_id=llm,
        parent_run_id=node,
    )
    fake_openai["chat"].responses.append({"model": "gpt-5", "choices": []})
    sys.modules["openai.resources.chat.completions"].Completions().create(
        model="gpt-5", messages=[]
    )
    h.on_llm_end(LLM_RESULT, run_id=llm)
    h.on_chain_end({}, run_id=node)
    h.on_chain_end({}, run_id=root)
    (model,) = spans_by_op(ingest, "chat")  # exactly one: no duplicate from the handler
    runs = {a["gen_ai.agent.name"]: a for a in spans_by_op(ingest, "invoke_agent")}
    assert model["gen_ai.response.model"] == "gpt-5"
    assert model["sibyl.parent_run_id"] == runs["agent"]["sibyl.task_id"]
    assert sibyl.current_run() is None  # previous run restored


def test_sensitive_tool_without_snapshot_fails_closed_and_never_runs(
    handler: Any, ingest: Ingest, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SIBYL_SENSITIVE_TOOLS", "payments.*, wire_*")
    ran: list[Any] = []
    root = chain(handler, "graph")
    with pytest.raises(sibyl.SibylActionBlocked) as info:
        run_tool(
            handler, "payments.transfer", {"amount": 5}, lambda amount: ran.append(amount), root
        )
    assert info.value.rule_id == "sibyl:fail_closed" and not ran
    assert run_tool(handler, "lookup", {"q": "x"}, lambda q: q, root) == "x"
    handler.on_chain_end({}, run_id=root)
    blocked = next(
        a
        for a in spans_by_op(ingest, "execute_tool")
        if a["gen_ai.tool.name"] == "payments.transfer"
    )
    assert (
        blocked["sibyl.action.effect"] == "block" and blocked["error.type"] == "SibylActionBlocked"
    )


def test_action_policy_gates_framework_tools_like_sibyl_tool(
    start: Callable[..., sibyl.Client],
    fake_langchain: Any,
    server: SnapshotServer,
    api: FakeActionApi,
    ingest: Ingest,
) -> None:
    server.publish(action_policies=[copy.deepcopy(PAYMENTS)])
    client = start(instrument=["langchain"])
    assert wait_for(lambda: client.snapshot is not None and bool(client.snapshot.action_policies))
    h = fake_langchain.handler()
    root = chain(h, "graph")
    ran: list[int] = []

    def transfer(amount: int, currency: str, to_account: str) -> str:
        ran.append(amount)
        return "sent"

    with pytest.raises(sibyl.SibylActionBlocked) as info:
        run_tool(
            h,
            "payments.transfer",
            {"amount": 25_000, "currency": "INR", "to_account": "A"},
            transfer,
            root,
        )
    assert info.value.rule_id == "transfer-over-limit" and not ran
    args = {"amount": 900, "currency": "INR", "to_account": "A"}
    assert run_tool(h, "payments.transfer", args, transfer, root) == "sent" and ran == [900]
    assert len(ingest.posts("/api/v1/action-decisions")) == 1
    assert (
        run_tool(h, "payments.refund", {"customer_id": "c"}, lambda customer_id: "ok", root) == "ok"
    )
    (hold,) = api.holds.values()
    assert hold["tool"] == "payments.refund" and hold["task_id"]


def test_tool_arguments_are_scrubbed_and_metadata_mode_ships_none(
    start: Callable[..., sibyl.Client], fake_langchain: Any, ingest: Ingest
) -> None:
    start(instrument=["langchain"])
    h = fake_langchain.handler()
    root = chain(h, "graph")
    run_tool(h, "http_get", {"token": SECRET}, lambda token: "fine", root)
    h.on_chain_end({}, run_id=root)
    (tool,) = spans_by_op(ingest, "execute_tool")
    assert (
        SECRET not in tool["gen_ai.tool.call.arguments"]
        and tool["sibyl.redaction.secrets_scrubbed"] >= 1
    )
    sibyl.shutdown(0.2)
    ingest.requests.clear()
    start(instrument=["langchain"], capture_mode="metadata")
    root = chain(h, "graph")
    run_tool(h, "http_get", {"token": SECRET}, lambda token: "fine", root)
    h.on_chain_end({}, run_id=root)
    (tool,) = spans_by_op(ingest, "execute_tool")
    assert "gen_ai.tool.call.arguments" not in tool and len(tool["sibyl.content_hash.args"]) == 64


def test_handler_callbacks_never_raise_on_bad_input(handler: Any) -> None:
    handler.on_chain_end({}, run_id=uuid4())  # unknown run
    handler.on_tool_end("x", run_id=uuid4())
    handler.on_llm_end(object(), run_id=uuid4())
    handler.on_chain_start(None, None, run_id="not-a-uuid", name=None)
    handler.on_tool_start(None, "", run_id=uuid4(), parent_run_id=uuid4())
