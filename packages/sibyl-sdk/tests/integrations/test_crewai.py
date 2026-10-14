"""CrewAI: event-bus listener → run tree (crew → agents → tools, delegation handoffs) and the
Action Gate on `BaseTool.run` / `CrewStructuredTool.invoke` / `ainvoke`."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import pytest
import sibyl
from sibyl.integrations import crewai
from sibyl.testing import Ingest, attrs


def by_op(ingest: Ingest, op: str) -> list[dict[str, Any]]:
    assert sibyl.flush(2)
    return [attrs(s) for s in ingest.spans() if attrs(s).get("gen_ai.operation.name") == op]


class Agent:
    def __init__(self, role: str, ident: str) -> None:
        self.role = role
        self.id = ident


@pytest.fixture
def crew(start: Callable[..., sibyl.Client], fake_crewai: Any) -> Any:
    start(instrument=())
    assert sibyl.instrument(libraries=["crewai"]) == ["crewai"]
    assert sibyl.instrument(libraries=["crewai"]) == ["crewai"]
    assert crewai.listener() is not None
    return fake_crewai


def emit(fake: Any, name: str, source: Any = None, **kwargs: Any) -> None:
    fake.bus.emit(source, getattr(fake.events, name)(**kwargs))


def test_crew_agents_tools_and_delegation_form_a_tree(crew: Any, ingest: Ingest) -> None:
    source = object()
    writer, editor = Agent("Writer", "a1"), Agent("Editor", "a2")
    emit(crew, "CrewKickoffStartedEvent", source, crew_name="content crew")
    emit(crew, "AgentExecutionStartedEvent", agent=writer)
    emit(crew, "ToolUsageStartedEvent", agent=writer, tool_name="search", tool_args={"q": "x"})
    emit(crew, "ToolUsageFinishedEvent", agent=writer, tool_name="search", output="hits")
    emit(
        crew,
        "ToolUsageStartedEvent",
        agent_role="Writer",
        tool_name="Delegate work to coworker",
        tool_args='{"coworker": "Editor", "task": "review"}',
    )
    emit(
        crew,
        "ToolUsageErrorEvent",
        agent_role="Writer",
        tool_name="Delegate work to coworker",
        error="busy",
    )
    emit(crew, "AgentExecutionCompletedEvent", agent=writer)
    emit(crew, "AgentExecutionStartedEvent", agent=editor)
    emit(crew, "AgentExecutionErrorEvent", agent=editor, error="timeout")
    emit(crew, "CrewKickoffFailedEvent", source, error="editor failed")
    runs = {a["gen_ai.agent.name"]: a for a in by_op(ingest, "invoke_agent")}
    root = runs["content crew"]
    assert root["error.type"] == "editor failed"
    assert runs["Writer"]["sibyl.parent_run_id"] == root["sibyl.task_id"]
    assert runs["Writer"]["sibyl.handoff_to_agent"] == "Editor"
    assert runs["Editor"]["sibyl.step_index"] == 1 and runs["Editor"]["error.type"] == "timeout"
    tools = {a["gen_ai.tool.name"]: a for a in by_op(ingest, "execute_tool")}
    assert tools["search"]["sibyl.parent_run_id"] == runs["Writer"]["sibyl.task_id"]
    delegate = tools["Delegate work to coworker"]
    assert delegate["sibyl.handoff_to_agent"] == "Editor" and delegate["error.type"] == "ToolError"
    assert sibyl.current_run() is None


def test_crew_completion_closes_the_root(crew: Any, ingest: Ingest) -> None:
    source = object()
    emit(crew, "CrewKickoffStartedEvent", source, crew_name="c")
    emit(crew, "CrewKickoffCompletedEvent", source)
    emit(crew, "CrewKickoffCompletedEvent", source)  # duplicate end is ignored
    (run,) = by_op(ingest, "invoke_agent")
    assert run["gen_ai.agent.name"] == "c" and "error.type" not in run


def test_tools_are_gated_once_through_every_entry_point(
    crew: Any, monkeypatch: pytest.MonkeyPatch, ingest: Ingest
) -> None:
    monkeypatch.setenv("SIBYL_SENSITIVE_TOOLS", "send_*")
    ran: list[Any] = []
    lookup = crew.base_tool("lookup", lambda **kw: ran.append(kw) or "ok")
    send = crew.base_tool("send_payment", lambda **kw: ran.append(kw) or "sent")
    assert lookup.run(q=1) == "ok"
    assert crew.structured_tool("lookup", lookup).invoke({"q": 2}) == "ok"
    assert asyncio.run(crew.structured_tool("lookup", lookup).ainvoke({"q": 3})) == "ok"
    with pytest.raises(sibyl.SibylActionBlocked):
        send.run(amount=5)
    with pytest.raises(sibyl.SibylActionBlocked):
        crew.structured_tool("send_payment", send).invoke({"amount": 6})
    assert ran == [{"q": 1}, {"q": 2}, {"q": 3}]
    assert sibyl.flush(2)
    blocked = [e for e in ingest.events() if e["type"] == "policy.decision"]
    assert len(blocked) == 2  # structured invoke → BaseTool.run is checked once, not twice


def test_listener_tolerates_unknown_events(crew: Any) -> None:
    emit(crew, "AgentExecutionCompletedEvent", agent=Agent("Ghost", "g"))
    emit(crew, "ToolUsageFinishedEvent", agent_role="Ghost", tool_name="x")
    emit(crew, "CrewKickoffCompletedEvent", object())
