"""CrewAI: an event-bus listener (crew → agents → tools) plus a tool gate.

Run-tree mapping: a crew kickoff is the root run (crew name); each agent execution is a
child run named by the agent's role; tool usages are `execute_tool` spans under the agent's
run. CrewAI's delegation tools ("Delegate work to coworker", "Ask question to coworker")
record `handoff_to_agent` = the coworker. Model calls are captured by the instrumented
OpenAI/Anthropic/Google clients (CrewAI calls them through LiteLLM's SDK clients when the
provider SDK is used) and nest under the active agent run.

Action Gate: CrewAI's event handlers cannot stop a tool, so `install()` wraps
`BaseTool.run` and `CrewStructuredTool.invoke` / `ainvoke`: the pre-execution check runs
first and a blocked, denied or held call raises before the tool's code (CrewAI reports
the error to the agent; the tool never ran).
"""

from __future__ import annotations

import functools
import importlib
import threading
from typing import Any, Final

from sibyl import _gate
from sibyl._extract import get, plain
from sibyl._run import AgentRun, activate, close_run, current_run, open_run
from sibyl._spans import Span
from sibyl.integrations._common import agent_ref, end_tool_span, safe, start_tool_span

GATED: Final = "__sibyl_gated__"
DELEGATION_TOOLS: Final = frozenset({"delegate work to coworker", "ask question to coworker"})
EVENT_MODULES: Final = ("crewai.events", "crewai.utilities.events")
_install_lock = threading.Lock()
_installed: dict[str, Any] = {}


class SibylCrewListener:
    """Keeps the crew/agent/tool tree; handlers are `(source, event)` bus callbacks."""

    def __init__(self) -> None:
        self._crews: dict[int, tuple[AgentRun, AgentRun | None]] = {}
        self._agents: dict[str, tuple[AgentRun, AgentRun | None]] = {}
        self._tools: dict[str, list[Span | None]] = {}
        self._lock = threading.Lock()
        self._crew_stack: list[AgentRun] = []

    @staticmethod
    def _agent_key(event: Any) -> str:
        agent = get(event, "agent")
        role = get(agent, "role") or get(event, "agent_role") or "agent"
        ident = get(agent, "id") or get(event, "agent_id")
        return f"{role}:{ident}" if ident else str(role)

    def _crew_run(self) -> AgentRun | None:
        with self._lock:
            return self._crew_stack[-1] if self._crew_stack else None

    @safe
    def crew_started(self, source: Any, event: Any) -> None:
        name = str(get(event, "crew_name") or get(source, "name") or "crew")
        run = open_run(name, parent=current_run())
        with self._lock:
            self._crews[id(source)] = (run, current_run())
            self._crew_stack.append(run)
        activate(run)

    def _crew_end(self, source: Any, error: Any) -> None:
        with self._lock:
            entry = self._crews.pop(id(source), None)
            if entry is not None and entry[0] in self._crew_stack:
                self._crew_stack.remove(entry[0])
        if entry is not None:
            close_run(entry[0], error=error)
            activate(entry[1])

    @safe
    def crew_completed(self, source: Any, event: Any) -> None:
        self._crew_end(source, None)

    @safe
    def crew_failed(self, source: Any, event: Any) -> None:
        self._crew_end(source, str(get(event, "error") or "crew failed"))

    @safe
    def agent_started(self, source: Any, event: Any) -> None:
        role = str(get(event, "agent", "role") or get(event, "agent_role") or "agent")
        parent = self._crew_run() or current_run()
        run = open_run(role, parent=parent)
        with self._lock:
            self._agents[self._agent_key(event)] = (run, current_run())
        activate(run)

    def _agent_end(self, event: Any, error: Any) -> None:
        with self._lock:
            entry = self._agents.pop(self._agent_key(event), None)
        if entry is not None:
            close_run(entry[0], error=error)
            activate(entry[1])

    @safe
    def agent_completed(self, source: Any, event: Any) -> None:
        self._agent_end(event, None)

    @safe
    def agent_failed(self, source: Any, event: Any) -> None:
        self._agent_end(event, str(get(event, "error") or "agent failed"))

    def _agent_run(self, event: Any) -> AgentRun | None:
        key = self._agent_key(event)
        with self._lock:
            entry = self._agents.get(key)
            if entry is None:  # tool events may carry only the role
                role = str(get(event, "agent_role") or "")
                entry = next((v for k, v in self._agents.items() if k.split(":")[0] == role), None)
        return entry[0] if entry is not None else current_run()

    @safe
    def tool_started(self, source: Any, event: Any) -> None:
        name = str(get(event, "tool_name") or "tool")
        args = get(event, "tool_args")
        run = self._agent_run(event)
        handoff = None
        if name.strip().lower() in DELEGATION_TOOLS:
            handoff = agent_ref(get(_gate.tool_args(args), "coworker"))
            if handoff and run is not None and name.lower().startswith("delegate"):
                run.handoff_to(handoff)
        span = start_tool_span(run, name, plain(args), handoff_to=handoff)
        with self._lock:
            self._tools.setdefault(f"{self._agent_key(event)}|{name}", []).append(span)

    def _tool_end(self, event: Any, result: Any, error: Any) -> None:
        key = f"{self._agent_key(event)}|{get(event, 'tool_name') or 'tool'}"
        with self._lock:
            stack = self._tools.get(key) or []
            span = stack.pop() if stack else None
        end_tool_span(span, result=result, error=error)

    @safe
    def tool_finished(self, source: Any, event: Any) -> None:
        self._tool_end(event, plain(get(event, "output")), None)

    @safe
    def tool_failed(self, source: Any, event: Any) -> None:
        self._tool_end(event, None, str(get(event, "error") or "tool failed"))


_HANDLERS: Final = {
    "CrewKickoffStartedEvent": "crew_started",
    "CrewKickoffCompletedEvent": "crew_completed",
    "CrewKickoffFailedEvent": "crew_failed",
    "AgentExecutionStartedEvent": "agent_started",
    "AgentExecutionCompletedEvent": "agent_completed",
    "AgentExecutionErrorEvent": "agent_failed",
    "ToolUsageStartedEvent": "tool_started",
    "ToolUsageFinishedEvent": "tool_finished",
    "ToolUsageErrorEvent": "tool_failed",
}


def _events_module() -> Any:
    for name in EVENT_MODULES:
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        if getattr(module, "crewai_event_bus", None) is not None:
            return module
    raise ImportError("no CrewAI event bus found")


def _register(listener: SibylCrewListener) -> None:
    module = _events_module()
    bus = module.crewai_event_bus
    for event_name, method in _HANDLERS.items():
        event_cls = getattr(module, event_name, None)
        if event_cls is not None:
            bus.on(event_cls)(getattr(listener, method))


# ---------------------------------------------------------------------- Action Gate


def _tool_name(tool: Any) -> str:
    return str(getattr(tool, "name", None) or type(tool).__name__)


def _wrap_sync(original: Any, arg_reader: Any) -> Any:
    @functools.wraps(original)
    def gated(self: Any, *args: Any, **kwargs: Any) -> Any:
        return _gate.run_gated(
            _tool_name(self), arg_reader(args, kwargs), original, self, *args, **kwargs
        )

    setattr(gated, GATED, True)
    return gated


def _wrap_async(original: Any, arg_reader: Any) -> Any:
    @functools.wraps(original)
    async def gated(self: Any, *args: Any, **kwargs: Any) -> Any:
        return await _gate.arun_gated(
            _tool_name(self), arg_reader(args, kwargs), original, self, *args, **kwargs
        )

    setattr(gated, GATED, True)
    return gated


def _run_args(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    return kwargs if kwargs or not args else {"args": list(args)}


def _invoke_args(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    value = kwargs.get("input", args[0] if args else None)
    return plain(value) if value is not None else {}


def _patch(module_name: str, class_name: str, method: str, reader: Any, *, is_async: bool) -> None:
    try:
        module = importlib.import_module(module_name)
    except ImportError:
        return
    cls = getattr(module, class_name, None)
    original = getattr(cls, method, None) if cls is not None else None
    if original is None or getattr(original, GATED, False):
        return
    wrapper = _wrap_async(original, reader) if is_async else _wrap_sync(original, reader)
    setattr(cls, method, wrapper)


def install() -> bool:
    with _install_lock:
        if "listener" in _installed:
            return True
        listener = SibylCrewListener()
        _register(listener)
        _patch("crewai.tools.base_tool", "BaseTool", "run", _run_args, is_async=False)
        _patch(
            "crewai.tools.structured_tool",
            "CrewStructuredTool",
            "invoke",
            _invoke_args,
            is_async=False,
        )
        _patch(
            "crewai.tools.structured_tool",
            "CrewStructuredTool",
            "ainvoke",
            _invoke_args,
            is_async=True,
        )
        _installed["listener"] = listener
    return True


def listener() -> SibylCrewListener | None:
    return _installed.get("listener")
