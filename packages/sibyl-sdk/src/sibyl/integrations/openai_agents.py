"""OpenAI Agents SDK: a tracing processor (`agents.add_trace_processor`) plus a tool gate.

Run-tree mapping: a trace is the root run (workflow name); an `agent` span is a child run;
a `function` span is an `execute_tool` span; a `handoff` span records `handoff_to_agent` on
the run that handed off; `generation` / `response` spans become `gen_ai` spans only when the
OpenAI client is not instrumented (otherwise the client wrapper already captured the call,
nested under the agent's run).

Action Gate: tracing processors cannot stop a tool, so `install()` also wraps every
`FunctionTool` created afterwards: its `on_invoke_tool` runs the pre-execution check first
(a blocked, denied or held call raises; the tool never runs). Call `sibyl.instrument()`
before defining tools, or gate an existing one with `gate_tool(tool)`.
"""

from __future__ import annotations

import functools
import importlib
import threading
from dataclasses import dataclass
from typing import Any, Final

from sibyl import _gate
from sibyl._extract import Extracted, extract, get, plain
from sibyl._run import AgentRun, activate, close_run, current_run, open_run
from sibyl._spans import Span
from sibyl.integrations._common import (
    agent_ref,
    end_model_span,
    end_tool_span,
    is_active,
    model_span,
    safe,
    start_tool_span,
)

GATED: Final = "__sibyl_gated__"
_install_lock = threading.Lock()
_installed: dict[str, Any] = {}


@dataclass
class _Node:
    kind: str  # run | tool | model | handoff | skip
    run: AgentRun | None
    span: Span | None = None
    previous: AgentRun | None = None


def _error(span: Any) -> str | None:
    error = get(span, "error")
    if not error:
        return None
    message = get(error, "message")
    return str(message or error)[:256]


class SibylTracingProcessor:
    """Implements the `agents.tracing.TracingProcessor` interface."""

    def __init__(self) -> None:
        self._nodes: dict[str, _Node] = {}
        self._lock = threading.Lock()

    def _get(self, key: Any) -> _Node | None:
        with self._lock:
            return self._nodes.get(str(key)) if key else None

    def _put(self, key: Any, node: _Node) -> None:
        with self._lock:
            self._nodes[str(key)] = node

    def _pop(self, key: Any) -> _Node | None:
        with self._lock:
            return self._nodes.pop(str(key), None)

    def _parent_run(self, span: Any) -> AgentRun | None:
        node = self._get(get(span, "parent_id")) or self._get(get(span, "trace_id"))
        return node.run if node is not None else current_run()

    # ------------------------------------------------------------------ traces

    @safe
    def on_trace_start(self, trace: Any) -> None:
        name = str(get(trace, "name") or "agent workflow")
        run = open_run(name, parent=current_run())
        self._put(get(trace, "trace_id"), _Node("run", run, previous=current_run()))
        activate(run)

    @safe
    def on_trace_end(self, trace: Any) -> None:
        node = self._pop(get(trace, "trace_id"))
        if node is not None and node.run is not None:
            close_run(node.run)
            activate(node.previous)

    # ------------------------------------------------------------------ spans

    @safe
    def on_span_start(self, span: Any) -> None:
        data = get(span, "span_data")
        kind = get(data, "type")
        parent = self._parent_run(span)
        key = get(span, "span_id")
        if kind == "agent":
            run = open_run(str(get(data, "name") or "agent"), parent=parent)
            self._put(key, _Node("run", run, previous=current_run()))
            activate(run)
        elif kind == "function":
            name = str(get(data, "name") or "tool")
            tool = start_tool_span(parent, name, plain(get(data, "input")))
            self._put(key, _Node("tool", parent, tool))
        elif kind == "handoff":
            self._put(key, _Node("handoff", parent))
        elif kind in ("generation", "response") and not is_active("openai"):
            model = str(get(data, "model") or get(data, "response", "model") or "unknown")
            span_ = model_span(
                parent, provider="openai", model=model, inputs=plain(get(data, "input"))
            )
            self._put(key, _Node("model", parent, span_))

    @safe
    def on_span_end(self, span: Any) -> None:
        node = self._pop(get(span, "span_id"))
        if node is None:
            return
        data = get(span, "span_data")
        error = _error(span)
        if node.kind == "run" and node.run is not None:
            close_run(node.run, error=error)
            activate(node.previous)
        elif node.kind == "tool":
            end_tool_span(node.span, result=plain(get(data, "output")), error=error)
        elif node.kind == "handoff":
            target = agent_ref(get(data, "to_agent"))
            if target and node.run is not None:
                node.run.handoff_to(target)
        elif node.kind == "model":
            end_model_span(node.span, _model_result(data), error=error)

    def shutdown(self) -> None:
        from sibyl import flush

        flush(2.0)

    def force_flush(self) -> None:
        from sibyl import flush

        flush(2.0)


def _model_result(data: Any) -> Extracted:
    response = get(data, "response")
    if response is not None:
        return extract("openai.responses", response)
    out = Extracted(response_model=get(data, "model"))
    usage = get(data, "usage") or {}
    out.input_tokens = get(usage, "input_tokens") or get(usage, "prompt_tokens")
    out.output_tokens = get(usage, "output_tokens") or get(usage, "completion_tokens")
    output = plain(get(data, "output"))
    out.output = output if isinstance(output, list) else None
    return out


# ---------------------------------------------------------------------- Action Gate


def gate_tool(tool: Any) -> Any:
    """Wrap one `FunctionTool`'s `on_invoke_tool` with the Action Gate (idempotent)."""
    invoke = getattr(tool, "on_invoke_tool", None)
    if invoke is None or getattr(invoke, GATED, False):
        return tool
    name = str(getattr(tool, "name", "tool"))

    @functools.wraps(invoke)
    async def gated(ctx: Any, input: Any) -> Any:
        call_id = get(ctx, "tool_call_id")
        return await _gate.arun_gated(name, input, invoke, ctx, input, call_id=call_id)

    setattr(gated, GATED, True)
    object.__setattr__(tool, "on_invoke_tool", gated)
    return tool


def _patch_function_tool(cls: Any) -> None:
    original = cls.__init__
    if getattr(original, GATED, False):
        return

    @functools.wraps(original)
    def init(self: Any, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        gate_tool(self)

    setattr(init, GATED, True)
    cls.__init__ = init


def install() -> bool:
    """Register the processor and gate `FunctionTool` (idempotent)."""
    with _install_lock:
        if "processor" in _installed:
            return True
        import agents

        processor = SibylTracingProcessor()
        add: Any = getattr(agents, "add_trace_processor", None)
        if add is None:
            add = importlib.import_module("agents.tracing").add_trace_processor
        add(processor)
        tool_cls = getattr(agents, "FunctionTool", None)
        if tool_cls is not None:
            _patch_function_tool(tool_cls)
        _installed["processor"] = processor
    return True


def processor() -> SibylTracingProcessor | None:
    return _installed.get("processor")
