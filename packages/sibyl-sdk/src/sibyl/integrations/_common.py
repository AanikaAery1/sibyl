"""Shared pieces for framework integrations: tool and model spans under a run-tree node.

Framework callbacks never raise into the framework except the Action Gate errors from a
pre-execution check; everything else is logged and swallowed (`safe`).
"""

from __future__ import annotations

import functools
import logging
import threading
from collections.abc import Callable
from typing import Any, Final

from sibyl import _state
from sibyl._extract import Extracted
from sibyl._ids import uuid7
from sibyl._run import AgentRun, tree_attributes
from sibyl._spans import KIND_CLIENT, Span
from sibyl._tool import _annotate

log = logging.getLogger("sibyl")
MAX_AGENT_REF: Final = 256
_active: set[str] = set()
_lock = threading.Lock()


def safe[F: Callable[..., Any]](fn: F) -> F:
    """Swallow and log any exception: telemetry must never break the framework."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except Exception:
            log.debug("sibyl: %s failed", getattr(fn, "__name__", "callback"), exc_info=True)
            return None

    return wrapper  # type: ignore[return-value]


def mark_active(library: str) -> None:
    with _lock:
        _active.add(library)


def is_active(library: str) -> bool:
    return library in _active


def reset_active() -> None:
    """Tests only: forget which libraries were instrumented."""
    with _lock:
        _active.clear()


def agent_ref(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text[:MAX_AGENT_REF] or None


def start_tool_span(
    run: AgentRun | None,
    name: str,
    args: Any,
    *,
    tool_type: str = "function",
    call_id: str | None = None,
    handoff_to: str | None = None,
) -> Span | None:
    client = _state.get()
    if client is None:
        return None
    if run is not None:
        run.tool_calls += 1
    parent = run.span_context if run is not None else None
    span = client.start_span(f"execute_tool {name}", parent=parent)
    span.set_many(
        {
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.tool.name": name[:256] or "tool",
            "gen_ai.tool.type": tool_type,
            "gen_ai.tool.call.id": call_id,
            "sibyl.tool.side_effect_class": "unknown",
            "sibyl.task_id": str(run.task_id) if run else None,
            **tree_attributes(run),
        }
    )
    if handoff_to:
        span.set("sibyl.handoff_to_agent", handoff_to)
    span.add_content("gen_ai.tool.call.arguments", "tool_args", args)
    return span


def end_tool_span(span: Span | None, result: Any = None, error: Any = None) -> None:
    if span is None:
        return
    if error is not None:
        name = type(error).__name__ if isinstance(error, BaseException) else "ToolError"
        span.set_error(name, str(error)[:256])
    elif result is not None:
        span.add_content("gen_ai.tool.call.result", "tool_result", result)
    span.end()


def annotate(span: Span | None, outcome: Any) -> None:
    _annotate(span, outcome)


def model_span(
    run: AgentRun | None,
    *,
    provider: str,
    model: str,
    operation: str = "chat",
    inputs: Any = None,
) -> Span | None:
    """A `gen_ai.*` client span for a model call the framework made through a client Sibyl
    does not wrap (finish it with `end_model_span`)."""
    client = _state.get()
    if client is None:
        return None
    if run is not None:
        run.model_calls += 1
    parent = run.span_context if run is not None else None
    span = client.start_span(f"{operation} {model}", kind=KIND_CLIENT, parent=parent)
    span.set_many(
        {
            "gen_ai.operation.name": operation,
            "gen_ai.provider.name": provider or "unknown",
            "gen_ai.request.model": model or "unknown",
            "sibyl.call_id": str(uuid7()),
            "sibyl.task_id": str(run.task_id) if run else None,
            **tree_attributes(run),
        }
    )
    if inputs is not None:
        span.add_content("gen_ai.input.messages", "input_messages", inputs)
    return span


def end_model_span(span: Span | None, found: Extracted | None, error: Any = None) -> None:
    if span is None:
        return
    if error is not None:
        name = type(error).__name__ if isinstance(error, BaseException) else "ModelError"
        span.set_error(name, str(error)[:256])
    elif found is not None:
        span.set_many(found.span_attributes())
        if found.output is not None:
            span.add_content("gen_ai.output.messages", "output_messages", found.output)
    span.end()
