"""`sibyl.agent()`: the task boundary (an `invoke_agent` span, sync and async).

Enter emits `agent.invoke(phase=start)` on `/v1/events`; exit ends the `invoke_agent` span
in the critical lane with status ok | error | handed_off | cancelled. Nested runs share the
trace and record `parent_task_id`. Exceptions always propagate unchanged.

Run tree (D50, frozen names): every run, model call and tool call records `parent_run_id`
(the task id of the run that directly contains it) and `step_index` (its 0-based order in
that run); a run that hands work to another agent records `handoff_to_agent`. Framework
integrations open and close runs with `open_run()` / `close_run()`, which never use
context-variable tokens (framework callbacks may end a run in another context).
"""

from __future__ import annotations

import itertools
import time
from collections.abc import Mapping
from contextvars import ContextVar, Token
from types import TracebackType
from typing import TYPE_CHECKING, Any, Literal
from uuid import UUID

from sibyl import _state
from sibyl._emit import envelope
from sibyl._ids import new_trace_id, uuid7
from sibyl._spans import KIND_INTERNAL, Span, SpanContext, current_context, use_context
from sibyl._types import Outcome

if TYPE_CHECKING:
    from sibyl_schemas.models import HandoffPacket

    from sibyl._client import Client

_RUN: ContextVar[AgentRun | None] = ContextVar("sibyl_current_run", default=None)
MAX_AGENT_REF = 256


def current_run() -> AgentRun | None:
    return _RUN.get()


def _as_uuid(value: str | UUID | None) -> UUID | None:
    if value is None:
        return None
    return value if isinstance(value, UUID) else UUID(str(value))


class AgentRun:
    def __init__(
        self,
        name: str | None = None,
        *,
        agent_id: str | UUID | None = None,
        task_id: str | UUID | None = None,
        goal: str | None = None,
        conversation_id: str | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> None:
        client = _state.get()
        self._client = client
        self.name = name or (client.agent_name() if client else "agent")
        explicit = _as_uuid(agent_id) if agent_id and _looks_uuid(agent_id) else None
        self.agent_id: UUID | None = explicit or (client.agent_id if client else None)
        self.task_id: UUID = _as_uuid(task_id) or uuid7()
        self.parent_task_id: UUID | None = None
        self.step_index: int | None = None
        self.handoff_to_agent: str | None = None
        self._step_seq = itertools.count()
        self.goal = goal
        self.conversation_id = conversation_id
        self.attributes = dict(attributes or {})
        self.trace_id = ""
        self.steps = 0
        self.tool_calls = 0
        self.model_calls = 0
        self.cost_usd = 0.0
        self.started_at = time.time()
        self.latest_checkpoint: dict[str, Any] | None = None
        self.checkpoint_seq = 0
        self._status: str | None = None
        self._span: Span | None = None
        self._tokens: tuple[Token[AgentRun | None], Any] | None = None
        self._ctx_manager: Any = None

    # ------------------------------------------------------------------ context

    def _open(self, parent: AgentRun | None, ctx: SpanContext | None) -> SpanContext:
        """Start the span and emit `agent.invoke(phase=start)`; no context variables."""
        if parent is not None:
            self.parent_task_id = parent.task_id
            if self.step_index is None:
                self.step_index = parent.next_step()
        client = self._client
        if client is not None:
            self._span = client.start_span(
                f"invoke_agent {self.name}", kind=KIND_INTERNAL, critical=True, parent=ctx
            )
            span_ctx = self._span.context
        else:
            span_ctx = SpanContext(ctx.trace_id if ctx else new_trace_id(), "0" * 16)
        self.trace_id = span_ctx.trace_id
        self._emit_start()
        return span_ctx

    def _close(self, status: str | None, error_type: str | None, message: str | None) -> None:
        final = self._status or status or ("error" if error_type else "ok")
        span = self._span
        if span is not None:
            span.set_many(self._span_attributes(final))
            if error_type is not None:
                span.set_error(error_type, message)
            span.end()

    def __enter__(self) -> AgentRun:
        span_ctx = self._open(_RUN.get(), current_context())
        self._ctx_manager = use_context(span_ctx)
        self._ctx_manager.__enter__()
        self._tokens = (_RUN.set(self), None)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        self._close(
            None,
            exc_type.__name__ if exc_type is not None else None,
            str(exc) if exc else None,
        )
        if self._tokens is not None:
            _RUN.reset(self._tokens[0])
        if self._ctx_manager is not None:
            self._ctx_manager.__exit__(exc_type, exc, tb)
        return False

    async def __aenter__(self) -> AgentRun:
        return self.__enter__()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        return self.__exit__(exc_type, exc, tb)

    def _span_attributes(self, status: str) -> dict[str, Any]:
        attrs: dict[str, Any] = {
            "gen_ai.operation.name": "invoke_agent",
            "gen_ai.agent.name": self.name,
            "sibyl.task_id": str(self.task_id),
            "sibyl.invoke.status": status,
            "sibyl.invoke.steps": self.steps,
            "sibyl.invoke.tool_calls": self.tool_calls,
            "sibyl.invoke.model_calls": self.model_calls,
        }
        if self.agent_id:
            attrs["gen_ai.agent.id"] = str(self.agent_id)
        if self.parent_task_id:
            attrs["sibyl.parent_task_id"] = str(self.parent_task_id)
            attrs["sibyl.parent_run_id"] = str(self.parent_task_id)
        if self.step_index is not None:
            attrs["sibyl.step_index"] = self.step_index
        if self.handoff_to_agent:
            attrs["sibyl.handoff_to_agent"] = self.handoff_to_agent
        if self.conversation_id:
            attrs["gen_ai.conversation.id"] = self.conversation_id
        for key, value in self.attributes.items():
            if isinstance(value, (str, bool, int, float)):
                attrs[f"app.{key}" if not key.startswith(("app.", "sibyl.")) else key] = value
        return attrs

    def _emit_start(self) -> None:
        client = self._client
        if client is None:
            return
        attrs: dict[str, Any] = {"phase": "start", "agent_name": self.name[:256]}
        if self.parent_task_id:
            attrs["parent_task_id"] = str(self.parent_task_id)
            attrs["parent_run_id"] = str(self.parent_task_id)
        if self.step_index is not None:
            attrs["step_index"] = self.step_index
        span = self._span
        client.emit_event(
            envelope(
                client,
                "agent.invoke",
                attrs,
                task_id=str(self.task_id),
                trace_id=self.trace_id,
                span_id=span.span_id if span else None,
            )
        )

    # ------------------------------------------------------------------ API

    @property
    def client(self) -> Client | None:
        return self._client

    @property
    def span_id(self) -> str | None:
        return self._span.span_id if self._span else None

    @property
    def span_context(self) -> SpanContext | None:
        return self._span.context if self._span else None

    def next_step(self) -> int:
        """The next 0-based `step_index` inside this run (thread-safe under the GIL)."""
        return next(self._step_seq)

    def handoff_to(self, agent: str | UUID) -> None:
        """Record an agent-to-agent handoff (`handoff_to_agent`); the run itself ends normally.
        For a handoff to a person use `handoff(packet)`."""
        ref = str(agent).strip()[:MAX_AGENT_REF]
        if ref:
            self.handoff_to_agent = ref

    def set_goal(self, goal: str) -> None:
        self.goal = goal

    def outcome(
        self, outcome: Outcome, *, reason: str | None = None, rework: bool | None = None
    ) -> None:
        from sibyl._labels import emit_outcome

        emit_outcome(self, outcome, reason=reason, rework=rework)

    def handoff(self, packet: HandoffPacket) -> UUID:
        from sibyl._handoff import request

        packet_id = request(packet, run=self)
        self._status = "handed_off"
        return packet_id

    def cancel(self, reason: str | None = None) -> None:
        self._status = "cancelled"
        if self._span is not None and reason:
            self._span.set("sibyl.invoke.cancel_reason", reason[:200])


def _looks_uuid(value: str | UUID) -> bool:
    if isinstance(value, UUID):
        return True
    try:
        UUID(value)
    except ValueError:
        return False
    return True


def agent(
    name: str | None = None,
    *,
    agent_id: str | UUID | None = None,
    task_id: str | UUID | None = None,
    goal: str | None = None,
    conversation_id: str | None = None,
    attributes: Mapping[str, Any] | None = None,
) -> AgentRun:
    """Open a task boundary: `with sibyl.agent(goal=...) as run:` (or `async with`)."""
    return AgentRun(
        name,
        agent_id=agent_id,
        task_id=task_id,
        goal=goal,
        conversation_id=conversation_id,
        attributes=attributes,
    )


def tree_attributes(run: AgentRun | None) -> dict[str, Any]:
    """`sibyl.parent_run_id` + `sibyl.step_index` for a call made directly inside `run`."""
    if run is None:
        return {}
    return {"sibyl.parent_run_id": str(run.task_id), "sibyl.step_index": run.next_step()}


def open_run(
    name: str,
    *,
    parent: AgentRun | None,
    step_index: int | None = None,
    attributes: Mapping[str, Any] | None = None,
) -> AgentRun:
    """Framework integrations: start a run under `parent` (or the current run) without
    touching context variables. Pair with `close_run()`; use `activate()` to make calls made
    inside the framework's step nest under it."""
    run = AgentRun(name, attributes=attributes)
    if step_index is not None:
        run.step_index = max(0, int(step_index))
    effective = parent if parent is not None else _RUN.get()
    parent_ctx = effective.span_context if effective is not None else current_context()
    run._open(effective, parent_ctx)
    return run


def close_run(
    run: AgentRun,
    *,
    status: str | None = None,
    error: BaseException | str | None = None,
) -> None:
    if isinstance(error, BaseException):
        run._close(status, type(error).__name__, str(error)[:256])
    elif error:
        run._close(status, str(error)[:120], None)
    else:
        run._close(status, None, None)


def activate(run: AgentRun | None) -> None:
    """Make `run` the current run (and its span the current span) in this context, without a
    reset token: callers restore the previous run by activating it again."""
    _RUN.set(run)
    from sibyl._spans import _CURRENT

    _CURRENT.set(run.span_context if run is not None else None)
