"""`@sibyl.tool`: wraps sync, async and generator callables in an `execute_tool` span.

Exceptions propagate unchanged. Arguments and results are captured as deferred content
(scrubbed on the exporter thread) unless capture is off or the mode is `metadata`.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any, overload

from sibyl import _state
from sibyl._actions import Mode, Verdict
from sibyl._errors import SibylActionBlocked, SibylError
from sibyl._run import current_run, tree_attributes
from sibyl._spans import Span, use_context
from sibyl._types import SideEffectClass, ToolType


class _ToolSpec:
    def __init__(
        self,
        fn: Callable[..., Any],
        *,
        name: str | None,
        tool_type: ToolType,
        side_effect: SideEffectClass,
        capture_args: bool | None,
        capture_result: bool | None,
        mcp_server: str | None,
        sensitive: bool = False,
        mode: Mode = "wait",
    ) -> None:
        if mode not in ("wait", "async"):
            raise ValueError("mode must be 'wait' or 'async'")
        self.fn = fn
        self.sensitive = sensitive
        self.mode: Mode = mode
        self.name: str = str(name or getattr(fn, "__name__", "tool"))
        self.tool_type = tool_type
        self.side_effect = side_effect
        self.capture_args = capture_args
        self.capture_result = capture_result
        self.mcp_server = mcp_server
        try:
            self.signature: inspect.Signature | None = inspect.signature(fn)
        except (TypeError, ValueError):
            self.signature = None

    def start(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Span | None:
        client = _state.get()
        if client is None:
            return None
        run = current_run()
        if run is not None:
            run.tool_calls += 1
        span = client.start_span(f"execute_tool {self.name}")
        span.set_many(
            {
                "gen_ai.operation.name": "execute_tool",
                "gen_ai.tool.name": self.name,
                "gen_ai.tool.type": self.tool_type,
                "sibyl.tool.side_effect_class": self.side_effect,
                "sibyl.mcp.server": self.mcp_server,
                "sibyl.task_id": str(run.task_id) if run else None,
                **tree_attributes(run),
            }
        )
        if self.capture_args is not False:
            span.add_content("gen_ai.tool.call.arguments", "tool_args", self._bound(args, kwargs))
        return span

    def gate(self, args: tuple[Any, ...], kwargs: dict[str, Any], span: Span | None) -> None:
        """Action Gate before the function runs; raises `SibylActionBlocked` /
        `SibylActionHeld` / `SibylActionDenied` (the function then never runs)."""
        client = _state.get()
        if client is None:
            if self.sensitive:
                raise SibylActionBlocked(
                    self.name, "sibyl:uninitialized", "Sibyl has not been initialized"
                )
            return
        run = current_run()
        try:
            verdict = client.actions.check(
                self.name,
                self._bound(args, kwargs),
                sensitive=self.sensitive,
                mode=self.mode,
                task_id=str(run.task_id) if run else None,
            )
        except SibylError as exc:
            _annotate(span, exc)
            raise
        _annotate(span, verdict)

    async def agate(self, args: tuple[Any, ...], kwargs: dict[str, Any], span: Span | None) -> None:
        client = _state.get()
        if client is None:
            if self.sensitive:
                raise SibylActionBlocked(
                    self.name, "sibyl:uninitialized", "Sibyl has not been initialized"
                )
            return
        run = current_run()
        try:
            verdict = await client.actions.acheck(
                self.name,
                self._bound(args, kwargs),
                sensitive=self.sensitive,
                mode=self.mode,
                task_id=str(run.task_id) if run else None,
            )
        except SibylError as exc:
            _annotate(span, exc)
            raise
        _annotate(span, verdict)

    def _bound(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        if self.signature is None:
            return {"args": list(args), "kwargs": kwargs}
        try:
            bound = self.signature.bind_partial(*args, **kwargs)
        except TypeError:
            return {"args": list(args), "kwargs": kwargs}
        return dict(bound.arguments)

    def finish(
        self,
        span: Span | None,
        result: Any = None,
        exc: BaseException | None = None,
        *,
        has_result: bool = True,
    ) -> None:
        if span is None:
            return
        if exc is not None:
            span.set_error(type(exc).__name__, str(exc))
        elif has_result and self.capture_result is not False:
            span.add_content("gen_ai.tool.call.result", "tool_result", result)
        span.end()


def _wrap(spec: _ToolSpec) -> Callable[..., Any]:
    fn = spec.fn
    if inspect.isasyncgenfunction(fn):

        @functools.wraps(fn)
        async def agen_wrapper(*args: Any, **kwargs: Any) -> AsyncIterator[Any]:
            span = spec.start(args, kwargs)
            try:
                await spec.agate(args, kwargs, span)
                async for item in fn(*args, **kwargs):
                    yield item
            except BaseException as exc:
                spec.finish(span, exc=exc)
                raise
            spec.finish(span, has_result=False)

        return agen_wrapper
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            span = spec.start(args, kwargs)
            try:
                await spec.agate(args, kwargs, span)
                with _maybe_ctx(span):
                    result = await fn(*args, **kwargs)
            except BaseException as exc:
                spec.finish(span, exc=exc)
                raise
            spec.finish(span, result)
            return result

        return async_wrapper
    if inspect.isgeneratorfunction(fn):

        @functools.wraps(fn)
        def gen_wrapper(*args: Any, **kwargs: Any) -> Iterator[Any]:
            span = spec.start(args, kwargs)
            try:
                spec.gate(args, kwargs, span)
                yield from fn(*args, **kwargs)
            except BaseException as exc:
                spec.finish(span, exc=exc)
                raise
            spec.finish(span, has_result=False)

        return gen_wrapper

    @functools.wraps(fn)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        span = spec.start(args, kwargs)
        try:
            spec.gate(args, kwargs, span)
            with _maybe_ctx(span):
                result = fn(*args, **kwargs)
        except BaseException as exc:
            spec.finish(span, exc=exc)
            raise
        spec.finish(span, result)
        return result

    return sync_wrapper


def _annotate(span: Span | None, outcome: Verdict | SibylError) -> None:
    if span is None:
        return
    if isinstance(outcome, Verdict):
        if outcome.decision.rule_id is None and outcome.held_action_id is None:
            return
        span.set("sibyl.action.effect", "approved" if outcome.held_action_id else "allow")
        span.set("sibyl.action.rule_id", outcome.decision.rule_id)
        span.set("sibyl.action.held_action_id", outcome.held_action_id)
        return
    effect = {
        "SibylActionBlocked": "block",
        "SibylActionHeld": "held",
        "SibylActionDenied": "denied",
    }.get(type(outcome).__name__)
    if effect is not None:
        span.set("sibyl.action.effect", effect)
        span.set("sibyl.action.rule_id", getattr(outcome, "rule_id", None))
        span.set("sibyl.action.held_action_id", getattr(outcome, "held_action_id", None))


class _NullCtx:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: object) -> None:
        return None


def _maybe_ctx(span: Span | None) -> Any:
    return use_context(span.context) if span is not None else _NullCtx()


@overload
def tool[**P, R](fn: Callable[P, R], /) -> Callable[P, R]: ...
@overload
def tool[**P, R](
    *,
    name: str | None = None,
    tool_type: ToolType = "function",
    side_effect: SideEffectClass = "unknown",
    capture_args: bool | None = None,
    capture_result: bool | None = None,
    mcp_server: str | None = None,
    sensitive: bool = False,
    mode: Mode = "wait",
) -> Callable[[Callable[P, R]], Callable[P, R]]: ...
def tool(
    fn: Callable[..., Any] | None = None,
    /,
    *,
    name: str | None = None,
    tool_type: ToolType = "function",
    side_effect: SideEffectClass = "unknown",
    capture_args: bool | None = None,
    capture_result: bool | None = None,
    mcp_server: str | None = None,
    sensitive: bool = False,
    mode: Mode = "wait",
) -> Any:
    """`sensitive=True` fails closed without a fresh policy snapshot; `mode="async"` raises
    `SibylActionHeld` for an escalated call instead of waiting for the decision."""

    def decorate(target: Callable[..., Any]) -> Callable[..., Any]:
        spec = _ToolSpec(
            target,
            name=name,
            tool_type=tool_type,
            side_effect=side_effect,
            capture_args=capture_args,
            capture_result=capture_result,
            mcp_server=mcp_server,
            sensitive=sensitive,
            mode=mode,
        )
        return _wrap(spec)

    return decorate(fn) if fn is not None else decorate
