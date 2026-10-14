"""Sibyl Python SDK (Apache-2.0): agent telemetry, checkpoints, handoffs and the kill switch.

    import sibyl
    sibyl.instrument()        # one line: SIBYL_* env, auto-detect clients + frameworks
    # or, with explicit configuration:
    sibyl.init(agent_id="quote-assistant")           # SIBYL_API_KEY, SIBYL_ENDPOINT
    with sibyl.agent(goal="Quote order A-1") as run:
        ...
        run.outcome("success")

Zero code: `sibyl-run app.py [args]` (or `python -m sibyl.run app.py`).

The SDK never raises into application code except `SibylKilled`, `SibylPolicyUnavailable`
(fail-closed agents only), `SibylConfigError` from `init()`, and the Action Gate's
`SibylActionBlocked` / `SibylActionHeld` / `SibylActionDenied` from a gated tool call.
It does not route: inline fallback is the gateway's job. Public surface: API.md §8.2.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import timedelta
from typing import Any, Literal, overload
from uuid import UUID

import httpx

from sibyl import _gate, _state
from sibyl._actions import ActionConfig, Mode, Verdict
from sibyl._client import Client
from sibyl._config import ExporterConfig, PolicyConfig, resolve
from sibyl._errors import (
    SibylActionBlocked,
    SibylActionDenied,
    SibylActionHeld,
    SibylConfigError,
    SibylError,
    SibylKilled,
    SibylPolicyUnavailable,
)
from sibyl._exporter import ExporterStats
from sibyl._handoff import checkpoint, handoff
from sibyl._instrument import instrument_client
from sibyl._labels import feedback, outcome
from sibyl._obo import on_behalf_of
from sibyl._run import AgentRun, agent, current_run
from sibyl._scrub import ScrubContext, ScrubHook
from sibyl._snapshot import PolicySnapshot
from sibyl._tool import tool
from sibyl._types import (
    CaptureMode,
    FailMode,
    FailureMode,
    Outcome,
    RoutingState,
    SideEffect,
    SideEffectClass,
    Step,
    ToolType,
)
from sibyl._version import __version__

__all__ = [
    "ActionConfig",
    "AgentRun",
    "CaptureMode",
    "Client",
    "ExporterConfig",
    "ExporterStats",
    "FailMode",
    "FailureMode",
    "Outcome",
    "PolicyConfig",
    "PolicySnapshot",
    "RoutingState",
    "ScrubContext",
    "ScrubHook",
    "SibylActionBlocked",
    "SibylActionDenied",
    "SibylActionHeld",
    "SibylConfigError",
    "SibylError",
    "SibylKilled",
    "SibylPolicyUnavailable",
    "SideEffect",
    "SideEffectClass",
    "Step",
    "ToolType",
    "__version__",
    "acheck_action",
    "agent",
    "check_action",
    "checkpoint",
    "current_run",
    "feedback",
    "flush",
    "get_client",
    "handoff",
    "init",
    "instrument",
    "on_behalf_of",
    "outcome",
    "policy",
    "shutdown",
    "tool",
]


def init(
    api_key: str | None = None,
    *,
    endpoint: str | None = None,
    agent_id: str | UUID | None = None,
    capture_mode: CaptureMode | None = None,
    env: Literal["live", "test"] | None = None,
    instrument: Sequence[str] | Literal["auto"] = "auto",
    scrub: ScrubHook | Sequence[ScrubHook] | None = None,
    exporter: ExporterConfig | None = None,
    policy: PolicyConfig | None = None,
    resource_attributes: Mapping[str, str] | None = None,
    tracer_provider: Any | None = None,
    fail_mode: FailMode | None = None,
    transport: httpx.BaseTransport | None = None,
    actions: ActionConfig | None = None,
) -> Client:
    """Configure the process-wide client. Re-calling `init()` replaces the previous client.

    `capture_mode` defaults to `SIBYL_CAPTURE_MODE` or `full` (D12; the registry may only
    tighten it). `fail_mode` is a local-dev override used until a snapshot arrives; the
    registry wins. `transport` is for tests (an `httpx.MockTransport`).
    """
    if tracer_provider is not None:
        _state.warn_once("tracer_provider", "tracer_provider is not supported yet; ignored")
    settings = resolve(
        api_key=api_key,
        endpoint=endpoint,
        agent_id=str(agent_id) if agent_id is not None else None,
        capture_mode=capture_mode,
        env=env,
        fail_mode=fail_mode,
        instrument=instrument,
        exporter=exporter,
        policy=policy,
        resource_attributes=resource_attributes,
    )
    hooks: Sequence[ScrubHook] = (
        () if scrub is None else (scrub,) if callable(scrub) else tuple(scrub)
    )
    client = Client(settings, hooks=hooks, transport=transport, actions=actions)
    previous = _state.set_client(client)
    if previous is not None:
        previous.shutdown(timedelta(seconds=0.5))
    from sibyl.integrations import instrument_libraries

    instrument_libraries(settings.instrument)
    return client


@overload
def instrument(
    client: None = None,
    *,
    capture_mode: CaptureMode | None = None,
    libraries: Sequence[str] | Literal["auto"] = "auto",
    sensitive_tools: Iterable[str] | None = None,
) -> list[str]: ...
@overload
def instrument[C](
    client: C,
    *,
    capture_mode: CaptureMode | None = None,
    libraries: Sequence[str] | Literal["auto"] = "auto",
    sensitive_tools: Iterable[str] | None = None,
) -> C: ...
def instrument(
    client: Any = None,
    *,
    capture_mode: CaptureMode | None = None,
    libraries: Sequence[str] | Literal["auto"] = "auto",
    sensitive_tools: Iterable[str] | None = None,
) -> Any:
    """Plug-and-play monitoring (D50).

    `sibyl.instrument()` initialises from `SIBYL_*` env vars when `init()` has not run, then
    auto-detects and instruments every installed model client (OpenAI, Anthropic, Google
    Gen AI) and agent framework (LangChain/LangGraph, OpenAI Agents SDK, CrewAI); returns
    the names instrumented. `sibyl.instrument(client)` wraps one client instance and
    returns it. `sensitive_tools` (fnmatch globs) fail closed in the Action Gate for tools
    the frameworks run.
    """
    if sensitive_tools is not None:
        _gate.set_sensitive(sensitive_tools)
    if client is not None:
        return instrument_client(client, capture_mode=capture_mode)
    from sibyl._config import INSTRUMENTABLE
    from sibyl.integrations import instrument_libraries

    if _state.get() is None:
        init(instrument=libraries)
    names = INSTRUMENTABLE if libraries == "auto" else tuple(libraries)
    return instrument_libraries(names)


def check_action(
    tool: str,
    args: Any,
    *,
    sensitive: bool = False,
    mode: Mode = "wait",
    call_id: str | None = None,
) -> Verdict | None:
    """Action Gate for frameworks that execute tool calls themselves (an agent loop over
    `tool_calls`): call before running the tool. Raises `SibylActionBlocked`,
    `SibylActionHeld` (mode="async") or `SibylActionDenied`; None before `init()`."""
    client = _state.get()
    if client is None:
        return None
    return client.actions.check(tool, args, sensitive=sensitive, mode=mode, call_id=call_id)


async def acheck_action(
    tool: str,
    args: Any,
    *,
    sensitive: bool = False,
    mode: Mode = "wait",
    call_id: str | None = None,
) -> Verdict | None:
    """Async `check_action`: waiting for a held action never blocks the event loop."""
    client = _state.get()
    if client is None:
        return None
    return await client.actions.acheck(tool, args, sensitive=sensitive, mode=mode, call_id=call_id)


def get_client() -> Client:
    client = _state.get()
    if client is None:
        raise SibylConfigError("sibyl.init() has not been called")
    return client


def flush(timeout: timedelta | float | None = None) -> bool:
    client = _state.get()
    if client is None:
        return True
    seconds = timeout.total_seconds() if isinstance(timeout, timedelta) else timeout
    return client.exporter.flush(seconds)


def shutdown(timeout: timedelta | float | None = None) -> None:
    client = _state.set_client(None)
    if client is not None:
        seconds = timeout.total_seconds() if isinstance(timeout, timedelta) else timeout
        client.shutdown(None if seconds is None else timedelta(seconds=seconds))


class policy:
    """The agent's slice of the signed snapshot and the kill-switch check."""

    @staticmethod
    def current(agent_id: str | UUID | None = None) -> PolicySnapshot | None:
        client = _state.get()
        snap = client.snapshot if client else None
        if snap is None or agent_id is None:
            return snap
        return snap if str(agent_id) in (str(snap.agent_id), snap.slug) else None

    @staticmethod
    def check(agent_id: str | UUID | None = None) -> None:
        """Raises `SibylKilled` if killed (any freshness); `SibylPolicyUnavailable` only for
        fail-closed agents without a usable snapshot. Wrapped clients call this first."""
        client = _state.get()
        if client is not None:
            client.policy.check()

    @staticmethod
    def on_change(callback: Callable[[PolicySnapshot], None]) -> Callable[[], None]:
        client = _state.get()
        if client is None:
            _state.warn_once("on_change", "policy.on_change() before init() is ignored")
            return lambda: None
        return client.policy.on_change(callback)
