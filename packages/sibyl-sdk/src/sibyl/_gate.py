"""Action Gate for tools that frameworks execute (LangChain, OpenAI Agents SDK, CrewAI).

The same pre-execution check as `@sibyl.tool` (`ActionEnforcer.check`): the agent's action
policies from the signed snapshot, the authoritative counter, holds for a person. A tool is
sensitive when a policy lists it in `sensitive_tools`, or when its name matches a pattern
given to `sibyl.instrument(sensitive_tools=[...])` or `SIBYL_SENSITIVE_TOOLS` (comma-
separated `fnmatch` globs, e.g. `payments.*,send_email`). A sensitive tool fails closed
without a fresh snapshot. A blocked, denied or held call raises before the tool runs.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from collections.abc import Awaitable, Callable, Iterable
from contextvars import ContextVar
from typing import Any, Final

from sibyl import _state
from sibyl._actions import Verdict
from sibyl._errors import SibylActionBlocked
from sibyl._run import current_run

ENV_SENSITIVE: Final = "SIBYL_SENSITIVE_TOOLS"
_CALL_ID: Final = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")
_patterns: tuple[str, ...] = ()
_IN_GATE: ContextVar[str | None] = ContextVar("sibyl_in_gate", default=None)


def set_sensitive(patterns: Iterable[str] | None) -> None:
    """Replace the process-wide sensitive tool patterns (`instrument(sensitive_tools=...)`)."""
    global _patterns
    _patterns = tuple(p.strip() for p in (patterns or ()) if p and p.strip())


def _env_patterns() -> tuple[str, ...]:
    raw = os.environ.get(ENV_SENSITIVE, "")
    return tuple(p.strip() for p in raw.split(",") if p.strip())


def is_sensitive(tool: str) -> bool:
    return any(fnmatch.fnmatchcase(tool, p) for p in (*_patterns, *_env_patterns()))


def tool_args(raw: Any) -> Any:
    """Framework tool input as JSON-like data: a JSON object string is parsed, any other
    string is `{"input": ...}` so policy conditions can still address it."""
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except ValueError:
            return {"input": raw}
        return parsed if isinstance(parsed, dict) else {"input": parsed}
    return raw if raw is not None else {}


def _call_id(call_id: Any) -> str | None:
    return call_id if isinstance(call_id, str) and _CALL_ID.match(call_id) else None


def _check_args(tool: str, args: Any, call_id: Any) -> dict[str, Any]:
    run = current_run()
    return {
        "sensitive": is_sensitive(tool),
        "mode": "wait",
        "call_id": _call_id(call_id),
        "task_id": str(run.task_id) if run else None,
    }


def gate(tool: str, args: Any, *, call_id: Any = None) -> Verdict | None:
    """Decide a framework tool call before it runs; raises the Action Gate errors. None
    before `init()` for nonsensitive tools or inside a nested gate. Sensitive\n    tools fail closed when the SDK has not been initialized."""
    client = _state.get()
    if client is None:
        if is_sensitive(tool):
            raise SibylActionBlocked(
                tool, "sibyl:uninitialized", "Sibyl has not been initialized"
            )
        return None
    if _IN_GATE.get() == tool:
        return None
    return client.actions.check(tool, tool_args(args), **_check_args(tool, args, call_id))


async def agate(tool: str, args: Any, *, call_id: Any = None) -> Verdict | None:
    client = _state.get()
    if client is None:
        if is_sensitive(tool):
            raise SibylActionBlocked(
                tool, "sibyl:uninitialized", "Sibyl has not been initialized"
            )
        return None
    if _IN_GATE.get() == tool:
        return None
    return await client.actions.acheck(tool, tool_args(args), **_check_args(tool, args, call_id))


def run_gated(
    tool: str, args: Any, fn: Callable[..., Any], *a: Any, call_id: Any = None, **kw: Any
) -> Any:
    """Gate, then run `fn` with the gate marked as passed (nested gated layers of the same
    tool, e.g. CrewAI's structured tool calling `BaseTool.run`, do not check twice)."""
    gate(tool, args, call_id=call_id)
    token = _IN_GATE.set(tool)
    try:
        return fn(*a, **kw)
    finally:
        _IN_GATE.reset(token)


async def arun_gated(
    tool: str, args: Any, fn: Callable[..., Awaitable[Any]], *a: Any, call_id: Any = None, **kw: Any
) -> Any:
    await agate(tool, args, call_id=call_id)
    token = _IN_GATE.set(tool)
    try:
        return await fn(*a, **kw)
    finally:
        _IN_GATE.reset(token)
