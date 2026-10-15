"""Sensitive SDK tool calls fail closed when the client has not been initialized."""

from __future__ import annotations

from typing import Any

import pytest
from sibyl import _state
from sibyl._errors import SibylActionBlocked
from sibyl._gate import agate, arun_gated, gate, run_gated, set_sensitive
from sibyl._tool import tool


@pytest.fixture(autouse=True)
def no_client() -> Any:
    original = _state.set_client(None)
    set_sensitive(())
    try:
        yield
    finally:
        set_sensitive(())
        _state.set_client(original)


def test_sensitive_decorated_sync_tool_refused_before_side_effect() -> None:
    called: list[str] = []

    @tool(sensitive=True)
    def payment() -> None:
        called.append("charged")

    with pytest.raises(SibylActionBlocked, match="uninitialized"):
        payment()
    assert not called


async def test_sensitive_decorated_async_tool_refused_before_side_effect() -> None:
    called: list[str] = []

    @tool(sensitive=True)
    async def email() -> None:
        called.append("sent")

    with pytest.raises(SibylActionBlocked, match="uninitialized"):
        await email()
    assert not called


def test_sensitive_generator_refused_before_first_iteration() -> None:
    called: list[str] = []

    @tool(sensitive=True)
    def events() -> Any:
        called.append("started")
        yield "value"

    with pytest.raises(SibylActionBlocked, match="uninitialized"):
        next(events())
    assert not called


async def test_sensitive_async_generator_refused_before_first_iteration() -> None:
    called: list[str] = []

    @tool(sensitive=True)
    async def events() -> Any:
        called.append("started")
        yield "value"

    with pytest.raises(SibylActionBlocked, match="uninitialized"):
        await anext(events())
    assert not called


def test_framework_adapter_sensitive_pattern_refused_before_side_effect() -> None:
    set_sensitive(("payments.*",))
    called: list[str] = []
    with pytest.raises(SibylActionBlocked, match="uninitialized"):
        gate("payments.transfer", {"amount": "500"})
    with pytest.raises(SibylActionBlocked, match="uninitialized"):
        run_gated("payments.transfer", {}, lambda: called.append("charged"))
    assert not called


async def test_async_framework_adapter_sensitive_pattern_refused() -> None:
    set_sensitive(("send_email",))
    called: list[str] = []

    async def send() -> None:
        called.append("sent")

    with pytest.raises(SibylActionBlocked, match="uninitialized"):
        await agate("send_email", {})
    with pytest.raises(SibylActionBlocked, match="uninitialized"):
        await arun_gated("send_email", {}, send)
    assert not called


def test_nonsensitive_uninitialized_tools_preserve_existing_noop_mode() -> None:
    @tool
    def harmless() -> str:
        return "ok"

    assert harmless() == "ok"
    assert gate("harmless", {}) is None
