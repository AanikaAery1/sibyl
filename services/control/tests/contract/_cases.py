"""Shared plumbing for the generated suites: per-operation marks and the two ways to call a route.

Strictness (G1, INT-1 item 6): an operation of an implemented module carries no xfail marker, so
every generated case for it must pass and a regression fails the run. A module is **pending**
while any of its operations is still mounted as a 501 stub (``api/_stubs.py`` names those
endpoints ``stub_<operationId>``), computed from the app at import, so a wave 2 module turns
strict by itself the moment its last stub is replaced. Pending cases are
``xfail(strict=False)`` and only absorb ``AssertionError`` (a crashing harness still fails). An
operation exempt by ruling (a 501 stub such as ``generateAgentBom``) is ``xfail(strict=True)``
and does not make its module pending: the day it is implemented, the unexpected pass forces its
exemption to be removed. An operation cut by ruling but *guarded* (``scenarios.CUT_BY_RULING``,
e.g. ``createDataExport``: authorised, then 501) keeps every guard-level case strict; only its
world-level (2xx) cases are ``xfail(strict=True)``, so implementing it forces the same cleanup.
``scenarios.KNOWN_GAPS`` are real findings (route or contract bugs) tracked as
``xfail(strict=True)`` per (test, operation) until fixed.

Guard-level cases call the in-memory ``harness`` (decided before any handler). Cases that need
real objects call the ``contract_world`` with the operation's scenario.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from uuid import uuid4

import pytest
from fastapi.routing import APIRoute
from sibyl_control.api.app import create_app
from sibyl_control.api.contract import API_PREFIX, ContractOperation, operations

from ._examples import concrete_path, request_body, required_query
from ._world_kit import Req
from .scenarios import CUT_BY_RULING, EXEMPT, KNOWN_GAPS, SCENARIOS

STUB_BY_RULING = frozenset({"generateAgentBom"})


def _endpoints(routes: Any) -> Iterator[Any]:
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
            continue
        original = getattr(route, "original_router", None)
        if original is not None:
            yield from _endpoints(original.routes)


def stubbed_operations() -> frozenset[str]:
    """Operation ids still mounted as 501 stubs in the assembled app."""
    app = create_app()
    return frozenset(
        r.name
        for r in _endpoints(app.routes)
        if getattr(r.endpoint, "__name__", "").startswith("stub_")
    )


STUBS = stubbed_operations()
_MODULE_OF = {op.operation_id: op.module for op in operations()}
PENDING_MODULES = frozenset(_MODULE_OF[s] for s in STUBS if s not in STUB_BY_RULING)
PENDING = pytest.mark.xfail(
    strict=False, raises=AssertionError, reason="wave 2 lane builds this module concurrently"
)
STUBBED = pytest.mark.xfail(strict=True, reason="501 by ruling (cut to Phase 1.5)")


def pending(op: ContractOperation) -> bool:
    return op.module in PENDING_MODULES


def needs_world(op: ContractOperation) -> bool:
    """True when the case runs on the DB world (implemented, not a stub, not exempt)."""
    return not pending(op) and op.operation_id not in EXEMPT


def guard_params(ops: list[ContractOperation]) -> list[Any]:
    """Guard-level cases: strict unless pending or stubbed by ruling."""
    out = []
    for op in ops:
        marks: list[Any] = []
        if op.operation_id in STUB_BY_RULING:
            marks.append(STUBBED)
        elif pending(op):
            marks.append(PENDING)
        out.append(pytest.param(op, marks=marks, id=op.operation_id))
    return out


def world_params(ops: list[ContractOperation], test: str = "") -> list[Any]:
    """DB-level cases: strict on the world; pending modules and exemptions stay non-strict."""
    out = []
    for op in ops:
        marks: list[Any] = []
        gap = KNOWN_GAPS.get((test, op.operation_id))
        cut = CUT_BY_RULING.get(op.operation_id)
        if op.operation_id in STUB_BY_RULING:
            marks.append(STUBBED)
        elif pending(op):
            marks.append(PENDING)
        elif gap is not None:
            marks.append(pytest.mark.xfail(strict=True, raises=AssertionError, reason=gap))
        elif cut is not None:
            marks.append(pytest.mark.xfail(strict=True, raises=AssertionError, reason=cut))
        elif op.operation_id in EXEMPT:
            marks.append(
                pytest.mark.xfail(
                    strict=False, raises=AssertionError, reason=EXEMPT[op.operation_id]
                )
            )
        out.append(pytest.param(op, marks=marks, id=op.operation_id))
    return out


def call(harness: Any, op: ContractOperation, token: str | None, *, if_match: str = '"0"') -> Any:
    """In-memory call with generated ids and an example body."""
    headers = {"Idempotency-Key": f"wall-{op.operation_id}", "If-Match": if_match}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return harness.client.request(
        op.method.upper(),
        concrete_path(op),
        params=required_query(op),
        json=request_body(op),
        headers=headers,
    )


def default_token(op: ContractOperation) -> str:
    return "keys" if op.principals == ("api_key",) else "owner"


def scenario(world: Any, op: ContractOperation) -> Req:
    return SCENARIOS[op.operation_id](world)


def world_call(world: Any, op: ContractOperation, req: Req, token: str | None = None) -> Any:
    who = token or req.who or default_token(op)
    headers = world.headers(who, **{"Idempotency-Key": str(uuid4())}, **req.headers)
    if req.if_match is not None:
        headers["If-Match"] = req.if_match
    path = req.path if req.path.startswith("/.well-known") else API_PREFIX + req.path
    return world.client.request(
        op.method.upper(), path, json=req.body, params=req.params, headers=headers
    )
