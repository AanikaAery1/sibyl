"""Audit completeness (T10, ST5), generated from ``x-sibyl-audit``: one case per route.

Audited routes (``x-sibyl-audit-when: always``) must answer 2xx, append at least one row, only
declared actions, and return the receipt; unaudited routes must answer 2xx and append nothing.
Conditionally audited routes (``conditional``, or ``worker`` when the worker writes the row later)
must answer 2xx and append only declared actions; a receipt, when present, names the tenant.
Implemented modules run on the DB-backed ``contract_world`` (rows read back from the real hash
chain); pending wave 2 modules stay non-strict on the in-memory harness (see ``_cases``).
"""

from __future__ import annotations

import pytest
from sibyl_control.api.contract import ContractOperation, operations
from sibyl_control.core.audit import RECEIPT_HEADER

from ._cases import call, needs_world, scenario, world_call, world_params
from .conftest import TENANT_A

API_OPS = [op for op in operations() if op.surface != "ingest"]
ALWAYS = [op for op in API_OPS if op.audit and op.audit_when == "always"]
NEVER = [op for op in API_OPS if not op.audit and op.scope != "public"]
CONDITIONAL = [op for op in API_OPS if op.audit and op.audit_when != "always"]


def _memory_token(op: ContractOperation) -> str:
    return "keys-a" if op.principals == ("api_key",) else "owner-a"


@pytest.mark.parametrize("op", world_params(ALWAYS, "audit"))
def test_audited_route_writes_declared_rows_and_a_receipt(request, op) -> None:
    if not needs_world(op):
        harness = request.getfixturevalue("harness")
        resp = call(harness, op, _memory_token(op), if_match="*")
        assert 200 <= resp.status_code < 300, resp.text
        written = [a for a in harness.audit.actions(TENANT_A) if a != "access.denied"]
        assert written, "no audit row"
        assert set(written) <= set(op.audit)
        assert resp.headers.get(RECEIPT_HEADER, "").startswith(f"{TENANT_A}:")
        return
    world = request.getfixturevalue("cworld")
    req = scenario(world, op)
    head = world.audit_head(world.a.id)
    resp = world_call(world, op, req)
    assert 200 <= resp.status_code < 300, resp.text
    written = [a for a in world.audit_since(world.a.id, head) if a != "access.denied"]
    assert written, "no audit row"
    assert set(written) <= set(op.audit), written
    assert resp.headers.get(RECEIPT_HEADER, "").startswith(f"{world.a.id}:")


@pytest.mark.parametrize("op", world_params(NEVER))
def test_unaudited_route_writes_nothing(request, op) -> None:
    if not needs_world(op):
        harness = request.getfixturevalue("harness")
        resp = call(harness, op, _memory_token(op))
        assert 200 <= resp.status_code < 300, resp.text
        assert harness.audit.actions(TENANT_A) == []
        assert RECEIPT_HEADER not in resp.headers
        return
    world = request.getfixturevalue("cworld")
    req = scenario(world, op)
    head = world.audit_head(world.a.id)
    resp = world_call(world, op, req)
    assert 200 <= resp.status_code < 300, resp.text
    assert world.audit_since(world.a.id, head) == []
    assert RECEIPT_HEADER not in resp.headers


@pytest.mark.parametrize("op", world_params(CONDITIONAL, "conditional_audit"))
def test_conditionally_audited_route_writes_only_declared_rows(request, op) -> None:
    if not needs_world(op):
        harness = request.getfixturevalue("harness")
        resp = call(harness, op, _memory_token(op), if_match="*")
        assert 200 <= resp.status_code < 300, resp.text
        written = [a for a in harness.audit.actions(TENANT_A) if a != "access.denied"]
        assert set(written) <= set(op.audit), written
        return
    world = request.getfixturevalue("cworld")
    req = scenario(world, op)
    head = world.audit_head(world.a.id)
    resp = world_call(world, op, req)
    assert 200 <= resp.status_code < 300, resp.text
    written = [a for a in world.audit_since(world.a.id, head) if a != "access.denied"]
    assert set(written) <= set(op.audit), written
    receipt = resp.headers.get(RECEIPT_HEADER)
    assert receipt is None or receipt.startswith(f"{world.a.id}:"), receipt
