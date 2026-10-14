"""The governance module's authz/audit wall cases on a real database (lane U).

The generated contract suites (``tests/contract``) run without a database, so their
foreign-tenant 404 and audit-completeness cases cannot pass for database-backed handlers; this
module runs the same rules against PG17 for every governance operation:

* audited routes write at least one row, only declared actions, and return the receipt of a
  declared row; unaudited routes write nothing and return no receipt;
* ids of another tenant are 404, never 403;
* every route refuses a principal without its scope with 403 + ``access.denied``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
import sibyl_lane_u_helpers as h
from sibyl_control.api.contract import operations
from sibyl_control.worker.housekeeping import anchors

RECEIPT = "X-Sibyl-Audit-Receipt"
NOW = datetime.now(UTC)
GOV = {op.operation_id: op for op in operations() if op.module == "governance"}
CUT = {"createDataExport"}  # Phase 1.5 (ROADMAP A8): guarded 501


def _hold_body(agent: str) -> dict[str, Any]:
    return {
        "scope_kind": "agent",
        "scope_ref": agent,
        "window_from": (NOW - timedelta(days=1)).isoformat(),
        "expires_at": (NOW + timedelta(days=5)).isoformat(),
        "reason": "contract wall hold",
    }


@pytest.fixture(scope="module")
def seeded(world: Any) -> dict[str, str]:
    h.append_rows(world, world.a.id, 3)
    world.tick(anchors)
    agent = str(world.add_agent(world.a, "wall-agent"))
    hold = world.post("security_admin", "/legal-holds", _hold_body(agent)).json()["id"]
    other = str(world.add_agent(world.a, "wall-agent-2"))
    request = world.post(
        "owner",
        "/erasure-requests",
        {
            "scope_kind": "agent",
            "scope_ref": other,
            "legal_basis": "other",
            "reason": "contract wall erasure",
        },
    ).json()["id"]
    export = world.post(
        "owner", "/audit/exports", {"from_seq": 0, "to_seq": 1, "format": "jsonl"}
    ).json()["id"]
    return {"agent": agent, "hold": hold, "request": request, "export": export}


Call = Callable[[Any, dict[str, str]], tuple[str, str, Any, str]]

CALLS: dict[str, Call] = {
    "listAuditEvents": lambda w, s: ("GET", "/audit/events", None, "auditor"),
    "getAuditEvent": lambda w, s: ("GET", "/audit/events/1", None, "auditor"),
    "listAuditAnchors": lambda w, s: ("GET", "/audit/anchors", None, "auditor"),
    "listAuditSigningKeys": lambda w, s: ("GET", "/audit/signing-keys", None, "auditor"),
    "verifyAuditChain": lambda w, s: ("POST", "/audit/verifications", {}, "auditor"),
    "createAuditExport": lambda w, s: (
        "POST",
        "/audit/exports",
        {"from_seq": 0, "to_seq": 2, "format": "jsonl"},
        "owner",
    ),
    "getAuditExport": lambda w, s: ("GET", f"/audit/exports/{s['export']}", None, "owner"),
    "listErasureRequests": lambda w, s: ("GET", "/erasure-requests", None, "owner"),
    "requestErasure": lambda w, s: (
        "POST",
        "/erasure-requests",
        {
            "scope_kind": "agent",
            "scope_ref": str(w.add_agent(w.a, f"wall-{uuid4().hex[:8]}")),
            "legal_basis": "other",
            "reason": "contract wall erasure",
        },
        "owner",
    ),
    "getErasureRequest": lambda w, s: ("GET", f"/erasure-requests/{s['request']}", None, "auditor"),
    "actOnErasureRequest": lambda w, s: (
        "POST",
        f"/erasure-requests/{s['request']}/actions",
        {"action": "reject", "reason": "contract wall rejection"},
        "approver",
    ),
    "getErasureCertificate": lambda w, s: (
        "GET",
        f"/erasure-requests/{s['request']}/certificate",
        None,
        "auditor",
    ),
    "listLegalHolds": lambda w, s: ("GET", "/legal-holds", None, "auditor"),
    "placeLegalHold": lambda w, s: (
        "POST",
        "/legal-holds",
        _hold_body(str(w.add_agent(w.a, f"wall-{uuid4().hex[:8]}"))),
        "security_admin",
    ),
    "releaseLegalHold": lambda w, s: (
        "POST",
        f"/legal-holds/{s['hold']}/release",
        {"reason": "contract wall release"},
        "security_admin",
    ),
}


def test_every_governance_operation_has_a_wall_case() -> None:
    assert set(GOV) - CUT == set(CALLS)


def _send(world: Any, method: str, path: str, body: Any, token: str) -> Any:
    headers = world.idem(token) if method == "POST" else world.headers(token)
    return world.client.request(method, "/api/v1" + path, json=body, headers=headers)


@pytest.mark.parametrize("operation_id", sorted(CALLS))
def test_audit_completeness_on_pg(world: Any, seeded: dict[str, str], operation_id: str) -> None:
    op = GOV[operation_id]
    method, path, body, token = CALLS[operation_id](world, seeded)
    before = world.head(world.a.id)
    resp = _send(world, method, path, body, token)
    if operation_id == "getErasureCertificate":  # 409 not_completed is its only state here
        assert resp.status_code == 409
        assert world.head(world.a.id) == before
        return
    assert 200 <= resp.status_code < 300, resp.text
    written = world.actions(world.a.id, before)
    if not op.audit:
        assert written == [] and RECEIPT not in resp.headers
        return
    human = [a for a in written if a in op.audit]
    assert human, f"no declared audit row in {written}"
    receipt = resp.headers[RECEIPT]
    tenant, seq, digest = receipt.split(":")
    row = world.fetchrow(
        "SELECT action, hash FROM sibyl.audit_events WHERE tenant_id = $1 AND seq = $2",
        world.a.id,
        int(seq),
    )
    assert tenant == str(world.a.id) and row["hash"].hex() == digest and row["action"] in op.audit


FOREIGN = {
    "getAuditEvent": lambda s: ("GET", "/audit/events/{top}", None),
    "getAuditExport": lambda s: ("GET", f"/audit/exports/{s['export']}", None),
    "getErasureRequest": lambda s: ("GET", f"/erasure-requests/{s['request']}", None),
    "actOnErasureRequest": lambda s: (
        "POST",
        f"/erasure-requests/{s['request']}/actions",
        {"action": "cancel", "reason": "foreign cancel try"},
    ),
    "getErasureCertificate": lambda s: (
        "GET",
        f"/erasure-requests/{s['request']}/certificate",
        None,
    ),
    "releaseLegalHold": lambda s: (
        "POST",
        f"/legal-holds/{s['hold']}/release",
        {"reason": "foreign release try"},
    ),
}


@pytest.mark.parametrize("operation_id", sorted(FOREIGN))
def test_foreign_tenant_ids_are_404(world: Any, seeded: dict[str, str], operation_id: str) -> None:
    method, path, body = FOREIGN[operation_id](seeded)
    path = path.replace("{top}", str(world.head(world.a.id)))
    resp = _send(world, method, path, body, "owner-b")
    assert resp.status_code == 404, resp.text


@pytest.mark.parametrize("operation_id", sorted(CALLS))
def test_principal_without_scope_is_403_and_audited(
    world: Any, seeded: dict[str, str], operation_id: str
) -> None:
    method, path, body, _ = CALLS[operation_id](world, seeded)
    before = world.head(world.a.id)
    resp = _send(world, method, path, body, "nobody")
    assert resp.status_code == 403
    assert "access.denied" in world.actions(world.a.id, before)
