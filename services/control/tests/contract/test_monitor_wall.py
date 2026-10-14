"""D53 authz matrix for monitor-bound keys (lane EXTMON), generated from the OpenAPI document.

* A monitor key reaches exactly the read routes that list ``monitor:read`` plus ``/findings``
  and ``/monitors/self``; every other protected route refuses it (guard level, in memory).
* On real objects (``contract_world``): an all-groups monitor reads every such route; a monitor
  watching group g1 gets 404 for an agent outside g1 and lists without it; findings are
  refused outside the watched groups, while the monitor is paused, and after it is revoked.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from sibyl_control.api.contract import ContractOperation, operations
from sibyl_control.core.authz import Grant, Principal, PrincipalKind

from ._cases import STUBS, call, scenario, world_call
from .conftest import TENANT_A
from .pg_world import ContractWorld
from .scenarios_monitors import finding_body

API_OPS = [op for op in operations() if op.surface != "ingest"]
MONITOR_ROUTES = [op for op in API_OPS if "monitor:read" in (*op.scope_any, op.scope)]
MONITOR_WRITES = [op for op in API_OPS if op.scope == "findings:write"]
REACHABLE = {op.operation_id for op in MONITOR_ROUTES + MONITOR_WRITES}
UNREACHABLE = [
    op
    for op in API_OPS
    if op.scope not in ("public", "authenticated")
    and op.operation_id not in REACHABLE
    and op.operation_id not in STUBS  # a 501 stub answers before any guard
]
# Reads about one agent's object (404 outside the watched groups) and lists (filtered).
SINGLE = (
    "getAgent",
    "getAgentHealth",
    "getRun",
    "getAgentDrift",
    "getHeldAction",
    "getFinding",
)
LISTS = ("listAgents", "listRuns", "listHeldActions", "listFindings", "listAlerts")


def test_reachable_set_is_pinned() -> None:
    assert REACHABLE == {
        "listAgents",
        "getAgent",
        "getFleetHealth",
        "getAgentHealth",
        "listRuns",
        "getRun",
        "getAgentDrift",
        "listAlerts",
        "getAlert",
        "listIncidents",
        "getIncident",
        "listHeldActions",
        "getHeldAction",
        "listFindings",
        "getFinding",
        "getMonitorSelf",
        "submitFinding",
    }
    for op in MONITOR_ROUTES + MONITOR_WRITES:
        assert "api_key" in op.principals, op.operation_id
        if op.method == "get" and op.operation_id != "getMonitorSelf":
            assert "group" in op.object_rules, op.operation_id


@pytest.fixture
def monitor_token(harness: Any) -> str:
    grants = {s: Grant(s) for s in ("monitor:read", "findings:write")}
    principal = Principal(PrincipalKind.API_KEY, TENANT_A, uuid4(), grants, monitor_id=uuid4())
    harness.principals.add("monitor-a", principal)
    return "monitor-a"


@pytest.mark.parametrize("op", UNREACHABLE, ids=[op.operation_id for op in UNREACHABLE])
def test_monitor_key_is_refused_everywhere_else(harness: Any, monitor_token: str, op) -> None:
    resp = call(harness, op, monitor_token)
    assert resp.status_code == 403, (op.operation_id, resp.text)


def _as(world: ContractWorld, op: ContractOperation, who: str) -> Any:
    req = scenario(world, op)
    return req, world_call(world, op, req, who)


@pytest.mark.parametrize("op", MONITOR_ROUTES, ids=[op.operation_id for op in MONITOR_ROUTES])
def test_all_groups_monitor_reads(cworld: ContractWorld, op) -> None:
    _, resp = _as(cworld, op, "monitor")
    assert resp.status_code == 200, (op.operation_id, resp.text)


@pytest.mark.parametrize("op_id", SINGLE)
def test_group_limited_monitor_gets_404_outside_its_groups(cworld: ContractWorld, op_id) -> None:
    op = next(o for o in API_OPS if o.operation_id == op_id)
    _, resp = _as(cworld, op, "monitor-g1")
    assert resp.status_code == 404, (op_id, resp.text)


@pytest.mark.parametrize("op_id", LISTS)
def test_group_limited_monitor_lists_only_its_groups(cworld: ContractWorld, op_id) -> None:
    op = next(o for o in API_OPS if o.operation_id == op_id)
    req, resp = _as(cworld, op, "monitor-g1")
    assert resp.status_code == 200, resp.text
    every = world_call(cworld, op, req, "monitor").json()["data"]
    seen = resp.json()["data"]
    assert len(seen) < len(every) or not every
    allowed = {str(a) for k, a in cworld.a.agents.items() if k in ("in_g1", "in_g2")}
    for item in seen:
        agent = item.get("agent_id") or (item["id"] if op_id == "listAgents" else None)
        assert agent in allowed, (op_id, item)


def _submit(world: ContractWorld, who: str, body: dict[str, Any]) -> Any:
    return world.client.post("/api/v1/findings", json=body, headers=world.idem(who))


def test_findings_respect_the_watched_groups(cworld: ContractWorld) -> None:
    a = cworld.a
    inside = _submit(cworld, "monitor-g1", finding_body(str(a.agents["in_g2"])))
    assert inside.status_code == 201, inside.text
    assert inside.json()["agent_id"] == str(a.agents["in_g2"])
    assert inside.json()["source"] == "external" and inside.json()["advisory"] is True
    outside = _submit(cworld, "monitor-g1", finding_body(str(a.agents["other"])))
    assert outside.status_code == 404, outside.text
    fleet = {
        "kind": "fleet_summary",
        "subject_kind": "fleet",
        "severity": "info",
        "summary": "Quiet day.",
    }
    assert _submit(cworld, "monitor-g1", fleet).status_code == 404
    assert _submit(cworld, "monitor", fleet).status_code == 201
    missing = finding_body(str(uuid4()))
    assert _submit(cworld, "monitor", missing).status_code == 404


def test_findings_need_an_active_monitor(cworld: ContractWorld) -> None:
    created = cworld.client.post(
        "/api/v1/monitors",
        json={"name": f"pausable-{uuid4().hex[:6]}", "kind": "api", "key_env": "test"},
        headers=cworld.idem("owner"),
    ).json()
    cworld.tokens["pausable"] = created["api_key"]["secret"]
    body = finding_body(str(cworld.a.agents["in_g1"]))
    assert _submit(cworld, "pausable", body).status_code == 201
    paused = cworld.client.patch(
        f"/api/v1/monitors/{created['id']}",
        json={"state": "paused"},
        headers=cworld.headers("owner", **{"If-Match": '"1"'}),
    )
    assert paused.status_code == 200, paused.text
    refused = _submit(cworld, "pausable", body)
    assert refused.status_code == 409 and refused.json()["type"].endswith("/not_active")
    # reads keep working while paused
    me = cworld.client.get("/api/v1/monitors/self", headers=cworld.headers("pausable"))
    assert me.status_code == 200 and me.json()["state"] == "paused"
    revoked = cworld.client.post(
        f"/api/v1/monitors/{created['id']}/revoke",
        json={"reason": "contract: the monitor is retired"},
        headers=cworld.idem("owner"),
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["keys"] == [] and revoked.json()["state"] == "revoked"
    gone = cworld.client.get("/api/v1/monitors/self", headers=cworld.headers("pausable"))
    assert gone.status_code == 401


def test_monitor_findings_are_audited_as_the_key(cworld: ContractWorld) -> None:
    head = cworld.audit_head(cworld.a.id)
    resp = _submit(cworld, "monitor", finding_body(str(cworld.a.agents["in_g1"])))
    assert resp.status_code == 201
    row = cworld.admin.fetchrow(
        "SELECT actor_type, actor_key_id, detail FROM sibyl.audit_events"
        " WHERE tenant_id = $1 AND seq > $2 AND action = 'finding.submitted'",
        cworld.a.id,
        head,
    )
    assert row["actor_type"] == "api_key"
    assert row["actor_key_id"] == cworld.key_ids["monitor"]
    assert row["detail"]["monitor_id"] == str(cworld.monitor_ids["monitor"])
