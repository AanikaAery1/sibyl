"""Lane S scenarios: incidents, approvals, kill switches and the operator queue (lifted from lane
S's ``test_contract_s_pg``, retired once these covered it). Agents and approved chains are built
by direct SQL like lane S's own world; the requests go through the api."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from ._world_kit import Req, Scenario, _api, model, unique
from .pg_world import ContractWorld

S_REASON = "contract scenario: operator action with a reason"


def s_agent(
    w: ContractWorld, *, tier: int = 2, group: UUID | None = None, with_model: bool = True
) -> UUID:
    """An agent by direct SQL (lane S world): optional current version, registered routing,
    and a passthrough continuity plan."""
    agent_id = uuid4()
    w.admin.execute(
        "INSERT INTO sibyl.agent (tenant_id, id, slug, name, kind, tier, fail_mode, lifecycle,"
        " agent_group_id) VALUES ($1, $2, $3, $3, 'autonomous_agent', $4, 'closed', 'deployed',"
        " $5)",
        w.a.id,
        agent_id,
        unique("sagent"),
        tier,
        group,
    )
    if with_model:
        version = uuid4()
        w.admin.execute(
            "INSERT INTO sibyl.agent_version (tenant_id, id, agent_id, version_no,"
            " primary_model_id, source) VALUES ($1, $2, $3, 1, $4, 'api')",
            w.a.id,
            version,
            agent_id,
            model(w),
        )
        w.admin.execute(
            "UPDATE sibyl.agent SET current_version_id = $3 WHERE tenant_id = $1 AND id = $2",
            w.a.id,
            agent_id,
            version,
        )
    w.admin.in_tenant(
        w.a.id,
        "SELECT * FROM sibyl.routing_apply($1, $2, NULL, NULL, 'active', NULL, 'register',"
        " 'system', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, $3,"
        " 'route.changed', NULL, NULL, NULL, NULL)",
        w.a.id,
        agent_id,
        f"register:{agent_id}",
    )
    w.admin.in_tenant(
        w.a.id,
        "INSERT INTO sibyl.continuity_plan (tenant_id, agent_id, credential_mode,"
        " approval_timeout_policy) VALUES ($1, $2, 'passthrough', 'hold')"
        " ON CONFLICT (tenant_id, agent_id) DO NOTHING",
        w.a.id,
        agent_id,
    )
    return agent_id


def s_chain(w: ContractWorld, agent_id: UUID, steps: list[dict[str, Any]]) -> dict[str, UUID]:
    """An approved chain wired into the plan (requester owner, approver security admin)."""
    chain = uuid4()
    version = w.admin.fetchval(
        "SELECT coalesce(max(version_no), 0) + 1 FROM sibyl.fallback_chain"
        " WHERE tenant_id = $1 AND agent_id = $2",
        w.a.id,
        agent_id,
    )
    w.admin.execute(
        "INSERT INTO sibyl.fallback_chain (tenant_id, id, agent_id, version_no,"
        " requested_by_user_id) VALUES ($1, $2, $3, $4, $5)",
        w.a.id,
        chain,
        agent_id,
        version,
        w.a.users["owner"],
    )
    out: dict[str, UUID] = {}
    for position, step in enumerate(steps):
        sid = uuid4()
        w.admin.execute(
            "INSERT INTO sibyl.fallback_step (tenant_id, id, chain_id, position, kind,"
            " provider_id, model_id, backup_agent_id, credential_id, risk)"
            " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            w.a.id,
            sid,
            chain,
            position,
            step["kind"],
            step.get("provider_id"),
            step.get("model_id"),
            step.get("backup_agent_id"),
            step.get("credential_id"),
            step.get("risk", "low"),
        )
        out[step["kind"]] = sid
    w.admin.execute(
        "UPDATE sibyl.fallback_chain SET status = 'approved', approved_by_user_id = $3,"
        " approved_at = now() WHERE tenant_id = $1 AND id = $2",
        w.a.id,
        chain,
        w.a.users["approver"],
    )
    w.admin.in_tenant(
        w.a.id,
        "UPDATE sibyl.continuity_plan SET fallback_chain_id = $3 WHERE tenant_id = $1"
        " AND agent_id = $2",
        w.a.id,
        agent_id,
        chain,
    )
    return out


def _incident(w: ContractWorld, action: str = "quarantine") -> str:
    resp = _api(
        w, "POST", "/incidents", {"agent_id": str(s_agent(w)), "action": action, "reason": S_REASON}
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


def _approval(w: ContractWorld) -> str:
    backup = s_agent(w, with_model=False)
    target = s_agent(w, tier=1)
    steps = s_chain(w, target, [{"kind": "backup_agent", "backup_agent_id": backup}])
    resp = _api(
        w,
        "POST",
        "/incidents",
        {
            "agent_id": str(target),
            "action": "failover",
            "target": {"step_id": str(steps["backup_agent"])},
            "reason": S_REASON,
        },
    )
    assert resp.status_code == 202, resp.text
    return str(resp.json()["approval"]["id"])


def _kill(w: ContractWorld) -> str:
    resp = _api(
        w,
        "POST",
        "/kill-switches",
        {
            "scope_kind": "agent",
            "scope_id": str(s_agent(w)),
            "reason": "contract scenario kill switch pull",
        },
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


def _task(w: ContractWorld) -> str:
    rows = w.admin.in_tenant(
        w.a.id,
        "INSERT INTO sibyl.handoff_task (tenant_id, agent_id, task_id, packet_id, packet,"
        " packet_sha256, fidelity, failure_mode, trigger_kind, assembled_by, priority,"
        ' deadline_at, next_action, summary) VALUES ($1, $2, $3, $4, \'{"schema": "x"}\'::jsonb,'
        " $5, 'request_only', 'tool_failure', 'operator', 'control_plane', 2,"
        " now() + interval '1 hour', 'do it', 'contract task') RETURNING id",
        w.a.id,
        s_agent(w),
        uuid4(),
        uuid4(),
        b"\x01" * 32,
    )
    return str(rows[0]["id"])


LANE_S: dict[str, Scenario] = {
    "listIncidents": lambda w: Req("/incidents"),
    "getIncident": lambda w: Req(f"/incidents/{_incident(w)}"),
    "openIncident": lambda w: Req(
        "/incidents", {"agent_id": str(s_agent(w)), "action": "degrade", "reason": S_REASON}
    ),
    "actOnIncident": lambda w: Req(
        f"/incidents/{_incident(w)}/actions", {"action": "release", "reason": S_REASON}
    ),
    "listApprovals": lambda w: Req("/approvals"),
    "getApproval": lambda w: Req(f"/approvals/{_approval(w)}"),
    "listKillSwitches": lambda w: Req("/kill-switches"),
    "pullKillSwitch": lambda w: Req(
        "/kill-switches",
        {
            "scope_kind": "agent",
            "scope_id": str(s_agent(w)),
            "reason": "contract scenario: pull it",
        },
    ),
    "releaseKillSwitch": lambda w: Req(f"/kill-switches/{_kill(w)}/release", {"reason": S_REASON}),
    "ackKillSwitch": lambda w: Req(
        f"/kill-switches/{_kill(w)}/acks", {"gateway_id": "gw-1", "snapshot_version": 3}, who="keys"
    ),
    "listQueue": lambda w: Req("/queue"),
    "getHandoffTask": lambda w: Req(f"/handoff-tasks/{_task(w)}"),
    "getHandoffPacket": lambda w: Req(f"/handoff-tasks/{_task(w)}/packet"),
    "actOnHandoffTask": lambda w: Req(
        f"/handoff-tasks/{_task(w)}/actions", {"action": "claim"}, who="operator"
    ),
}
