"""Read models: ``Incident`` (failover saga + transition + approval + alert + health evidence +
handoff tasks + available actions, B1), ``HandoffTask``/summary and ``KillSwitch``.

Lists are serialised in batches (one query per joined table, not per row).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any
from uuid import UUID

from ..auth.common import iso
from ..reads.common import approval_view, public_factors, s, transition_view

AUTOMATED = ("rule", "policy")
_TRANSITIONS_SQL = (
    "SELECT t.*, (SELECT u.id FROM sibyl.routing_transition u WHERE u.tenant_id = t.tenant_id"
    " AND u.inverse_of = t.id) AS undone_by FROM sibyl.routing_transition t"
    " WHERE t.tenant_id = $1 AND t.id = ANY($2::uuid[])"
)


def routing_view(rs: Mapping[str, Any] | None, agent_id: UUID) -> dict[str, Any]:
    if rs is None:
        return {
            "agent_id": str(agent_id),
            "state": "active",
            "target_kind": "primary",
            "routing_version": 0,
            "state_since": None,
        }
    return {
        "agent_id": str(rs["agent_id"]),
        "state": rs["state"],
        "target_kind": rs["target_kind"],
        "target_provider_id": s(rs["target_provider_id"]),
        "target_model_id": s(rs["target_model_id"]),
        "target_agent_id": s(rs["target_agent_id"]),
        "current_step_id": s(rs["current_step_id"]),
        "canary_pct": rs["canary_pct"],
        "routing_version": rs["routing_version"],
        "operator_hold_until": iso(rs["operator_hold_until"]),
        "state_since": iso(rs["state_since"]),
    }


def full_approval_view(row: Mapping[str, Any]) -> dict[str, Any]:
    out = approval_view(row)
    out["decision_reason"] = row["decision_reason"]
    out["resolved_by_timeout"] = row["resolved_by_timeout"]
    return out


def task_summary(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "agent_id": str(row["agent_id"]),
        "incident_id": s(row["failover_id"]),
        "state": row["state"],
        "priority": row["priority"],
        "fidelity": row["fidelity"],
        "failure_mode": row["failure_mode"],
        "deadline_at": iso(row["deadline_at"]),
        "claimed_by": s(row["claimed_by_user_id"]),
        "summary": row["summary"],
        "created_at": iso(row["created_at"]),
    }


def task_view(row: Mapping[str, Any]) -> dict[str, Any]:
    out = task_summary(row)
    out.update(
        {
            "claimed_at": iso(row["claimed_at"]),
            "lock_expires_at": iso(row["claim_lock_until"]),
            "accountable_user_id": s(row["accountable_user_id"]),
            "outcome": row["outcome"],
            "outcome_note": row["outcome_note"],
            "completed_at": iso(row["completed_at"]),
            "next_action": row["next_action"],
            "packet_sha256": bytes(row["packet_sha256"]).hex() if row["packet_sha256"] else None,
            "trigger_kind": row["trigger_kind"],
            "assembled_by": row["assembled_by"],
            "reclaim_count": row["reclaim_count"],
            "rating": row["rating"],
        }
    )
    return out


def _alert_view(row: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "id": str(row["id"]),
        "rule_code": row["code"],
        "severity": row["severity"],
        "state": row["state"],
        "first_fired_at": iso(row["first_fired_at"]),
        "summary": row["summary"],
        "provider_incident_id": s(row["provider_incident_id"]),
        "hold_suppressed_count": row["hold_suppressed_count"],
    }


def _health_view(row: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "health_snapshot_id": str(row["id"]),
        "score": row["score"],
        "band": row["band"],
        "evaluated_at": iso(row["evaluated_at"]),
        "factors": public_factors(row["factors"]),
    }


def available_actions(
    row: Mapping[str, Any],
    rs: Mapping[str, Any] | None,
    transition: Mapping[str, Any] | None,
    approval: Mapping[str, Any] | None,
) -> list[str]:
    """What a human may do next (state-based; the caller's scopes are checked on POST)."""
    out: list[str] = []
    state = row["state"]
    routing_state = rs["state"] if rs is not None else None
    if state == "waiting_approval" and approval is not None and approval["state"] == "pending":
        out += ["approve", "deny"]
    saga = row["kind"] in ("failover", "preemptive")
    if saga and (
        state in ("pending", "waiting_approval")
        or (state == "running" and row["step"] in ("validate", "check_viability", "write_routing"))
    ):
        out.append("cancel")
    automated = (
        transition is not None
        and transition["actor_kind"] in AUTOMATED
        and transition["undone_by"] is None
        and rs is not None
        and rs["last_transition_id"] == transition["id"]
    )
    if automated:
        out.append("undo")
    if routing_state in ("quarantined", "killed"):
        out.append("release")
    if (
        routing_state == "failed_over"
        and state == "done"
        and row["kind"] in ("failover", "preemptive")
    ):
        out.append("fail_back")
    if rs is not None and rs["operator_hold_until"] is not None:
        out.append("clear_hold")
    return out


async def incident_views(
    conn: Any, tenant: UUID, rows: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    if not rows:
        return []
    agents = list({r["agent_id"] for r in rows})
    ids = [r["id"] for r in rows]
    states = {
        r["agent_id"]: r
        for r in await conn.fetch(
            "SELECT * FROM sibyl.routing_state WHERE tenant_id = $1 AND agent_id = ANY($2::uuid[])",
            tenant,
            agents,
        )
    }
    transition_ids = [r["routing_transition_id"] for r in rows if r["routing_transition_id"]]
    transitions = {r["id"]: r for r in await conn.fetch(_TRANSITIONS_SQL, tenant, transition_ids)}
    approvals = {
        r["id"]: r
        for r in await conn.fetch(
            "SELECT * FROM sibyl.approval WHERE tenant_id = $1 AND failover_id = ANY($2::uuid[])"
            " ORDER BY created_at",
            tenant,
            ids,
        )
    }
    by_failover: dict[UUID, Any] = {a["failover_id"]: a for a in approvals.values()}
    alert_ids = [r["trigger_alert_id"] for r in rows if r["trigger_alert_id"]]
    alerts = {
        r["id"]: r
        for r in await conn.fetch(
            "SELECT a.*, r.code FROM sibyl.alert a JOIN sibyl.alert_rule r"
            " ON r.tenant_id = a.tenant_id AND r.id = a.rule_id"
            " WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[])",
            tenant,
            alert_ids,
        )
    }
    snap_ids = [r["health_snapshot_id"] for r in rows if r["health_snapshot_id"]]
    snapshots = {
        r["id"]: r
        for r in await conn.fetch(
            "SELECT id, score, band, evaluated_at, factors FROM sibyl.health_snapshot"
            " WHERE tenant_id = $1 AND id = ANY($2::uuid[])",
            tenant,
            snap_ids,
        )
    }
    tasks: dict[UUID, list[dict[str, Any]]] = defaultdict(list)
    for t in await conn.fetch(
        "SELECT * FROM sibyl.handoff_task WHERE tenant_id = $1 AND failover_id = ANY($2::uuid[])"
        " ORDER BY priority, deadline_at, id",
        tenant,
        ids,
    ):
        tasks[t["failover_id"]].append(task_summary(t))
    out = []
    for r in rows:
        rs = states.get(r["agent_id"])
        transition = transitions.get(r["routing_transition_id"])
        approval = by_failover.get(r["id"])
        results = dict(r["step_results"] or {})
        chosen = (results.get("check_viability") or {}).get("chosen")
        out.append(
            {
                "id": str(r["id"]),
                "agent_id": str(r["agent_id"]),
                "kind": r["kind"],
                "state": r["state"],
                "step": r["step"],
                "priority": r["priority"],
                "actor_kind": r["actor_kind"],
                "requested_by_user_id": s(r["requested_by_user_id"]),
                "from_state": r["from_state"],
                "to_state": r["to_state"],
                "rule_codes": list(r["rule_codes"] or []),
                "trigger_alert_id": s(r["trigger_alert_id"]),
                "operator_hold_until": iso(rs["operator_hold_until"]) if rs is not None else None,
                "chosen_step": chosen,
                "undo_plan": dict(r["undo_plan"] or {}) or None,
                "step_results": results,
                "error": r["error"],
                "created_at": iso(r["created_at"]),
                "finished_at": iso(r["finished_at"]),
                "routing": routing_view(rs, r["agent_id"]),
                "transition": transition_view(transition) if transition is not None else None,
                "approval": full_approval_view(approval) if approval is not None else None,
                "alert": _alert_view(alerts.get(r["trigger_alert_id"])),
                "health_evidence": _health_view(snapshots.get(r["health_snapshot_id"])),
                "handoff_tasks": tasks.get(r["id"], []),
                "available_actions": available_actions(r, rs, transition, approval),
            }
        )
    return out


async def incident_view(conn: Any, tenant: UUID, failover_id: UUID) -> dict[str, Any] | None:
    row = await conn.fetchrow(
        "SELECT * FROM sibyl.failover WHERE tenant_id = $1 AND id = $2", tenant, failover_id
    )
    if row is None:
        return None
    return (await incident_views(conn, tenant, [row]))[0]


async def kill_switch_views(
    conn: Any, tenant: UUID, rows: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    if not rows:
        return []
    ids = [r["id"] for r in rows]
    acks: dict[UUID, list[dict[str, Any]]] = defaultdict(list)
    for a in await conn.fetch(
        "SELECT * FROM sibyl.kill_switch_ack WHERE tenant_id = $1 AND kill_switch_id ="
        " ANY($2::uuid[])"
        " ORDER BY applied_at",
        tenant,
        ids,
    ):
        acks[a["kill_switch_id"]].append(
            {
                "kill_switch_id": str(a["kill_switch_id"]),
                "gateway_id": a["gateway_id"],
                "snapshot_version": a["snapshot_version"],
                "applied_at": iso(a["applied_at"]),
            }
        )
    affected: dict[UUID, list[str]] = defaultdict(list)
    for f in await conn.fetch(
        "SELECT agent_id, kill_switch_id FROM sibyl.failover"
        " WHERE tenant_id = $1 AND kind = 'kill' AND kill_switch_id = ANY($2::uuid[])"
        " ORDER BY created_at, id",
        tenant,
        ids,
    ):
        affected[f["kill_switch_id"]].append(str(f["agent_id"]))
    return [
        {
            "id": str(r["id"]),
            "scope_kind": r["scope_kind"],
            "scope_id": s(r["scope_id"]),
            "state": r["state"],
            "reason": r["reason"],
            "pulled_by": s(r["pulled_by"]),
            "pulled_via_break_glass": r["pulled_by_key_id"] is not None,
            "pulled_at": iso(r["pulled_at"]),
            "routing_version_at_pull": r["routing_version_at_pull"],
            "released_by": s(r["released_by"]),
            "released_at": iso(r["released_at"]),
            "affected_agent_ids": affected.get(r["id"], []),
            "acks": acks.get(r["id"], []),
        }
        for r in rows
    ]
