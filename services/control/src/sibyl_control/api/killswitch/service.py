"""Kill switch pull and release (API.md §5.7, §6.5; D20, D34, R31).

Pull, one transaction: the ``kill_switch`` row; per affected agent, any live saga cancelled,
``routing_apply(→ killed, trigger operator)`` (audit ``killswitch.pulled``) and a
``failover(kind=kill, priority=immediate)`` record; one ``killswitch.pulled`` row for the switch;
outbox ``killswitch.pulled``. The break-glass key additionally writes ``access.break_glass`` and
``audit.anchor_now`` (anchor within 10 s); it reads no OIDC or membership data.

D34: a second tenant-scope kill within 10 minutes must come from a different owner (409
``second_owner_required``). Release is session-only with step-up (a key can never release); it
returns to ``active`` only the agents this switch killed that no other pulled switch covers.
"""

from __future__ import annotations

import hashlib
from typing import Any
from uuid import UUID

from ...core.audit import AuditRecord
from ...core.outbox import OutboxMessage
from ...core.problems import ProblemError
from ...worker.saga import engine, routing
from ...worker.saga.model import Actor, Env

SECOND_KILL_WINDOW_S = 600

_PROVIDER_AGENTS_SQL = """
SELECT rs.agent_id, rs.state FROM sibyl.routing_state rs
  JOIN sibyl.agent a ON a.tenant_id = rs.tenant_id AND a.id = rs.agent_id
  LEFT JOIN sibyl.agent_version v ON v.tenant_id = a.tenant_id AND v.id = a.current_version_id
  LEFT JOIN sibyl.model m ON m.tenant_id = v.tenant_id AND m.id = v.primary_model_id
 WHERE rs.tenant_id = $1 AND (m.provider_id = $2 OR rs.target_provider_id = $2)
"""


def ip_hash(ip: str) -> str:
    return hashlib.sha256(ip.encode()).hexdigest()[:32]


async def affected_agents(
    conn: Any, tenant: UUID, scope_kind: str, scope_id: UUID | None
) -> list[Any]:
    """Every agent the scope covers, already-killed ones included: each switch records a
    ``kill`` row per covered agent, so coverage on release is exact for overlapping switches."""
    if scope_kind == "tenant":
        return list(
            await conn.fetch(
                "SELECT agent_id, state FROM sibyl.routing_state WHERE tenant_id = $1"
                " ORDER BY agent_id",
                tenant,
            )
        )
    if scope_kind == "agent":
        return list(
            await conn.fetch(
                "SELECT agent_id, state FROM sibyl.routing_state WHERE tenant_id = $1"
                " AND agent_id = $2",
                tenant,
                scope_id,
            )
        )
    return list(await conn.fetch(_PROVIDER_AGENTS_SQL + " ORDER BY rs.agent_id", tenant, scope_id))


async def check_scope(conn: Any, tenant: UUID, scope_kind: str, scope_id: UUID | None) -> None:
    if (scope_kind == "tenant") != (scope_id is None):
        raise ProblemError(
            "validation_failed", "scope_id is required for agent/provider scope only"
        )
    if scope_kind == "agent":
        found = await conn.fetchval(
            "SELECT 1 FROM sibyl.agent WHERE tenant_id = $1 AND id = $2", tenant, scope_id
        )
    elif scope_kind == "provider":
        found = await conn.fetchval(
            "SELECT 1 FROM sibyl.provider WHERE tenant_id = $1 AND id = $2", tenant, scope_id
        )
    else:
        found = True
    if not found:
        raise ProblemError("not_found", f"unknown {scope_kind}")


async def second_owner_rule(conn: Any, tenant: UUID, actor: Actor, roles: frozenset[str]) -> None:
    """D34 / R31: a second tenant-scope kill within 10 minutes needs a different owner."""
    if actor.kind != "human":
        return  # break-glass keys have their own numeric caps
    recent = await conn.fetchval(
        "SELECT pulled_by FROM sibyl.kill_switch WHERE tenant_id = $1 AND scope_kind = 'tenant'"
        " AND pulled_by IS NOT NULL AND pulled_at > now() - make_interval(secs => $2)"
        " ORDER BY pulled_at DESC LIMIT 1",
        tenant,
        SECOND_KILL_WINDOW_S,
    )
    if recent is None:
        return
    if recent == actor.user_id or "owner" not in roles:
        raise ProblemError(
            "second_owner_required",
            "a second tenant-wide kill within 10 minutes must come from a different owner",
        )


async def _cancel_live(conn: Any, env: Env, tenant: UUID, agent_id: UUID) -> list[str]:
    rows = await conn.fetch(
        "SELECT * FROM sibyl.failover WHERE tenant_id = $1 AND agent_id = $2"
        " AND state IN ('pending', 'running', 'waiting_approval') FOR UPDATE",
        tenant,
        agent_id,
    )
    for row in rows:
        await engine.finish(conn, env, tenant, dict(row), "cancelled", "killed")
    return [str(r["id"]) for r in rows]


async def _record(
    conn: Any,
    tenant: UUID,
    *,
    agent_id: UUID,
    kind: str,
    actor: Actor,
    from_state: str,
    to_state: str,
    transition_id: UUID | None,
    kill_switch_id: UUID,
    results: dict[str, Any],
    key: str,
) -> UUID:
    """One done ``kill`` / ``release`` failover row naming its switch (``kill_switch_id``)."""
    value: UUID = await conn.fetchval(
        "INSERT INTO sibyl.failover (tenant_id, agent_id, kind, state, step, priority,"
        " idempotency_key, actor_kind, actor_key_id, requested_by_user_id, from_state, to_state,"
        " routing_transition_id, kill_switch_id, step_results, finished_at)"
        " VALUES ($1, $2, $3, 'done', 'done', 'immediate', $4, $5, $6, $7, $8, $9, $10, $11,"
        "         $12::jsonb, now()) RETURNING id",
        tenant,
        agent_id,
        kind,
        key,
        actor.kind,
        actor.key_id if actor.kind == "api_key" else None,
        actor.user_id if actor.kind == "human" else None,
        from_state,
        to_state,
        transition_id,
        kill_switch_id,
        results,
    )
    return value


async def pull(
    conn: Any,
    env: Env,
    tenant: UUID,
    *,
    actor: Actor,
    roles: frozenset[str],
    scope_kind: str,
    scope_id: UUID | None,
    reason: str,
    client_ip: str,
) -> UUID:
    await check_scope(conn, tenant, scope_kind, scope_id)
    taken = await conn.fetchval(
        "SELECT id FROM sibyl.kill_switch WHERE tenant_id = $1 AND scope_kind = $2"
        " AND scope_id IS NOT DISTINCT FROM $3 AND state = 'pulled'",
        tenant,
        scope_kind,
        scope_id,
    )
    if taken is not None:
        raise ProblemError("already_pulled", extensions={"kill_switch_id": str(taken)})
    if scope_kind == "tenant":
        await second_owner_rule(conn, tenant, actor, roles)
    version = await conn.fetchval("SELECT routing_version FROM sibyl.tenant WHERE id = $1", tenant)
    ks = await conn.fetchval(
        "INSERT INTO sibyl.kill_switch (tenant_id, scope_kind, scope_id, reason, pulled_by,"
        " pulled_by_key_id, step_up_session_id, routing_version_at_pull)"
        " VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
        tenant,
        scope_kind,
        scope_id,
        reason,
        actor.user_id if actor.kind == "human" else None,
        actor.key_id if actor.kind == "api_key" else None,
        actor.session_id if actor.kind == "human" else None,
        int(version or 0),
    )
    detail_base = {
        "scope_kind": scope_kind,
        "scope_id": None if scope_id is None else str(scope_id),
        "session_id": None if actor.session_id is None else str(actor.session_id),
        "kill_switch_id": str(ks),
    }
    killed: list[str] = []
    for agent in await affected_agents(conn, tenant, scope_kind, scope_id):
        if agent["state"] == "killed":
            # Already killed by another switch: record coverage only (no routing change), so
            # releasing either switch keeps the agent killed while the other still covers it.
            await _record(
                conn,
                tenant,
                agent_id=agent["agent_id"],
                kind="kill",
                actor=actor,
                from_state="killed",
                to_state="killed",
                transition_id=None,
                kill_switch_id=ks,
                results={"already_killed": True},
                key=f"kill:{ks}:{agent['agent_id']}",
            )
            continue
        cancelled = await _cancel_live(conn, env, tenant, agent["agent_id"])
        applied = await routing.apply(
            conn,
            tenant,
            agent["agent_id"],
            expected_from=agent["state"],
            to_state="killed",
            trigger="operator",
            actor=actor,
            idempotency_key=f"kill:{ks}:{agent['agent_id']}",
            audit_action="killswitch.pulled",
            reason=reason,
            audit_detail={**detail_base, "snapshot_version": int(version or 0) + 1},
            request_id=env.request_id,
        )
        await _record(
            conn,
            tenant,
            agent_id=agent["agent_id"],
            kind="kill",
            actor=actor,
            from_state=agent["state"],
            to_state="killed",
            transition_id=applied.transition_id,
            kill_switch_id=ks,
            results={"cancelled_sagas": cancelled},
            key=f"kill:{ks}:{agent['agent_id']}",
        )
        killed.append(str(agent["agent_id"]))
    version = await conn.fetchval("SELECT routing_version FROM sibyl.tenant WHERE id = $1", tenant)
    await conn.execute(
        "UPDATE sibyl.kill_switch SET routing_version_at_pull = $3 WHERE tenant_id = $1 AND id ="
        " $2",
        tenant,
        ks,
        int(version or 0),
    )
    await env.audit.append(
        conn,
        tenant,
        AuditRecord(
            action="killswitch.pulled",
            **actor.audit_fields(),
            resource_type="kill_switch",
            resource_id=ks,
            reason=reason,
            detail={**detail_base, "snapshot_version": int(version or 0), "affected": len(killed)},
            request_id=env.request_id,
        ),
    )
    if actor.kind == "api_key":
        await env.audit.append(
            conn,
            tenant,
            AuditRecord(
                action="access.break_glass",
                **actor.audit_fields(),  # the key itself (B21, via core.audit.audit_actor)
                resource_type="kill_switch",
                resource_id=ks,
                detail={
                    "api_key_id": str(actor.key_id),
                    "action_taken": "killswitch.pull",
                    "scope_kind": scope_kind,
                    "scope_id": None if scope_id is None else str(scope_id),
                    "ip_hash": ip_hash(client_ip),
                },
                request_id=env.request_id,
            ),
        )
        await env.outbox.emit(
            conn,
            tenant,
            OutboxMessage.for_event(
                "audit.anchor_now",
                "kill_switch",
                ks,
                {"reason": "break_glass", "kill_switch_id": str(ks)},
            ),
        )
    await env.outbox.emit(
        conn,
        tenant,
        OutboxMessage.for_event(
            "killswitch.pulled",
            "kill_switch",
            ks,
            {
                "kill_switch_id": str(ks),
                "scope_kind": scope_kind,
                "scope_id": None if scope_id is None else str(scope_id),
                "routing_version": int(version or 0),
            },
        ),
    )
    return UUID(str(ks))


async def _covered_elsewhere(conn: Any, tenant: UUID, ks: UUID) -> set[UUID]:
    """Agents another still-pulled switch covers (they stay killed). Coverage is the switch's
    recorded ``kill`` rows, written for every agent in scope at pull time."""
    rows = await conn.fetch(
        "SELECT DISTINCT f.agent_id FROM sibyl.failover f JOIN sibyl.kill_switch k"
        " ON k.tenant_id = f.tenant_id AND k.id = f.kill_switch_id"
        " WHERE f.tenant_id = $1 AND f.kind = 'kill' AND k.state = 'pulled' AND k.id <> $2",
        tenant,
        ks,
    )
    return {r["agent_id"] for r in rows}


async def _state_before_kill(conn: Any, tenant: UUID, agent_id: UUID) -> str:
    value = await conn.fetchval(
        "SELECT from_state FROM sibyl.failover WHERE tenant_id = $1 AND agent_id = $2"
        " AND kind = 'kill' AND routing_transition_id IS NOT NULL"
        " ORDER BY created_at DESC LIMIT 1",
        tenant,
        agent_id,
    )
    return str(value or "active")


async def release(
    conn: Any,
    env: Env,
    tenant: UUID,
    kill_switch_id: UUID,
    *,
    actor: Actor,
    reason: str,
) -> list[str]:
    ks = await conn.fetchrow(
        "SELECT * FROM sibyl.kill_switch WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        tenant,
        kill_switch_id,
    )
    if ks is None:
        raise ProblemError("not_found")
    if ks["state"] != "pulled":
        raise ProblemError("not_pulled")
    await conn.execute(
        "UPDATE sibyl.kill_switch SET state = 'released', released_by = $3, released_at = now(),"
        " release_reason = $4, release_session_id = $5 WHERE tenant_id = $1 AND id = $2",
        tenant,
        kill_switch_id,
        actor.user_id,
        reason,
        actor.session_id,
    )
    killed_for = int(
        await conn.fetchval(
            "SELECT extract(epoch FROM now() - $1::timestamptz)::int", ks["pulled_at"]
        )
    )
    detail = {
        "scope_kind": ks["scope_kind"],
        "scope_id": None if ks["scope_id"] is None else str(ks["scope_id"]),
        "killed_for_s": killed_for,
        "kill_switch_id": str(kill_switch_id),
        "pulled_via": "break_glass" if ks["pulled_by_key_id"] is not None else "session",
    }
    covered = await _covered_elsewhere(conn, tenant, kill_switch_id)
    victims = await conn.fetch(
        "SELECT DISTINCT f.agent_id FROM sibyl.failover f JOIN sibyl.routing_state rs"
        " ON rs.tenant_id = f.tenant_id AND rs.agent_id = f.agent_id AND rs.state = 'killed'"
        " WHERE f.tenant_id = $1 AND f.kind = 'kill' AND f.kill_switch_id = $2",
        tenant,
        kill_switch_id,
    )
    released: list[str] = []
    for v in victims:
        agent_id = v["agent_id"]
        if agent_id in covered:
            continue
        before = await _state_before_kill(conn, tenant, agent_id)
        applied = await routing.apply(
            conn,
            tenant,
            agent_id,
            expected_from="killed",
            to_state="active",
            trigger="operator",
            actor=actor,
            idempotency_key=f"release:{kill_switch_id}:{agent_id}",
            audit_action="killswitch.released",
            reason=reason,
            audit_detail=detail,
            request_id=env.request_id,
        )
        await _record(
            conn,
            tenant,
            agent_id=agent_id,
            kind="release",
            actor=actor,
            from_state="killed",
            to_state="active",
            transition_id=applied.transition_id,
            kill_switch_id=kill_switch_id,
            results={},
            key=f"release:{kill_switch_id}:{agent_id}",
        )
        if before == "quarantined":
            # A kill never un-quarantines: the agent goes back to quarantine (needs quarantine:act
            # and its own audit to leave it).
            await routing.apply(
                conn,
                tenant,
                agent_id,
                expected_from="active",
                to_state="quarantined",
                trigger="operator",
                actor=actor,
                idempotency_key=f"release:{kill_switch_id}:{agent_id}:requarantine",
                audit_action="quarantine.applied",
                reason=reason,
                audit_detail={"cause": "restored_after_kill", "policy_violation_ids": []},
                request_id=env.request_id,
            )
        released.append(str(agent_id))
    await env.audit.append(
        conn,
        tenant,
        AuditRecord(
            action="killswitch.released",
            **actor.audit_fields(),
            resource_type="kill_switch",
            resource_id=kill_switch_id,
            reason=reason,
            detail={**detail, "released_agents": len(released)},
            request_id=env.request_id,
        ),
    )
    await env.outbox.emit(
        conn,
        tenant,
        OutboxMessage.for_event(
            "killswitch.released",
            "kill_switch",
            kill_switch_id,
            {"kill_switch_id": str(kill_switch_id), "released_agents": len(released)},
        ),
    )
    return released
