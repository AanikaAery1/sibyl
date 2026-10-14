"""Handoff tasks: build (saga step ``create_handoff_tasks`` and SDK packets) and expiry.

* ``in_flight`` — the agent's tasks seen in the last 15 minutes (events or checkpoints) that have
  no ``task.outcome`` / handoff event and no open handoff task, with their latest checkpoint.
* ``create_for_saga`` — one task per in-flight task (``checkpoint`` fidelity when a checkpoint
  exists, else ``request_only``), or a single ``request_only`` task when the agent is handed to
  people (operator or rule, e.g. no viable fallback, S-15) with nothing in flight. Audit
  ``handoff.created``, outbox ``handoff.queued``.
  With ``hold_unsafe_only`` (a failover to a non-human route) only the tasks that may not
  continue on the new route by themselves get a task: those whose checkpoint records a side
  effect that is not ``idempotent: true`` (A-4, ``side_effects``). The step result carries the
  side-effect ledger of every in-flight task.
* ``build_sdk_tasks`` — SDK ``handoff.requested`` events become tasks that reference the stored
  packet (``packet_ref_id``); the control plane sets the deadline (D23) and accountability.
* ``expire`` / ``lapse_claims`` — queued tasks past their deadline expire (counts against the RTO
  SLI); claims whose 30-minute lock lapsed go back to the queue.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from ...core.audit import AuditRecord, AuditWriter
from ...core.outbox import OutboxMessage, OutboxWriter
from ..saga.model import IN_FLIGHT_WINDOW, MAX_TASKS_PER_SAGA, TIER_RTO_S, Actor
from .packet import BuiltPacket, PacketContext, TaskInput, build, checkpoint_age_p95
from .side_effects import ledger_of, unsafe_to_resume

FAILURE_MODES = frozenset(
    {
        "provider_outage",
        "latency_degradation",
        "quality_collapse",
        "prompt_injection",
        "policy_violation",
        "tool_failure",
        "data_source_failure",
        "infinite_loop",
        "cost_runaway",
        "permission_error",
        "model_deprecation",
        "silent_drift",
    }
)
CLAIM_LOCK = timedelta(minutes=30)
MAX_LEDGER_ENTRIES = 200

_IN_FLIGHT_SQL = """
WITH seen AS (
  SELECT task_id, min(ts) AS first_ts FROM sibyl.events
   WHERE tenant_id = $1 AND agent_id = $2 AND task_id IS NOT NULL AND ts > now() - $3::interval
   GROUP BY task_id
  HAVING bool_and(event_type NOT IN ('task.outcome', 'handoff.requested', 'handoff.completed',
                                     'handoff.returned'))
  UNION
  SELECT task_id, min(created_at) FROM sibyl.checkpoint
   WHERE tenant_id = $1 AND agent_id = $2 AND created_at > now() - $3::interval
   GROUP BY task_id
)
SELECT s.task_id, min(s.first_ts) AS first_ts FROM seen s
 WHERE NOT EXISTS (SELECT 1 FROM sibyl.events e WHERE e.tenant_id = $1 AND e.task_id = s.task_id
                     AND e.ts > now() - $3::interval
                     AND e.event_type IN ('task.outcome', 'handoff.requested', 'handoff.completed'))
   AND NOT EXISTS (SELECT 1 FROM sibyl.handoff_task h WHERE h.tenant_id = $1 AND h.task_id =
     s.task_id
                     AND h.state IN ('queued', 'claimed'))
 GROUP BY s.task_id ORDER BY min(s.first_ts) LIMIT $4
"""
_LATEST_CHECKPOINT_SQL = """
SELECT DISTINCT ON (task_id) task_id, id, seq, created_at, doc, capture_mode FROM sibyl.checkpoint
 WHERE tenant_id = $1 AND agent_id = $2 AND task_id = ANY($3::uuid[])
   AND created_at > now() - $4::interval
 ORDER BY task_id, seq DESC, created_at DESC
"""
_FIRST_INPUT_SQL = """
SELECT DISTINCT ON (e.task_id) e.task_id, e.trace_id, p.uri, p.sha256, p.size_bytes, p.content_type
  FROM sibyl.events e LEFT JOIN sibyl.payload_refs p
    ON p.tenant_id = e.tenant_id AND p.id = e.payload_ref_id AND p.state = 'stored'
 WHERE e.tenant_id = $1 AND e.task_id = ANY($2::uuid[]) AND e.event_type = 'gen_ai.request'
   AND e.ts > now() - $3::interval
 ORDER BY e.task_id, e.ts
"""
_INSERT_SQL = """
INSERT INTO sibyl.handoff_task (tenant_id, id, agent_id, failover_id, routing_transition_id,
  task_id,
  packet_id, packet, packet_ref_id, packet_sha256, fidelity, failure_mode, trigger_kind, rule_code,
  alert_id, assembled_by, priority, deadline_at, accountable_user_id, next_action, summary)
VALUES ($1, sibyl.uuidv7(), $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11, $12, $13, $14, $15,
        $16, $17, $18, $19, $20)
ON CONFLICT DO NOTHING
RETURNING id
"""


@dataclass(frozen=True)
class Accountability:
    owner: str
    owner_user_id: UUID | None
    on_call: str | None
    on_call_user_id: UUID | None
    business_process: str | None
    rto_s: int


async def accountability(
    conn: Any, tenant: UUID, agent_id: UUID, tier: int, owner_user_id: UUID | None
) -> Accountability:
    row = await conn.fetchrow(
        "SELECT (SELECT coalesce(u.email, u.display_name) FROM sibyl.app_user u"
        "         WHERE u.tenant_id = a.tenant_id AND u.id = a.owner_user_id) AS owner,"
        " (SELECT bp.name FROM sibyl.business_process bp WHERE bp.tenant_id = a.tenant_id"
        "    AND bp.id = a.business_process_id) AS business_process,"
        " p.rto_s, p.on_call_user_id, p.on_call_ref,"
        " (SELECT coalesce(u.email, u.display_name) FROM sibyl.app_user u"
        "   WHERE u.tenant_id = a.tenant_id AND u.id = p.on_call_user_id) AS on_call"
        " FROM sibyl.agent a LEFT JOIN sibyl.continuity_plan p"
        "   ON p.tenant_id = a.tenant_id AND p.agent_id = a.id"
        " WHERE a.tenant_id = $1 AND a.id = $2",
        tenant,
        agent_id,
    )
    return Accountability(
        owner=(row["owner"] if row and row["owner"] else "unassigned"),
        owner_user_id=owner_user_id,
        on_call=(row["on_call"] or row["on_call_ref"]) if row else None,
        on_call_user_id=row["on_call_user_id"] if row else None,
        business_process=row["business_process"] if row else None,
        rto_s=int(row["rto_s"]) if row and row["rto_s"] else TIER_RTO_S.get(int(tier), 14400),
    )


async def in_flight(conn: Any, tenant: UUID, agent_id: UUID) -> list[TaskInput]:
    rows = await conn.fetch(_IN_FLIGHT_SQL, tenant, agent_id, IN_FLIGHT_WINDOW, MAX_TASKS_PER_SAGA)
    ids = [r["task_id"] for r in rows]
    if not ids:
        return []
    checkpoints = {
        r["task_id"]: r
        for r in await conn.fetch(_LATEST_CHECKPOINT_SQL, tenant, agent_id, ids, IN_FLIGHT_WINDOW)
    }
    inputs = {
        r["task_id"]: r for r in await conn.fetch(_FIRST_INPUT_SQL, tenant, ids, IN_FLIGHT_WINDOW)
    }
    out: list[TaskInput] = []
    for task_id in ids:
        cp = checkpoints.get(task_id)
        first = inputs.get(task_id)
        trace = first["trace_id"].hex if first is not None and first["trace_id"] else None
        out.append(
            TaskInput(
                task_id=task_id,
                checkpoint_id=cp["id"] if cp else None,
                checkpoint_seq=cp["seq"] if cp else None,
                checkpoint_at=cp["created_at"] if cp else None,
                checkpoint_doc=cp["doc"] if cp else None,
                capture_mode=cp["capture_mode"] if cp else None,
                first_input=dict(first) if first is not None and first["uri"] else None,
                trace_ids=(trace,) if trace else (),
            )
        )
    return out


async def insert_task(
    conn: Any,
    tenant: UUID,
    *,
    agent_id: UUID,
    failover_id: UUID | None,
    transition_id: UUID | None,
    task_id: UUID,
    packet_id: UUID,
    built: BuiltPacket | None,
    packet_ref_id: UUID | None = None,
    packet_sha256: bytes | None = None,
    fidelity: str,
    failure_mode: str,
    trigger_kind: str,
    rule_code: str | None,
    alert_id: UUID | None,
    assembled_by: str,
    priority: int,
    deadline_at: datetime,
    accountable_user_id: UUID | None,
    next_action: str,
    summary: str,
) -> UUID | None:
    row_id: UUID | None = await conn.fetchval(
        _INSERT_SQL,
        tenant,
        agent_id,
        failover_id,
        transition_id,
        task_id,
        packet_id,
        built.packet if built is not None else None,
        packet_ref_id,
        built.sha256 if built is not None else packet_sha256,
        fidelity,
        failure_mode,
        trigger_kind,
        rule_code,
        alert_id,
        assembled_by,
        max(1, min(3, priority)),
        deadline_at,
        accountable_user_id,
        next_action[:2000],
        summary[:500],
    )
    return row_id


async def announce(
    conn: Any,
    tenant: UUID,
    *,
    audit: AuditWriter,
    outbox: OutboxWriter,
    actor: Actor,
    task_row_id: UUID,
    task_id: UUID,
    agent_id: UUID,
    packet_sha256: bytes,
    fidelity: str,
    trigger: str,
    request_id: UUID | None = None,
) -> None:
    await audit.append(
        conn,
        tenant,
        AuditRecord(
            action="handoff.created",
            actor_type=actor.kind,
            actor_id=actor.user_id or actor.rule_id,
            actor_key_id=actor.key_id,
            resource_type="handoff_task",
            resource_id=task_row_id,
            detail={
                "task_id": str(task_id),
                "handoff_task_id": str(task_row_id),
                "agent_id": str(agent_id),
                "packet_sha256": packet_sha256.hex(),
                "fidelity": fidelity,
                "trigger": trigger,
            },
            request_id=request_id,
        ),
    )
    await outbox.emit(
        conn,
        tenant,
        OutboxMessage.for_event(
            "handoff.queued",
            "handoff_task",
            task_row_id,
            {"handoff_task_id": str(task_row_id), "agent_id": str(agent_id), "fidelity": fidelity},
        ),
    )


@dataclass(frozen=True)
class SagaTaskSpec:
    """The saga's view of a handoff: who, why, and from which transition."""

    failover_id: UUID
    transition_id: UUID | None
    agent: Mapping[str, Any]
    failure_mode: str
    trigger_kind: str
    rule_code: str | None
    alert_id: UUID | None
    health_snapshot_id: UUID | None
    reason: str
    actor: Actor


async def create_for_saga(
    conn: Any,
    tenant: UUID,
    spec: SagaTaskSpec,
    *,
    audit: AuditWriter,
    outbox: OutboxWriter,
    request_id: UUID | None = None,
    hold_unsafe_only: bool = False,
    seen: list[TaskInput] | None = None,
) -> dict[str, Any]:
    """Build and store the tasks; returns the step result (counts, RPO evidence, A-4 ledger).

    ``hold_unsafe_only``: build tasks only for in-flight work that may not be resumed
    automatically (non-idempotent recorded side effects); the rest continues on the new route.
    ``seen``: the in-flight tasks the caller already read (saves a second query)."""
    tasks = list(seen) if seen is not None else await in_flight(conn, tenant, spec.agent["id"])
    unsafe = [t for t in tasks if unsafe_to_resume(t)]
    held = {t.task_id for t in unsafe}
    ledger = ledger_of(tasks)
    if hold_unsafe_only:
        to_build = unsafe
    else:
        to_build = list(tasks)
        if not to_build:  # the agent's work goes to people even with no tracked task in flight
            new_id = await conn.fetchval("SELECT sibyl.uuidv7()")
            to_build = [TaskInput(task_id=new_id)]
    if not to_build:
        empty = {"checkpoint": 0, "request_only": 0}
        return _record(tasks, unsafe, ledger, [], empty, None, hold_mode=hold_unsafe_only)
    acct = await accountability(
        conn, tenant, spec.agent["id"], int(spec.agent["tier"]), spec.agent.get("owner_user_id")
    )
    policy_version = await conn.fetchval(
        "SELECT routing_version FROM sibyl.tenant WHERE id = $1", tenant
    )
    now = await conn.fetchval("SELECT now()")
    ctx = PacketContext(
        tenant_id=tenant,
        agent_id=spec.agent["id"],
        agent_name=str(spec.agent["slug"]),
        tier=int(spec.agent["tier"]),
        rto_s=acct.rto_s,
        failure_mode=spec.failure_mode if spec.failure_mode in FAILURE_MODES else "tool_failure",
        trigger_kind=spec.trigger_kind,
        rule_code=spec.rule_code,
        alert_id=spec.alert_id,
        health_snapshot_id=spec.health_snapshot_id,
        policy_version=int(policy_version or 0),
        transition_id=spec.transition_id,
        owner=acct.owner,
        on_call=acct.on_call,
        business_process=acct.business_process,
        reason=spec.reason,
    )
    created: list[str] = []
    fidelity: dict[str, int] = {"checkpoint": 0, "request_only": 0}
    for task in to_build:
        packet_id = await conn.fetchval("SELECT sibyl.uuidv7()")
        built = build(
            ctx, task, packet_id=packet_id, now=now, side_effect_hold=task.task_id in held
        )
        row_id = await insert_task(
            conn,
            tenant,
            agent_id=spec.agent["id"],
            failover_id=spec.failover_id,
            transition_id=spec.transition_id,
            task_id=task.task_id,
            packet_id=packet_id,
            built=built,
            fidelity=built.fidelity,
            failure_mode=ctx.failure_mode,
            trigger_kind=spec.trigger_kind,
            rule_code=spec.rule_code,
            alert_id=spec.alert_id,
            assembled_by="control_plane",
            priority=int(spec.agent["tier"]),
            deadline_at=built.deadline_at,
            accountable_user_id=acct.on_call_user_id or acct.owner_user_id,
            next_action=built.next_action,
            summary=built.summary,
        )
        if row_id is None:  # already built by an earlier attempt of this saga
            continue
        fidelity[built.fidelity] += 1
        created.append(str(row_id))
        await announce(
            conn,
            tenant,
            audit=audit,
            outbox=outbox,
            actor=spec.actor,
            task_row_id=row_id,
            task_id=task.task_id,
            agent_id=spec.agent["id"],
            packet_sha256=built.sha256,
            fidelity=built.fidelity,
            trigger=spec.trigger_kind,
            request_id=request_id,
        )
    rpo_p95 = checkpoint_age_p95(to_build, now)
    rpo_target = await conn.fetchval(
        "SELECT rpo_s FROM sibyl.continuity_plan WHERE tenant_id = $1 AND agent_id = $2",
        tenant,
        spec.agent["id"],
    )
    rpo = {
        "checkpoint_age_p95_s": rpo_p95,
        "rpo_s": rpo_target,
        "rpo_met": None if rpo_p95 is None or rpo_target is None else rpo_p95 <= rpo_target,
    }
    counted = tasks if hold_unsafe_only else to_build
    return _record(counted, unsafe, ledger, created, fidelity, rpo, hold_mode=hold_unsafe_only)


def _record(
    tasks: list[TaskInput],
    unsafe: list[TaskInput],
    ledger: list[dict[str, Any]],
    created: list[str],
    fidelity: dict[str, int],
    rpo: dict[str, Any] | None,
    *,
    hold_mode: bool,
) -> dict[str, Any]:
    """The ``create_handoff_tasks`` step result. ``continued_on_new_route`` counts in-flight
    tasks left to the new route (0 when everything went to the human queue)."""
    out: dict[str, Any] = {
        "in_flight": len(tasks),
        "created": created,
        "fidelity": fidelity,
        "held_for_operator": [str(t.task_id) for t in unsafe],
        "continued_on_new_route": len(tasks) - len(unsafe) if hold_mode else 0,
        "side_effect_ledger": ledger[:MAX_LEDGER_ENTRIES],
    }
    if len(ledger) > MAX_LEDGER_ENTRIES:
        out["side_effect_ledger_truncated"] = len(ledger)
    if rpo is not None:
        out.update(rpo)
    return out


async def count_in_flight(conn: Any, tenant: UUID, agent_id: UUID) -> int:
    rows = await conn.fetch(_IN_FLIGHT_SQL, tenant, agent_id, IN_FLIGHT_WINDOW, MAX_TASKS_PER_SAGA)
    return len(rows)


# --- worker loop: SDK packets, expiry, lapsed claims ------------------------------------------

_SDK_EVENTS_SQL = """
SELECT e.event_id, e.ts, e.agent_id, e.task_id, e.payload_ref_id, e.payload_sha256, e.attrs,
       a.tier, a.slug, a.owner_user_id
  FROM sibyl.events e JOIN sibyl.agent a ON a.tenant_id = e.tenant_id AND a.id = e.agent_id
 WHERE e.tenant_id = $1 AND e.event_type = 'handoff.requested' AND e.task_id IS NOT NULL
   AND e.ts > now() - $2::interval
   AND NOT EXISTS (SELECT 1 FROM sibyl.handoff_task h WHERE h.tenant_id = e.tenant_id
                     AND (h.packet_id = e.event_id OR (h.task_id = e.task_id AND h.failover_id IS
                       NULL
                          AND h.assembled_by = 'sdk')))
 ORDER BY e.ts LIMIT $3
"""
SDK_LOOKBACK = timedelta(hours=1)


def _attr(attrs: Mapping[str, Any] | None, *names: str) -> Any:
    for name in names:
        if attrs and attrs.get(name) is not None:
            return attrs[name]
    return None


async def build_sdk_tasks(
    conn: Any, tenant: UUID, *, audit: AuditWriter, outbox: OutboxWriter, limit: int = 50
) -> int:
    """SDK ``handoff.requested`` events → tasks referencing the stored packet."""
    n = 0
    for ev in await conn.fetch(_SDK_EVENTS_SQL, tenant, SDK_LOOKBACK, limit):
        if ev["payload_ref_id"] is None or ev["payload_sha256"] is None:
            continue  # metadata capture: no packet was stored; nothing to hand to a human
        attrs = ev["attrs"] or {}
        acct = await accountability(conn, tenant, ev["agent_id"], ev["tier"], ev["owner_user_id"])
        mode = _attr(attrs, "sibyl.handoff.failure_mode", "failure_mode")
        fidelity = _attr(attrs, "sibyl.handoff.fidelity", "fidelity")
        packet_id = _attr(attrs, "sibyl.handoff.packet_id", "packet_id")
        try:
            pid = UUID(str(packet_id)) if packet_id else ev["event_id"]
        except ValueError:
            pid = ev["event_id"]
        row_id = await insert_task(
            conn,
            tenant,
            agent_id=ev["agent_id"],
            failover_id=None,
            transition_id=None,
            task_id=ev["task_id"],
            packet_id=pid,
            built=None,
            packet_ref_id=ev["payload_ref_id"],
            packet_sha256=bytes(ev["payload_sha256"]),
            fidelity=fidelity if fidelity in ("checkpoint", "request_only") else "request_only",
            failure_mode=mode if mode in FAILURE_MODES else "tool_failure",
            trigger_kind="sdk_explicit",
            rule_code=None,
            alert_id=None,
            assembled_by="sdk",
            priority=int(ev["tier"]),
            deadline_at=ev["ts"] + timedelta(seconds=acct.rto_s),
            accountable_user_id=acct.on_call_user_id or acct.owner_user_id,
            next_action=str(_attr(attrs, "sibyl.handoff.next_action", "next_action") or "")
            or "Review the SDK handoff packet and finish the task.",
            summary=str(_attr(attrs, "sibyl.handoff.summary", "summary") or "")
            or f"{ev['slug']}: SDK handoff",
        )
        if row_id is None:
            continue
        n += 1
        await announce(
            conn,
            tenant,
            audit=audit,
            outbox=outbox,
            actor=Actor("system"),
            task_row_id=row_id,
            task_id=ev["task_id"],
            agent_id=ev["agent_id"],
            packet_sha256=bytes(ev["payload_sha256"]),
            fidelity="request_only" if fidelity != "checkpoint" else "checkpoint",
            trigger="sdk_explicit",
        )
    return n


async def expire(conn: Any, tenant: UUID, *, audit: AuditWriter, outbox: OutboxWriter) -> int:
    rows = await conn.fetch(
        "UPDATE sibyl.handoff_task SET state = 'expired', outcome = 'expired_unclaimed'"
        " WHERE tenant_id = $1 AND state = 'queued' AND deadline_at <= now()"
        " RETURNING id, task_id, agent_id, extract(epoch FROM deadline_at - created_at)::int AS"
        " ttl",
        tenant,
    )
    for r in rows:
        await audit.append(
            conn,
            tenant,
            AuditRecord(
                action="handoff.expired",
                actor_type="system",
                resource_type="handoff_task",
                resource_id=r["id"],
                detail={"task_id": str(r["task_id"]), "ttl_s": int(r["ttl"] or 0)},
            ),
        )
        await outbox.emit(
            conn,
            tenant,
            OutboxMessage.for_event(
                "handoff.expired",
                "handoff_task",
                r["id"],
                {"handoff_task_id": str(r["id"]), "agent_id": str(r["agent_id"])},
            ),
        )
    return len(rows)


async def lapse_claims(conn: Any, tenant: UUID, *, audit: AuditWriter) -> int:
    rows = await conn.fetch(
        "UPDATE sibyl.handoff_task SET state = 'queued', claimed_by_user_id = NULL,"
        " claimed_at = NULL, claim_lock_until = NULL"
        " WHERE tenant_id = $1 AND state = 'claimed' AND claim_lock_until <= now()"
        " RETURNING id, task_id",
        tenant,
    )
    for r in rows:
        await audit.append(
            conn,
            tenant,
            AuditRecord(
                action="handoff.claim_released",
                actor_type="system",
                resource_type="handoff_task",
                resource_id=r["id"],
                detail={"task_id": str(r["task_id"]), "cause": "lock_lapsed"},
            ),
        )
    return len(rows)
