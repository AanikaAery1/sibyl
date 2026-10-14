"""Held-action timeouts (ACTION-GATE.md §3): a pending hold past ``expires_at`` (creation +
the policy's ``hold_timeout_s``) is ``expired`` with decision ``deny`` (the default is always
deny), audited ``action.expired`` (actor ``system``) and announced on the ``action`` topic so the
waiting enforcement point stops at once. Its decision trail ends with an ``expired`` entry
(``api/action_gate/history.py`` shape).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from ...core.audit import AuditRecord
from ...core.outbox import OutboxMessage
from ..saga.model import Env

log = logging.getLogger("sibyl.held_actions")
_DUE_SQL = """
SELECT id FROM sibyl.held_action
 WHERE tenant_id = $1 AND state = 'pending' AND expires_at <= now()
 ORDER BY expires_at LIMIT $2
"""
_EXPIRE_SQL = """
UPDATE sibyl.held_action h SET state = 'expired', decision = 'deny', resolved_by_timeout = true,
       decided_at = now(),
       history = h.history || jsonb_build_array(jsonb_build_object(
         'at', sibyl.rfc3339(now()), 'kind', 'expired', 'user_id', NULL, 'key_id', NULL,
         'reason', 'hold timeout; default deny', 'step_up', false, 'code', NULL,
         'approvals', jsonb_array_length(h.approvals)))
  FROM (SELECT id FROM sibyl.held_action WHERE tenant_id = $1 AND id = $2 AND state = 'pending'
          AND expires_at <= now() FOR UPDATE SKIP LOCKED) due
 WHERE h.tenant_id = $1 AND h.id = due.id
RETURNING h.*
"""


@dataclass(frozen=True)
class Expired:
    held_action_id: UUID
    agent_id: UUID


async def expire_one(conn: Any, env: Env, tenant: UUID, held_action_id: UUID) -> Expired | None:
    row = await conn.fetchrow(_EXPIRE_SQL, tenant, held_action_id)
    if row is None:
        return None
    await env.audit.append(
        conn,
        tenant,
        AuditRecord(
            action="action.expired",
            actor_type="system",
            resource_type="held_action",
            resource_id=row["id"],
            detail={
                "held_action_id": str(row["id"]),
                "agent_id": str(row["agent_id"]),
                "tool": row["tool"],
                "hold_timeout_s": int(row["hold_timeout_s"]),
                "decision": "deny",
            },
        ),
    )
    await env.outbox.emit(
        conn,
        tenant,
        OutboxMessage.for_event(
            "action.expired",
            "held_action",
            row["id"],
            {
                "held_action_id": str(row["id"]),
                "agent_id": str(row["agent_id"]),
                "tool": row["tool"],
                "state": "expired",
                "decision": "deny",
            },
        ),
    )
    return Expired(row["id"], row["agent_id"])


async def run_tenant(db: Any, env: Env, tenant: UUID, *, limit: int = 100) -> list[Expired]:
    async with db.tenant_tx(tenant, readonly=True) as conn:
        due = [r["id"] for r in await conn.fetch(_DUE_SQL, tenant, limit)]
    out: list[Expired] = []
    for held_action_id in due:
        try:
            async with db.tenant_tx(tenant) as conn:
                await conn.execute("SELECT sibyl.audit_lock($1)", tenant)
                done = await expire_one(conn, env, tenant, held_action_id)
        except Exception:
            log.exception("held action %s could not be expired", held_action_id)
            continue
        if done is not None:
            out.append(done)
    return out
