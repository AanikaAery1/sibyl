"""Send due deliveries: claim, send outside any transaction, record (D53).

1. **Claim** (one short transaction): up to ``CLAIM`` due rows (``pending`` / ``retrying`` with
   ``next_attempt_at <= now()``) are leased by pushing ``next_attempt_at`` forward, so another
   worker skips them; each is joined to its webhook and monitor, and the webhook's secret is
   opened.
2. **Send** with no transaction held (``deliver.send``: allowlist of one host, connect-time
   address check, TLS verified, signed).
3. **Record** (one short transaction per delivery): delivered, retrying with backoff, or dead
   (``webhook.delivery_failed`` audited, system actor). A webhook whose deliveries keep dying is
   disabled.

A paused monitor's deliveries wait (re-leased for five minutes); a revoked monitor's or disabled
webhook's are dead-lettered without a request. The secret never leaves this module's locals.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Final
from uuid import UUID

from ...core.audit import AuditActor, AuditRecord, AuditWriter
from ...core.crypto.envelope import KeyEncryptionKey
from ...core.llm.types import EgressRefused
from .deliver import (
    DISABLE_AFTER_FAILURES,
    MAX_ATTEMPTS,
    DeliveryResult,
    TransportFactory,
    backoff_s,
    render_body,
    send,
    signed_headers,
    webhook_policy,
)
from .secrets import SecretUnavailable, open_secret

CLAIM: Final = 20
LEASE: Final = timedelta(minutes=2)
PAUSED_WAIT: Final = timedelta(minutes=5)
SYSTEM_ACTOR: Final = AuditActor("system", None, None, None)
_DEV_HOSTS_SQL = "SELECT sibyl.base_url_dev_hosts()"
_CLAIM_SQL = """
UPDATE sibyl.webhook_delivery d SET next_attempt_at = now() + $3::interval
  FROM (SELECT id FROM sibyl.webhook_delivery
         WHERE tenant_id = $1 AND status IN ('pending', 'retrying') AND next_attempt_at <= now()
         ORDER BY next_attempt_at
         LIMIT $2
         FOR UPDATE SKIP LOCKED) due
 WHERE d.tenant_id = $1 AND d.id = due.id
RETURNING d.id, d.webhook_id, d.monitor_id, d.event_type, d.payload, d.attempts
"""
_TARGET_SQL = """
SELECT w.url, w.state AS webhook_state, m.state AS monitor_state
  FROM sibyl.monitor_webhook w
  JOIN sibyl.monitor m ON m.tenant_id = w.tenant_id AND m.id = w.monitor_id
 WHERE w.tenant_id = $1 AND w.id = $2
"""
_WAIT_SQL = (
    "UPDATE sibyl.webhook_delivery SET next_attempt_at = now() + $3::interval"
    " WHERE tenant_id = $1 AND id = $2"
)
_DELIVERED_SQL = """
UPDATE sibyl.webhook_delivery SET status = 'delivered', attempts = attempts + 1,
       last_attempt_at = now(), response_code = $3, error = NULL, settled_at = now()
 WHERE tenant_id = $1 AND id = $2
"""
_RETRY_SQL = """
UPDATE sibyl.webhook_delivery SET status = 'retrying', attempts = attempts + 1,
       last_attempt_at = now(), response_code = $3, error = $4,
       next_attempt_at = now() + $5::interval
 WHERE tenant_id = $1 AND id = $2
"""
_DEAD_SQL = """
UPDATE sibyl.webhook_delivery SET status = 'dead', attempts = attempts + $5,
       last_attempt_at = CASE WHEN $5 > 0 THEN now() ELSE last_attempt_at END,
       response_code = $3, error = $4, settled_at = now()
 WHERE tenant_id = $1 AND id = $2
RETURNING attempts
"""
_WEBHOOK_OK_SQL = """
UPDATE sibyl.monitor_webhook SET consecutive_failures = 0, last_delivery_at = now(),
       last_delivery_status = 'delivered', last_response_code = $3
 WHERE tenant_id = $1 AND id = $2
"""
_WEBHOOK_RETRY_SQL = """
UPDATE sibyl.monitor_webhook SET last_delivery_at = now(), last_delivery_status = 'retrying',
       last_response_code = $3
 WHERE tenant_id = $1 AND id = $2
"""
_WEBHOOK_DEAD_SQL = """
UPDATE sibyl.monitor_webhook SET consecutive_failures = consecutive_failures + 1,
       last_delivery_at = now(), last_delivery_status = 'dead', last_response_code = $3,
       state = CASE WHEN consecutive_failures + 1 >= $4 THEN 'disabled' ELSE state END,
       disabled_reason = CASE WHEN consecutive_failures + 1 >= $4 AND state = 'enabled'
                              THEN 'deliveries kept failing' ELSE disabled_reason END
 WHERE tenant_id = $1 AND id = $2
"""


@dataclass(frozen=True)
class Claimed:
    id: UUID
    webhook_id: UUID
    monitor_id: UUID
    event_type: str
    payload: Mapping[str, Any]
    attempts: int


@dataclass
class Prepared:
    claimed: Claimed
    url: str = ""
    secret: str = field(default="", repr=False)
    policy: Any = None
    skip: str | None = None  # wait | dead:<reason>


@dataclass(frozen=True)
class DispatchDeps:
    kek: KeyEncryptionKey
    audit: AuditWriter
    settings: Any
    transport_factory: TransportFactory | None = None


async def claim(conn: Any, tenant: UUID) -> list[Claimed]:
    rows = await conn.fetch(_CLAIM_SQL, tenant, CLAIM, LEASE)
    out = []
    for r in rows:
        payload = r["payload"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        out.append(
            Claimed(
                r["id"], r["webhook_id"], r["monitor_id"], r["event_type"], payload, r["attempts"]
            )
        )
    return out


async def prepare(conn: Any, deps: DispatchDeps, tenant: UUID, item: Claimed) -> Prepared:
    prepared = Prepared(item)
    target = await conn.fetchrow(_TARGET_SQL, tenant, item.webhook_id)
    if (
        target is None
        or target["webhook_state"] != "enabled"
        or target["monitor_state"] == "revoked"
    ):
        prepared.skip = "dead:webhook_disabled"
        return prepared
    if target["monitor_state"] == "paused":
        prepared.skip = "wait"
        return prepared
    dev = await conn.fetchval(_DEV_HOSTS_SQL)
    try:
        prepared.policy = webhook_policy(target["url"], deps.settings, dev)
    except EgressRefused:
        prepared.skip = "dead:egress_refused"
        return prepared
    try:
        prepared.secret = await open_secret(conn, deps.kek, tenant, item.webhook_id)
    except SecretUnavailable:
        prepared.skip = "dead:secret_unavailable"
        return prepared
    prepared.url = target["url"]
    return prepared


async def deliver_one(deps: DispatchDeps, prepared: Prepared) -> DeliveryResult:
    item = prepared.claimed
    body = render_body(item.payload)
    headers = signed_headers(
        prepared.secret,
        body,
        event_id=str(item.payload.get("id", item.id)),
        event_type=item.event_type,
        delivery_id=item.id,
    )
    prepared.secret = ""
    return await send(
        prepared.url, body, headers, prepared.policy, transport_factory=deps.transport_factory
    )


async def record(
    conn: Any,
    deps: DispatchDeps,
    tenant: UUID,
    item: Claimed,
    result: DeliveryResult | None,
    skip: str | None = None,
) -> str:
    """Persist one outcome; returns ``delivered`` | ``retrying`` | ``dead`` | ``waiting``."""
    if skip == "wait":
        await conn.execute(_WAIT_SQL, tenant, item.id, PAUSED_WAIT)
        return "waiting"
    if skip is not None:
        reason = skip.removeprefix("dead:")
        await _dead(conn, deps, tenant, item, 0, reason, attempted=0)
        return "dead"
    assert result is not None
    if result.ok:
        await conn.execute(_DELIVERED_SQL, tenant, item.id, result.http_status)
        await conn.execute(_WEBHOOK_OK_SQL, tenant, item.webhook_id, result.http_status)
        return "delivered"
    attempts = item.attempts + 1
    if result.retryable and attempts < MAX_ATTEMPTS:
        wait = timedelta(seconds=backoff_s(attempts))
        await conn.execute(
            _RETRY_SQL, tenant, item.id, result.http_status or None, result.error, wait
        )
        await conn.execute(_WEBHOOK_RETRY_SQL, tenant, item.webhook_id, result.http_status or None)
        return "retrying"
    await _dead(
        conn, deps, tenant, item, result.http_status, result.error or "http_error", attempted=1
    )
    return "dead"


async def _dead(
    conn: Any,
    deps: DispatchDeps,
    tenant: UUID,
    item: Claimed,
    http_status: int,
    error: str,
    *,
    attempted: int,
) -> None:
    attempts = await conn.fetchval(
        _DEAD_SQL, tenant, item.id, http_status or None, error[:200], attempted
    )
    await conn.execute(
        _WEBHOOK_DEAD_SQL, tenant, item.webhook_id, http_status or None, DISABLE_AFTER_FAILURES
    )
    record = AuditRecord(
        action="webhook.delivery_failed",
        resource_type="monitor_webhook",
        resource_id=item.webhook_id,
        detail={
            "monitor_id": str(item.monitor_id),
            "webhook_id": str(item.webhook_id),
            "delivery_id": str(item.id),
            "event_type": item.event_type,
            "attempts": int(attempts or 0),
            "http_status": int(http_status or 0),
            "error": error,
        },
        **SYSTEM_ACTOR.fields(),
    )
    await deps.audit.append(conn, tenant, record)
