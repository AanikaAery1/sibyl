"""``/monitors/{id}/webhooks``: add a signed webhook, and send it a test ``ping``.

* The URL passes the provider ``base_url`` gates (``sibyl.is_allowlisted_base_url()``: https,
  public literal or FQDN, development doubles only through ``base_url_dev_host``; plus a resolver
  check that refuses names resolving to non-public addresses) and the deployment's
  ``SIBYL_WEBHOOK_ALLOWED_HOSTS`` when set (422 ``base_url_not_allowlisted``). Deliveries
  re-check the address at connect time (``worker.webhooks.deliver``).
* The signing secret is generated here, sealed under the tenant credential key and returned
  once (an Idempotency-Key replay carries ``secret: null``).
* The test sends one signed ``ping`` after the Idempotency-Key claim with no transaction held,
  records it as a settled delivery and audits ``webhook.tested``; a receiver failure is 200
  with ``ok`` false.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sibyl_schemas.models.monitor import WebhookCreate

from ...core.llm.types import EgressRefused
from ...core.problems import ProblemError
from ...worker.webhooks.deliver import (
    DeliveryResult,
    envelope,
    render_body,
    send,
    signed_headers,
    webhook_policy,
)
from ...worker.webhooks.secrets import (
    SecretUnavailable,
    new_secret,
    open_secret,
    seal_secret,
)
from ..auth.common import Outcome as Written
from ..auth.common import actor_record, human_reason, lane_state, principal_of, run_mutation
from ..auth.runtime import kek_for
from ..contract import API_PREFIX
from ..deps import AuthContext, get_services, guard
from ..registry._kit import Outcome, audit, require_db, services_of
from ..registry.ssrf import check_base_url
from ..sentinel.runtime import run_after_claim
from .routes import load_monitor
from .views import WEBHOOK_COLUMNS, webhook_view

BASE = API_PREFIX + "/monitors/{monitor_id}/webhooks"
RESOURCE = "monitor_webhook"
router = APIRouter()
_INSERT_SQL = f"""
INSERT INTO sibyl.monitor_webhook (tenant_id, id, monitor_id, url, event_types, credential_id,
  ciphertext, nonce, tenant_key_id, key_version, created_by_user_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING {WEBHOOK_COLUMNS}
"""  # noqa: S608 (constant columns)
_GET_SQL = (
    f"SELECT {WEBHOOK_COLUMNS} FROM sibyl.monitor_webhook"  # noqa: S608 (constant columns)
    " WHERE tenant_id = $1 AND id = $2 AND monitor_id = $3"
)
_DEV_HOSTS_SQL = "SELECT sibyl.base_url_dev_hosts()"
_PING_SQL = """
INSERT INTO sibyl.webhook_delivery (tenant_id, id, webhook_id, monitor_id, event_type, event_key,
  payload, status, attempts, last_attempt_at, response_code, error, settled_at)
VALUES ($1, $2, $3, $4, 'ping', $5, $6::jsonb, $7, 1, now(), $8, $9, now())
"""


async def _vet_url(conn: Any, settings: Any, url: str) -> None:
    try:
        await check_base_url(conn, url)
    except ProblemError:
        raise ProblemError(
            "base_url_not_allowlisted",
            "the webhook URL must be https on a public host (checked again at connect time)",
        ) from None
    try:
        webhook_policy(url, settings, await conn.fetchval(_DEV_HOSTS_SQL))
    except EgressRefused:
        raise ProblemError(
            "base_url_not_allowlisted",
            "the webhook host is not on this deployment's SIBYL_WEBHOOK_ALLOWED_HOSTS",
        ) from None


@router.post(BASE)
async def create_monitor_webhook(
    request: Request,
    monitor_id: UUID,
    body: WebhookCreate,
    ctx: Annotated[AuthContext, Depends(guard("createMonitorWebhook"))],
) -> Response:
    principal = principal_of(ctx)
    services = get_services(request)
    reason = human_reason(request, body.reason, ctx.op.operation_id)
    kek = kek_for(request)  # 503 before any write when the vault is not configured

    async def mutate(conn: Any) -> Written:
        tenant = principal.tenant_id
        monitor = await load_monitor(conn, tenant, monitor_id, lock=True)
        if monitor["state"] == "revoked":
            raise ProblemError("not_active", "the monitor is revoked")
        await _vet_url(conn, services.settings, body.url)
        webhook_id = uuid4()
        credential_id = uuid4()
        secret = new_secret()
        blob, key_id = await seal_secret(conn, kek, tenant, credential_id, secret)
        row = await conn.fetchrow(
            _INSERT_SQL,
            tenant,
            webhook_id,
            monitor_id,
            body.url,
            [e.value for e in body.event_types],
            credential_id,
            blob.ciphertext,
            blob.nonce,
            key_id,
            blob.key_version,
            principal.id,
        )
        receipt = await services.audit.append(
            conn,
            tenant,
            actor_record(
                ctx,
                "monitor.updated",
                resource_type="monitor",
                resource_id=monitor_id,
                resource_ref=monitor["name"],
                detail={
                    "monitor_id": str(monitor_id),
                    "change": {
                        "webhook_created": {
                            "webhook_id": str(webhook_id),
                            "host": body.url.split("/")[2] if "//" in body.url else body.url,
                            "event_types": sorted(e.value for e in body.event_types),
                        }
                    },
                },
                reason=reason,
            ),
        )
        view = webhook_view(row)
        return Written(
            201,
            view | {"secret": secret},
            headers={"Location": f"{API_PREFIX}/monitors/{monitor_id}/webhooks/{webhook_id}"},
            receipt=receipt,
            replay_body=view | {"secret": None},
        )

    return await run_mutation(request, ctx, mutate, idempotent=True)


@dataclass(frozen=True)
class _Ping:
    webhook: Any
    delivery_id: UUID
    payload: dict[str, Any]
    result: DeliveryResult


async def _ping(ctx: AuthContext, monitor_id: UUID, webhook_id: UUID) -> _Ping:
    services = services_of(ctx)
    db = require_db(services)
    request = ctx.request
    assert request is not None
    kek = kek_for(request)
    tenant = ctx.tenant_id
    delivery_id = uuid4()
    async with db.tenant_tx(tenant, readonly=True) as conn:
        monitor = await load_monitor(conn, tenant, monitor_id)
        webhook = await conn.fetchrow(_GET_SQL, tenant, webhook_id, monitor_id)
        if webhook is None:
            raise ProblemError("not_found")
        if monitor["state"] == "revoked" or webhook["state"] != "enabled":
            raise ProblemError("not_active", "the webhook or its monitor is not active")
        try:
            secret = await open_secret(conn, kek, tenant, webhook_id)
        except SecretUnavailable:
            raise ProblemError(
                "service_unavailable", "the webhook secret cannot be opened"
            ) from None
        dev = await conn.fetchval(_DEV_HOSTS_SQL)
    payload = envelope(
        event_id=uuid4(),
        event_type="ping",
        created_at=datetime.now(UTC),
        tenant_id=tenant,
        monitor_id=monitor_id,
        data={"message": "Sibyl webhook test", "webhook_id": str(webhook_id)},
    )
    body = render_body(payload)
    headers = signed_headers(
        secret, body, event_id=payload["id"], event_type="ping", delivery_id=delivery_id
    )
    del secret
    try:
        policy = webhook_policy(webhook["url"], services.settings, dev)
    except EgressRefused:
        result = DeliveryResult(False, 0, "egress_refused", 0)
    else:
        factory = lane_state(request).get("webhook_transport")
        result = await send(webhook["url"], body, headers, policy, transport_factory=factory)
    return _Ping(webhook, delivery_id, payload, result)


@router.post(BASE + "/{webhook_id}/test")
async def test_monitor_webhook(
    monitor_id: UUID,
    webhook_id: UUID,
    ctx: Annotated[AuthContext, Depends(guard("testMonitorWebhook"))],
) -> Response:
    async def prelude() -> _Ping:
        return await _ping(ctx, monitor_id, webhook_id)

    async def work(conn: Any, ping: _Ping) -> Outcome:
        result = ping.result
        await conn.execute(
            _PING_SQL,
            ctx.tenant_id,
            ping.delivery_id,
            webhook_id,
            monitor_id,
            f"ping:{ping.delivery_id}",
            ping.payload,
            "delivered" if result.ok else "dead",
            result.http_status or None,
            result.error,
        )
        receipt = await audit(
            conn,
            ctx,
            "webhook.tested",
            resource_type=RESOURCE,
            resource_id=webhook_id,
            detail={
                "monitor_id": str(monitor_id),
                "webhook_id": str(webhook_id),
                "ok": result.ok,
                "http_status": result.http_status,
                "error": result.error,
                "latency_ms": result.latency_ms,
            },
        )
        body = {
            "ok": result.ok,
            "http_status": result.http_status,
            "error": result.error,
            "latency_ms": result.latency_ms,
            "delivery_id": str(ping.delivery_id),
        }
        return Outcome(body, receipt=receipt)

    return await run_after_claim(ctx, prelude, work)
