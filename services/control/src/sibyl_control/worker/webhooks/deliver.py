"""One signed webhook delivery over the guarded network path (D53).

Every request:

* goes only to the webhook's own registered host (``EgressPolicy`` allowlist of one), and only
  when the deployment's ``SIBYL_WEBHOOK_ALLOWED_HOSTS`` (if set) allows that host;
* is https (``http`` only for ``base_url_dev_host`` development doubles), carries no userinfo,
  follows no redirect and ignores environment proxies;
* resolves the host **at connect time** and refuses any non-public address (``GuardedBackend``,
  rebinding-safe); TLS is always verified (a CA bundle can be added, never removed);
* is signed ``Sibyl-Signature: t=<unix>,v1=<HMAC-SHA256(secret, t.body)>`` over the exact bytes
  sent; the secret is never logged.

A 2xx answer is delivered; anything else is retried with exponential backoff (30 s doubling to
one hour, with jitter) and dead-lettered after ``MAX_ATTEMPTS``. An egress refusal is final.
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final
from uuid import UUID

import httpx
from sibyl_schemas.values import (
    DELIVERY_ID_HEADER,
    EVENT_ID_HEADER,
    EVENT_TYPE_HEADER,
    SIGNATURE_HEADER,
)
from sibyl_schemas.webhook_signature import signature_header

from ...core.llm.egress import EgressPolicy, dev_hosts_of, guarded_transport, host_of
from ...core.llm.types import EgressRefused
from ..jobs.net import is_ssrf_refusal

MAX_ATTEMPTS: Final = 8
BASE_BACKOFF_S: Final = 30.0
MAX_BACKOFF_S: Final = 3600.0
TIMEOUT_S: Final = 10.0
CONNECT_TIMEOUT_S: Final = 3.0
MAX_RESPONSE_BYTES: Final = 64 * 1024
USER_AGENT: Final = "Sibyl-Webhooks/1"
DISABLE_AFTER_FAILURES: Final = 50
"""A webhook whose last 50 deliveries all died is disabled (re-create it to resume)."""

TransportFactory = Callable[[EgressPolicy], httpx.AsyncBaseTransport]


@dataclass(frozen=True)
class DeliveryResult:
    ok: bool
    http_status: int
    error: str | None  # None | http_error | timeout | transport | egress_refused
    latency_ms: int

    @property
    def retryable(self) -> bool:
        return not self.ok and self.error != "egress_refused"


def _matches(host: str, entry: str) -> bool:
    entry = entry.strip().lower().rstrip(".")
    if not entry:
        return False
    if entry.startswith("*."):
        entry = entry[1:]
    if entry.startswith("."):
        return host.endswith(entry) and host != entry.lstrip(".")
    return host == entry


def deployment_allows(host: str, allowlist: str | Iterable[str] | None) -> bool:
    """``SIBYL_WEBHOOK_ALLOWED_HOSTS``: comma-separated hosts or ``.suffix`` / ``*.suffix``
    entries. Unset or empty allows any public host (the connect-time check still applies)."""
    entries = allowlist.split(",") if isinstance(allowlist, str) else list(allowlist or ())
    entries = [e for e in entries if e.strip()]
    if not entries:
        return True
    host = host.lower().rstrip(".")
    return any(_matches(host, e) for e in entries)


def webhook_policy(url: str, settings: Any, dev_hosts: Iterable[str] | None = None) -> EgressPolicy:
    """The egress policy for one webhook URL; raises ``EgressRefused`` when the deployment's
    allowlist does not include its host."""
    host = host_of(url)
    if not host:
        raise EgressRefused("webhook", "the URL has no host")
    allowlist = getattr(settings, "webhook_allowed_hosts", "") if settings is not None else ""
    if not deployment_allows(host, allowlist):
        raise EgressRefused("webhook", f"host {host} is not on SIBYL_WEBHOOK_ALLOWED_HOSTS")
    policy = EgressPolicy(
        allowed_hosts=frozenset({host}),
        dev_hosts=dev_hosts_of(dev_hosts),
        ca_file=getattr(settings, "upstream_ca_file", None) if settings is not None else None,
    )
    policy.check(url)
    return policy


def render_body(document: Mapping[str, Any]) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")


def envelope(
    *,
    event_id: UUID,
    event_type: str,
    created_at: datetime,
    tenant_id: UUID,
    monitor_id: UUID,
    data: Mapping[str, Any],
) -> dict[str, Any]:
    """The delivered JSON document (references and states only)."""
    return {
        "id": str(event_id),
        "type": event_type,
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
        "tenant_id": str(tenant_id),
        "monitor_id": str(monitor_id),
        "data": dict(data),
        "advisory": True,
    }


def signed_headers(
    secret: str,
    body: bytes,
    *,
    event_id: str,
    event_type: str,
    delivery_id: UUID,
    timestamp: int | None = None,
) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        SIGNATURE_HEADER: signature_header(secret, body, timestamp=timestamp),
        EVENT_ID_HEADER: event_id,
        EVENT_TYPE_HEADER: event_type,
        DELIVERY_ID_HEADER: str(delivery_id),
    }


def backoff_s(attempts: int, *, jitter: float | None = None) -> float:
    """Seconds before attempt ``attempts + 1`` (``attempts`` >= 1 already made)."""
    base = min(BASE_BACKOFF_S * float(2 ** max(attempts - 1, 0)), MAX_BACKOFF_S)
    spread = random.random() if jitter is None else jitter  # noqa: S311 (not security relevant)
    return base * (1 + 0.2 * spread)


async def send(
    url: str,
    body: bytes,
    headers: Mapping[str, str],
    policy: EgressPolicy,
    *,
    transport_factory: TransportFactory | None = None,
    timeout_s: float = TIMEOUT_S,
) -> DeliveryResult:
    started = time.monotonic()

    def done(ok: bool, status: int, error: str | None) -> DeliveryResult:
        return DeliveryResult(ok, status, error, int((time.monotonic() - started) * 1000))

    try:
        policy.check(url)
        transport = (
            transport_factory(policy)
            if transport_factory is not None
            else guarded_transport(policy)
        )
        client = httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(timeout_s, connect=min(CONNECT_TIMEOUT_S, timeout_s)),
            follow_redirects=False,
            trust_env=False,
        )
        async with client, asyncio.timeout(timeout_s):
            async with client.stream("POST", url, content=body, headers=dict(headers)) as resp:
                seen = 0
                async for chunk in resp.aiter_bytes():
                    seen += len(chunk)
                    if seen > MAX_RESPONSE_BYTES:
                        break
                status = resp.status_code
    except EgressRefused:
        return done(False, 0, "egress_refused")
    except (TimeoutError, httpx.TimeoutException):
        return done(False, 0, "timeout")
    except httpx.HTTPError as exc:
        return done(False, 0, "egress_refused" if is_ssrf_refusal(exc) else "transport")
    if 200 <= status < 300:
        return done(True, status, None)
    return done(False, status, "http_error")
