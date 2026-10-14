"""Build a real GatewayApp over a signed test snapshot whose providers point at a fake upstream."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sibyl_gateway.credentials.vault import CredentialVault
from sibyl_gateway.limits import Limits
from sibyl_gateway.policy.service import SnapshotPolicyView
from sibyl_gateway.policy.store import SnapshotStore
from sibyl_gateway.policy.verify import PinnedKeySet
from sibyl_gateway.proxy.app import GatewayApp
from sibyl_gateway.proxy.upstream import UpstreamClient, UpstreamSettings
from sibyl_gateway.telemetry.events import EventFactory
from sibyl_gateway.telemetry.queue import TelemetryQueue
from sibyl_schemas.scrub import SecretsScrubber

from ..support import OPENAI, PEPPER, SIM, TENANT, TestSigner, body, tenant_block

PROVIDER_KEY = "sk-proj-clientcredential0123456789abcdef"


@dataclass
class Harness:
    app: GatewayApp
    view: SnapshotPolicyView
    store: SnapshotStore
    vault: CredentialVault
    telemetry: TelemetryQueue
    signer: TestSigner

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://gw")

    def events(self, kind: str = "gen_ai.request") -> list[dict[str, Any]]:
        return [e for e in self.telemetry.pending() if e["type"] == kind]


def make_gateway(
    upstream_url: str | None,
    mutate: Callable[[dict[str, Any]], None] | None = None,
    *,
    age_s: float = 0,
    ttfb_s: float = 5.0,
    load: bool = True,
    actions: Any = None,
) -> Harness:
    signer = TestSigner()
    store = SnapshotStore(PinnedKeySet.from_document(signer.key_set()))
    vault = CredentialVault()
    view = SnapshotPolicyView(store, pepper=PEPPER, env="live", vault=vault)
    if load:
        block = tenant_block()
        if upstream_url:
            block["providers"][str(OPENAI)]["base_url"] = f"{upstream_url}/v1"
            block["providers"][str(SIM)]["base_url"] = f"{upstream_url}/sim/v1"
        if mutate:
            mutate(block)
        issued = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=age_s)
        raw, kid, sig = signer.deliver(body(1, issued_at=issued, tenants={str(TENANT): block}))
        store.offer("gw", raw, kid=kid, signature=sig)
    upstream = UpstreamClient(
        UpstreamSettings(ttfb_s=ttfb_s, connect_s=2, dev_hosts=("127.0.0.1",))
    )
    telemetry = TelemetryQueue(None)
    events = EventFactory("gw-test", SecretsScrubber(hashlib.sha256(b"salt").digest()))
    app = GatewayApp(
        view, upstream, events, telemetry, gateway_id="gw-test", limits=Limits(), actions=actions
    )
    return Harness(app, view, store, vault, telemetry, signer)


def chat(model: str = "gpt-5.4", **extra: Any) -> dict[str, Any]:
    return {"model": model, "messages": [{"role": "user", "content": "hi"}], **extra}


def headers(key: str, agent: str | None = "quote-assistant", **extra: str) -> dict[str, str]:
    out = {"X-Sibyl-Key": key, "Authorization": f"Bearer {PROVIDER_KEY}"}
    if agent:
        out["X-Sibyl-Agent"] = agent
    out.update(extra)
    return out
