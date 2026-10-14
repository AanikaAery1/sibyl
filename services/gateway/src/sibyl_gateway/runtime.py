"""Wires G-policy and G-hot into one ASGI app from ``GatewayConfig``.

Missing trust material never weakens checks: without pinned keys nothing verifies, without a
pepper no key authenticates, so the data plane refuses (``sibyl_no_snapshot`` / 401) while
``/healthz`` stays up and ``/readyz`` reports why it is not ready.
"""

from __future__ import annotations

import asyncio
import logging
import os
import ssl
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx

from .actions.api import ActionApi
from .config import GatewayConfig
from .credentials.vault import CredentialVault
from .limits import Limits
from .policy.fetcher import SnapshotFetcher
from .policy.keychain import KeyChain
from .policy.service import SnapshotPolicyView
from .policy.store import SnapshotStore
from .policy.verify import KeySetError, PinnedKey, PinnedKeySet
from .proxy.app import GatewayApp
from .proxy.upstream import UpstreamClient, UpstreamSettings
from .telemetry.events import EventFactory
from .telemetry.queue import HttpIngestSink, TelemetryQueue
from .telemetry.scrubcheck import checked_scrubber

log = logging.getLogger("sibyl.gateway")


def _keychain(config: GatewayConfig) -> KeyChain | None:
    if not config.pinned_key_json:
        return None
    try:
        chain = KeyChain.from_pin_json(config.pinned_key_json, state_dir=config.snapshot_dir)
    except KeySetError as exc:
        log.error("pinned snapshot key unusable: %s", exc)
        return None
    log.info("key-set chain replayed %d set(s) from disk", chain.replay())
    return chain


def _pinned(config: GatewayConfig, chain: KeyChain | None) -> PinnedKeySet:
    if chain is not None:
        return chain.verification_keys(datetime.now(UTC))
    if config.pinned_keys_json:
        try:
            return PinnedKeySet.from_json(config.pinned_keys_json)
        except KeySetError as exc:
            log.error("pinned snapshot keys unusable: %s", exc)
    # A key nobody holds: every snapshot is refused as unknown_kid (fail closed).
    return PinnedKeySet([PinnedKey("__unpinned__", os.urandom(32))])


def _client(ca_file: str | None, timeout: float = 10.0) -> httpx.AsyncClient:
    verify: ssl.SSLContext | bool = ssl.create_default_context(cafile=ca_file) if ca_file else True
    return httpx.AsyncClient(
        timeout=timeout, verify=verify, trust_env=False, follow_redirects=False
    )


def ingest_router(store: Any, routes: Mapping[str, str]) -> Callable[[Any], str | None]:
    """tenant id -> the ingest key of the stream whose verified snapshot carries that tenant
    (B-03); ``None`` for a tenant no stream fronts, so its telemetry is dropped."""

    def key_for(tenant: Any) -> str | None:
        try:
            wanted = UUID(str(tenant))
        except ValueError:
            return None
        for stream, doc in store.documents().items():
            if wanted in doc.tenants:
                return routes.get(stream)
        return None

    return key_for


def build_gateway(config: GatewayConfig) -> GatewayApp:
    """Raises ``ScrubberUnsafe`` (refuse to start) when content could leave unscrubbed."""
    for problem in config.problems():
        log.warning("gateway config: %s", problem)
    chain = _keychain(config)
    store = SnapshotStore(_pinned(config, chain), snapshot_dir=config.snapshot_dir)
    vault = CredentialVault()
    view = SnapshotPolicyView(
        store, pepper=config.pepper or os.urandom(32), env=config.env, vault=vault
    )
    upstream = UpstreamClient(
        UpstreamSettings(
            connect_s=config.connect_s,
            ttfb_s=config.ttfb_s,
            dev_hosts=config.dev_hosts,
            ca_file=config.upstream_ca_file,
        )
    )
    control = _client(config.control_ca_file)
    streams = config.streams()
    routes = config.ingest_routes()
    sink: HttpIngestSink | None = None
    if config.ingest_url and routes:
        sink = HttpIngestSink(config.ingest_url, ingest_router(store, routes), control)
    elif config.ingest_url and config.ingest_key and not config.tenant_keys:
        sink = HttpIngestSink(config.ingest_url, config.ingest_key, control)  # disk-only, 1 tenant
    telemetry = TelemetryQueue(sink)
    events = EventFactory(config.gateway_id, checked_scrubber(config.scrub_salt, env=config.env))
    fetcher = (
        SnapshotFetcher(
            store,
            vault,
            control_url=config.control_url,
            streams=streams,
            client=control,
            gateway_id=config.gateway_id,
            poll_s=config.poll_s,
            keychain=chain,
        )
        if config.control_url and streams
        else None
    )

    def key_for(tenant: UUID) -> str | None:
        """The gateway key of the stream whose snapshot carries this tenant (R26)."""
        for stream, doc in store.documents().items():
            if tenant in doc.tenants:
                return streams.get(stream)
        return None

    actions = ActionApi(config.control_url, control, key_for) if config.control_url else None

    async def startup() -> None:
        loaded = await asyncio.to_thread(store.load_persisted)
        log.info("gateway %s: %d persisted snapshot stream(s) loaded", config.gateway_id, loaded)
        telemetry.start()
        if fetcher is not None:
            fetcher.start()

    async def shutdown() -> None:
        if fetcher is not None:
            await fetcher.stop()
        await telemetry.stop()
        vault.clear()
        await upstream.aclose()
        await control.aclose()

    app = GatewayApp(
        view,
        upstream,
        events,
        telemetry,
        gateway_id=config.gateway_id,
        limits=Limits(),
        on_startup=[startup],
        on_shutdown=[shutdown],
        actions=actions,
    )
    app.fetcher = fetcher  # type: ignore[attr-defined]
    return app
