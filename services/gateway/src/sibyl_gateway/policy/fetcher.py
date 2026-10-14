"""Background refresh of snapshots, sealed credential bundles and kill acknowledgements.

One stream per configured tenant key (R26). Every ``poll_s`` the fetcher asks the api for the
snapshot with ``If-None-Match: "<held version>"``; a 200 is verified over the raw bytes received
and installed in a worker thread (never on the event loop). After each install, and before the
bundle's 300 s expiry, it fetches the sealed credentials the snapshot references, and it acks
every kill switch it has not acked yet. Failures never touch the held snapshot: freshness simply
ages into ``stale``/``expired`` and the fail-mode matrix takes over.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

import httpx

from ..credentials.sealing import SEAL_HEADER
from ..credentials.vault import CredentialVault
from .keychain import KeyChain, KeySetRejected
from .keysync import ChainFetchError, follow_chain
from .snapshot import PolicyDocument
from .store import SnapshotStore
from .verify import SnapshotRejected

log = logging.getLogger("sibyl.gateway.policy")
SNAPSHOT_PATH = "/api/v1/policy/snapshot"
CREDENTIALS_PATH = "/api/v1/policy/credentials"
KEYS_REFRESH_S = 3600.0
KEYS_RETRY_S = 60.0
BUNDLE_REFRESH_S = 240.0
MAX_IDS = 100


@dataclass
class FetchStats:
    installed: int = 0
    not_modified: int = 0
    rejected: dict[str, int] = field(default_factory=dict)
    errors: int = 0
    bundles: int = 0
    acks: int = 0
    key_sets: int = 0
    key_set_rejected: dict[str, int] = field(default_factory=dict)


class SnapshotFetcher:
    def __init__(
        self,
        store: SnapshotStore,
        vault: CredentialVault,
        *,
        control_url: str,
        streams: dict[str, str],
        client: httpx.AsyncClient,
        gateway_id: str,
        poll_s: float = 5.0,
        on_rejected: Callable[[str, str, int | None], None] | None = None,
        keychain: KeyChain | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._vault = vault
        self._base = control_url.rstrip("/")
        self._streams = dict(streams)
        self._client = client
        self._gateway_id = gateway_id
        self._poll_s = poll_s
        self._on_rejected = on_rejected
        self._bundle_at: dict[str, float] = {}
        self._acked: set[tuple[UUID, int]] = set()
        self._task: asyncio.Task[None] | None = None
        self._keychain = keychain
        self._clock = clock or (lambda: datetime.now(UTC))
        self._keys_at: float | None = None
        self.stats = FetchStats()

    def _auth(self, stream: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._streams[stream]}"}

    async def refresh(self, stream: str) -> str:
        headers = self._auth(stream)
        held = self._store.held_version(stream)
        if held is not None:
            headers["If-None-Match"] = f'"{held}"'
        try:
            resp = await self._client.get(self._base + SNAPSHOT_PATH, headers=headers)
        except httpx.HTTPError as exc:
            self.stats.errors += 1
            log.warning("snapshot fetch %s failed: %s", stream, type(exc).__name__)
            return "error"
        if resp.status_code == 304:
            self.stats.not_modified += 1
            await self._maybe_bundle(stream)
            return "not_modified"
        if resp.status_code != 200:
            self.stats.errors += 1
            log.warning("snapshot fetch %s answered %s", stream, resp.status_code)
            return "error"
        kid = resp.headers.get("x-sibyl-snapshot-kid", "")
        signature = resp.headers.get("x-sibyl-snapshot-signature", "")
        try:
            doc = await asyncio.to_thread(
                self._store.offer, stream, resp.content, kid=kid, signature=signature
            )
        except SnapshotRejected as exc:
            if exc.cause == "unknown_kid":
                await self.refresh_keys(force=True)  # a rotation we have not followed yet
            self.stats.rejected[exc.cause] = self.stats.rejected.get(exc.cause, 0) + 1
            log.critical("snapshot.rejected stream=%s cause=%s held=%s", stream, exc.cause, held)
            if self._on_rejected is not None:
                self._on_rejected(stream, exc.cause, held)
            return f"rejected:{exc.cause}"
        self.stats.installed += 1
        await self._after_install(stream, doc)
        return "installed"

    async def _after_install(self, stream: str, doc: PolicyDocument) -> None:
        self._bundle_at.pop(stream, None)
        await self._maybe_bundle(stream)
        for block in doc.tenants.values():
            for kill_id in block.kill_switch_ids:
                await self._ack(stream, kill_id, doc.version)

    async def _maybe_bundle(self, stream: str) -> None:
        last = self._bundle_at.get(stream)
        if last is not None and time.monotonic() - last < BUNDLE_REFRESH_S:
            return
        doc = self._store.documents().get(stream)
        if doc is None:
            return
        for tenant_id, block in doc.tenants.items():
            ids = sorted(str(cid) for cid in block.credential_ids())[:MAX_IDS]
            if not ids:
                continue
            try:
                resp = await self._client.get(
                    self._base + CREDENTIALS_PATH,
                    params={"ids": ",".join(ids)},
                    headers={**self._auth(stream), SEAL_HEADER: self._vault.seal_public_key},
                )
            except httpx.HTTPError as exc:
                log.warning("credential bundle fetch failed: %s", type(exc).__name__)
                return
            if resp.status_code != 200:
                log.warning("credential bundle refused: %s", resp.status_code)
                return
            self.stats.bundles += self._vault.install_bundle(tenant_id, resp.json())
        self._bundle_at[stream] = time.monotonic()

    async def _ack(self, stream: str, kill_id: UUID, version: int) -> None:
        if any(k == kill_id for k, _ in self._acked):
            return
        try:
            resp = await self._client.post(
                f"{self._base}/api/v1/kill-switches/{kill_id}/acks",
                json={"gateway_id": self._gateway_id, "snapshot_version": version},
                headers={
                    **self._auth(stream),
                    "Idempotency-Key": f"ack-{kill_id}-{self._gateway_id}",
                },
            )
        except httpx.HTTPError:
            return
        if resp.status_code < 300:
            self._acked.add((kill_id, version))
            self.stats.acks += 1

    async def refresh_keys(self, *, force: bool = False) -> str:
        """Catch the signed key-set chain up from the held sequence (``?since=``, B10)."""
        chain = self._keychain
        if chain is None:
            return "static"
        last = self._keys_at
        wait = KEYS_RETRY_S if force else KEYS_REFRESH_S
        if last is not None and time.monotonic() - last < wait:
            return "skipped"
        self._keys_at = time.monotonic()
        now = self._clock()
        try:
            result = await follow_chain(self._client, self._base, chain, now=now)
        except ChainFetchError as exc:
            log.warning("key set fetch failed: %s", exc)
            return "error"
        except KeySetRejected as exc:
            cause = exc.cause.value
            count = self.stats.key_set_rejected.get(cause, 0) + 1
            self.stats.key_set_rejected[cause] = count
            log.critical(
                "key_set.rejected cause=%s member=%s held=%d", cause, exc.index, chain.sequence
            )
            self._store.set_keys(chain.verification_keys(now))
            return f"rejected:{cause}"
        self._store.set_keys(chain.verification_keys(now))  # not_after may have passed
        if result.adopted == 0:
            return "not_modified"
        self.stats.key_sets += result.adopted
        log.info("key set chain caught up to sequence %d", result.sequence)
        return "installed"

    async def refresh_all(self) -> None:
        await self.refresh_keys()
        for stream in list(self._streams):
            await self.refresh(stream)
        self._vault.purge()

    def start(self) -> None:
        if self._task is None and self._streams:
            self._task = asyncio.create_task(self._run(), name="sibyl-policy-refresh")

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    async def _run(self) -> None:
        while True:
            try:
                await self.refresh_all()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("policy refresh loop error")
            await asyncio.sleep(self._poll_s)
