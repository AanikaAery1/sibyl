"""Holds the verified snapshots, one stream per configured tenant key (R26, D31).

``offer()`` runs the verification order, indexes the body and swaps an immutable index in with
one reference assignment, so the hot path never sees a half-installed snapshot. A rejected
delivery leaves everything as it was. Accepted deliveries are persisted to
``SIBYL_SNAPSHOT_DIR`` (raw bytes + kid + signature + the version high-water mark) and
re-verified on start, so a restart during a control-plane outage still serves under the
fail-mode matrix instead of refusing everything.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from .snapshot import KeyEntry, PolicyDocument, TenantBlock, index_snapshot
from .verify import PinnedKeySet, SnapshotRejected, verify_snapshot
from .view import PolicyState, PolicyStatus

log = logging.getLogger("sibyl.gateway.policy")
_STREAM = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_STATE_RANK = {
    PolicyState.FRESH: 0,
    PolicyState.STALE: 1,
    PolicyState.EXPIRED: 2,
    PolicyState.UNAVAILABLE: 3,
}


def utcnow() -> datetime:
    return datetime.now(UTC)


def status_of(doc: PolicyDocument | None, now: datetime) -> PolicyStatus:
    if doc is None:
        return PolicyStatus(PolicyState.UNAVAILABLE)
    snap = doc.snapshot
    age = max(0, int((now - snap.issued_at).total_seconds()))
    if now <= snap.expires_at:
        state = PolicyState.FRESH
    elif now <= snap.expires_at + timedelta(seconds=snap.grace_s):
        state = PolicyState.STALE
    else:
        state = PolicyState.EXPIRED
    return PolicyStatus(state, version=snap.version, kid=snap.kid, age_s=age)


@dataclass(frozen=True)
class _Index:
    streams: Mapping[str, PolicyDocument] = field(default_factory=dict)
    by_tenant: Mapping[UUID, tuple[TenantBlock, PolicyDocument]] = field(default_factory=dict)
    by_prefix: Mapping[str, tuple[TenantBlock, KeyEntry, PolicyDocument]] = field(
        default_factory=dict
    )


def _build_index(streams: Mapping[str, PolicyDocument]) -> _Index:
    by_tenant: dict[UUID, tuple[TenantBlock, PolicyDocument]] = {}
    by_prefix: dict[str, tuple[TenantBlock, KeyEntry, PolicyDocument]] = {}
    for doc in sorted(streams.values(), key=lambda d: d.version):
        for tenant_id, block in doc.tenants.items():
            by_tenant[tenant_id] = (block, doc)
            for prefix, key in block.keys.items():
                by_prefix[prefix] = (block, key, doc)
    return _Index(dict(streams), by_tenant, by_prefix)


class SnapshotStore:
    def __init__(
        self,
        keys: PinnedKeySet,
        *,
        snapshot_dir: Path | None = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._keys = keys
        self._dir = snapshot_dir
        self._clock = clock
        self._index = _Index()
        self._high_water: dict[str, int] = {}
        self._lock = threading.Lock()
        self.listeners: list[Callable[[str, PolicyDocument], None]] = []

    # -- writes (background refresher thread) --------------------------------------------

    def set_keys(self, keys: PinnedKeySet) -> None:
        """Adopt the verification keys of a newly accepted key set (rotation, R33/M6)."""
        with self._lock:
            self._keys = keys

    def offer(self, stream: str, raw: bytes, *, kid: str, signature: str) -> PolicyDocument:
        """Verify and install one delivery; raises ``SnapshotRejected`` (held one stays)."""
        _check_stream(stream)
        with self._lock:
            snap = verify_snapshot(
                raw,
                kid=kid,
                signature=signature,
                keys=self._keys,
                held_version=self._high_water.get(stream),
                now=self._clock(),
            )
            doc = index_snapshot(snap)
            self._install(stream, doc)
        self._persist(stream, doc)
        for listener in list(self.listeners):
            try:
                listener(stream, doc)
            except Exception:
                log.exception("snapshot listener failed")
        return doc

    def _install(self, stream: str, doc: PolicyDocument) -> None:
        streams = dict(self._index.streams)
        streams[stream] = doc
        self._high_water[stream] = max(self._high_water.get(stream, 0), doc.version)
        self._index = _build_index(streams)

    def load_persisted(self) -> int:
        """Re-verify every persisted stream; returns how many were installed."""
        if self._dir is None or not self._dir.is_dir():
            return 0
        loaded = 0
        for path in sorted(self._dir.glob("*.snapshot.json")):
            stream = path.name.removesuffix(".snapshot.json")
            try:
                record = json.loads(path.read_text("utf-8"))
                raw = base64.b64decode(record["raw"], validate=True)
                with self._lock:
                    snap = verify_snapshot(
                        raw,
                        kid=record["kid"],
                        signature=record["signature"],
                        keys=self._keys,
                        held_version=None,
                        now=self._clock(),
                    )
                    self._install(stream, index_snapshot(snap))
                    floor = int(record.get("high_water", 0))
                    self._high_water[stream] = max(self._high_water[stream], floor)
                loaded += 1
            except (OSError, ValueError, KeyError, TypeError, SnapshotRejected) as exc:
                log.warning("persisted snapshot %s ignored: %s", path.name, exc)
        return loaded

    def _persist(self, stream: str, doc: PolicyDocument) -> None:
        if self._dir is None:
            return
        snap = doc.snapshot
        record = {
            "kid": snap.kid,
            "signature": snap.signature,
            "version": snap.version,
            "high_water": self._high_water.get(stream, snap.version),
            "raw": base64.b64encode(snap.raw).decode("ascii"),
        }
        try:
            self._dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            target = self._dir / f"{stream}.snapshot.json"
            tmp = target.with_suffix(f".tmp{os.getpid()}")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(record, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, target)
        except OSError:
            log.exception("could not persist snapshot stream %s", stream)

    # -- reads (hot path: dict lookups on an immutable index) ----------------------------

    @property
    def ever_loaded(self) -> bool:
        return bool(self._index.streams)

    def tenant(self, tenant_id: UUID) -> tuple[TenantBlock, PolicyDocument] | None:
        return self._index.by_tenant.get(tenant_id)

    def key(self, prefix: str) -> tuple[TenantBlock, KeyEntry, PolicyDocument] | None:
        return self._index.by_prefix.get(prefix)

    def documents(self) -> Mapping[str, PolicyDocument]:
        return self._index.streams

    def held_version(self, stream: str) -> int | None:
        doc = self._index.streams.get(stream)
        return doc.version if doc is not None else None

    def status(self, now: datetime | None = None) -> PolicyStatus:
        """The worst state across streams (drives ``/readyz`` and process-level health)."""
        now = now or self._clock()
        docs = list(self._index.streams.values())
        if not docs:
            return PolicyStatus(PolicyState.UNAVAILABLE)
        statuses = [status_of(doc, now) for doc in docs]
        return max(statuses, key=lambda s: (_STATE_RANK[s.state], s.age_s or 0))

    def tenant_status(self, doc: PolicyDocument, now: datetime | None = None) -> PolicyStatus:
        return status_of(doc, now or self._clock())


def _check_stream(stream: str) -> None:
    if not _STREAM.fullmatch(stream):
        raise ValueError("stream names are [A-Za-z0-9_-]{1,64}")
