"""Issue, sign and cache policy snapshots (ADR-9, chair ruling B4).

One tenant per caller (D31/R26). Every request rebuilds the tenant block inside one
``tenant_tx``; a new version is issued only when the block changed or the cached issue is older
than ``ttl/2`` (so a gateway polling every few seconds always holds a fresh one), and each issue
takes the next value of the global ``policy_snapshot_issue`` sequence (strictly monotonic) and
records ``(version, sha256, signer_kid, tenant_versions, agents_count)``. The served bytes are the
RFC 8785 canonical body; the detached Ed25519 signature covers exactly them. Size budget B4:
raw <= 3 MiB and gzip <= 2 MiB, otherwise 503 ``snapshot_unavailable``.
"""

from __future__ import annotations

import gzip
import hashlib
import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sibyl_schemas.canonical import canonicalize
from sibyl_schemas.values import SNAPSHOT_DEFAULT_GRACE_S, SNAPSHOT_DEFAULT_TTL_S

from ...core.crypto.envelope import KeyEncryptionKey, LocalKek
from ...core.db import Database
from ...core.problems import ProblemError
from ...core.settings import Settings
from .builder import SnapshotScope, build_tenant_block, iso
from .credentials import build_bundle
from .keys import (
    SignerResolver,
    SignerUnavailable,
    active_row,
    chain_page,
    ensure_current,
    load_rows,
    sets_since,
)

log = logging.getLogger("sibyl.api.snapshot")
MAX_RAW_BYTES = 3 * 1024 * 1024
MAX_GZIP_BYTES = 2 * 1024 * 1024
DEFAULT_DEMO_HOSTS = ("127.0.0.1", "localhost", "sim")


@dataclass(frozen=True)
class Issued:
    version: int
    kid: str
    signature: str
    raw: bytes = field(repr=False)
    gz: bytes = field(repr=False)
    digest: str
    minted: float


def utcnow() -> datetime:
    return datetime.now(UTC)


class SnapshotService:
    def __init__(
        self,
        db: Database | None,
        *,
        demo: bool = False,
        resolver: SignerResolver | None = None,
        kek: KeyEncryptionKey | None = None,
        demo_hosts: Iterable[str] = DEFAULT_DEMO_HOSTS,
        clock: Callable[[], datetime] = utcnow,
        ttl_s: int = SNAPSHOT_DEFAULT_TTL_S,
        grace_s: int = SNAPSHOT_DEFAULT_GRACE_S,
        max_raw: int = MAX_RAW_BYTES,
        max_gzip: int = MAX_GZIP_BYTES,
    ) -> None:
        self.db = db
        self.demo = demo
        self.resolver = resolver or SignerResolver()
        self.kek = kek
        self.demo_hosts = tuple(demo_hosts)
        self.clock = clock
        self.ttl_s, self.grace_s = ttl_s, grace_s
        self.max_raw, self.max_gzip = max_raw, max_gzip
        self._cache: dict[tuple[UUID, UUID | None, bool], Issued] = {}

    @classmethod
    def from_settings(cls, db: Database | None, settings: Settings | None) -> SnapshotService:
        kek = None
        if settings is not None and settings.kek is not None:
            kek = LocalKek.from_env(settings.kek_id, settings.kek.get_secret_value())
        return cls(db, demo=bool(settings and settings.demo), kek=kek)

    def _db(self) -> Database:
        if self.db is None:
            raise ProblemError("snapshot_unavailable", "no database configured")
        return self.db

    async def snapshot(self, scope: SnapshotScope) -> Issued:
        key = (scope.tenant_id, scope.agent_id, scope.include_keys)
        async with self._db().tenant_tx(scope.tenant_id) as conn:
            try:
                block = await build_tenant_block(conn, scope, demo_mode=self.demo)
            except LookupError:
                raise ProblemError("snapshot_unavailable") from None
            if scope.require_agent and str(scope.agent_id) not in block["agents"]:
                raise ProblemError("not_found")
            digest = hashlib.sha256(canonicalize(block)).hexdigest()
            cached = self._cache.get(key)
            if (
                cached is not None
                and cached.digest == digest
                and time.monotonic() - cached.minted < self.ttl_s / 2
            ):
                return cached
            issued = await self._issue(conn, scope.tenant_id, block, digest)
        self._cache[key] = issued
        return issued

    async def _issue(
        self, conn: Any, tenant_id: UUID, block: dict[str, Any], digest: str
    ) -> Issued:
        rows = await load_rows(conn)
        row = active_row(rows)
        try:
            if row is None:
                raise SignerUnavailable("no active snapshot key")
            signer = self.resolver.resolve(row)
        except SignerUnavailable as exc:
            log.error("snapshot signing unavailable: %s", exc)
            raise ProblemError("snapshot_unavailable") from None
        version = int(
            await conn.fetchval("SELECT nextval('sibyl.policy_snapshot_issue_version_seq')")
        )
        clock = self.clock().astimezone(UTC)
        now = clock.replace(microsecond=clock.microsecond // 1000 * 1000)
        body = {
            "schema": "sibyl.policy_snapshot/1",
            "version": version,
            "issued_at": iso(now),
            "expires_at": iso(now + timedelta(seconds=self.ttl_s)),
            "ttl_s": self.ttl_s,
            "grace_s": self.grace_s,
            "kid": signer.kid,
            "tenants": {str(tenant_id): block},
        }
        raw = canonicalize(body)
        gz = gzip.compress(raw, compresslevel=6)
        if len(raw) > self.max_raw or len(gz) > self.max_gzip:
            log.error("snapshot over budget: raw=%d gz=%d tenant=%s", len(raw), len(gz), tenant_id)
            raise ProblemError("snapshot_unavailable", "snapshot exceeds the size budget")
        await conn.execute(
            "INSERT INTO sibyl.policy_snapshot_issue"
            " (version, issued_at, sha256, signer_kid, tenant_versions, agents_count)"
            " VALUES ($1, $2, $3, $4, $5, $6)",
            version,
            now,
            hashlib.sha256(raw).digest(),
            signer.kid,
            {str(tenant_id): block["routing_version"]},
            len(block["agents"]),
        )
        return Issued(
            version, signer.kid, signer.sign_bytes(raw), raw, gz, digest, time.monotonic()
        )

    async def key_set(self) -> dict[str, Any]:
        """The latest signed key set, issuing what the chain needs first (B10)."""
        async with self._db().system_tx() as conn:
            try:
                latest = await ensure_current(conn, self.resolver, now=self.clock())
            except SignerUnavailable as exc:
                log.error("key set unavailable: %s", exc)
                raise ProblemError("snapshot_unavailable") from None
        return latest.document

    async def key_chain(self, since: int) -> dict[str, Any]:
        """``KeySetChain``: every set with ``sequence > since`` so a verifier pinned to the
        genesis key (or to any accepted set) can catch up in one request (B10)."""
        async with self._db().system_tx() as conn:
            try:
                latest = await ensure_current(conn, self.resolver, now=self.clock())
            except SignerUnavailable as exc:
                log.error("key set unavailable: %s", exc)
                raise ProblemError("snapshot_unavailable") from None
            sets = await sets_since(conn, since)
        return chain_page(sets, latest)

    async def credentials(
        self, scope: SnapshotScope, ids: list[UUID], seal_key: bytes | None
    ) -> dict[str, Any]:
        async with self._db().tenant_tx(scope.tenant_id, readonly=True) as conn:
            return await build_bundle(
                conn,
                tenant_id=scope.tenant_id,
                ids=ids,
                bound_agent=scope.agent_id,
                seal_key=seal_key,
                kek=self.kek,
                demo=self.demo,
                demo_hosts=self.demo_hosts,
            )
