"""Tenant DEKs: the one wrap convention and the two providers (chair ruling B11).

``tenant_key.wrapped_dek`` is a fresh AES-256 DEK sealed by the KEK (``SIBYL_KEK``, ``LocalKek``
in Phase 1) with AAD ``tenant_id ‖ purpose ‖ version`` (length-prefixed ``build_aad``;
``LocalKek`` additionally binds its ``kek_id``), so a wrapped DEK cannot be replayed into another
tenant, purpose or version. Every writer (``sibyl tenant create``, ``sibyl seed``, the
tenant-key rotate route, test harnesses) wraps with ``wrap_dek`` / ``new_wrapped_dek`` and every
reader unwraps through a provider here, so the convention cannot drift between lanes again.

Two providers, one row-to-key rule:

* ``PgDekProvider``: pool-backed (one read-only tenant transaction per miss), unwrapped keys
  cached for at most 60 s (risk T6a) and dropped at once by ``invalidate(tenant)``.
* ``ConnDekProvider``: on the caller's open tenant transaction, no cache (registry writes,
  snapshot credential bundles, worker jobs).

A shredded row has no wrapped key, so nothing here can produce its DEK again: that is the
crypto-shred. Errors are plain exceptions (``KeyShredded`` ⊂ ``DekUnavailable``); each route maps
them to its own problem code.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from ..db import Database
from ..problems import ProblemError
from .envelope import (
    PURPOSES,
    DataKey,
    DecryptionError,
    KeyEncryptionKey,
    LocalKek,
    build_aad,
    generate_dek,
)

MAX_CACHE_TTL_S = 60.0


class DekUnavailable(Exception):
    """No usable DEK: missing, wrapped under a different KEK, or unwrap failed."""


class KeyShredded(DekUnavailable):
    """The DEK was crypto-shredded (erasure); nothing can be sealed or opened under it."""


def dek_wrap_aad(tenant_id: UUID, purpose: str, version: int) -> bytes:
    """The KEK wrap AAD of one ``tenant_key`` row (B11: tenant ‖ purpose ‖ version)."""
    return build_aad(tenant_id, purpose, version)


def wrap_dek(
    kek: KeyEncryptionKey, tenant_id: UUID, purpose: str, version: int, dek: bytes
) -> bytes:
    return kek.wrap(dek, dek_wrap_aad(tenant_id, purpose, version))


def unwrap_dek(
    kek: KeyEncryptionKey, tenant_id: UUID, purpose: str, version: int, wrapped: bytes
) -> bytes:
    """Raises ``DecryptionError`` when any of tenant, purpose, version or KEK differs."""
    return kek.unwrap(wrapped, dek_wrap_aad(tenant_id, purpose, version))


@dataclass(frozen=True)
class WrappedDek:
    material: bytes = field(repr=False)
    wrapped: bytes = field(repr=False)


def new_wrapped_dek(
    kek: KeyEncryptionKey, tenant_id: UUID, purpose: str, version: int
) -> WrappedDek:
    """A fresh DEK and its wrapped form for ``tenant_create`` / ``tenant_key_rotate``."""
    if purpose not in PURPOSES:
        raise ValueError(f"unknown DEK purpose {purpose!r}")
    dek = generate_dek()
    return WrappedDek(dek, wrap_dek(kek, tenant_id, purpose, version, dek))


def kek_from_settings(settings: Any) -> LocalKek:
    """The process KEK from ``Settings`` (503 ``service_unavailable`` when it is not set)."""
    kek = getattr(settings, "kek", None)
    if kek is None:
        raise ProblemError("service_unavailable", "the key-encryption key is not configured")
    return LocalKek.from_env(settings.kek_id, kek.get_secret_value())


_KEY_SQL = (
    "SELECT id, version, wrapped_dek, kek_id, state FROM sibyl.tenant_key"
    " WHERE tenant_id = $1 AND purpose = $2 AND "
)
ACTIVE_SQL = _KEY_SQL + "state = 'active'"
VERSION_SQL = _KEY_SQL + "version = $3"
ANY_SHREDDED_SQL = (
    "SELECT EXISTS (SELECT 1 FROM sibyl.tenant_key WHERE tenant_id = $1 AND purpose = $2"
    " AND state = 'shredded')"
)


async def load_key(
    conn: Any, kek: KeyEncryptionKey, tenant_id: UUID, purpose: str, version: int | None
) -> DataKey:
    """Read one ``tenant_key`` row on ``conn`` (a tenant transaction) and unwrap it."""
    if version is None:
        row = await conn.fetchrow(ACTIVE_SQL, tenant_id, purpose)
        if row is None and await conn.fetchval(ANY_SHREDDED_SQL, tenant_id, purpose):
            raise KeyShredded(f"the {purpose} key is shredded and none is active")
    else:
        row = await conn.fetchrow(VERSION_SQL, tenant_id, purpose, version)
    if row is None:
        raise DekUnavailable(f"no {purpose} key for the tenant")
    if row["state"] == "shredded" or row["wrapped_dek"] is None:
        raise KeyShredded(f"{purpose} key v{row['version']} is shredded")
    if row["kek_id"] != kek.kek_id:
        raise DekUnavailable(f"{purpose} key v{row['version']} is wrapped under another KEK")
    try:
        material = unwrap_dek(
            kek, tenant_id, purpose, int(row["version"]), bytes(row["wrapped_dek"])
        )
    except DecryptionError:
        raise DekUnavailable(f"{purpose} key v{row['version']} does not unwrap") from None
    return DataKey(row["id"], purpose, int(row["version"]), material)


class ConnDekProvider:
    """``DekProvider`` on the caller's open tenant transaction (no cache)."""

    def __init__(self, conn: Any, kek: KeyEncryptionKey) -> None:
        self._conn = conn
        self._kek = kek

    async def active(self, tenant_id: UUID, purpose: str) -> DataKey:
        return await load_key(self._conn, self._kek, tenant_id, purpose, None)

    async def by_version(self, tenant_id: UUID, purpose: str, version: int) -> DataKey:
        return await load_key(self._conn, self._kek, tenant_id, purpose, version)


@dataclass(frozen=True)
class _Cached:
    key: DataKey
    expires: float


class PgDekProvider:
    """``DekProvider`` over the pool: one read-only tenant transaction per cache miss."""

    def __init__(
        self,
        db: Database,
        kek: KeyEncryptionKey,
        *,
        ttl_s: float = MAX_CACHE_TTL_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_s > MAX_CACHE_TTL_S:
            raise ValueError("DEK cache TTL is capped at 60 s (risk T6)")
        self._db = db
        self._kek = kek
        self._ttl = ttl_s
        self._clock = clock
        self._cache: dict[tuple[UUID, str, int | None], _Cached] = {}

    @property
    def kek(self) -> KeyEncryptionKey:
        return self._kek

    def invalidate(self, tenant_id: UUID, purpose: str | None = None) -> None:
        """Drop cached keys of a tenant (all purposes, or one): rotation, shred, erasing."""
        for slot in [s for s in self._cache if s[0] == tenant_id and purpose in (None, s[1])]:
            del self._cache[slot]

    async def active(self, tenant_id: UUID, purpose: str) -> DataKey:
        return await self._get(tenant_id, purpose, None)

    async def by_version(self, tenant_id: UUID, purpose: str, version: int) -> DataKey:
        return await self._get(tenant_id, purpose, version)

    async def _get(self, tenant_id: UUID, purpose: str, version: int | None) -> DataKey:
        slot = (tenant_id, purpose, version)
        hit = self._cache.get(slot)
        now = self._clock()
        if hit is not None and hit.expires > now:
            return hit.key
        async with self._db.tenant_tx(tenant_id, readonly=True) as conn:
            key = await load_key(conn, self._kek, tenant_id, purpose, version)
        entry = _Cached(key, now + self._ttl)
        self._cache[slot] = entry
        self._cache[(tenant_id, purpose, key.version)] = entry
        return key
