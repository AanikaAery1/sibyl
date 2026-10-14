"""Shared plumbing for the lane U housekeeping loops.

* Tenant iteration: the tenant list is the one allowlisted cross-tenant read; every other
  statement runs inside ``Database.tenant_tx``. Each unit takes a transaction-scoped advisory
  lock per ``(loop, tenant)`` and skips the tenant when another worker holds it.
* Tenant-less maintenance (``partition_ensure_ahead`` / ``partition_retire_expired``) runs in
  ``Database.system_tx()``; nothing here touches the Database's private pool.
* Runtime objects built from ``Settings`` once per process and cached on the loop context's
  settings object identity: the anchor signer, the BlobStore and the DEK provider (the kernel
  ``core.crypto.deks.PgDekProvider`` under ``kek_from_settings``).
"""

from __future__ import annotations

import base64
import binascii
import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from ...core.blob.base import BlobStore
from ...core.crypto.deks import PgDekProvider, kek_from_settings
from ...core.crypto.signing import Ed25519Signer

TRY_LOCK_SQL = "SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))"
LIVE_TENANTS_SQL = "SELECT id FROM sibyl.tenant WHERE status <> 'erased' ORDER BY id"
ALL_TENANTS_SQL = "SELECT id FROM sibyl.tenant ORDER BY id"
ANCHOR_PURPOSE = "audit_anchor"


class SignerUnavailable(RuntimeError):
    """No usable audit-anchor signing key (never says more than that in logs)."""


async def tenants(db: Any, *, include_erased: bool = False) -> list[UUID]:
    async with db.pre_tenant() as conn:
        rows = await conn.fetch(ALL_TENANTS_SQL if include_erased else LIVE_TENANTS_SQL)
    return [row["id"] for row in rows]


async def try_lock(conn: Any, loop: str, tenant_id: UUID | str) -> bool:
    return bool(await conn.fetchval(TRY_LOCK_SQL, f"{loop}:{tenant_id}"))


# --- anchor signer --------------------------------------------------------------------------


def _seed(text: str) -> bytes:
    text = text.strip()
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        try:
            raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        except (binascii.Error, ValueError):
            raise SignerUnavailable("anchor signing key is not hex or base64url") from None
    if len(raw) != 32:
        raise SignerUnavailable("anchor signing key must be a 32-byte Ed25519 seed")
    return raw


def _seed_from_ref(ref: str, environ: dict[str, str] | None = None) -> bytes | None:
    import os

    scheme, _, target = ref.partition(":")
    env = os.environ if environ is None else environ
    if scheme == "env" and target in env:
        return _seed(env[target])
    if scheme == "file" and target and Path(target).is_file():
        return _seed(Path(target).read_text("utf-8"))
    return None


@dataclass(frozen=True)
class AnchorKey:
    kid: str
    public_key: bytes
    private_key_ref: str


async def active_anchor_key(conn: Any) -> AnchorKey | None:
    row = await conn.fetchrow(
        "SELECT kid, public_key, private_key_ref FROM sibyl.signing_key"
        " WHERE purpose = $1 AND state = 'active'",
        ANCHOR_PURPOSE,
    )
    if row is None:
        return None
    return AnchorKey(row["kid"], bytes(row["public_key"]), row["private_key_ref"])


async def anchor_public_keys(conn: Any) -> dict[str, tuple[bytes, str]]:
    """kid -> (raw public key, state) for every audit-anchor key ever published."""
    rows = await conn.fetch(
        "SELECT kid, public_key, state FROM sibyl.signing_key WHERE purpose = $1", ANCHOR_PURPOSE
    )
    return {r["kid"]: (bytes(r["public_key"]), r["state"]) for r in rows}


def resolve_signer(key: AnchorKey, settings: Any) -> Ed25519Signer:
    """``SIBYL_ANCHOR_SIGNING_KEY`` (worker secret) first, then the row's ``private_key_ref``.

    The signer is used only when its public key equals the published one, so a wrong secret
    can never produce anchors that verifiers would reject later.
    """
    candidates: list[bytes] = []
    secret = getattr(settings, "anchor_signing_key", None)
    if secret is not None and secret.get_secret_value():
        candidates.append(_seed(secret.get_secret_value()))
    from_ref = _seed_from_ref(key.private_key_ref)
    if from_ref is not None:
        candidates.append(from_ref)
    for seed in candidates:
        signer = Ed25519Signer.from_seed(key.kid, seed)
        if signer.public_key_raw == key.public_key:
            return signer
    raise SignerUnavailable(f"no private key matches audit-anchor key {key.kid}")


# --- runtime objects ------------------------------------------------------------------------

_RUNTIME: dict[tuple[int, str], Any] = {}


def runtime_object(settings: Any, name: str, factory: Any) -> Any:
    key = (id(settings), name)
    if key not in _RUNTIME:
        _RUNTIME[key] = factory()
    return _RUNTIME[key]


def install(settings: Any, name: str, value: Any) -> None:
    """Tests (and alternative wiring) pre-seed a runtime object for ``settings``."""
    _RUNTIME[(id(settings), name)] = value


def blob_store(settings: Any) -> BlobStore:
    def build() -> BlobStore:
        backend = getattr(settings, "blob_backend", "fs")
        if backend == "fs":
            from ...core.blob.fs import FsBlobStore

            return FsBlobStore(settings.blob_root)
        module = importlib.import_module("sibyl_control.core.blob.s3")
        store: BlobStore = module.S3BlobStore(module.S3Config.from_env())
        return store

    store: BlobStore = runtime_object(settings, "blob", build)
    return store


def dek_provider(db: Any, settings: Any) -> PgDekProvider:
    """The kernel DEK provider over ``db`` (one per ``(settings, db)``; KEK from settings)."""
    provider: PgDekProvider = runtime_object(
        settings, f"deks:{id(db)}", lambda: PgDekProvider(db, kek_from_settings(settings))
    )
    return provider
