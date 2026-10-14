"""Memory-only vault of unsealed fallback credentials (D11, security-auditor §2.3).

The X25519 key pair is generated per process and never leaves memory; bundles are sealed to
its public key (``X-Sibyl-Seal-Key``). Plaintexts live in ``SecretHandle`` objects for at most
``expires_in_s`` (≤ 300 s), keyed by credential id, are zeroised on replacement, expiry and
``clear()``, and are never written to disk or logs.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ..policy.view import CredentialRef, SecretHandle
from .sealing import SealError, b64url, open_sealed, public_bytes, seal_aad

log = logging.getLogger("sibyl.gateway.credentials")
MAX_TTL_S = 300


@dataclass
class _Held:
    key_version: int
    auth_scheme: str
    handle: SecretHandle
    expires_at: datetime


def utcnow() -> datetime:
    return datetime.now(UTC)


class CredentialVault:
    def __init__(self, *, clock: Callable[[], datetime] = utcnow) -> None:
        self._private = X25519PrivateKey.generate()
        self._clock = clock
        self._items: dict[UUID, _Held] = {}
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"CredentialVault(items={len(self._items)})"

    @property
    def seal_public_key(self) -> str:
        return b64url(public_bytes(self._private))

    def install_bundle(self, tenant_id: UUID, bundle: Mapping[str, Any]) -> int:
        """Unseal every item; a bad item is skipped (and logged by id), never half-installed."""
        ttl = min(int(bundle.get("expires_in_s", MAX_TTL_S)), MAX_TTL_S)
        expires_at = self._clock() + timedelta(seconds=max(ttl, 0))
        fresh: dict[UUID, _Held] = {}
        for raw_id, item in dict(bundle.get("items") or {}).items():
            try:
                credential_id = UUID(str(raw_id))
                version = int(item["key_version"])
                secret = open_sealed(
                    self._private, item["secret"], seal_aad(tenant_id, credential_id, version)
                )
            except (SealError, KeyError, TypeError, ValueError):
                log.warning("credential bundle item %s rejected", str(raw_id)[:36])
                continue
            fresh[credential_id] = _Held(
                version, str(item.get("auth_scheme", "bearer")), SecretHandle(secret), expires_at
            )
        with self._lock:
            for credential_id, held in fresh.items():
                old = self._items.get(credential_id)
                if old is not None:
                    old.handle.zeroise()
                self._items[credential_id] = held
        return len(fresh)

    def get(self, ref: CredentialRef) -> SecretHandle | None:
        held = self._items.get(ref.credential_id)
        if held is None or held.key_version != ref.key_version:
            return None
        if self._clock() >= held.expires_at:
            self.purge()
            return None
        return held.handle

    def key_version(self, credential_id: UUID) -> int | None:
        held = self._items.get(credential_id)
        return held.key_version if held is not None else None

    def auth_scheme(self, credential_id: UUID) -> str | None:
        held = self._items.get(credential_id)
        return held.auth_scheme if held is not None else None

    def purge(self) -> int:
        now = self._clock()
        with self._lock:
            stale = [cid for cid, held in self._items.items() if now >= held.expires_at]
            for cid in stale:
                self._items.pop(cid).handle.zeroise()
        return len(stale)

    def clear(self) -> None:
        with self._lock:
            for held in self._items.values():
                held.handle.zeroise()
            self._items.clear()
