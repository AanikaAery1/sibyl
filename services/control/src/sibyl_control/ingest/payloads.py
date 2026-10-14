"""Seal payload bodies into the BlobStore and describe them for ``payload_refs`` (R19, D7).

The sealing convention and blob layout live in ``core.crypto.sealed`` (B11): AES-256-GCM under
the tenant's active ``payload`` DEK, AAD ``tenant ‖ payload ‖ version ‖ payload_ref ‖ object id``,
blob ``SBLP | format | key version | nonce | ciphertext+tag``. The blob is written (create-only)
before its ``payload_refs`` row is inserted; the reads route opens it with the same helpers.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from ..core.blob.base import BlobStore, payload_key
from ..core.crypto.envelope import DekProvider
from ..core.crypto.sealed import SEALED_CONTENT_TYPE, seal_payload
from .ids import uuid7


def blob_ref(tenant_id: UUID, key: str) -> str:
    """``PayloadRef.ref`` (``blob://<tenant>/<date>/...``) for a ``tenant/<tenant>/...`` key."""
    prefix = f"tenant/{tenant_id}/"
    return f"blob://{tenant_id}/{key[len(prefix) :]}"


@dataclass(frozen=True)
class SealedPayload:
    id: UUID
    key: str
    sha256: bytes  # of the plaintext (post-redaction)
    size_bytes: int
    stored_bytes: int
    tenant_key_id: UUID
    key_version: int
    nonce: bytes
    content_type: str
    parts: tuple[str, ...]
    kind: str
    source_kind: str
    capture_mode: str
    redaction_profile_hash: bytes
    created_at: datetime
    expires_at: datetime
    agent_id: UUID | None
    api_key_id: UUID | None
    source_id: UUID | None

    def ref(self, tenant_id: UUID, *, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ref": blob_ref(tenant_id, self.key),
            "sha256": self.sha256.hex(),
            "bytes": self.size_bytes,
            "content_type": self.content_type,
        }
        if self.parts:
            out["parts"] = list(self.parts)
        out.update(extra or {})
        return out


class PayloadSealer:
    def __init__(self, store: BlobStore, deks: DekProvider) -> None:
        self._store = store
        self._deks = deks

    async def seal(
        self,
        tenant_id: UUID,
        plaintext: bytes,
        *,
        kind: str,
        source_kind: str,
        content_type: str,
        parts: tuple[str, ...],
        capture_mode: str,
        redaction_profile_hash: bytes,
        now: datetime,
        retention: timedelta,
        agent_id: UUID | None = None,
        api_key_id: UUID | None = None,
        source_id: UUID | None = None,
        object_id: UUID | None = None,
    ) -> SealedPayload:
        object_id = object_id or uuid7(now)
        key = payload_key(tenant_id, now.date(), kind, object_id)
        sealed = await seal_payload(self._deks, tenant_id, object_id, plaintext)
        packed = sealed.packed
        await self._store.put(key, packed, content_type=SEALED_CONTENT_TYPE)
        return SealedPayload(
            id=object_id,
            key=key,
            sha256=hashlib.sha256(plaintext).digest(),
            size_bytes=len(plaintext),
            stored_bytes=len(packed),
            tenant_key_id=sealed.key_id,
            key_version=sealed.blob.key_version,
            nonce=sealed.blob.nonce,
            content_type=content_type,
            parts=parts,
            kind=kind,
            source_kind=source_kind,
            capture_mode=capture_mode,
            redaction_profile_hash=redaction_profile_hash,
            created_at=now,
            expires_at=now + retention,
            agent_id=agent_id,
            api_key_id=api_key_id,
            source_id=source_id,
        )
