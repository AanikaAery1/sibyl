"""BlobStore protocol (D7, D10, D14): payload bodies, raw batches, exports, erasure ledger.

Keys are ``tenant/{tenant_id}/{yyyy-mm-dd}/{kind}/{id}.bin`` (DATAMODEL payload_refs.uri).
Objects are already encrypted by the caller (``core.crypto.envelope``); stores never see
plaintext. Adapters speak the S3 API or the local filesystem only (no provider SDK calls, D14).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from typing import Protocol, runtime_checkable
from uuid import UUID

MAX_KEY_LENGTH = 1024
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class BlobError(Exception):
    pass


class BlobNotFound(BlobError):
    pass


class BlobExists(BlobError):
    pass


class InvalidBlobKey(BlobError, ValueError):
    pass


@dataclass(frozen=True)
class BlobInfo:
    key: str
    size: int
    sha256: str  # hex of the stored (encrypted) bytes
    content_type: str


def validate_key(key: str) -> str:
    """Relative, ``/``-separated, no empty/dot segments, conservative charset."""
    if not key or len(key) > MAX_KEY_LENGTH or key.startswith("/"):
        raise InvalidBlobKey("blob key must be relative and at most 1024 chars")
    for segment in key.split("/"):
        if segment in ("", ".", "..") or not _SEGMENT_RE.fullmatch(segment):
            raise InvalidBlobKey("blob key has an invalid segment")
    return key


def payload_key(tenant_id: UUID, day: date, kind: str, object_id: UUID) -> str:
    return validate_key(f"tenant/{tenant_id}/{day.isoformat()}/{kind}/{object_id}.bin")


@runtime_checkable
class BlobStore(Protocol):
    async def put(
        self, key: str, data: bytes, *, content_type: str, if_absent: bool = True
    ) -> BlobInfo:
        """Write ``data``; with ``if_absent`` an existing key raises ``BlobExists``."""
        ...

    async def get(self, key: str) -> bytes:
        """Read; a missing key raises ``BlobNotFound``."""
        ...

    async def head(self, key: str) -> BlobInfo | None: ...

    async def delete(self, key: str) -> bool:
        """True when an object was removed (idempotent)."""
        ...

    async def list_prefix(self, prefix: str, *, limit: int = 1000) -> list[str]: ...

    async def presigned_get(self, key: str, *, expires_s: int) -> str | None:
        """A time-limited download URL, or None when the adapter cannot sign."""
        ...
