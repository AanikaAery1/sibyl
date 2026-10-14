"""Objects sealed under a tenant DEK: contexts, the payload blob layout and seal/open helpers (B11).

Every object is AES-256-GCM under a tenant DEK with AAD
``envelope_aad(tenant, purpose, version, context)`` = ``tenant ‖ purpose ‖ version ‖ context``,
where the object context binds the object identity (length-prefixed ``build_aad``):

=====================  =====================================================  ==============
object                 context                                                purpose
=====================  =====================================================  ==============
payload blob           ``payload_ref ‖ <payload_refs.id>``                     ``payload``
provider credential    ``provider_credential ‖ <provider_credential.id>``      ``credential``
OIDC client secret     ``oidc_issuer ‖ <oidc_issuer.id> ‖ client_secret``      ``config``
=====================  =====================================================  ==============

so ciphertext copied to another tenant, purpose, key version or object fails to open.

Payload blob layout (``BlobStore`` object, written create-only before its ``payload_refs`` row):
``SBLP`` magic, format byte (1), key version (u32 BE), 96-bit nonce, ciphertext+tag;
``payload_refs`` repeats key version and nonce. Credentials keep ciphertext, nonce and key
version in columns; the compact form (OIDC client secret) is ``nonce ‖ ciphertext``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import NamedTuple
from uuid import UUID

from ..blob.base import BlobStore
from .envelope import (
    NONCE_BYTES,
    DataKey,
    DekProvider,
    EncryptedBlob,
    Sealed,
    build_aad,
    envelope_aad,
    open_sealed,
    seal,
)

MAGIC = b"SBLP"
FORMAT = 1
SEALED_CONTENT_TYPE = "application/vnd.sibyl.sealed"
PAYLOAD_PURPOSE = "payload"
CREDENTIAL_PURPOSE = "credential"
CONFIG_PURPOSE = "config"
_HEADER = struct.Struct(">4sBI12s")


class SealedFormatError(ValueError):
    """Bytes that are not a sealed Sibyl payload (truncated, other magic or format)."""


def payload_context(object_id: UUID) -> bytes:
    return build_aad("payload_ref", object_id)


def credential_context(credential_id: UUID) -> bytes:
    return build_aad("provider_credential", credential_id)


def issuer_secret_context(issuer_id: UUID) -> bytes:
    return build_aad("oidc_issuer", issuer_id, "client_secret")


def pack(blob: EncryptedBlob) -> bytes:
    return _HEADER.pack(MAGIC, FORMAT, blob.key_version, blob.nonce) + blob.ciphertext


def unpack(raw: bytes) -> EncryptedBlob:
    if len(raw) < _HEADER.size:
        raise SealedFormatError("sealed object is truncated")
    magic, fmt, version, nonce = _HEADER.unpack_from(raw)
    if magic != MAGIC or fmt != FORMAT:
        raise SealedFormatError("not a sealed Sibyl payload")
    return EncryptedBlob(version, nonce, raw[_HEADER.size :])


@dataclass(frozen=True)
class SealedObject:
    """A sealed object plus the ``tenant_key`` row it was sealed under."""

    blob: EncryptedBlob
    key_id: UUID

    @property
    def packed(self) -> bytes:
        return pack(self.blob)


async def _seal(
    deks: DekProvider, tenant_id: UUID, purpose: str, plaintext: bytes, context: bytes
) -> tuple[EncryptedBlob, DataKey]:
    dek = await deks.active(tenant_id, purpose)
    sealed = seal(dek.material, plaintext, envelope_aad(tenant_id, purpose, dek.version, context))
    return EncryptedBlob(dek.version, sealed.nonce, sealed.ciphertext), dek


async def _open(
    deks: DekProvider, tenant_id: UUID, purpose: str, blob: EncryptedBlob, context: bytes
) -> bytes:
    dek = await deks.by_version(tenant_id, purpose, blob.key_version)
    aad = envelope_aad(tenant_id, purpose, blob.key_version, context)
    return open_sealed(dek.material, Sealed(blob.nonce, blob.ciphertext), aad)


async def seal_payload(
    deks: DekProvider, tenant_id: UUID, object_id: UUID, plaintext: bytes
) -> SealedObject:
    blob, dek = await _seal(deks, tenant_id, PAYLOAD_PURPOSE, plaintext, payload_context(object_id))
    return SealedObject(blob, dek.key_id)


async def open_payload_blob(
    deks: DekProvider, tenant_id: UUID, object_id: UUID, blob: EncryptedBlob
) -> bytes:
    return await _open(deks, tenant_id, PAYLOAD_PURPOSE, blob, payload_context(object_id))


async def open_payload(
    store: BlobStore, deks: DekProvider, tenant_id: UUID, key: str, object_id: UUID
) -> bytes:
    """Read and decrypt one sealed payload; raises once the tenant's DEK is shredded."""
    return await open_payload_blob(deks, tenant_id, object_id, unpack(await store.get(key)))


async def seal_credential(
    deks: DekProvider, tenant_id: UUID, credential_id: UUID, secret: bytes
) -> SealedObject:
    blob, dek = await _seal(
        deks, tenant_id, CREDENTIAL_PURPOSE, secret, credential_context(credential_id)
    )
    return SealedObject(blob, dek.key_id)


async def open_credential(
    deks: DekProvider, tenant_id: UUID, credential_id: UUID, blob: EncryptedBlob
) -> bytes:
    return await _open(deks, tenant_id, CREDENTIAL_PURPOSE, blob, credential_context(credential_id))


class CompactSealed(NamedTuple):
    ciphertext: bytes  # nonce ‖ ciphertext+tag
    key_id: UUID
    key_version: int


async def seal_compact(
    deks: DekProvider, tenant_id: UUID, purpose: str, plaintext: bytes, context: bytes
) -> CompactSealed:
    blob, dek = await _seal(deks, tenant_id, purpose, plaintext, context)
    return CompactSealed(blob.nonce + blob.ciphertext, dek.key_id, dek.version)


async def open_compact(
    deks: DekProvider, tenant_id: UUID, purpose: str, version: int, raw: bytes, context: bytes
) -> bytes:
    blob = EncryptedBlob(version, raw[:NONCE_BYTES], raw[NONCE_BYTES:])
    return await _open(deks, tenant_id, purpose, blob, context)
