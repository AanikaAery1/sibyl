"""Envelope encryption interface (D7, D11, D17; security-auditor datamodel §5).

KEK (``SIBYL_KEK``, local AES-256-GCM in Phase 1; a KMS adapter later) wraps per-tenant DEKs
stored in ``tenant_key`` by purpose (``payload``, ``credential``, ``config``). Objects are sealed
with AES-256-GCM under the active DEK with AAD binding tenant, purpose, key version and an object
context, so ciphertext cannot be replayed into another tenant or object. Crypto-shred = the DEK
row loses its wrapped key; nothing here can decrypt afterwards.
"""

from __future__ import annotations

import base64
import os
import struct
from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32
NONCE_BYTES = 12
PURPOSES: tuple[str, ...] = ("payload", "credential", "config")


class DecryptionError(Exception):
    """Authentication failed: wrong key, wrong AAD, or tampered ciphertext."""


@dataclass(frozen=True)
class Sealed:
    nonce: bytes
    ciphertext: bytes = field(repr=False)


def generate_dek() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def build_aad(*parts: str | UUID | int) -> bytes:
    """Length-prefixed concatenation, so ("ab","c") and ("a","bc") differ."""
    out = bytearray()
    for part in parts:
        raw = str(part).encode("utf-8")
        out += struct.pack(">I", len(raw)) + raw
    return bytes(out)


def _check_key(key: bytes) -> None:
    if len(key) != KEY_BYTES:
        raise ValueError("AES-256-GCM keys are 32 bytes")


def seal(key: bytes, plaintext: bytes, aad: bytes) -> Sealed:
    _check_key(key)
    nonce = os.urandom(NONCE_BYTES)
    return Sealed(nonce, AESGCM(key).encrypt(nonce, plaintext, aad))


def open_sealed(key: bytes, sealed: Sealed, aad: bytes) -> bytes:
    _check_key(key)
    try:
        return AESGCM(key).decrypt(sealed.nonce, sealed.ciphertext, aad)
    except InvalidTag:
        raise DecryptionError("authentication failed") from None


class KeyEncryptionKey(Protocol):
    kek_id: str

    def wrap(self, dek: bytes, aad: bytes) -> bytes: ...

    def unwrap(self, wrapped: bytes, aad: bytes) -> bytes: ...


class LocalKek:
    """Phase 1 KEK held in process memory from ``SIBYL_KEK`` (base64url, 32 bytes)."""

    def __init__(self, kek_id: str, material: bytes) -> None:
        _check_key(material)
        self.kek_id = kek_id
        self._material = material

    def __repr__(self) -> str:
        return f"LocalKek(kek_id={self.kek_id!r})"

    @classmethod
    def from_env(cls, kek_id: str, value: str) -> LocalKek:
        return cls(kek_id, base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))

    def wrap(self, dek: bytes, aad: bytes) -> bytes:
        sealed = seal(self._material, dek, build_aad(self.kek_id) + aad)
        return sealed.nonce + sealed.ciphertext

    def unwrap(self, wrapped: bytes, aad: bytes) -> bytes:
        sealed = Sealed(wrapped[:NONCE_BYTES], wrapped[NONCE_BYTES:])
        return open_sealed(self._material, sealed, build_aad(self.kek_id) + aad)


@dataclass(frozen=True)
class DataKey:
    key_id: UUID
    purpose: str
    version: int
    material: bytes = field(repr=False)


class DekProvider(Protocol):
    """Resolves unwrapped DEKs from ``tenant_key``; raises when shredded (lane I/U implement)."""

    async def active(self, tenant_id: UUID, purpose: str) -> DataKey: ...

    async def by_version(self, tenant_id: UUID, purpose: str, version: int) -> DataKey: ...


@dataclass(frozen=True)
class EncryptedBlob:
    key_version: int
    nonce: bytes
    ciphertext: bytes = field(repr=False)


def envelope_aad(tenant_id: UUID, purpose: str, version: int, context: bytes) -> bytes:
    """AAD of an object sealed under a tenant DEK: ``tenant ‖ purpose ‖ version`` (the same
    prefix the KEK wraps the DEK with, B11) followed by the object context."""
    return build_aad(tenant_id, purpose, version) + context


class EnvelopeCipher:
    def __init__(self, deks: DekProvider) -> None:
        self._deks = deks

    _aad = staticmethod(envelope_aad)

    async def encrypt(
        self, tenant_id: UUID, purpose: str, plaintext: bytes, *, context: bytes
    ) -> EncryptedBlob:
        dek = await self._deks.active(tenant_id, purpose)
        sealed = seal(dek.material, plaintext, self._aad(tenant_id, purpose, dek.version, context))
        return EncryptedBlob(dek.version, sealed.nonce, sealed.ciphertext)

    async def decrypt(
        self, tenant_id: UUID, purpose: str, blob: EncryptedBlob, *, context: bytes
    ) -> bytes:
        dek = await self._deks.by_version(tenant_id, purpose, blob.key_version)
        aad = self._aad(tenant_id, purpose, blob.key_version, context)
        return open_sealed(dek.material, Sealed(blob.nonce, blob.ciphertext), aad)
