"""``sibyl-seal/1``: vaulted provider secrets sealed to the gateway's X25519 key (D11).

The api decrypts ``provider_credential`` under the tenant DEK and seals each secret to the
public key the gateway presents in ``X-Sibyl-Seal-Key``; only the gateway process holding the
matching private key (generated at start, memory only) can open it. Construction:

    e        = fresh X25519 key pair (per item)
    shared   = X25519(e.private, gateway.public)
    key      = HKDF-SHA256(shared, salt = e.public || gateway.public, info = "sibyl-seal/1", 32)
    sealed   = base64url(e.public[32] || nonce[12] || AES-256-GCM(key, nonce, secret, aad))
    aad      = length-prefixed("sibyl-seal/1", tenant_id, credential_id, key_version)

The AAD binds a sealed item to its tenant, credential and key version, so an item cannot be
replayed under another credential id. The control plane implements the same construction
(``sibyl_control.api.snapshot.sealing``); ``tests/api/snapshot`` proves the two interoperate.
"""

from __future__ import annotations

import base64
import binascii
import os
import struct
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SEAL_SCHEME = "sibyl-seal/1"
SEAL_HEADER = "X-Sibyl-Seal-Key"
_PUB = 32
_NONCE = 12
_TAG = 16


class SealError(ValueError):
    """The sealed item is malformed or does not authenticate under this key and AAD."""


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or "=" in text:
        raise SealError("expected unpadded base64url")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise SealError("expected unpadded base64url") from None


def seal_aad(tenant_id: UUID | str, credential_id: UUID | str, key_version: int) -> bytes:
    out = bytearray()
    for part in (SEAL_SCHEME, str(tenant_id), str(credential_id), str(int(key_version))):
        raw = part.encode("utf-8")
        out += struct.pack(">I", len(raw)) + raw
    return bytes(out)


def public_bytes(key: X25519PrivateKey | X25519PublicKey) -> bytes:
    public = key.public_key() if isinstance(key, X25519PrivateKey) else key
    return public.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _derive(shared: bytes, ephemeral_pub: bytes, recipient_pub: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=ephemeral_pub + recipient_pub,
        info=SEAL_SCHEME.encode("ascii"),
    )
    return hkdf.derive(shared)


def seal(recipient_public: bytes, plaintext: bytes, aad: bytes) -> str:
    """Seal ``plaintext`` to a raw 32-byte X25519 public key (reference; the api does this)."""
    if len(recipient_public) != _PUB:
        raise SealError("X25519 public keys are 32 bytes")
    recipient = X25519PublicKey.from_public_bytes(recipient_public)
    ephemeral = X25519PrivateKey.generate()
    ephemeral_pub = public_bytes(ephemeral)
    key = _derive(ephemeral.exchange(recipient), ephemeral_pub, recipient_public)
    nonce = os.urandom(_NONCE)
    return b64url(ephemeral_pub + nonce + AESGCM(key).encrypt(nonce, plaintext, aad))


def open_sealed(private_key: X25519PrivateKey, sealed: str, aad: bytes) -> bytes:
    raw = b64url_decode(sealed)
    if len(raw) < _PUB + _NONCE + _TAG:
        raise SealError("sealed item too short")
    ephemeral_pub, nonce, ciphertext = raw[:_PUB], raw[_PUB : _PUB + _NONCE], raw[_PUB + _NONCE :]
    try:
        shared = private_key.exchange(X25519PublicKey.from_public_bytes(ephemeral_pub))
    except ValueError:
        raise SealError("bad ephemeral key") from None
    key = _derive(shared, ephemeral_pub, public_bytes(private_key))
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise SealError("sealed item does not authenticate") from None
