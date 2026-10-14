"""``sibyl-seal/1``: seal a vaulted secret to the requesting gateway's X25519 key (D11).

Byte-for-byte the construction of ``sibyl_gateway.credentials.sealing`` (control must not
import the gateway; ``tests/api/snapshot`` proves they interoperate):

    sealed = b64url(e.pub[32] || nonce[12] || AES-256-GCM(HKDF-SHA256(X25519(e, G),
             salt = e.pub || G.pub, info = "sibyl-seal/1"), nonce, secret, aad))
    aad    = length-prefixed("sibyl-seal/1", tenant_id, credential_id, key_version)
"""

from __future__ import annotations

import os
import re
from uuid import UUID

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ...core.crypto.envelope import build_aad
from ...core.crypto.signing import b64url, b64url_decode

SEAL_SCHEME = "sibyl-seal/1"
SEAL_HEADER = "X-Sibyl-Seal-Key"
_B64URL_43 = re.compile(r"^[A-Za-z0-9_-]{43}$")


def seal_aad(tenant_id: UUID | str, credential_id: UUID | str, key_version: int) -> bytes:
    """Length-prefixed (``core.crypto.envelope.build_aad``, B11) scheme ‖ tenant ‖ id ‖ version."""
    return build_aad(SEAL_SCHEME, str(tenant_id), str(credential_id), int(key_version))


def parse_seal_key(value: str | None) -> bytes | None:
    """The gateway's raw X25519 public key from the header, or ``None`` when unusable."""
    if not value or not _B64URL_43.fullmatch(value.strip()):
        return None
    raw = b64url_decode(value.strip())
    if len(raw) != 32 or raw == bytes(32):
        return None
    return raw


def seal(recipient_public: bytes, plaintext: bytes, aad: bytes) -> str:
    recipient = X25519PublicKey.from_public_bytes(recipient_public)
    ephemeral = X25519PrivateKey.generate()
    ephemeral_pub = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=ephemeral_pub + recipient_public,
        info=SEAL_SCHEME.encode("ascii"),
    ).derive(ephemeral.exchange(recipient))
    nonce = os.urandom(12)
    return b64url(ephemeral_pub + nonce + AESGCM(key).encrypt(nonce, plaintext, aad))
