"""Envelope encryption for provider credentials (D7, D11; security-auditor §2.3).

The convention is the kernel's (B11, ``core.crypto.deks`` / ``core.crypto.sealed``): the KEK
wraps one DEK per tenant and purpose in ``tenant_key`` with AAD ``tenant ‖ purpose ‖ version``;
a secret is sealed under the active ``credential`` DEK with the object context
``provider_credential ‖ credential_id``, so a ciphertext copied onto another row fails to open.
The snapshot credential bundle (lane G) and the worker's credential probe open it with the same
helpers. This module only adapts errors to problems for the credential routes.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from ...core.crypto.deks import ConnDekProvider, DekUnavailable, kek_from_settings
from ...core.crypto.envelope import PURPOSES, EncryptedBlob, KeyEncryptionKey
from ...core.crypto.sealed import CREDENTIAL_PURPOSE, open_credential, seal_credential
from ...core.problems import ProblemError

__all__ = [
    "CREDENTIAL_PURPOSE",
    "TENANT_KEY_PURPOSES",
    "kek_from_settings",
    "open_secret",
    "seal_secret",
]

TENANT_KEY_PURPOSES: tuple[str, ...] = PURPOSES


async def seal_secret(
    conn: Any, kek: KeyEncryptionKey, tenant_id: UUID, credential_id: UUID, secret: str
) -> tuple[EncryptedBlob, UUID]:
    """Encrypt ``secret`` under the active credential DEK; returns the blob and the key row id."""
    try:
        sealed = await seal_credential(
            ConnDekProvider(conn, kek), tenant_id, credential_id, secret.encode()
        )
    except DekUnavailable:
        raise ProblemError("service_unavailable", "no usable credential key") from None
    return sealed.blob, sealed.key_id


async def open_secret(
    conn: Any, kek: KeyEncryptionKey, tenant_id: UUID, credential_id: UUID, blob: EncryptedBlob
) -> bytes:
    """Decrypt a vaulted secret (tests and tools); the api never returns it."""
    return await open_credential(ConnDekProvider(conn, kek), tenant_id, credential_id, blob)
