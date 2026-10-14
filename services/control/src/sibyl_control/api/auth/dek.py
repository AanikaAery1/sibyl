"""OIDC client secrets under the tenant ``config`` DEK (D7, D17).

The DEK-wrap convention, the providers and ``kek_from_settings`` are the kernel's (B11,
``core.crypto.deks``); the KEK (``SIBYL_KEK``) never enters Postgres. A client secret is sealed
with the object context ``oidc_issuer ‖ issuer_id ‖ client_secret`` and stored in the compact
form ``nonce ‖ ciphertext`` with the ``tenant_key`` row id (``core.crypto.sealed``).
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from ...core.crypto.deks import DekUnavailable
from ...core.crypto.envelope import DecryptionError, DekProvider
from ...core.crypto.sealed import (
    CONFIG_PURPOSE,
    issuer_secret_context,
    open_compact,
    seal_compact,
)
from ...core.problems import ProblemError


async def seal_issuer_secret(
    deks: DekProvider, tenant_id: UUID, issuer_id: UUID, secret: str
) -> tuple[bytes, UUID]:
    """→ (``client_secret_ct`` = nonce ‖ ciphertext, ``client_secret_key_id``)."""
    try:
        sealed = await seal_compact(
            deks, tenant_id, CONFIG_PURPOSE, secret.encode(), issuer_secret_context(issuer_id)
        )
    except DekUnavailable:
        raise ProblemError("service_unavailable", "no usable config key") from None
    return sealed.ciphertext, sealed.key_id


async def open_issuer_secret(
    deks: DekProvider, conn: Any, tenant_id: UUID, issuer_id: UUID, ct: bytes, key_id: UUID
) -> str:
    version = await conn.fetchval(
        "SELECT version FROM sibyl.tenant_key WHERE tenant_id = $1 AND id = $2", tenant_id, key_id
    )
    if version is None:
        raise ProblemError("internal_error")
    try:
        plain = await open_compact(
            deks,
            tenant_id,
            CONFIG_PURPOSE,
            int(version),
            bytes(ct),
            issuer_secret_context(issuer_id),
        )
    except DekUnavailable:
        raise ProblemError("service_unavailable", "the issuer secret key is unavailable") from None
    except DecryptionError:
        raise ProblemError("internal_error") from None
    return plain.decode()
