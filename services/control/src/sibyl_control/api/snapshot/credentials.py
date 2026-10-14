"""Sealed credential bundle for ``GET /api/v1/policy/credentials`` (D11, security-auditor §2.3).

Only ``credential_id``s referenced by a fallback step of an APPROVED chain of an agent the key
may see are released (else 403 ``credential_not_in_snapshot``); demo mode releases only
credentials whose ``base_url`` host is a registered sim double (409 ``demo_mode``, R55). Each
secret is decrypted under the tenant ``credential`` DEK and immediately sealed to the gateway's
X25519 key; plaintext never leaves this function and is never logged.

Decryption uses the kernel convention (B11, ``core.crypto.sealed.open_credential``), the same one
the registry seals with: DEK wrap AAD ``tenant ‖ purpose ‖ version``, credential object context
``provider_credential ‖ credential_id``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from ...core.crypto.deks import ConnDekProvider
from ...core.crypto.envelope import EncryptedBlob, KeyEncryptionKey
from ...core.crypto.sealed import open_credential
from ...core.problems import ProblemError
from .sealing import seal, seal_aad

BUNDLE_TTL_S = 300
MAX_IDS = 100


def parse_ids(raw: str) -> list[UUID]:
    try:
        ids = [UUID(part.strip()) for part in raw.split(",") if part.strip()]
    except ValueError:
        raise ProblemError("validation_failed", "ids must be comma-separated uuids") from None
    if not ids or len(ids) > MAX_IDS:
        raise ProblemError("validation_failed", f"between 1 and {MAX_IDS} ids")
    return sorted(set(ids))


_ALLOWED_SQL = """
SELECT DISTINCT s.credential_id
  FROM sibyl.fallback_step s
  JOIN sibyl.fallback_chain c ON c.tenant_id = s.tenant_id AND c.id = s.chain_id
  JOIN sibyl.agent a ON a.tenant_id = c.tenant_id AND a.id = c.agent_id
 WHERE c.status = 'approved' AND a.lifecycle <> 'retired'
   AND s.credential_id = ANY($1::uuid[]) AND ($2::uuid IS NULL OR c.agent_id = $2)
"""
_CREDS_SQL = """
SELECT id, auth_scheme, base_url, ciphertext, nonce, key_version
  FROM sibyl.provider_credential
 WHERE id = ANY($1::uuid[]) AND status IN ('active', 'rotating')
"""


async def build_bundle(
    conn: Any,
    *,
    tenant_id: UUID,
    ids: Sequence[UUID],
    bound_agent: UUID | None,
    seal_key: bytes | None,
    kek: KeyEncryptionKey | None,
    demo: bool,
    demo_hosts: Iterable[str],
) -> dict[str, Any]:
    allowed = {r["credential_id"] for r in await conn.fetch(_ALLOWED_SQL, list(ids), bound_agent)}
    rows = {r["id"]: r for r in await conn.fetch(_CREDS_SQL, list(ids))}
    if set(ids) - allowed or set(ids) - set(rows):
        raise ProblemError("credential_not_in_snapshot")
    if demo:
        hosts = {h.lower() for h in demo_hosts}
        for row in rows.values():
            if (urlsplit(row["base_url"]).hostname or "").lower() not in hosts:
                raise ProblemError("demo_mode", "demo mode releases only sim-double credentials")
    if seal_key is None:
        raise ProblemError("validation_failed", "X-Sibyl-Seal-Key must be a 32-byte X25519 key")
    if kek is None:
        raise ProblemError("snapshot_unavailable", "credential vault is not configured")
    deks = ConnDekProvider(conn, kek)
    items: dict[str, Any] = {}
    for credential_id in ids:
        row = rows[credential_id]
        blob = EncryptedBlob(int(row["key_version"]), bytes(row["nonce"]), bytes(row["ciphertext"]))
        try:
            secret = await open_credential(deks, tenant_id, credential_id, blob)
        except Exception:
            raise ProblemError("snapshot_unavailable", "a credential could not be opened") from None
        try:
            sealed = seal(seal_key, secret, seal_aad(tenant_id, credential_id, row["key_version"]))
        except ValueError:  # low-order X25519 point
            raise ProblemError("validation_failed", "unusable X-Sibyl-Seal-Key") from None
        finally:
            del secret
        items[str(credential_id)] = {
            "auth_scheme": row["auth_scheme"],
            "secret": sealed,
            "base_url": row["base_url"],
            "key_version": int(row["key_version"]),
        }
    return {"expires_in_s": BUNDLE_TTL_S, "items": items}
