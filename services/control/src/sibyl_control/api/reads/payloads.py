"""``GET /payloads/{ref_id}``: the decrypted body as stored (API.md §5.10, security-auditor §3.4).

Who may read:
* ``payloads:read`` (unaudited grant) for a payload of an agent in the caller's groups → served,
  no audit row;
* ``payloads:reveal``, or an auditor's audited (A) ``payloads:read`` → served only with
  ``X-Sibyl-Reveal-Reason`` (≥ 10 chars, else 428) and a ``data.revealed`` row in the same
  transaction as the read;
* ``handoff_packet`` / ``checkpoint_state`` kinds additionally need ``packets:read``;
* ``anchor_export`` (audit exports, lane U) needs ``audit:export``, or the audited reveal path
  above (``data.revealed`` with a reason); a plain ``payloads:read`` is not enough;
* anything else is 404 (no existence oracle). ``swept`` → 404 ``payload_swept``,
  ``shredded`` (or its DEK gone) → 410 ``payload_shredded``.

Decryption: the blob ingest wrote is opened with the kernel helpers (B11,
``core.crypto.sealed``): ``SBLP`` layout, AES-256-GCM under the tenant ``payload`` DEK version
``key_version``, object context ``payload_ref ‖ ref_id``. The blob header must repeat the row's
key version and nonce and the plaintext must hash to the row's sha256, else 500.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import Response

from ...core.authz import Grant
from ...core.blob.base import BlobNotFound, BlobStore
from ...core.crypto.deks import DekUnavailable, KeyShredded
from ...core.crypto.envelope import DecryptionError
from ...core.crypto.sealed import SealedFormatError, open_payload_blob, unpack
from ...core.problems import ProblemError
from ..auth import runtime
from ..auth.common import actor_record, lane_state, parse_uuid, principal_of, tenant_tx
from ..contract import API_PREFIX
from ..deps import AuthContext, get_services, guard

router = APIRouter()
PACKET_KINDS = frozenset({"handoff_packet", "checkpoint_state"})
EXPORT_KINDS = frozenset({"anchor_export"})
REVEAL_HEADER = "X-Sibyl-Reveal-Reason"


def blob_store(request: Request) -> BlobStore:
    state = lane_state(request)
    if "blob" not in state:
        settings = get_services(request).settings
        store = None
        if settings is not None and settings.blob_backend == "fs":
            try:
                module = importlib.import_module("sibyl_control.core.blob.fs")
                factory = getattr(module, "FsBlobStore", None) or getattr(
                    module, "FileBlobStore", None
                )
                store = factory(settings.blob_root) if factory is not None else None
            except ImportError:
                store = None
        if store is None:
            raise ProblemError("service_unavailable", "no blob store is configured")
        state["blob"] = store
    blob: BlobStore = state["blob"]
    return blob


def _covers(grant: Grant | None, group: UUID | None) -> bool:
    return grant is not None and (grant.group_ids is None or group in grant.group_ids)


def _decide(ctx: AuthContext, row: Any, reason: str | None) -> bool:
    """→ True when the read must be audited as a reveal. Raises 404/428 otherwise."""
    principal = principal_of(ctx)
    group = row["agent_group_id"]
    read = principal.grants.get("payloads:read")
    reveal = principal.grants.get("payloads:reveal")
    ctx.object_rule_checked("packet_kinds_need_packets_read")
    if row["kind"] in PACKET_KINDS and not _covers(principal.grants.get("packets:read"), group):
        raise ProblemError("not_found", audit_denied=True)
    ctx.object_rule_checked("group")
    ctx.object_rule_checked("auditor_reveal")
    export = row["kind"] in EXPORT_KINDS
    if export and principal.grants.get("audit:export") is not None:
        return False
    if not export and read is not None and not read.audited and _covers(read, group):
        return False
    audited_read = read is not None and read.audited and _covers(read, group)
    if reveal is None and not audited_read:
        raise ProblemError("not_found", audit_denied=True)
    if reason is None or len(reason.strip()) < 10:
        raise ProblemError("reveal_reason_required")
    return True


async def _open(request: Request, tenant: UUID, rid: UUID, row: Any, raw: bytes) -> bytes:
    try:
        blob = unpack(raw)
        if blob.key_version != row["key_version"] or blob.nonce != bytes(row["nonce"]):
            raise SealedFormatError("blob header disagrees with payload_refs")
        return await open_payload_blob(runtime.deks_for(request), tenant, rid, blob)
    except KeyShredded:
        raise ProblemError("payload_shredded") from None
    except DekUnavailable:
        raise ProblemError("service_unavailable", "the payload key is unavailable") from None
    except (SealedFormatError, DecryptionError):
        raise ProblemError("internal_error") from None


@router.get(API_PREFIX + "/payloads/{ref_id}")
async def get_payload(
    request: Request,
    ref_id: str,
    ctx: Annotated[AuthContext, Depends(guard("getPayload"))],
    reveal_reason: Annotated[str | None, Header(alias=REVEAL_HEADER, max_length=500)] = None,
) -> Response:
    rid = parse_uuid(ref_id)
    services = get_services(request)
    tenant = ctx.tenant_id
    async with tenant_tx(services, tenant, audit_lock=True) as conn:
        row = await conn.fetchrow(
            "SELECT p.*, a.agent_group_id FROM sibyl.payload_refs p"
            " LEFT JOIN sibyl.agent a ON a.tenant_id = p.tenant_id AND a.id = p.agent_id"
            " WHERE p.tenant_id = $1 AND p.id = $2 LIMIT 1",
            tenant,
            rid,
        )
        if row is None:
            raise ProblemError("not_found")
        audited = _decide(ctx, row, reveal_reason)
        if row["state"] == "swept":
            raise ProblemError("payload_swept")
        if row["state"] == "shredded":
            raise ProblemError("payload_shredded")
        try:
            sealed = await blob_store(request).get(row["uri"])
        except BlobNotFound:
            raise ProblemError("payload_swept") from None
        body = await _open(request, tenant, rid, row, sealed)
        if not hmac.compare_digest(hashlib.sha256(body).digest(), bytes(row["sha256"])):
            raise ProblemError("internal_error")
        headers = {
            "ETag": f'"{bytes(row["sha256"]).hex()}"',
            "X-Sibyl-Capture-Mode": row["capture_mode"],
            "X-Sibyl-Redaction-Profile": bytes(row["redaction_profile_hash"]).hex(),
        }
        if audited:
            receipt = await services.audit.append(
                conn,
                tenant,
                actor_record(
                    ctx,
                    "data.revealed",
                    resource_type="payload_ref",
                    resource_id=rid,
                    detail={
                        "payload_ref": str(rid),
                        "payload_sha256": bytes(row["sha256"]).hex(),
                        "agent_id": str(row["agent_id"]) if row["agent_id"] else None,
                        "reveal_reason": reveal_reason.strip() if reveal_reason else None,
                        "kind": row["kind"],
                    },
                    reason=reveal_reason,
                ),
            )
            headers["X-Sibyl-Audit-Receipt"] = receipt.header_value()
    return Response(body, media_type=row["content_type"], headers=headers)
