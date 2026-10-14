"""Held-action arguments at rest: scrubbed of secrets, then sealed as one ``payload_refs`` row
(kind ``action_args``, source ``held_action``) under the tenant's payload DEK (B11), the blob in
the BlobStore like every captured payload. Humans read them back on ``GET /held-actions/{id}``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from fastapi import Request
from sibyl_schemas.scrub import PROFILE_HASH, ScrubField, ScrubInputTooLarge, SecretsScrubber

from ...core.blob.base import BlobStore, payload_key
from ...core.crypto.deks import ConnDekProvider, DekUnavailable
from ...core.crypto.sealed import SEALED_CONTENT_TYPE, open_payload, seal_payload
from ...core.problems import ProblemError
from ..auth.runtime import kek_for
from ..deps import get_services
from ..reads.payloads import blob_store

log = logging.getLogger("sibyl.api.action_gate")
ARGS_RETENTION = timedelta(days=30)
_STATE_SCRUBBER = "action_gate_scrubber"
_PROCESS_SALT = secrets.token_bytes(32)


def scrubber(request: Request) -> SecretsScrubber:
    """The api holds no ``SIBYL_SCRUB_SALT`` by default; the salt only keys the replacement
    fingerprints, so without one a per-process random salt is used (fingerprints of the same
    secret then differ across processes, the scrubbing itself does not)."""
    state = request.app.state
    cached = getattr(state, _STATE_SCRUBBER, None)
    if cached is None:
        settings = get_services(request).settings
        salt_value = getattr(settings, "scrub_salt", None) if settings is not None else None
        salt = salt_value.get_secret_value().encode() if salt_value is not None else _PROCESS_SALT
        cached = SecretsScrubber(salt)
        setattr(state, _STATE_SCRUBBER, cached)
    value: SecretsScrubber = cached
    return value


def scrub_args(request: Request, args: Any) -> Any:
    try:
        clean, _ = scrubber(request).scrub_json(args, ScrubField.TOOL_ARGS)
    except ScrubInputTooLarge:
        raise ProblemError("payload_too_large", "tool arguments are too large to scrub") from None
    return clean


async def seal_args(
    conn: Any,
    request: Request,
    *,
    tenant: UUID,
    agent_id: UUID,
    held_action_id: UUID,
    api_key_id: UUID,
    clean: Any,
    now: datetime,
) -> UUID:
    """Write the sealed blob, then its ``payload_refs`` row → the payload ref id."""
    store = blob_store(request)
    plaintext = json.dumps(clean, separators=(",", ":"), ensure_ascii=False).encode()
    ref = uuid4()
    try:
        sealed = await seal_payload(ConnDekProvider(conn, kek_for(request)), tenant, ref, plaintext)
    except DekUnavailable:
        raise ProblemError("service_unavailable", "no usable payload key") from None
    key = payload_key(tenant, now.date(), "action_args", ref)
    packed = sealed.packed
    await store.put(key, packed, content_type=SEALED_CONTENT_TYPE)
    await conn.execute(
        "INSERT INTO sibyl.payload_refs (tenant_id, id, created_at, kind, uri, content_type, parts,"
        " sha256, size_bytes, stored_bytes, tenant_key_id, key_version, nonce, capture_mode,"
        " redaction_profile_hash, api_key_id, agent_id, source_kind, source_id, expires_at)"
        " VALUES ($1, $2, $3, 'action_args', $4, 'application/json', '{tool_args}', $5, $6, $7,"
        " $8, $9, $10, 'redacted', $11, $12, $13, 'held_action', $14, $15)",
        tenant,
        ref,
        now,
        key,
        hashlib.sha256(plaintext).digest(),
        len(plaintext),
        len(packed),
        sealed.key_id,
        sealed.blob.key_version,
        sealed.blob.nonce,
        bytes.fromhex(PROFILE_HASH),
        api_key_id,
        agent_id,
        held_action_id,
        now + ARGS_RETENTION,
    )
    return ref


async def open_args(conn: Any, request: Request, tenant: UUID, ref: UUID | None) -> Any:
    """The scrubbed arguments, or ``None`` when they are gone (swept, shredded, no blob store)."""
    if ref is None:
        return None
    row = await conn.fetchrow(
        "SELECT uri, state FROM sibyl.payload_refs WHERE tenant_id = $1 AND id = $2", tenant, ref
    )
    if row is None or row["state"] != "stored":
        return None
    try:
        store: BlobStore = blob_store(request)
        raw = await open_payload(
            store, ConnDekProvider(conn, kek_for(request)), tenant, row["uri"], ref
        )
    except Exception:
        log.warning("held-action args %s could not be opened", ref, exc_info=True)
        return None
    return json.loads(raw)
