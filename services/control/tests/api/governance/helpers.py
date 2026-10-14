"""Seed helpers for the lane U suites (pure functions over the harness ``World``)."""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sibyl_control.core.audit import AuditRecord, PgAuditWriter
from sibyl_control.core.blob.base import payload_key


def append_rows(world: Any, tenant: UUID, n: int = 1, *, agent: UUID | None = None) -> None:
    """``n`` system audit rows (``resource_type = agent`` when ``agent`` is given)."""

    async def run() -> None:
        async with world.worker_db.tenant_tx(tenant) as conn:
            for i in range(n):
                await PgAuditWriter().append(
                    conn,
                    tenant,
                    AuditRecord(
                        action="audit.verified",
                        actor_type="system",
                        resource_type="agent" if agent else "tenant",
                        resource_id=agent or tenant,
                        detail={"from_seq": 0, "to_seq": i, "anchors_checked": 0},
                    ),
                )

    world.run(run())


def add_payload(
    world: Any,
    tenant: UUID,
    *,
    agent: UUID | None,
    created_at: datetime | None = None,
    expires_at: datetime | None = None,
    kind: str = "span_content",
    body: bytes | None = None,
) -> tuple[UUID, str]:
    """A payload row plus its blob (opaque bytes; nothing decrypts them in these tests)."""
    created = created_at or datetime.now(UTC)
    expires = expires_at or created + timedelta(days=30)
    ref = uuid4()
    ensure_partitions(world, "payload_refs", created, created + timedelta(seconds=1))
    key = payload_key(tenant, created.date(), kind, ref)
    data = body or os.urandom(64)
    world.run(world.blob.put(key, data, content_type="application/vnd.sibyl.sealed"))
    key_row = world.fetchrow(
        "SELECT id, version FROM sibyl.tenant_key WHERE tenant_id = $1 AND purpose = 'payload'"
        " AND state = 'active'",
        tenant,
    )
    world.admin.execute(
        "INSERT INTO sibyl.payload_refs (tenant_id, id, created_at, kind, uri, sha256,"
        " size_bytes, stored_bytes, tenant_key_id, key_version, nonce, capture_mode,"
        " redaction_profile_hash, agent_id, source_kind, expires_at)"
        " VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9, $10, 'full', $11, $12, 'event', $13)",
        tenant,
        ref,
        created,
        kind,
        key,
        hashlib.sha256(data).digest(),
        len(data),
        key_row["id"],
        key_row["version"],
        os.urandom(12),
        hashlib.sha256(b"profile").digest(),
        agent,
        expires,
    )
    return ref, key


def ensure_partitions(world: Any, table: str, start: datetime, end: datetime) -> None:
    world.run(_ensure(world, table, start, end))


async def _ensure(world: Any, table: str, start: datetime, end: datetime) -> None:
    async with world.worker_db.system_tx() as conn:
        await conn.execute("SELECT sibyl.partition_ensure($1, $2, $3)", table, start, end)
