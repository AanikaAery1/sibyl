"""The kernel's outbox writer against the real ``sibyl.outbox`` (0012): xid8 default, NOT NULLs."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from sibyl_control.core.db import Database as KernelDatabase
from sibyl_control.core.outbox import OutboxMessage, PgOutboxWriter

from .conftest import Conn
from .fixtures import create_tenant


def test_writer_inserts_with_defaults_and_a_generated_key(
    admin: Conn, kernel_db: KernelDatabase, loop: asyncio.AbstractEventLoop
) -> None:
    tenant, agent = create_tenant(admin, "outbox-writer"), uuid4()
    messages = (
        OutboxMessage("policy", "policy_changed", "agent", agent, {"routing_version": 2}),
        OutboxMessage("audit", "audit.anchor_now", "tenant", tenant, {}, "anchor:1"),
    )

    async def emit() -> None:
        async with kernel_db.tenant_tx(tenant) as conn:
            for message in messages:
                await PgOutboxWriter().emit(conn, tenant, message)

    loop.run_until_complete(emit())
    rows = admin.fetch(
        "SELECT topic, idempotency_key, xid IS NOT NULL AS has_xid FROM sibyl.outbox "
        "WHERE tenant_id = $1 "
        "AND (idempotency_key = 'anchor:1' OR idempotency_key LIKE 'outbox:%')",
        tenant,
    )
    assert sorted((r["topic"], r["idempotency_key"].split(":")[0]) for r in rows) == [
        ("audit", "anchor"),
        ("policy", "outbox"),
    ]
    assert all(r["has_xid"] for r in rows)


def test_message_without_an_aggregate_is_refused() -> None:
    with pytest.raises(ValueError, match="aggregate_id"):
        OutboxMessage("policy", "policy_changed", "agent", None, {})  # type: ignore[arg-type]
