"""(f) Commit-ordered xid8 cursors under interleaved commits (R60, risk T2, seams S5/S9) and
the two NOTIFY channels (R58/X2, risk T3)."""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

import asyncpg
import pytest

from .conftest import Conn, Database
from .fixtures import create_tenant, h32

NIL = uuid.UUID(int=0)
INSERT_OUTBOX = (
    "INSERT INTO sibyl.outbox (tenant_id, topic, event_type, aggregate_kind, aggregate_id, "
    "payload, "
    "idempotency_key) VALUES ($1, $2, $3, 'alert', $4, '{}', $5) RETURNING id, xid"
)


@pytest.fixture
def tenant(admin: Conn) -> uuid.UUID:
    """A fresh tenant per test: no test sees rows another one committed (G0-tests F15)."""
    return create_tenant(admin, f"cursor-{uuid.uuid4().hex[:8]}")


def _begin(conn: Conn, tenant: uuid.UUID) -> Any:
    tx = conn.raw.transaction()
    conn.run(tx.start())
    conn.execute("SELECT sibyl.set_tenant($1)", tenant)
    return tx


def _read(
    conn: Conn, tenant: uuid.UUID, after_xid: int, after_id: uuid.UUID
) -> list[asyncpg.Record]:
    with conn.tx(tenant, rollback=True):
        return conn.fetch(
            "SELECT id, xid FROM sibyl.outbox_read($1, $2, 1000)", after_xid, after_id
        )


def _read_eventually(conn: Conn, tenant: uuid.UUID, n: int) -> list[asyncpg.Record]:
    """Read from the start until ``n`` rows are below the (cluster-wide) commit horizon."""
    stop = time.monotonic() + 15
    while len(rows := _read(conn, tenant, 0, NIL)) < n and time.monotonic() < stop:
        conn.run(asyncio.sleep(0.02))
    return rows


def test_late_committing_writer_is_never_skipped(
    db: Database, tenant: uuid.UUID, roles: dict[str, Conn]
) -> None:
    early, late = db.connect("sibyl_app"), db.connect("sibyl_worker")
    consumer = roles["sibyl_app"]
    try:
        tx_early = _begin(early, tenant)
        first = early.fetchrow(INSERT_OUTBOX, tenant, "alert", "alert.fired", uuid.uuid4(), "early")
        tx_late = _begin(late, tenant)
        second = late.fetchrow(INSERT_OUTBOX, tenant, "alert", "alert.fired", uuid.uuid4(), "late")
        late.run(tx_late.commit())
        assert int(first["xid"]) < int(second["xid"])

        # A created_at cursor would already deliver the second row and later skip the first.
        with consumer.tx(tenant, rollback=True):
            naive = consumer.fetch(
                "SELECT id FROM sibyl.outbox WHERE tenant_id = $1 ORDER BY created_at, id", tenant
            )
        assert [r["id"] for r in naive] == [second["id"]]
        # The horizon holds back everything at or after the in-flight transaction.
        assert _read(consumer, tenant, 0, NIL) == []

        early.run(tx_early.commit())
        delivered = _read_eventually(consumer, tenant, 2)
        assert [r["id"] for r in delivered] == [first["id"], second["id"]]
        last = delivered[-1]
        assert _read(consumer, tenant, last["xid"], last["id"]) == []
    finally:
        early.close()
        late.close()


def test_rollup_dirty_set_uses_the_same_horizon(
    db: Database, tenant: uuid.UUID, admin: Conn
) -> None:
    with admin.tx(tenant):
        agent = uuid.uuid4()
        admin.execute(
            "INSERT INTO sibyl.agent (tenant_id, id, slug, name, kind, fail_mode) "
            "VALUES ($1, $2, 'cursor-agent', 'Cursor', 'chatbot', 'open')",
            tenant,
            agent,
        )
    insert = (
        "INSERT INTO sibyl.events (tenant_id, event_id, ts, event_type, source, agent_id, "
        "emitter_id, seq, "
        "policy_state, capture_mode, redaction_profile_hash, normaliser_version) VALUES ($1, $2, "
        "now(), "
        "'tool.call', 'sdk', $3, 'sdk-1', $4, 'fresh', 'metadata', $5, 'normaliser/1.0')"
    )
    slow, fast, worker = (
        db.connect("sibyl_ingest"),
        db.connect("sibyl_ingest"),
        db.connect("sibyl_worker"),
    )
    try:
        tx_slow = _begin(slow, tenant)
        slow.execute(insert, tenant, uuid.uuid4(), agent, 1, h32("p"))
        tx_fast = _begin(fast, tenant)
        fast.execute(insert, tenant, uuid.uuid4(), agent, 2, h32("p"))
        fast.run(tx_fast.commit())
        dirty = (
            "SELECT count(*) FROM sibyl.events WHERE tenant_id = $1 AND agent_id = $2 "
            "AND xid < sibyl.commit_horizon()"
        )
        with worker.tx(tenant, rollback=True):
            assert worker.fetchval(dirty, tenant, agent) == 0
        slow.run(tx_slow.commit())
        stop = time.monotonic() + 15  # the horizon is cluster-wide: wait out unrelated sessions
        while True:
            with worker.tx(tenant, rollback=True):
                seen = worker.fetchval(dirty, tenant, agent)
            if seen == 2 or time.monotonic() > stop:
                break
            worker.run(asyncio.sleep(0.02))
        assert seen == 2
    finally:
        for conn in (slow, fast, worker):
            conn.close()


def test_writers_cannot_forge_commit_order(roles: dict[str, Conn], tenant: uuid.UUID) -> None:
    app = roles["sibyl_app"]
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        with app.tx(tenant, rollback=True):
            app.execute(
                "INSERT INTO sibyl.outbox (tenant_id, topic, event_type, aggregate_kind, "
                "aggregate_id, payload, "
                "idempotency_key, xid) VALUES ($1, 'alert', 'alert.fired', 'alert', $2, '{}', "
                "'forge', '1')",
                tenant,
                uuid.uuid4(),
            )


def test_consumer_offsets_only_move_forward(roles: dict[str, Conn], tenant: uuid.UUID) -> None:
    worker = roles["sibyl_worker"]
    with worker.tx(tenant):
        worker.execute(
            "INSERT INTO sibyl.consumer_offsets (consumer_group, tenant_id, topic, last_xid, "
            "last_id) "
            "VALUES ('rollup_1m', $1, 'events', '100', $2)",
            tenant,
            NIL,
        )
    with pytest.raises(asyncpg.PostgresError, match="sibyl:immutable_row"):
        with worker.tx(tenant, rollback=True):
            worker.execute(
                "UPDATE sibyl.consumer_offsets SET last_xid = '99' WHERE tenant_id = $1", tenant
            )


def test_two_channels_one_notification_per_transaction(
    db: Database, tenant: uuid.UUID, roles: dict[str, Conn]
) -> None:
    listener = db.connect("sibyl_app")
    received: list[tuple[str, str]] = []

    def on_notify(_conn: Any, _pid: int, channel: str, payload: str) -> None:
        received.append((channel, payload))

    try:
        for channel in ("sibyl_policy", "sibyl_outbox"):
            listener.run(listener.raw.add_listener(channel, on_notify))
        writer = roles["sibyl_worker"]
        with writer.tx(tenant):
            for i, topic in enumerate(("alert", "handoff", "policy", "killswitch")):
                writer.fetchrow(
                    INSERT_OUTBOX,
                    tenant,
                    topic,
                    f"{topic}.x",
                    uuid.uuid4(),
                    f"n-{i}-{uuid.uuid4()}",
                )
        listener.run(_until(lambda: len(received) >= 2))
        listener.run(_settle(lambda: len(received)))
    finally:
        listener.close()
    assert sorted(received) == [("sibyl_outbox", str(tenant)), ("sibyl_policy", str(tenant))]


async def _until(condition: Any, limit_s: float = 5.0) -> None:
    """Poll until ``condition()`` holds (G0-tests F16: no fixed sleeps as assertions)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + limit_s
    while not condition():
        if loop.time() > deadline:
            raise AssertionError("condition not reached in time")
        await asyncio.sleep(0.01)


async def _settle(count: Any, rounds: int = 5) -> None:
    """Let the connection drain: after ``rounds`` empty polls no further notification arrived."""
    seen = count()
    for _ in range(rounds):
        await asyncio.sleep(0.02)
        assert count() == seen, "a duplicate notification arrived"


def _drain(
    conn: Conn,
    tenant: uuid.UUID,
    limit: int,
    topics: list[str] | None = None,
    *,
    expected: int,
    deadline_s: float = 15.0,
) -> list[uuid.UUID]:
    """Page with ``limit`` until ``expected`` rows arrived. The reader stops at the cluster-wide
    commit horizon, so an unrelated open transaction elsewhere on the cluster only delays rows;
    waiting for them (bounded) keeps the test deterministic."""
    seen: list[uuid.UUID] = []
    xid, last = 0, NIL
    stop = time.monotonic() + deadline_s
    while len(seen) < expected:
        with conn.tx(tenant, rollback=True):
            page = conn.fetch(
                "SELECT id, xid FROM sibyl.outbox_read($1, $2, $3, $4)", xid, last, limit, topics
            )
        if page:
            seen += [r["id"] for r in page]
            xid, last = int(page[-1]["xid"]), page[-1]["id"]
        elif time.monotonic() > stop:
            raise AssertionError(f"only {len(seen)} of {expected} rows below the horizon")
        else:
            conn.run(asyncio.sleep(0.02))
    with conn.tx(tenant, rollback=True):
        rest = conn.fetch(
            "SELECT id FROM sibyl.outbox_read($1, $2, $3, $4)", xid, last, limit, topics
        )
    return seen + [r["id"] for r in rest]


def test_paging_through_one_transaction_with_limit_one_misses_nothing(
    roles: dict[str, Conn], tenant: uuid.UUID
) -> None:
    """Rows of one transaction share an xid; an `xid >` keyset would drop all but the first."""
    app = roles["sibyl_app"]
    with app.tx(tenant):
        ids = [
            app.fetchrow(INSERT_OUTBOX, tenant, "alert", "alert.fired", uuid.uuid4(), f"p{i}")["id"]
            for i in range(4)
        ]
    for limit in (1, 2, 3):
        drained = _drain(app, tenant, limit, expected=len(ids))
        assert sorted(drained) == sorted(ids) and len(drained) == len(ids), limit


def test_cursor_orders_by_commit_xid_not_by_id(
    db: Database, roles: dict[str, Conn], tenant: uuid.UUID
) -> None:
    """Lower xid, higher id: an id-ordered reader would deliver B first and then skip A."""
    first, second = db.connect("sibyl_app"), db.connect("sibyl_app")
    try:
        tx1 = _begin(first, tenant)
        first.fetchval("SELECT pg_current_xact_id()")  # takes the lower xid now
        tx2 = _begin(second, tenant)
        b = second.fetchrow(INSERT_OUTBOX, tenant, "alert", "alert.fired", uuid.uuid4(), "b")
        a = first.fetchrow(INSERT_OUTBOX, tenant, "alert", "alert.fired", uuid.uuid4(), "a")
        second.run(tx2.commit())
        first.run(tx1.commit())
    finally:
        first.close()
        second.close()
    assert int(a["xid"]) < int(b["xid"]) and a["id"] > b["id"]
    assert _drain(roles["sibyl_app"], tenant, 1, expected=2) == [a["id"], b["id"]]


def test_topic_filter_pages_only_the_requested_topics(
    roles: dict[str, Conn], tenant: uuid.UUID
) -> None:
    app = roles["sibyl_app"]
    with app.tx(tenant):
        rows = {
            topic: app.fetchrow(INSERT_OUTBOX, tenant, topic, f"{topic}.x", uuid.uuid4(), topic)[
                "id"
            ]
            for topic in ("alert", "policy", "handoff", "killswitch")
        }
    got = _drain(app, tenant, 1, ["policy", "killswitch"], expected=2)
    assert sorted(got) == sorted([rows["policy"], rows["killswitch"]])


def test_outbox_topics_are_the_coarse_set(roles: dict[str, Conn], tenant: uuid.UUID) -> None:
    with pytest.raises(asyncpg.CheckViolationError):
        with roles["sibyl_app"].tx(tenant, rollback=True):
            roles["sibyl_app"].fetchrow(
                INSERT_OUTBOX, tenant, "policy_changed", "x", uuid.uuid4(), "bad-topic"
            )
