"""SSE on PG17: a real LISTEN/NOTIFY round trip, cursor resume, reset frames, filtering, stream
caps and heartbeat re-validation.

Starlette's TestClient returns a streamed body once the app finishes, so every stream here runs
with a short ``max_lifetime_s`` and concurrent writes come from a background thread on its own
connection. The NOTIFY round trip itself is proven at the hub (commit → wake, no polling).

The reader serves rows only below the cluster-wide commit horizon (R60). Other lanes share this
PG17 cluster and their open transactions hold the horizon back, so seeded rows are awaited past
the horizon before a stream opens, and the concurrent-write test relies on the poll fallback.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections import Counter
from typing import Any
from uuid import UUID, uuid4

import asyncpg
import pytest
import sibyl_lane_a_kit as kit  # loaded by conftest
from sibyl_control.api.sse.hub import NotifyHub
from sibyl_control.api.sse.stream import StreamConfig

API = "/api/v1"
FAST = StreamConfig(heartbeat_s=0.2, poll_s=0.3, max_lifetime_s=2.5)


@pytest.fixture
def lane(lane_db: Any) -> Any:
    with kit.lane_app(lane_db, extra_state={"sse_config": FAST}) as app:
        yield app


def insert(
    db: Any,
    tenant: UUID,
    event_type: str,
    topic: str,
    *,
    agent: UUID | None = None,
    payload: dict[str, Any] | None = None,
) -> str:
    with db.admin.tx(tenant):
        row = db.admin.fetchrow(
            "INSERT INTO sibyl.outbox (tenant_id, topic, event_type, aggregate_kind, aggregate_id,"
            " payload,"
            " idempotency_key) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7) RETURNING xid::text AS"
            " xid, id",
            tenant,
            topic,
            event_type,
            "agent" if agent else "tenant",
            agent or tenant,
            payload if payload is not None else ({"agent_id": str(agent)} if agent else {}),
            f"test:{uuid4()}",
        )
    return f"{row['xid']}|{row['id']}"


def settle(db: Any, tenant: UUID, timeout_s: float = 60.0) -> None:
    """Wait until every committed outbox row of ``tenant`` is below the commit horizon."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        with db.admin.tx(tenant):
            ready = db.admin.fetchval(
                "SELECT coalesce(max(xid) < sibyl.commit_horizon(), true) FROM sibyl.outbox"
                " WHERE tenant_id = $1",
                tenant,
            )
        if ready:
            return
        time.sleep(0.1)
    raise AssertionError("the commit horizon did not pass the seeded rows")


def insert_later(
    db: Any, tenant: UUID, delay_s: float, event_type: str, topic: str, *, agent: UUID | None = None
) -> threading.Thread:
    async def run() -> None:
        await asyncio.sleep(delay_s)
        conn = await asyncpg.connect(db.dsn("postgres"))
        try:
            async with conn.transaction():
                await conn.execute("SELECT sibyl.set_tenant($1)", tenant)
                await conn.execute(
                    "INSERT INTO sibyl.outbox (tenant_id, topic, event_type, aggregate_kind,"
                    " aggregate_id,"
                    " payload, idempotency_key) VALUES ($1, $2, $3, 'tenant', $1, $4::text::jsonb,"
                    " $5)",
                    tenant,
                    topic,
                    event_type,
                    json.dumps({"agent_id": str(agent)} if agent else {}),
                    f"later:{uuid4()}",
                )
        finally:
            await conn.close()

    thread = threading.Thread(target=lambda: asyncio.run(run()))
    thread.start()
    return thread


def frames(text: str) -> list[dict[str, str]]:
    out = []
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if line.startswith(":"):
                fields.setdefault("comment", line[1:].strip())
                continue
            name, _, value = line.partition(":")
            fields[name] = value.strip()
        if fields:
            out.append(fields)
    return out


def events(text: str) -> list[dict[str, str]]:
    return [f for f in frames(text) if "event" in f]


def stream(lane: Any, token: str, **kw: Any) -> Any:
    headers = lane.bearer(token, **kw.pop("headers", {}))
    return lane.client.get(f"{API}/events/stream", headers=headers, **kw)


def test_notify_round_trip_wakes_the_hub(lane_db: Any, world: Any) -> None:
    """A committed outbox row reaches the hub through LISTEN/NOTIFY, for its tenant only."""

    async def run() -> tuple[int, int, bool]:
        hub = NotifyHub(lambda: asyncpg.connect(lane_db.dsn()))
        await hub.start()
        assert hub.listening
        mine, other = hub.subscribe(world.tenant), hub.subscribe(uuid4())
        conn = await asyncpg.connect(lane_db.dsn("postgres"))
        try:
            async with conn.transaction():
                await conn.execute("SELECT sibyl.set_tenant($1)", world.tenant)
                await conn.execute(
                    "INSERT INTO sibyl.outbox (tenant_id, topic, event_type, aggregate_kind,"
                    " aggregate_id,"
                    " payload, idempotency_key) VALUES ($1, 'policy', 'snapshot.issued', 'tenant',"
                    " $1, '{}', $2)",
                    world.tenant,
                    f"notify:{uuid4()}",
                )
                await asyncio.sleep(0.2)
                before_commit = mine.wake.is_set()
            await asyncio.wait_for(mine.wake.wait(), 2.0)
        finally:
            await conn.close()
            await hub.stop()
        return mine.notified, other.notified, before_commit

    mine, other, before_commit = asyncio.run(run())
    assert (mine, other, before_commit) == (1, 0, False)


def test_stream_delivers_a_concurrent_commit(lane: Any, world: Any) -> None:
    token = kit.add_session(lane.db, world.tenant, world.users["viewer"])
    settle(lane.db, world.tenant)
    lane.app.state.sibyl_lane_a["sse_config"] = StreamConfig(
        heartbeat_s=0.2, poll_s=0.3, max_lifetime_s=6.0
    )
    writer = insert_later(
        lane.db, world.tenant, 0.4, "alert.fired", "alert", agent=world.agents["in_g1"]
    )
    resp = stream(lane, token)
    writer.join()
    assert resp.status_code == 200 and resp.headers["content-type"].startswith("text/event-stream")
    got = events(resp.text)
    assert [e["event"] for e in got] == ["alert.fired"], resp.text
    xid, row_id = got[0]["id"].split("|")
    assert xid.isdigit() and UUID(row_id)
    assert json.loads(got[0]["data"]) == {"agent_id": str(world.agents["in_g1"])}
    assert frames(resp.text)[0]["retry"] == "3000"
    assert lane.app.state.sibyl_lane_a["sse_hub"].listening


def test_resume_with_last_event_id(lane: Any, world: Any) -> None:
    token = kit.add_session(lane.db, world.tenant, world.users["owner"])
    first = insert(lane.db, world.tenant, "graph.changed", "graph", payload={"graph_version": 1})
    second = insert(lane.db, world.tenant, "graph.changed", "graph", payload={"graph_version": 2})
    settle(lane.db, world.tenant)
    resp = stream(lane, token, headers={"Last-Event-ID": first})
    got = events(resp.text)
    assert [e["id"] for e in got] == [second]
    assert json.loads(got[0]["data"]) == {"graph_version": 2}
    fresh = stream(lane, token)
    assert events(fresh.text) == []  # no Last-Event-ID: live only
    assert frames(fresh.text)[0]["id"] == second  # announces the resume point


def test_expired_or_unknown_cursor_resets(lane: Any, world: Any) -> None:
    token = kit.add_session(lane.db, world.tenant, world.users["owner"])
    with lane.db.admin.tx(world.tenant):
        oldest = lane.db.admin.fetchrow(
            "SELECT xid::text AS xid, id FROM sibyl.outbox WHERE tenant_id = $1 ORDER BY xid, id"
            " LIMIT 1",
            world.tenant,
        )
    resp = stream(lane, token, headers={"Last-Event-ID": f"1|{uuid4()}"})
    got = events(resp.text)
    assert got[0]["event"] == "reset"
    assert json.loads(got[0]["data"]) == {
        "reason": "cursor_expired",
        "oldest": f"{oldest['xid']}|{oldest['id']}",
    }
    assert stream(lane, token, headers={"Last-Event-ID": "garbage"}).status_code == 422


def test_slow_consumer_gets_reset(lane_db: Any, world: Any) -> None:
    tight = StreamConfig(buffer=2, heartbeat_s=0.2, poll_s=0.3, max_lifetime_s=2.0)
    start = insert(lane_db, world.tenant, "graph.changed", "graph", payload={"graph_version": 0})
    for n in range(6):
        insert(lane_db, world.tenant, "graph.changed", "graph", payload={"graph_version": n + 1})
    settle(lane_db, world.tenant)
    with kit.lane_app(lane_db, extra_state={"sse_config": tight}) as lane:
        token = kit.add_session(lane_db, world.tenant, world.users["owner"])
        resp = stream(lane, token, headers={"Last-Event-ID": start})
    got = events(resp.text)
    assert got[-1]["event"] == "reset" and json.loads(got[-1]["data"]) == {
        "reason": "slow_consumer"
    }
    assert len(got) - 1 <= 2


def test_keys_see_policy_topics_only_and_bound_keys_their_agent(lane: Any, world: Any) -> None:
    kit.add_capture_policy(lane.db, world.tenant, world.users["owner"])
    admin = kit.add_session(lane.db, world.tenant, world.users["admin"])

    def key(agent: UUID | None) -> str:
        body = {"name": "k", "env": "test", "scopes": ["routing:read"]} | (
            {"agent_id": str(agent)} if agent else {}
        )
        return lane.client.post(
            f"{API}/api-keys", json=body, headers=lane.bearer(admin, **kit.idem())
        ).json()["secret"]

    tenant_key, bound_key = key(None), key(world.agents["in_g1"])
    settle(lane.db, world.tenant)
    start = insert(lane.db, world.tenant, "graph.changed", "graph", payload={"graph_version": 0})
    insert(lane.db, world.tenant, "alert.fired", "alert", agent=world.agents["in_g1"])
    mine = insert(lane.db, world.tenant, "policy_changed", "policy", agent=world.agents["in_g1"])
    theirs = insert(lane.db, world.tenant, "policy_changed", "policy", agent=world.agents["other"])
    issued = insert(lane.db, world.tenant, "snapshot.issued", "policy", payload={"version": 7})
    settle(lane.db, world.tenant)
    resume = {"Last-Event-ID": start}
    assert [e["id"] for e in events(stream(lane, tenant_key, headers=resume).text)] == [
        mine,
        theirs,
        issued,
    ]
    assert [e["id"] for e in events(stream(lane, bound_key, headers=resume).text)] == [mine, issued]
    assert stream(lane, tenant_key, params={"topics": "alert"}).status_code == 403
    assert (
        stream(lane, bound_key, params={"agent_id": str(world.agents["other"])}).status_code == 404
    )


def test_topic_and_agent_filters(lane: Any, world: Any) -> None:
    token = kit.add_session(lane.db, world.tenant, world.users["owner"])
    start = insert(lane.db, world.tenant, "graph.changed", "graph", payload={"graph_version": 0})
    fired = insert(lane.db, world.tenant, "alert.fired", "alert", agent=world.agents["in_g1"])
    insert(lane.db, world.tenant, "alert.resolved", "alert", agent=world.agents["in_g1"])
    other = insert(lane.db, world.tenant, "alert.fired", "alert", agent=world.agents["other"])
    settle(lane.db, world.tenant)
    resume = {"Last-Event-ID": start}
    by_event = events(stream(lane, token, params={"topics": "alert.fired"}, headers=resume).text)
    assert [e["id"] for e in by_event] == [fired, other]
    by_agent = events(
        stream(
            lane,
            token,
            params={"topics": "alert", "agent_id": str(world.agents["other"])},
            headers=resume,
        ).text
    )
    assert [e["id"] for e in by_agent] == [other]
    assert stream(lane, token, params={"topics": "bogus"}).status_code == 422
    assert stream(lane, token, params={"since": "2020-01-01T00:00:00Z"}).status_code == 422


def test_skipped_rows_move_the_resume_point(lane: Any, world: Any) -> None:
    token = kit.add_session(lane.db, world.tenant, world.users["owner"])
    start = insert(lane.db, world.tenant, "graph.changed", "graph", payload={"graph_version": 0})
    skipped = insert(lane.db, world.tenant, "alert.fired", "alert", agent=world.agents["in_g1"])
    settle(lane.db, world.tenant)
    resp = stream(
        lane,
        token,
        params={"agent_id": str(world.agents["other"])},
        headers={"Last-Event-ID": start},
    )
    assert events(resp.text) == []
    assert any(f.get("id") == skipped and f.get("comment") == "ping" for f in frames(resp.text))


def test_stream_cap_and_revocation(lane: Any, world: Any) -> None:
    token = kit.add_session(lane.db, world.tenant, world.users["viewer"])
    with lane.db.admin.tx(world.tenant):
        sid = lane.db.admin.fetchval(
            "SELECT id FROM sibyl.session WHERE tenant_id = $1 AND user_id = $2",
            world.tenant,
            world.users["viewer"],
        )
    counts: Counter[str] = lane.app.state.sibyl_lane_a.setdefault("sse_streams", Counter())
    counts[f"session:{sid}"] = 20
    capped = stream(lane, token)
    assert capped.status_code == 429 and capped.json()["type"].endswith("/stream_limit")
    counts[f"session:{sid}"] = 0

    def revoke() -> None:
        async def run() -> None:
            await asyncio.sleep(0.3)
            conn = await asyncpg.connect(lane.db.dsn("postgres"))
            try:
                await conn.execute("UPDATE sibyl.session SET revoked_at = now() WHERE id = $1", sid)
            finally:
                await conn.close()

        asyncio.run(run())

    lane.app.state.sibyl_lane_a["sse_config"] = StreamConfig(
        heartbeat_s=0.2, poll_s=0.3, max_lifetime_s=10.0
    )
    thread = threading.Thread(target=revoke)
    thread.start()
    started = time.monotonic()
    resp = stream(lane, token)
    thread.join()
    assert resp.status_code == 200 and time.monotonic() - started < 5  # ended by re-validation
    assert counts[f"session:{sid}"] == 0


def test_heartbeat_revalidation_does_not_extend_the_idle_window(lane: Any, world: Any) -> None:
    lane.app.state.sibyl_lane_a["auth_settings"] = kit.AuthSettings(
        session_secret=kit.SESSION_SECRET, session_touch_s=0
    )
    token = kit.add_session(lane.db, world.tenant, world.users["viewer"])
    resp = stream(lane, token)  # 2.5 s of heartbeats, each one re-resolving the session
    assert resp.status_code == 200 and resp.text.count(": ping") >= 5
    with lane.db.admin.tx(world.tenant):
        spread = lane.db.admin.fetchval(
            "SELECT extract(epoch FROM now() - last_seen_at) FROM sibyl.session"
            " WHERE tenant_id = $1 AND user_id = $2",
            world.tenant,
            world.users["viewer"],
        )
    assert spread > 1.5  # touched when the stream opened, never by the heartbeats
