from uuid import UUID, uuid4

import pytest
from sibyl_control.core.outbox import (
    EVENT_TOPICS,
    OUTBOX_CHANNEL,
    POLICY_CHANNEL,
    TOPICS,
    InMemoryOutboxWriter,
    OutboxMessage,
    PgOutboxWriter,
    channel_for,
)
from sibyl_control.core.problems import ProblemError
from sibyl_control.core.ratelimit import (
    POLICIES,
    InMemoryRateLimiter,
    RatePolicy,
    enforce,
)

TENANT = UUID("01927000-0000-7000-8000-000000000001")


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


async def test_token_bucket_allows_burst_then_refuses() -> None:
    clock = Clock()
    limiter = InMemoryRateLimiter(clock=clock)
    policy = RatePolicy("test", quota=3, window_s=60)
    decisions = [await limiter.hit("k", policy) for _ in range(4)]
    assert [d.allowed for d in decisions] == [True, True, True, False]
    assert decisions[2].remaining == 0
    assert decisions[3].retry_after_s == 20
    clock.t += 20
    assert (await limiter.hit("k", policy)).allowed


async def test_keys_are_independent() -> None:
    limiter = InMemoryRateLimiter(clock=Clock())
    policy = RatePolicy("test", quota=1, window_s=60)
    assert (await limiter.hit("a", policy)).allowed
    assert (await limiter.hit("b", policy)).allowed
    assert not (await limiter.hit("a", policy)).allowed


async def test_headers_follow_ietf_ratelimit_draft() -> None:
    limiter = InMemoryRateLimiter(clock=Clock())
    decision = await limiter.hit("k", RatePolicy("read", quota=600, window_s=60))
    headers = decision.headers()
    assert headers["RateLimit-Policy"] == '"read";q=600;w=60'
    assert headers["RateLimit"].startswith('"read";r=599;t=')


async def test_enforce_raises_429_with_retry_after() -> None:
    limiter = InMemoryRateLimiter(clock=Clock())
    policy = RatePolicy("tiny", quota=1, window_s=10)
    enforce(await limiter.hit("k", policy))
    with pytest.raises(ProblemError) as err:
        enforce(await limiter.hit("k", policy))
    assert err.value.status == 429
    assert err.value.headers["Retry-After"] == "10"


async def test_bounded_memory_evicts_oldest_keys() -> None:
    limiter = InMemoryRateLimiter(clock=Clock(), max_keys=2)
    policy = RatePolicy("t", quota=1, window_s=60)
    for k in ("a", "b", "c"):
        await limiter.hit(k, policy)
    assert len(limiter) == 2


def test_policy_table_matches_api_md_2_8() -> None:
    assert (POLICIES["read"].quota, POLICIES["read"].window_s) == (600, 60)
    assert (POLICIES["mutation"].quota, POLICIES["mutation"].window_s) == (60, 60)
    assert (POLICIES["break_glass_key"].quota, POLICIES["break_glass_key"].window_s) == (3, 600)
    assert (POLICIES["snapshot"].quota, POLICIES["snapshot"].window_s) == (2, 1)
    assert POLICIES["erasure_create"].window_s == 86400


def test_two_notify_channels() -> None:
    assert channel_for("policy") == POLICY_CHANNEL == "sibyl_policy"
    assert channel_for("killswitch") == POLICY_CHANNEL
    for topic in set(TOPICS) - {"policy", "killswitch"}:
        assert channel_for(topic) == OUTBOX_CHANNEL == "sibyl_outbox"
    assert len(TOPICS) == 14  # + job (B14), action (D48)
    assert EVENT_TOPICS["job.requested"] == "job"
    assert set(EVENT_TOPICS.values()) <= set(TOPICS)
    assert EVENT_TOPICS["policy_changed"] == "policy"
    assert EVENT_TOPICS["approval.requested"] == "approval"


def test_message_validation() -> None:
    OutboxMessage("policy", "policy_changed", "agent", uuid4(), {"routing_version": 3})
    with pytest.raises(ValueError, match="topic"):
        OutboxMessage("nope", "x", "agent", None, {})
    with pytest.raises(ValueError, match="content key"):
        OutboxMessage("incident", "incident.updated", "failover", None, {"prompt": "x"})
    with pytest.raises(ValueError, match="8 KB"):
        OutboxMessage("incident", "incident.updated", "failover", None, {"x": "y" * 9000})


async def test_in_memory_writer_records_messages() -> None:
    writer = InMemoryOutboxWriter()
    msg = OutboxMessage("policy", "policy_changed", "agent", uuid4(), {"routing_version": 1})
    await writer.emit(None, TENANT, msg)
    assert writer.messages(TENANT) == [msg]


class FakeConn:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple]] = []

    async def execute(self, sql: str, *args):
        self.calls.append((sql, args))
        return "INSERT 0 1"


async def test_pg_writer_inserts_into_outbox() -> None:
    conn = FakeConn()
    agent = uuid4()
    msg = OutboxMessage("policy", "policy_changed", "agent", agent, {"routing_version": 1}, "k1")
    await PgOutboxWriter().emit(conn, TENANT, msg)
    sql, args = conn.calls[0]
    assert "INSERT INTO sibyl.outbox" in sql
    assert args[:5] == (TENANT, "policy", "policy_changed", "agent", agent)
    assert args[6] == "k1"


# --- code review L4 / security LOW --------------------------------------------------------------


async def test_eviction_never_resets_an_exhausted_bucket() -> None:
    """Spraying fresh keys must not evict (and so refill) a throttled bucket."""
    clock = Clock()
    limiter = InMemoryRateLimiter(clock=clock, max_keys=3)
    policy = RatePolicy("t", quota=2, window_s=60)
    for _ in range(2):
        await limiter.hit("victim-of-own-abuse", policy)
    assert not (await limiter.hit("victim-of-own-abuse", policy)).allowed
    for i in range(50):
        await limiter.hit(f"spray-{i}", policy)
    assert len(limiter) <= 3 + 1  # bounded: table plus the shared overflow bucket
    assert not (await limiter.hit("victim-of-own-abuse", policy)).allowed


async def test_full_buckets_are_evicted_first_and_overflow_is_shared() -> None:
    clock = Clock()
    limiter = InMemoryRateLimiter(clock=clock, max_keys=2)
    policy = RatePolicy("t", quota=1, window_s=60)
    await limiter.hit("a", policy)
    await limiter.hit("b", policy)
    clock.t += 120  # a and b have refilled: evicting them loses nothing
    assert (await limiter.hit("c", policy)).allowed
    assert (await limiter.hit("d", policy)).allowed
    assert len(limiter) == 2
    # c and d are drained and the table is full: new keys share one coarse overflow bucket
    assert (await limiter.hit("e", policy)).allowed
    assert not (await limiter.hit("f", policy)).allowed


async def test_cost_above_capacity_is_a_programming_error() -> None:
    limiter = InMemoryRateLimiter(clock=Clock())
    with pytest.raises(ValueError, match="capacity"):
        await limiter.hit("k", RatePolicy("t", quota=3, window_s=60), cost=4)
    with pytest.raises(ValueError, match="cost"):
        await limiter.hit("k", RatePolicy("t", quota=3, window_s=60), cost=0)


async def test_peek_does_not_consume() -> None:
    limiter = InMemoryRateLimiter(clock=Clock())
    policy = RatePolicy("t", quota=1, window_s=60)
    assert (await limiter.peek("k", policy)).allowed
    assert (await limiter.peek("k", policy)).allowed
    await limiter.hit("k", policy)
    assert not (await limiter.peek("k", policy)).allowed
    assert len(limiter) == 1


def test_contract_tables_are_read_only() -> None:
    from sibyl_control.core.problems import SQLSTATE_MAP

    with pytest.raises(TypeError):
        POLICIES["read"] = POLICIES["mutation"]  # type: ignore[index]
    with pytest.raises(TypeError):
        SQLSTATE_MAP["23505"] = "internal_error"  # type: ignore[index]
