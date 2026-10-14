"""Status poller against PG17 with a local fake feed (httpx.MockTransport), as sibyl_worker."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any
from uuid import UUID

import httpx
import pytest
from sibyl_control.worker.loops import LoopContext
from sibyl_control.worker.status_poller import tick
from sibyl_control.worker.status_poller.feeds import FeedStatus
from sibyl_control.worker.status_poller.fetch import FeedError, FetchPolicy
from sibyl_control.worker.status_poller.poller import PollerSettings, Target, decide, poll
from sibyl_h_testkit import Kit

FEED = "https://status.provider-one.example/api/v2/summary.json"


class FakeFeed:
    """A status page whose indicator the test flips; counts requests per URL."""

    def __init__(self) -> None:
        self.indicator = "none"
        self.fail = False
        self.hits: dict[str, int] = {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.hits[str(request.url)] = self.hits.get(str(request.url), 0) + 1
        if self.fail:
            return httpx.Response(503)
        return httpx.Response(200, json={"status": {"indicator": self.indicator}, "incidents": []})


async def _public(host: str) -> list[str]:
    return ["93.184.216.34"]


def run_poll(kit: Kit, feed: FakeFeed, tenants: list[UUID], **settings: Any) -> Any:
    async def go() -> Any:
        async with httpx.AsyncClient(transport=httpx.MockTransport(feed)) as client:
            return await poll(
                kit.worker,
                client=client,
                policy=FetchPolicy(resolve=_public),
                settings=PollerSettings(**settings),
                tenants=tenants,
            )

    return kit.run(go())


def statuses(kit: Kit, tenant: UUID) -> list[str]:
    return [
        r["status"]
        for r in kit.q(
            "SELECT status FROM sibyl.provider_status WHERE tenant_id = $1 ORDER BY created_at",
            tenant,
        )
    ]


def test_poll_writes_on_change_only(kit: Kit) -> None:
    t = kit.tenant()
    kit.provider(t, feed=FEED)
    feed = FakeFeed()
    run_poll(kit, feed, [t])
    run_poll(kit, feed, [t])
    assert statuses(kit, t) == ["operational"]
    feed.indicator = "critical"
    res = run_poll(kit, feed, [t])
    assert res.written == 1 and statuses(kit, t) == ["operational", "major_outage"]


def test_one_fetch_per_url_across_tenants(kit: Kit) -> None:
    t1, t2 = kit.tenant(), kit.tenant()
    kit.provider(t1, feed=FEED)
    kit.provider(t2, feed=FEED)
    feed = FakeFeed()
    run_poll(kit, feed, [t1, t2])
    assert feed.hits == {FEED: 1}
    assert statuses(kit, t1) == statuses(kit, t2) == ["operational"]


def test_failed_fetch_does_not_move_status_until_stale(kit: Kit) -> None:
    t = kit.tenant()
    kit.provider(t, feed=FEED)
    feed = FakeFeed()
    run_poll(kit, feed, [t])
    feed.fail = True
    res = run_poll(kit, feed, [t])
    assert res.failed == 1 and statuses(kit, t) == ["operational"]
    res = run_poll(kit, feed, [t], stale_s=0)
    assert statuses(kit, t) == ["operational", "unknown"]
    run_poll(kit, feed, [t], stale_s=0)
    assert statuses(kit, t) == ["operational", "unknown"], "unknown is written once"


def test_disallowed_feed_url_is_skipped_and_kind_default_used(kit: Kit) -> None:
    t = kit.tenant()
    kit.provider(t, slug="internal", feed="https://10.0.0.8/status.json")
    feed = FakeFeed()
    res = run_poll(kit, feed, [t])
    assert res.skipped and not feed.hits and statuses(kit, t) == []
    t2 = kit.tenant()
    pid = kit.provider(t2, slug="known")
    kit.in_tenant(t2, "UPDATE sibyl.provider SET is_known_provider = true WHERE id = $1", pid)
    run_poll(kit, feed, [t2], feeds={"openai": FEED})
    assert statuses(kit, t2) == ["operational"]


def test_decide_refreshes_after_refresh_window() -> None:
    from datetime import UTC, datetime

    now = datetime(2026, 10, 10, tzinfo=UTC)
    target = Target(UUID(int=1), UUID(int=2), FEED, "operational", now - timedelta(seconds=700))
    ok = FeedStatus("operational", None, {})
    assert decide(target, ok, now, PollerSettings()) is not None
    fresh = Target(UUID(int=1), UUID(int=2), FEED, "operational", now - timedelta(seconds=10))
    assert decide(fresh, ok, now, PollerSettings()) is None
    assert decide(fresh, FeedError("x"), now, PollerSettings()) is None


def test_tick_logs_failures_and_never_raises(kit: Kit, monkeypatch: pytest.MonkeyPatch) -> None:
    import sibyl_control.worker.status_poller as poller_pkg

    async def offline(host: str) -> list[str]:
        raise OSError("offline")

    monkeypatch.setenv("SIBYL_STATUS_DEV_HOSTS", '["sibyl-sim"]')
    monkeypatch.setattr(poller_pkg, "FetchPolicy", lambda **kw: FetchPolicy(resolve=offline, **kw))
    t = kit.tenant()
    kit.provider(t, feed=FEED)
    ctx = LoopContext("status_poller", kit.worker, None, logging.getLogger("t"))
    kit.run(tick(ctx))  # every feed fails to resolve: logged, nothing raised
    assert statuses(kit, t) == ["unknown"], "first poll with no prior row records unknown"


def test_polled_major_outage_feeds_the_r4_factor(kit: Kit) -> None:
    from datetime import UTC, datetime

    from sibyl_control.worker.rollup.pipeline import rollup_tenant
    from sibyl_control.worker.scoring.runner import score_tenant
    from sibyl_h_testkit import calls, settle

    t = kit.tenant()
    kit.provider(t, feed=FEED)
    a = kit.agent(t, tier=2)
    # the agent's own calls fail: a page its traffic corroborates (a clean agent under a
    # major_outage page is the contradicted, leading case: worker/scoring test_status_lies.py)
    kit.events(t, calls(a, datetime.now(UTC) - timedelta(seconds=40), 30, errors=30))
    feed = FakeFeed()
    feed.indicator = "critical"
    run_poll(kit, feed, [t])

    settle(kit, t, 30, lambda conn: rollup_tenant(conn, t))

    async def go() -> Any:
        async with kit.worker.tenant_tx(t) as conn:
            return await score_tenant(conn, t)

    ev = kit.run(go()).evaluations[a]
    assert ev.outcomes["provider_status"].severity == 1
    assert any(f["rule"] == "provider_status" and f["penalty"] == 60 for f in ev.factors)
