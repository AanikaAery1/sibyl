"""Lane P's prepare hook (INT-1): ``install()`` registers the feed loader as
``Extensions.prepare``, so the scoring tick itself loads the trend state and budgets the
leading evaluators read, once per tenant, on the tick's transaction and with the tick's ``now``.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from typing import Any
from uuid import UUID

import pytest
from sibyl_control.worker import predict
from sibyl_control.worker.predict import feed
from sibyl_control.worker.scoring.extensions import registered, reset
from sibyl_control.worker.scoring.runner import score_tenant

from .p_sim import PSim, request, spread


@pytest.fixture
def installed() -> Iterator[None]:
    reset()
    predict.install()
    yield
    predict.install()


def test_install_registers_the_feed_loader_as_the_prepare_hook(installed: None) -> None:
    ext = registered()
    assert ext.prepare is feed.prepare
    assert ext.leading is predict.leading_extension
    assert ext.horizons is predict.horizons_extension
    assert predict.EXTENSIONS == ext


def _steady(agent: UUID) -> Any:
    return lambda lo, hi: [request(agent, ts) for ts in spread(lo, hi, 6)]


def test_a_scoring_tick_loads_the_feed_once_per_tenant(
    kit: Any, installed: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    loads: list[tuple[UUID, datetime, bool]] = []
    real = feed.load_feed

    async def counting(conn: Any, tenant: UUID, now: datetime) -> feed.Feed:
        same_tx = await conn.fetchval("SELECT current_setting('app.tenant_id', true)")
        loads.append((tenant, now, same_tx == str(tenant)))
        return await real(conn, tenant, now)

    monkeypatch.setattr(feed, "load_feed", counting)
    t = kit.tenant()
    kit.provider(t)
    a = kit.agent(t, tier=2)
    sim = PSim(kit, t, minutes=8, extensions=None)  # the registered (installed) extensions
    sim.run(360, _steady(a))  # one closed 5-minute bucket: trend state exists
    assert kit.val("SELECT count(*) FROM sibyl.agent_trend_state WHERE agent_id = $1", a) > 0
    kit.exe(
        "UPDATE sibyl.agent_trend_state SET ewma = 0.03, cusum_pos = 7.5"
        " WHERE agent_id = $1 AND metric = 'error_rate'",
        a,
    )
    loads.clear()
    sim.step(_steady(a))
    assert loads == [(t, sim.now, True)], "once per tenant tick, same tx, same now"
    l1 = sim.scores[-1].evaluations[a].outcomes["error_trend"]
    assert l1.evaluated and "CUSUM 7.5 > 5" in l1.explanation, l1.explanation

    other = kit.tenant()
    kit.agent(other, tier=3)
    loads.clear()

    async def score_other() -> None:
        async with kit.worker.tenant_tx(other) as conn:
            await score_tenant(conn, other, now=sim.now)

    kit.run(score_other())
    assert loads == [(other, sim.now, True)]
