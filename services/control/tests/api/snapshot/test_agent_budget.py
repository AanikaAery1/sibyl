"""Real PostgreSQL ledger integration tests (snapshot fixture migrates an isolated PG17 DB)."""

from __future__ import annotations

import asyncio
from decimal import Decimal
from uuid import uuid4

import pytest

from sibyl_control.core.agent_budget import (
    BudgetConfigurationError,
    ReservationConflict,
    reserve_monthly,
    settle_monthly,
)

from .conftest import Api


async def test_concurrent_reservations_do_not_oversubscribe(api: Api) -> None:
    """Every concurrent gateway sees the same locked 1500 USD period row."""
    tenant, agent = api.world.tenant, api.world.agent_a
    requests = [uuid4() for _ in range(25)]
    results = await asyncio.gather(
        *(reserve_monthly(api.db, tenant, agent, req, Decimal("100")) for req in requests)
    )
    granted = [req for req, outcome in zip(requests, results, strict=True) if outcome.may_dispatch]
    assert len(granted) == 15
    assert sum(outcome.status == "exhausted" for outcome in results) == 10

    duplicate = await reserve_monthly(api.db, tenant, agent, granted[0], Decimal("100"))
    assert duplicate.status == "duplicate_pending" and not duplicate.may_dispatch
    with pytest.raises(ReservationConflict):
        await reserve_monthly(api.db, tenant, agent, granted[0], Decimal("101"))

    assert await settle_monthly(api.db, tenant, granted[0], Decimal("60")) is True
    assert await settle_monthly(api.db, tenant, granted[0], Decimal("60")) is False
    with pytest.raises(ReservationConflict):
        await settle_monthly(api.db, tenant, granted[0], Decimal("70"))
    again = await reserve_monthly(api.db, tenant, agent, granted[0], Decimal("100"))
    assert again.status == "already_settled" and not again.may_dispatch

    # Settlement refunds only the unused part of a confirmed bill.
    remaining = await reserve_monthly(api.db, tenant, agent, uuid4(), Decimal("40"))
    assert remaining.may_dispatch
    over = await reserve_monthly(api.db, tenant, agent, uuid4(), Decimal("0.00000001"))
    assert over.status == "exhausted"

    async with api.db.tenant_tx(tenant, readonly=True) as conn:
        period = await conn.fetchrow(
            "SELECT spent_usd, reserved_usd FROM sibyl.agent_budget_period"
            " WHERE tenant_id=$1 AND agent_id=$2",
            tenant, agent,
        )
        assert Decimal(period["spent_usd"]) == Decimal("60")
        assert Decimal(period["reserved_usd"]) == Decimal("1440")


async def test_unconfigured_budget_fails_closed(api: Api) -> None:
    # agent_b has no continuity_plan and may not receive a priced reservation.
    with pytest.raises(BudgetConfigurationError):
        await reserve_monthly(
            api.db, api.world.tenant, api.world.agent_b, uuid4(), Decimal("0.10")
        )


@pytest.mark.parametrize("amount", [
    Decimal("0"), Decimal("-1"), Decimal("NaN"), Decimal("Infinity"),
])
async def test_invalid_estimates_are_rejected(api: Api, amount: Decimal) -> None:
    with pytest.raises(BudgetConfigurationError):
        await reserve_monthly(
            api.db, api.world.tenant, api.world.agent_a, uuid4(), amount
        )
