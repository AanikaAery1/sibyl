"""Atomic monthly budget reservations, shared by all gateways through Postgres.

The caller must arrange a reservation BEFORE every billable provider attempt and
settle it after authoritative usage is known. Unknown prices must fail closed.
This module is intentionally NOT wired into gateway dispatch yet; it is the
transactional ledger foundation, not an end-to-end spending guarantee.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import ROUND_CEILING, Decimal, InvalidOperation
from typing import Any, Literal
from uuid import UUID

from .db import Database

_CENTIMICRO = Decimal("0.00000001")
_MAX_USD = Decimal("9999999999.99999999")


class BudgetConfigurationError(ValueError):
    """A strict limit or price estimate needed to reserve is unavailable."""


class ReservationConflict(ValueError):
    """An idempotency key is reused with incompatible reservation details."""


class UnknownReservation(LookupError):
    """The reservation does not exist in this tenant."""


@dataclass(frozen=True)
class ReserveResult:
    status: Literal["granted", "duplicate_pending", "already_settled", "exhausted"]
    period_start: date
    requested_usd: Decimal

    @property
    def may_dispatch(self) -> bool:
        """Only a newly created reservation permits a NEW upstream attempt."""
        return self.status == "granted"


def _dollars(value: Decimal, *, allow_zero: bool) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise BudgetConfigurationError("a finite Decimal amount is required")
    try:
        amount = value.quantize(_CENTIMICRO, rounding=ROUND_CEILING)
    except InvalidOperation as exc:
        raise BudgetConfigurationError("amount exceeds ledger precision") from exc
    if amount < 0 or (amount == 0 and not allow_zero) or amount > _MAX_USD:
        raise BudgetConfigurationError("invalid reservation or settlement amount")
    return amount


async def reserve_monthly(
    db: Database,
    tenant_id: UUID,
    agent_id: UUID,
    request_id: UUID,
    estimated_usd: Decimal,
) -> ReserveResult:
    """Reserve a priced worst-case call in a single tenant transaction.

    The cap comes directly from the tenant's continuity_plan (never from a
    gateway-supplied budget). Locking the shared period row serializes concurrent
    gateways and requests for the same agent. A repeated idempotency key cannot
    authorize a second upstream dispatch.
    """
    amount = _dollars(estimated_usd, allow_zero=False)

    async def operation(conn: Any) -> ReserveResult:
        period: date = await conn.fetchval(
            "SELECT date_trunc('month', now() AT TIME ZONE 'UTC')::date"
        )
        await conn.execute(
            "INSERT INTO sibyl.agent_budget_period (tenant_id, agent_id, period_start)"
            " VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            tenant_id, agent_id, period,
        )
        # Every update (including settlement) locks period before reservation.
        row = await conn.fetchrow(
            "SELECT spent_usd, reserved_usd FROM sibyl.agent_budget_period"
            " WHERE tenant_id=$1 AND agent_id=$2 AND period_start=$3 FOR UPDATE",
            tenant_id, agent_id, period,
        )
        if row is None:
            raise BudgetConfigurationError("agent budget row not visible")

        existing = await conn.fetchrow(
            "SELECT agent_id, period_start, reserved_usd, state"
            " FROM sibyl.agent_budget_reservation"
            " WHERE tenant_id=$1 AND request_id=$2",
            tenant_id, request_id,
        )
        if existing is not None:
            if existing["agent_id"] != agent_id or Decimal(existing["reserved_usd"]) != amount:
                raise ReservationConflict("request_id reused for another agent or amount")
            return ReserveResult(
                "duplicate_pending" if existing["state"] == "pending" else "already_settled",
                existing["period_start"],
                amount,
            )

        cap = await conn.fetchval(
            "SELECT budget_usd_month FROM sibyl.continuity_plan"
            " WHERE tenant_id=$1 AND agent_id=$2",
            tenant_id, agent_id,
        )
        if cap is None:
            raise BudgetConfigurationError("hard monthly budget is not configured")
        limit = _dollars(Decimal(cap), allow_zero=True)
        balance = Decimal(row["spent_usd"]) + Decimal(row["reserved_usd"])
        if balance + amount > limit:
            return ReserveResult("exhausted", period, amount)

        updated = await conn.fetchval(
            "UPDATE sibyl.agent_budget_period"
            " SET reserved_usd=reserved_usd+$4, updated_at=now()"
            " WHERE tenant_id=$1 AND agent_id=$2 AND period_start=$3"
            " AND spent_usd + reserved_usd + $4 <= $5"
            " RETURNING reserved_usd",
            tenant_id, agent_id, period, amount, limit,
        )
        if updated is None:
            return ReserveResult("exhausted", period, amount)
        await conn.execute(
            "INSERT INTO sibyl.agent_budget_reservation"
            " (tenant_id, request_id, agent_id, period_start, reserved_usd)"
            " VALUES ($1, $2, $3, $4, $5)",
            tenant_id, request_id, agent_id, period, amount,
        )
        return ReserveResult("granted", period, amount)

    return await db.run_in_tenant_tx(tenant_id, operation)


async def settle_monthly(
    db: Database,
    tenant_id: UUID,
    request_id: UUID,
    actual_usd: Decimal,
) -> bool:
    """Settle one reservation, once; returns False for an exact duplicate.

    Charge actual cost even when it EXCEEDS the reserved estimate: hiding a
    provider overage is worse than acknowledging a budget violation.
    A failed/uncertain provider attempt must not be refunded until confirmed
    unbilled. Never automatically expire or reclaim pending reservations.
    """
    actual = _dollars(actual_usd, allow_zero=True)

    async def operation(conn: Any) -> bool:
        # Read location, then lock the PERIOD first: avoids lock inversion with reserve.
        location = await conn.fetchrow(
            "SELECT agent_id, period_start FROM sibyl.agent_budget_reservation"
            " WHERE tenant_id=$1 AND request_id=$2",
            tenant_id, request_id,
        )
        if location is None:
            raise UnknownReservation(str(request_id))
        await conn.fetchrow(
            "SELECT spent_usd FROM sibyl.agent_budget_period"
            " WHERE tenant_id=$1 AND agent_id=$2 AND period_start=$3 FOR UPDATE",
            tenant_id, location["agent_id"], location["period_start"],
        )
        held = await conn.fetchrow(
            "SELECT reserved_usd, actual_usd, state"
            " FROM sibyl.agent_budget_reservation"
            " WHERE tenant_id=$1 AND request_id=$2 FOR UPDATE",
            tenant_id, request_id,
        )
        if held is None:
            raise UnknownReservation(str(request_id))
        if held["state"] == "settled":
            if Decimal(held["actual_usd"]) != actual:
                raise ReservationConflict("settlement replay has a different amount")
            return False
        reserved = Decimal(held["reserved_usd"])
        result = await conn.fetchval(
            "UPDATE sibyl.agent_budget_period"
            " SET reserved_usd=reserved_usd-$4, spent_usd=spent_usd+$5,"
            " updated_at=now() WHERE tenant_id=$1 AND agent_id=$2 AND period_start=$3"
            " AND reserved_usd >= $4 RETURNING spent_usd",
            tenant_id, location["agent_id"], location["period_start"], reserved, actual,
        )
        if result is None:
            raise ReservationConflict("reserved balance cannot cover the settlement")
        await conn.execute(
            "UPDATE sibyl.agent_budget_reservation"
            " SET state='settled', actual_usd=$3, settled_at=now()"
            " WHERE tenant_id=$1 AND request_id=$2 AND state='pending'",
            tenant_id, request_id, actual,
        )
        return True

    return await db.run_in_tenant_tx(tenant_id, operation)
