"""Daily budget (UTC day) with reservation: concurrent callers never overshoot it.

1. ``reserve`` adds a worst-case estimate with one conditional update
   (``spent_usd + estimate <= daily_budget_usd``); ``False`` means "skip, budget exhausted".
2. The call runs outside any transaction.
3. ``settle`` swaps the reservation for the actual cost (a provider error refunds it entirely;
   a bad-output failure keeps what the provider billed) and counts tokens, calls, findings.

The estimate is an upper bound by construction (generous chars-per-token, ``max_tokens`` for
the answer, twice for the repair call), so a settled day can exceed its budget only when a
provider bills more output than ``max_tokens``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from typing import Any, Final
from uuid import UUID

from ...core.llm import Price, Usage, cost_usd, estimate_tokens

CALLS_PER_FINDING: Final = 2  # the structured call plus at most one repair

_ENSURE_SQL = (
    "INSERT INTO sibyl.sentinel_usage (tenant_id, day) VALUES ($1, $2) ON CONFLICT DO NOTHING"
)
_RESERVE_SQL = """
UPDATE sibyl.sentinel_usage SET spent_usd = spent_usd + $3
 WHERE tenant_id = $1 AND day = $2 AND spent_usd + $3 <= $4
RETURNING spent_usd
"""
_SETTLE_SQL = """
UPDATE sibyl.sentinel_usage
   SET spent_usd = greatest(spent_usd - $3 + $4, 0), tokens_in = tokens_in + $5,
       tokens_out = tokens_out + $6, calls = calls + $7, findings = findings + $8,
       failures = failures + $9
 WHERE tenant_id = $1 AND day = $2
"""
_LOCK_SQL = (
    "SELECT spent_usd, exhausted_at FROM sibyl.sentinel_usage WHERE tenant_id = $1 AND day = $2"
    " FOR UPDATE"
)
_SKIP_BUDGET_SQL = """
UPDATE sibyl.sentinel_usage SET skipped_budget = skipped_budget + 1,
       exhausted_at = coalesce(exhausted_at, now())
 WHERE tenant_id = $1 AND day = $2
"""
_SKIP_SAMPLING_SQL = """
UPDATE sibyl.sentinel_usage SET skipped_sampling = skipped_sampling + $3
 WHERE tenant_id = $1 AND day = $2
"""
_TODAY_SQL = "SELECT * FROM sibyl.sentinel_usage WHERE tenant_id = $1 AND day = $2"


def estimate_cost(prompt_text: str, max_tokens: int, price: Price) -> Decimal:
    usage = Usage(estimate_tokens(prompt_text), max_tokens)
    return cost_usd(usage, price) * CALLS_PER_FINDING


async def reserve(conn: Any, tenant: UUID, day: date, budget: Decimal, amount: Decimal) -> bool:
    await conn.execute(_ENSURE_SQL, tenant, day)
    return await conn.fetchval(_RESERVE_SQL, tenant, day, amount, budget) is not None


@dataclass(frozen=True)
class Settlement:
    reserved: Decimal
    actual: Decimal
    usage: Usage
    calls: int
    finding: bool
    failed: bool


async def settle(conn: Any, tenant: UUID, day: date, s: Settlement) -> None:
    await conn.execute(_ENSURE_SQL, tenant, day)
    await conn.execute(
        _SETTLE_SQL,
        tenant,
        day,
        s.reserved,
        s.actual,
        s.usage.input_tokens,
        s.usage.output_tokens,
        s.calls,
        1 if s.finding else 0,
        1 if s.failed else 0,
    )


async def record_budget_skip(conn: Any, tenant: UUID, day: date) -> tuple[bool, Decimal]:
    """Count a skip; ``True`` the first time the day's budget runs out (audit it once)."""
    await conn.execute(_ENSURE_SQL, tenant, day)
    row = await conn.fetchrow(_LOCK_SQL, tenant, day)
    first = row["exhausted_at"] is None
    await conn.execute(_SKIP_BUDGET_SQL, tenant, day)
    return first, Decimal(row["spent_usd"])


async def record_sampling_skips(conn: Any, tenant: UUID, day: date, n: int) -> None:
    if n <= 0:
        return
    await conn.execute(_ENSURE_SQL, tenant, day)
    await conn.execute(_SKIP_SAMPLING_SQL, tenant, day, n)


async def today(conn: Any, tenant: UUID, day: date) -> dict[str, Any] | None:
    row = await conn.fetchrow(_TODAY_SQL, tenant, day)
    return None if row is None else dict(row)
