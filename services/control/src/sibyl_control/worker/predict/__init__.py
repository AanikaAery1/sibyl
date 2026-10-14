"""Prediction loop (lane P): leading rules L1-L4 + provider facet, horizons, sparse
``prediction`` rows, outcomes, and the tier gate into lane S's saga (ML.md §4, §7.3).

Importing this package registers the feed loader (``prepare``), the leading evaluator and the
horizon predictor with the health engine (``worker.scoring.extensions``); the worker imports it
when it resolves the loop table, before any tick runs. The scoring tick then runs ``prepare``
once per tenant right after ``load_tenant`` (same transaction, same ``now``), scores the leading
rules from that feed and writes the horizons into ``health_snapshot``; this loop's tick turns
snapshots into predictions.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from ..scoring.config import EngineConfig
from ..scoring.engine import Evaluation
from ..scoring.extensions import Extensions, register
from ..scoring.features import AgentInputs
from ..scoring.rules import RuleOutcome
from .feed import current, prepare
from .horizons import predict_horizons
from .leading import evaluate_leading

if TYPE_CHECKING:
    from ...core.settings import Settings
    from ..loops import LoopContext

LOOP = "predict"


def leading_extension(
    inputs: AgentInputs, config: EngineConfig, now: datetime
) -> list[RuleOutcome]:
    return evaluate_leading(inputs, current(inputs.agent_id, now), config, now)


def horizons_extension(
    inputs: AgentInputs, evaluation: Evaluation, config: EngineConfig, now: datetime
) -> tuple[dict[str, Any], str | None]:
    return predict_horizons(inputs, evaluation, config, now, current(inputs.agent_id, now))


EXTENSIONS = Extensions(leading=leading_extension, horizons=horizons_extension, prepare=prepare)


def install() -> None:
    """Register lane P with the scoring tick (idempotent)."""
    register(leading=EXTENSIONS.leading, horizons=EXTENSIONS.horizons, prepare=EXTENSIONS.prepare)


install()


async def run_tenant(
    conn: Any, tenant: UUID, now: datetime | None = None, *, settings: Settings
) -> Any:
    from .outcomes import fill_outcomes
    from .writer import write_predictions

    now = now or await conn.fetchval("SELECT now()")
    result = await write_predictions(conn, tenant, now, settings=settings)
    await fill_outcomes(conn, tenant, now)
    return result


async def tick(ctx: LoopContext) -> None:
    """Predictions for every active tenant, one transaction each. The D36 gate comes from
    ``ctx.settings`` (B20), as the saga's ``worker_env`` does."""
    from ..rollup.tenancy import active_tenants, try_lock

    for tenant in await active_tenants(ctx.db):
        try:
            async with ctx.db.tenant_tx(tenant) as conn:
                if not await try_lock(conn, LOOP, tenant):
                    continue
                result = await run_tenant(conn, tenant, settings=ctx.settings)
            for call in result.gate_calls:
                ctx.log.info(
                    "predicted failover offered: agent %s band %s %s mode %s -> %s",
                    call.agent_id,
                    call.band,
                    call.confidence,
                    call.mode,
                    call.failover_id,
                )
        except Exception:
            ctx.log.exception("prediction failed for tenant %s", tenant)


__all__ = [
    "EXTENSIONS",
    "LOOP",
    "horizons_extension",
    "install",
    "leading_extension",
    "prepare",
    "tick",
]
