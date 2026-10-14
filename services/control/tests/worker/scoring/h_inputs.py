"""Builders for pure-engine tests: an ``AgentInputs`` from a handful of counts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sibyl_control.worker.scoring.features import AgentInputs, WindowStats, latency_hist

NOW = datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)
AGENT = UUID("00000000-0000-7000-8000-000000000001")
PROVIDER = UUID("00000000-0000-7000-8000-0000000000aa")


def window(
    *,
    req: int = 0,
    err: int = 0,
    latencies: list[int] | None = None,
    refusals: int = 0,
    truncations: int = 0,
    empty: int = 0,
    tool_calls: int = 0,
    tool_distinct: int = 0,
    schema_bad: int = 0,
    server_errors: int = 0,
) -> WindowStats:
    lat = latencies if latencies is not None else [500] * req
    return WindowStats(
        request_count=req,
        error_count=err,
        server_error_count=server_errors,
        refusal_count=refusals,
        finish_length_count=truncations,
        empty_output_count=empty,
        tool_call_count=tool_calls,
        tool_seq_hash_distinct=tool_distinct,
        tool_schema_invalid_count=schema_bad,
        latency_hist=latency_hist(lat),
    )


def inputs(*, tier: int = 2, plan: bool = True, **counts: object) -> AgentInputs:
    w5 = window(**counts)  # type: ignore[arg-type]
    return AgentInputs(
        agent_id=AGENT,
        tier=tier,
        created_at=NOW - timedelta(days=30),
        provider="provider-one",
        provider_id=PROVIDER,
        model="large-1",
        model_class="large",
        w5=w5,
        w1=w5,
        request_count_1h=max(int(w5.request_count) * 12, 0),
        active_minutes_1h=60,
        has_plan=plan,
    )
