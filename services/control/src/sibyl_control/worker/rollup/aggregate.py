"""Pure counter aggregation for the rollup grains (ML.md §2.6; db §1.2).

Events become rows keyed ``(agent_id, provider, model, bucket_start)``. Events without a model
(tool calls, task outcomes, feedback, handoffs, policy decisions) land in the unattributed row
``provider = '' AND model = ''`` so per-agent ratios still sum across rows. Every counter is a
plain sum so a parent grain is the sum of its children; histograms add element-wise and
``ratelimit_remaining_min`` (per-mille headroom, see ``_headroom``) merges by ``least()``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID

from ..scoring.features import ZERO_HIST, hist_bucket

EPOCH = datetime(2000, 1, 1, tzinfo=UTC)
UNATTRIBUTED = ""

HIST_COLUMNS: tuple[str, ...] = ("latency_hist", "ttfb_hist", "context_util_hist")
DECIMAL_COLUMNS: frozenset[str] = frozenset({"cost_usd", "feedback_sum", "tokens_out_sumsq"})
SHARED_COUNTERS: tuple[str, ...] = (
    "request_count",
    "error_count",
    "timeout_count",
    "rate_limit_count",
    "server_error_count",
    "blocked_count",
    "inline_fallback_count",
    "breaker_open_count",
    "tool_call_count",
    "late_count",
    "policy_stale_count",
    "tokens_in",
    "tokens_out",
    "cost_usd",
    "retry_count",
    "finish_length_count",
    "finish_tool_calls_count",
    "refusal_count",
    "empty_output_count",
    "tool_error_count",
    "tool_schema_invalid_count",
    "output_chars_sum",
    "tokens_out_sumsq",
    "tool_seq_hash_distinct",
)
AGENT_ONLY: tuple[str, ...] = (
    "task_count",
    "task_success_count",
    "task_failure_count",
    "handoff_count",
    "feedback_count",
    "feedback_sum",
)
SUMMED: tuple[str, ...] = SHARED_COUNTERS + AGENT_ONLY
AGENT_COLUMNS: tuple[str, ...] = (*SUMMED, *HIST_COLUMNS, "ratelimit_remaining_min")
PROVIDER_COLUMNS: tuple[str, ...] = (*SHARED_COUNTERS, *HIST_COLUMNS, "ratelimit_remaining_min")

ROLLED_EVENT_TYPES: tuple[str, ...] = (
    "gen_ai.request",
    "tool.call",
    "task.outcome",
    "handoff.requested",
    "feedback",
    "policy.decision",
)
SCHEMA_ERROR_TYPES = frozenset({"schema_validation", "invalid_arguments", "ValidationError"})
TASK_SUCCESS = frozenset({"success", "partial"})
TASK_FAILURE = frozenset({"failure", "abandoned"})

Key = tuple[UUID, str, str, datetime]


def bucket_start(ts: datetime, width_s: int) -> datetime:
    """``date_bin(width, ts, '2000-01-01')`` (the CHECK on agent_metrics_5m uses this grid)."""
    offset = int((ts - EPOCH).total_seconds() // width_s) * width_s
    return EPOCH + timedelta(seconds=offset)


def empty_row(columns: Iterable[str] = AGENT_COLUMNS) -> dict[str, Any]:
    row: dict[str, Any] = {}
    for col in columns:
        if col in HIST_COLUMNS:
            row[col] = list(ZERO_HIST)
        elif col == "ratelimit_remaining_min":
            row[col] = None
        elif col in DECIMAL_COLUMNS:
            row[col] = Decimal(0)
        else:
            row[col] = 0
    return row


def _truthy(value: Any) -> bool:
    return str(value).lower() in ("true", "t", "1") if value is not None else False


def _falsy(value: Any) -> bool:
    return str(value).lower() in ("false", "f", "0") if value is not None else False


def _float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _headroom(e: Mapping[str, Any]) -> int | None:
    """Per-mille rate-limit headroom: ``attrs.ratelimit.headroom`` else remaining / limit."""
    head = _float(e.get("rl_headroom"))
    if head is None:
        rem, lim = _float(e.get("rl_rem")), _float(e.get("rl_lim"))
        if rem is not None and lim:
            head = rem / lim
    if head is None:
        return None
    return max(0, min(1000, round(head * 1000)))


def _gen_ai(row: dict[str, Any], e: Mapping[str, Any]) -> None:
    status = e.get("status")
    cls = e.get("error_class")
    http = e.get("http_status")
    row["request_count"] += 1
    row["error_count"] += status == "error"
    row["timeout_count"] += cls == "timeout"
    row["rate_limit_count"] += cls == "rate_limit" or http == 429
    row["server_error_count"] += cls == "server_error" or (http is not None and http >= 500)
    row["blocked_count"] += cls == "blocked"
    row["inline_fallback_count"] += e.get("route_decision") == "inline_fallback" or _truthy(
        e.get("inline_fb")
    )
    row["breaker_open_count"] += e.get("breaker_state") == "open"
    row["late_count"] += bool(e.get("is_late"))
    row["policy_stale_count"] += e.get("policy_state") in ("stale", "expired", "unavailable")
    tokens_out = int(e.get("tokens_out") or 0)
    row["tokens_in"] += int(e.get("tokens_in") or 0)
    row["tokens_out"] += tokens_out
    row["tokens_out_sumsq"] += Decimal(tokens_out * tokens_out)
    row["cost_usd"] += Decimal(e.get("cost_usd") or 0)
    attempt = _float(e.get("retry_attempt"))
    row["retry_count"] += attempt is not None and attempt > 1
    row["finish_length_count"] += bool(e.get("fin_length"))
    row["finish_tool_calls_count"] += bool(e.get("fin_tools"))
    row["refusal_count"] += status == "ok" and (
        bool(e.get("fin_filter")) or _truthy(e.get("refusal"))
    )
    row["empty_output_count"] += status == "ok" and tokens_out == 0
    row["output_chars_sum"] += int(_float(e.get("output_chars")) or 0)
    head = _headroom(e)
    if head is not None:
        cur = row["ratelimit_remaining_min"]
        row["ratelimit_remaining_min"] = head if cur is None else min(cur, head)
    if e.get("latency_ms") is not None:
        row["latency_hist"][hist_bucket(e["latency_ms"])] += 1
    if e.get("ttfb_ms") is not None:
        row["ttfb_hist"][hist_bucket(e["ttfb_ms"])] += 1
    ctx = _float(e.get("ctx"))
    if ctx is not None:
        row["context_util_hist"][hist_bucket(ctx * 1000)] += 1


def _other(row: dict[str, Any], e: Mapping[str, Any], tools: set[str]) -> None:
    kind = e.get("event_type")
    if kind == "tool.call":
        row["tool_call_count"] += 1
        row["tool_error_count"] += e.get("status") == "error"
        row["tool_schema_invalid_count"] += _falsy(e.get("schema_valid")) or (
            e.get("error_type") in SCHEMA_ERROR_TYPES
        )
        # Loop proxy: distinct (task, tool) pairs. A task hammering one tool collapses to one
        # pair; a call without a task is its own pair, so loops are only seen inside tasks.
        task = e.get("task_id")
        tools.add(f"{task}:{e.get('tool_name')}" if task else f"event:{len(tools)}")
    elif kind == "task.outcome":
        row["task_count"] += 1
        row["task_success_count"] += e.get("outcome") in TASK_SUCCESS
        row["task_failure_count"] += e.get("outcome") in TASK_FAILURE
    elif kind == "handoff.requested":
        row["handoff_count"] += 1
    elif kind == "feedback":
        score = _float(e.get("fb_score"))
        if score is not None:
            row["feedback_count"] += 1
            row["feedback_sum"] += Decimal(str(score))
    elif kind == "policy.decision":
        row["breaker_open_count"] += e.get("action") == "breaker_open"


def aggregate_events(
    events: Iterable[Mapping[str, Any]], width_s: int
) -> dict[Key, dict[str, Any]]:
    """Recompute rows from scratch for every bucket the events touch."""
    out: dict[Key, dict[str, Any]] = {}
    tools: dict[Key, set[str]] = {}
    for e in events:
        key: Key = (
            e["agent_id"],
            e.get("p") or "",
            e.get("m") or "",
            bucket_start(e["ts"], width_s),
        )
        row = out.get(key)
        if row is None:
            row = out[key] = empty_row()
            tools[key] = set()
        if e.get("event_type") == "gen_ai.request":
            _gen_ai(row, e)
        else:
            _other(row, e, tools[key])
    for key, names in tools.items():
        out[key]["tool_seq_hash_distinct"] = len(names)
    return out


BIGINT_COLUMNS = frozenset({"tokens_in", "tokens_out", "output_chars_sum"})


def sql_agg(col: str, alias: str = "t") -> str:
    """SQL aggregate of one counter over child rows: sum, element-wise histogram, least()."""
    if col in HIST_COLUMNS:
        parts = ", ".join(f"sum({alias}.{col}[{i}])" for i in range(1, 41))
        return f"ARRAY[{parts}]::int[]"
    if col == "ratelimit_remaining_min":
        return f"min({alias}.{col})"
    if col in DECIMAL_COLUMNS:
        return f"sum({alias}.{col})"
    if col in BIGINT_COLUMNS:
        return f"sum({alias}.{col})::int8"
    return f"sum({alias}.{col})::int"
