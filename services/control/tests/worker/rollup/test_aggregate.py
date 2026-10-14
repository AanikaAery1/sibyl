"""Pure counter aggregation (events -> 1m rows, children -> parents)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

from sibyl_control.worker.rollup.aggregate import (
    AGENT_COLUMNS,
    aggregate_events,
    bucket_start,
    sql_agg,
)
from sibyl_control.worker.scoring.features import hist_bucket

T0 = datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)
A = uuid4()


def ev(**kw: object) -> dict[str, object]:
    base: dict[str, object] = {
        "agent_id": A,
        "p": "openai",
        "m": "gpt",
        "ts": T0 + timedelta(seconds=5),
        "event_type": "gen_ai.request",
        "status": "ok",
        "error_class": None,
        "http_status": 200,
        "latency_ms": 100,
        "ttfb_ms": 20,
        "tokens_in": 10,
        "tokens_out": 5,
        "cost_usd": Decimal("0.01"),
        "route_decision": "primary",
        "policy_state": "fresh",
        "is_late": False,
        "retry_attempt": None,
        "inline_fb": None,
        "breaker_state": None,
        "action": None,
        "rl_headroom": None,
        "rl_rem": None,
        "rl_lim": None,
        "ctx": None,
        "fin_length": False,
        "fin_filter": False,
        "fin_tools": False,
        "refusal": None,
        "output_chars": None,
        "tool_name": None,
        "task_id": None,
        "schema_valid": None,
        "error_type": None,
        "outcome": None,
        "fb_score": None,
    }
    base.update(kw)
    return base


def test_bucket_start_aligns_to_the_epoch_grid() -> None:
    assert bucket_start(T0 + timedelta(seconds=59), 60) == T0
    assert bucket_start(T0 + timedelta(minutes=7), 300) == T0 + timedelta(minutes=5)
    assert bucket_start(T0 + timedelta(minutes=59), 3600) == T0


def test_gen_ai_counters() -> None:
    rows = [
        ev(),
        ev(status="error", error_class="timeout", http_status=None, tokens_out=0),
        ev(status="error", error_class="rate_limit", http_status=429, tokens_out=0),
        ev(status="error", error_class="server_error", http_status=503),
        ev(route_decision="inline_fallback", retry_attempt="2", is_late=True),
        ev(breaker_state="open", policy_state="stale", rl_headroom="0.2"),
        ev(rl_rem="50", rl_lim="1000", ctx="0.9", fin_length=True, output_chars="120"),
        ev(fin_filter=True),
        ev(refusal="true"),
        ev(tokens_out=0),
    ]
    out = aggregate_events(rows, 60)
    assert list(out) == [(A, "openai", "gpt", T0)]
    r = out[(A, "openai", "gpt", T0)]
    assert r["request_count"] == 10 and r["error_count"] == 3
    assert (r["timeout_count"], r["rate_limit_count"], r["server_error_count"]) == (1, 1, 1)
    assert r["inline_fallback_count"] == 1 and r["retry_count"] == 1 and r["late_count"] == 1
    assert r["breaker_open_count"] == 1 and r["policy_stale_count"] == 1
    assert r["ratelimit_remaining_min"] == 50, "per-mille headroom, min of 200 and 50"
    assert r["finish_length_count"] == 1 and r["refusal_count"] == 2
    assert r["empty_output_count"] == 1, "tokens_out = 0 on status ok only"
    assert r["output_chars_sum"] == 120
    assert r["cost_usd"] == Decimal("0.10") and r["tokens_out_sumsq"] == 25 * 6 + 0 + 25
    assert sum(r["latency_hist"]) == 10 and r["latency_hist"][hist_bucket(100)] == 10
    assert r["context_util_hist"][hist_bucket(900)] == 1
    assert set(r) == set(AGENT_COLUMNS)


def test_tool_task_feedback_rows_land_in_the_unattributed_row() -> None:
    rows = [
        ev(event_type="tool.call", p="", m="", tool_name="lookup", task_id="t1"),
        ev(
            event_type="tool.call",
            p="",
            m="",
            tool_name="lookup",
            status="error",
            error_type="schema_validation",
            task_id="t1",
        ),
        ev(
            event_type="tool.call",
            p="",
            m="",
            tool_name="search",
            schema_valid="false",
            task_id="t1",
        ),
        ev(event_type="task.outcome", p="", m="", outcome="success"),
        ev(event_type="task.outcome", p="", m="", outcome="failure"),
        ev(event_type="handoff.requested", p="", m=""),
        ev(event_type="feedback", p="", m="", fb_score="-0.5"),
        ev(event_type="policy.decision", p="", m="", action="breaker_open"),
    ]
    r = aggregate_events(rows, 60)[(A, "", "", T0)]
    assert r["request_count"] == 0 and r["tool_call_count"] == 3
    assert r["tool_error_count"] == 1 and r["tool_schema_invalid_count"] == 2
    assert r["tool_seq_hash_distinct"] == 2, "distinct (task, tool) pairs"
    untasked = aggregate_events([ev(event_type="tool.call", p="", m="", tool_name="x")] * 3, 60)
    assert untasked[(A, "", "", T0)]["tool_seq_hash_distinct"] == 3, "no task: never a loop"
    assert (r["task_count"], r["task_success_count"], r["task_failure_count"]) == (2, 1, 1)
    assert r["handoff_count"] == 1 and r["feedback_count"] == 1
    assert r["feedback_sum"] == Decimal("-0.5") and r["breaker_open_count"] == 1


def test_sql_agg_shapes() -> None:
    assert sql_agg("request_count") == "sum(t.request_count)::int"
    assert sql_agg("tokens_out") == "sum(t.tokens_out)::int8"
    assert sql_agg("cost_usd") == "sum(t.cost_usd)"
    assert sql_agg("ratelimit_remaining_min") == "min(t.ratelimit_remaining_min)"
    hist = sql_agg("latency_hist", "x")
    assert hist.startswith("ARRAY[sum(x.latency_hist[1])") and hist.count("sum(") == 40
