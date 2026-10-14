"""OTLP traces and logs end to end: protobuf and JSON, partial success, dead letters,
heartbeats, gzip, the call_merge flush with cost at ingest, logs → observation.gap."""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

from sibyl_control.ingest.flusher import flush_tenant
from sibyl_control.ingest.otlp import decode_traces

from .conftest import FIXTURE_AGENT, World
from .otlp_build import chat_attrs, log_record, logs, span, traces

PB = Path(__file__).parent / "fixtures" / "otlp"


async def _flush(world: World) -> int:
    return await flush_tenant(
        world.db, world.tenant_id, world.services.cfg, now=datetime.now(UTC) + timedelta(minutes=1)
    )


async def _events(world: World, etype: str | None = None) -> list:
    sql = "SELECT * FROM sibyl.events WHERE tenant_id = $1"
    if etype:
        return await world.rows(sql + " AND event_type = $2", world.tenant_id, etype)
    return await world.rows(sql, world.tenant_id)


async def test_json_chat_span_is_staged_then_flushed_with_cost(world: World) -> None:
    body = traces([span(chat_attrs(**{"sibyl.agent_id": str(FIXTURE_AGENT)}))])
    resp = await world.post("/v1/otlp/traces", body)
    assert resp.status_code == 200
    assert resp.json() == {}
    assert await _events(world, "gen_ai.request") == []
    assert await _flush(world) == 1
    [row] = await _events(world, "gen_ai.request")
    assert row["agent_id"] == FIXTURE_AGENT
    assert (row["tokens_in"], row["tokens_out"], row["provider"], row["model"]) == (
        1000,
        500,
        "openai",
        "gpt-5-mini",
    )
    assert row["cost_usd"] == Decimal("0.00125000")  # 1000 * 0.25/1M + 500 * 2.00/1M
    assert row["latency_ms"] == 120
    assert row["raw_ref_id"] is not None
    assert row["normaliser_version"] == "normaliser/1.0"
    assert json.loads(row["attrs"]) if isinstance(row["attrs"], str) else row["attrs"]


async def test_protobuf_reference_batch(world: World) -> None:
    raw = (PB / "traces.pb").read_bytes()
    resp = await world.post("/v1/otlp/traces", raw, content_type="application/x-protobuf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/x-protobuf"
    # a chat span (2026-10 timestamp, ERROR status), a tool span and an unclassified GET span
    batch = decode_traces(raw, content_type="application/x-protobuf")
    assert batch.span_count == 3
    rows = await world.rows(
        "SELECT reason FROM sibyl.events_rejected WHERE tenant_id = $1", world.tenant_id
    )
    assert (
        len(await _events(world, "agent.discovered")) == 1
    )  # spans without identity auto-register
    accepted_or_rejected = (
        len(await _events(world, "tool.call"))
        + len(rows)
        + await world.val(
            "SELECT count(*) FROM sibyl.call_merge WHERE tenant_id = $1", world.tenant_id
        )
    )
    assert accepted_or_rejected == 2  # the GET span is raw-only


async def test_missing_required_is_partial_success(world: World) -> None:
    bad = span({"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai"})
    good = span(chat_attrs())
    resp = await world.post("/v1/otlp/traces", traces([bad, good]))
    assert resp.status_code == 200
    partial = resp.json()["partialSuccess"]
    assert partial["rejectedSpans"] == "1"
    entries = json.loads(partial["errorMessage"])
    assert entries == [
        {"trace_id": bad["traceId"], "span_id": bad["spanId"], "reason": "missing_required"}
    ]
    [rej] = await world.rows(
        "SELECT reason, head, raw_ref_id FROM sibyl.events_rejected WHERE tenant_id = $1",
        world.tenant_id,
    )
    assert rej["reason"] == "missing_required"
    assert rej["raw_ref_id"] is not None


async def test_unclassified_spans_are_raw_only_not_rejected(world: World) -> None:
    resp = await world.post("/v1/otlp/traces", traces([span({"http.method": "GET"}, name="GET /")]))
    assert resp.status_code == 200
    assert resp.json() == {}
    assert await _events(world) == []
    assert (
        await world.val(
            "SELECT count(*) FROM sibyl.events_rejected WHERE tenant_id = $1", world.tenant_id
        )
        == 0
    )
    raw = await world.val(
        "SELECT count(*) FROM sibyl.payload_refs WHERE tenant_id = $1 AND kind = 'raw_batch'",
        world.tenant_id,
    )
    assert raw == 1


async def test_empty_batch_is_a_heartbeat_that_writes_nothing(world: World) -> None:
    for body, ctype in ((b"", "application/x-protobuf"), (b"{}", "application/json")):
        resp = await world.post("/v1/otlp/traces", body, content_type=ctype)
        assert resp.status_code == 200
        assert resp.content in (b"", b"{}")
    assert (
        await world.val(
            "SELECT count(*) FROM sibyl.payload_refs WHERE tenant_id = $1", world.tenant_id
        )
        == 0
    )
    assert await world.val(
        "SELECT last_used_at IS NOT NULL FROM sibyl.api_key WHERE id = $1", world.keys["tenant"].id
    )


async def test_gzip_body_is_accepted(world: World) -> None:
    body = gzip.compress(
        traces(
            [
                span(
                    {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "lookup"},
                    name="tool",
                )
            ]
        )
    )
    resp = await world.post("/v1/otlp/traces", body, headers={"content-encoding": "gzip"})
    assert resp.status_code == 200
    [row] = await _events(world, "tool.call")
    attrs = row["attrs"] if isinstance(row["attrs"], dict) else json.loads(row["attrs"])
    assert attrs["tool_name"] == "lookup"


async def test_env_mismatch_is_per_event(world: World) -> None:
    resp = await world.post(
        "/v1/otlp/traces", traces([span(chat_attrs())], resource={"sibyl.env": "test"})
    )
    partial = resp.json()["partialSuccess"]
    assert json.loads(partial["errorMessage"])[0]["reason"] == "env_mismatch"


async def test_sdk_and_gateway_contributions_merge(world: World) -> None:
    call_id = "019276a1-4a2b-7c1d-8e30-f1e2d3c4b5a6"
    trace = "4bf92f3577b34da6a3ce929d0e0e4736"
    sdk = span(
        chat_attrs(
            **{
                "sibyl.call_id": call_id,
                "sibyl.source": "sdk",
                "gen_ai.conversation.id": "conv-1",
                "gen_ai.input.messages": '[{"role":"user","content":"hi"}]',
            }
        ),
        trace=trace,
    )
    gw = span(
        chat_attrs(
            **{
                "sibyl.call_id": call_id,
                "sibyl.source": "gateway",
                "gen_ai.usage.input_tokens": 2000,
                "http.response.status_code": 200,
            }
        ),
        trace=trace,
        duration_ms=900,
    )
    await world.post("/v1/otlp/traces", traces([sdk]))
    await world.post("/v1/otlp/traces", traces([gw]))
    state = await world.val(
        "SELECT state FROM sibyl.call_merge WHERE tenant_id = $1", world.tenant_id
    )
    assert state == "complete"
    assert (
        await flush_tenant(world.db, world.tenant_id, world.services.cfg) == 1
    )  # complete flushes at once
    [row] = await _events(world, "gen_ai.request")
    attrs = row["attrs"] if isinstance(row["attrs"], dict) else json.loads(row["attrs"])
    assert attrs["contributions"] == ["gateway", "sdk"]
    assert attrs["merge_state"] == "complete"
    assert attrs["conversation_id"] == "conv-1"  # sdk owns conversation
    assert row["tokens_in"] == 2000 and row["latency_ms"] == 900  # gateway owns usage and latency
    assert row["payload_ref_id"] is not None  # only the sdk carried a body
    late = span(chat_attrs(**{"sibyl.call_id": call_id, "sibyl.source": "sdk"}), trace=trace)
    resp = await world.post("/v1/otlp/traces", traces([late]))
    assert (
        json.loads(resp.json()["partialSuccess"]["errorMessage"])[0]["reason"]
        == "late_contribution"
    )


async def test_logs_buffer_report_becomes_observation_gap(world: World) -> None:
    records = [
        log_record(
            "sibyl.sdk.buffer", {"sibyl.sdk.dropped_spans": 12, "sibyl.emitter_id": "sdk:h:1"}
        ),
        log_record("app.log", {}, body="free text log line"),
    ]
    resp = await world.post("/v1/otlp/logs", logs(records))
    assert resp.status_code == 200
    assert resp.json() == {}
    [row] = await _events(world, "observation.gap")
    attrs = row["attrs"] if isinstance(row["attrs"], dict) else json.loads(row["attrs"])
    assert attrs["cause"] == "buffer_dropped" and attrs["events_dropped"] == 12
    assert row["agent_id"] is None
    assert len(await _events(world)) == 1  # the free-text log is raw-only


async def test_logs_protobuf_reference(world: World) -> None:
    resp = await world.post(
        "/v1/otlp/logs", (PB / "logs.pb").read_bytes(), content_type="application/x-protobuf"
    )
    assert resp.status_code == 200
    assert resp.content == b""


async def test_content_log_event_without_call_attributes_is_raw_only(world: World) -> None:
    resp = await world.post(
        "/v1/otlp/logs", logs([log_record("gen_ai.content.prompt", {}, body="hello")])
    )
    assert resp.status_code == 200
    assert await _events(world) == []


async def test_get_is_405_and_unknown_content_type_415(world: World) -> None:
    resp = await world.client.get("/v1/otlp/traces")
    assert resp.status_code == 405
    resp = await world.post("/v1/otlp/traces", b"x", content_type="text/plain")
    assert resp.status_code == 415
