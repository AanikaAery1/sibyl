"""Pure unit tests for the normaliser pieces (no database)."""

from __future__ import annotations

import gzip
import hashlib
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
from sibyl_control.core.problems import ProblemError
from sibyl_control.core.ratelimit import InMemoryRateLimiter
from sibyl_control.ingest.backpressure import Backpressure
from sibyl_control.ingest.body import inflate
from sibyl_control.ingest.config import IngestConfig
from sibyl_control.ingest.flusher import merge
from sibyl_control.ingest.ids import deterministic_uuid7, span_event_id, uuid7
from sibyl_control.ingest.normalise import derive
from sibyl_control.ingest.normalise.envelope import (
    fit_attrs,
    from_row_attrs,
    ingest_block,
    to_row_attrs,
)
from sibyl_control.ingest.normalise.fields import as_int, as_uuid, rfc3339_ns
from sibyl_control.ingest.normalise.identity import Directory, resolve, unclaimed_slug
from sibyl_control.ingest.normalise.jsonb_size import jsonb_size
from sibyl_control.ingest.normalise.scrubbing import PiiRedactor, strictest
from sibyl_control.ingest.normalise.semconv import span_candidate
from sibyl_control.ingest.otlp.model import Scope, Span
from sibyl_control.ingest.service import (
    Outcome,
    Rejection,
    _compact_for_cache,
    events_response,
    otlp_partial,
)
from sibyl_control.ingest.store import AgentRow

TENANT = UUID("01927000-0000-7000-8000-0000000000a1")
TRACE = bytes.fromhex("4bf92f3577b34da6a3ce929d0e0e4736")
SPAN = bytes.fromhex("00f067aa0ba902b7")


def test_span_event_ids_are_deterministic_uuidv7() -> None:
    a = span_event_id(TENANT, TRACE, SPAN, "sdk", 1_791_640_000_123_456_789)
    assert a == span_event_id(TENANT, TRACE, SPAN, "sdk", 1_791_640_000_123_456_789)
    assert a != span_event_id(TENANT, TRACE, SPAN, "gateway", 1_791_640_000_123_456_789)
    assert a != span_event_id(uuid4(), TRACE, SPAN, "sdk", 1_791_640_000_123_456_789)
    assert a.version == 7 and str(a)[19] in "89ab"
    assert int.from_bytes(a.bytes[:6], "big") == 1_791_640_000_123  # ms from the span end
    assert uuid7().version == 7
    assert deterministic_uuid7(1, "a", "bc") != deterministic_uuid7(1, "ab", "c")


def test_rfc3339_keeps_microseconds() -> None:
    assert rfc3339_ns(1_791_640_000_123_456_789) == "2026-10-10T13:46:40.123456Z"


def test_field_readers() -> None:
    assert as_uuid("0192767F-0000-7000-8000-00000000C010") == "0192767f-0000-7000-8000-00000000c010"
    assert as_uuid("nope") is None and as_uuid(3) is None
    assert (
        as_int("12") == 12
        and as_int(True) is None
        and as_int(-1, minimum=0) is None
        and as_int(2.0) == 2
    )


def test_inflate_caps() -> None:
    cfg = IngestConfig(max_decoded_bytes=1000)
    assert inflate(gzip.compress(b"a" * 1000), "gzip", cfg) == b"a" * 1000
    with pytest.raises(ProblemError) as caught:
        inflate(gzip.compress(b"a" * 1001), "gzip", cfg)
    assert caught.value.code == "payload_too_large"
    with pytest.raises(ProblemError):
        inflate(gzip.compress(b"x") + b"trailing", "gzip", cfg)
    assert inflate(b"raw", None, cfg) == b"raw"


@pytest.mark.parametrize(
    ("attrs", "expected"),
    [
        ({"status": "ok"}, None),
        ({"status": "error", "http_status": 429}, "rate_limit"),
        ({"status": "error", "error_type": "timeout"}, "timeout"),
        ({"status": "error", "http_status": 503}, "server_error"),
        ({"status": "error", "error_type": "404"}, "client_error"),
        ({"status": "error", "error_type": "ValueError"}, "other"),
    ],
)
def test_error_class(attrs: dict, expected: str | None) -> None:
    assert derive.error_class(attrs, "gen_ai.request") == expected


def test_cost_headroom_and_utilisation() -> None:
    price = derive.Price(
        Decimal("0.25"), Decimal("2.00"), Decimal("0.025"), "tenant/model/x", 128_000
    )
    usage = {"input_tokens": 1000, "output_tokens": 500, "cached_input_tokens": 400}
    assert derive.cost(usage, price) == Decimal("0.00116000")  # 600*.25 + 500*2 + 400*.025, per 1M
    assert derive.cost(usage, None) is None
    event = {
        "type": "gen_ai.request",
        "attrs": {
            "status": "ok",
            "usage": usage,
            "ratelimit": {
                "limit_requests": 100,
                "remaining_requests": 10,
                "limit_tokens": 1000,
                "remaining_tokens": 500,
            },
        },
    }
    klass, amount = derive.apply(event, price)
    assert klass is None and amount == Decimal("0.00116000")
    assert event["attrs"]["ratelimit"]["headroom"] == 0.1
    assert event["attrs"]["context"]["utilisation"] == pytest.approx(1000 / 128_000)
    assert event["attrs"]["cost_source"] == "tenant/model/x"


def _contribution(source: str, **attrs: object) -> dict:
    base = {
        "operation": "chat",
        "provider": "openai",
        "request_model": "m",
        "status": "ok",
        "latency_ms": 1.0,
        "contributions": [source],
        "merge_state": "partial",
    }
    event = {
        "event_id": f"id-{source}",
        "ts": "t",
        "source": source,
        "agent_id": f"agent-{source}",
        "task_id": None,
        "capture_mode": "full",
        "type": "gen_ai.request",
        "redaction_profile": {"rules_fired": [f"secrets.{source}"]},
        "attrs": base | attrs,
    }
    return {
        "event": event,
        "row": {
            "cost_usd": source,
            "payload_ref_id": f"p-{source}",
            "payload_sha256": None,
            "payload_bytes": 1,
        },
    }


def test_merge_follows_the_authority_table() -> None:
    sdk = _contribution("sdk", conversation_id="c", latency_ms=5.0, payload={"ref": "s"})
    gw = _contribution("gateway", latency_ms=900.0, usage={"input_tokens": 3})
    event, row = merge(sdk, gw)
    assert event["event_id"] == "id-gateway" and event["agent_id"] == "agent-sdk"
    assert event["attrs"]["latency_ms"] == 900.0 and event["attrs"]["usage"] == {"input_tokens": 3}
    assert event["attrs"]["conversation_id"] == "c" and event["attrs"]["payload"] == {"ref": "s"}
    assert (
        event["attrs"]["contributions"] == ["gateway", "sdk"]
        and event["attrs"]["merge_state"] == "complete"
    )
    assert row["cost_usd"] == "gateway" and row["payload_ref_id"] == "p-sdk"
    assert event["redaction_profile"]["rules_fired"] == ["secrets.gateway", "secrets.sdk"]
    only, _ = merge(sdk, None)
    assert only is sdk["event"]


def test_merge_sums_late_hits_and_recaps_rules() -> None:
    sdk = _contribution("sdk")
    gw = _contribution("gateway")
    sdk["event"]["redaction_profile"] = {
        "rules_fired": [f"secrets.s{i:02d}" for i in range(40)],
        "late_hits": 2,
    }
    gw["event"]["redaction_profile"] = {
        "rules_fired": [f"secrets.g{i:02d}" for i in range(40)],
        "late_hits": 1,
    }
    event, _ = merge(sdk, gw)
    profile = event["redaction_profile"]
    assert profile["late_hits"] == 3
    assert len(profile["rules_fired"]) == 64 and "ingest.rules_truncated" in profile["rules_fired"]
    clean, _ = merge(_contribution("sdk"), _contribution("gateway"))
    assert "late_hits" not in clean["redaction_profile"]


def test_merge_payload_from_the_stricter_side() -> None:
    sdk = _contribution("sdk", payload={"ref": "s"})
    gw = _contribution("gateway", payload={"ref": "g"})
    gw["event"]["capture_mode"] = "redacted"
    event, row = merge(sdk, gw)
    assert event["capture_mode"] == "redacted" and event["attrs"]["payload"] == {"ref": "g"}
    assert row["payload_ref_id"] == "p-gateway"


def test_identity_rules() -> None:
    a = AgentRow(uuid4(), "alpha", None, "open")
    b = AgentRow(uuid4(), "beta", None, "open")
    d = Directory()
    d.add(a)
    d.add(b)
    key = uuid4()
    assert resolve("alpha", "span_attr", "feedback", scope=None, directory=d, key_id=key).agent is a
    assert (
        resolve(str(b.id), "span_attr", "feedback", scope=None, directory=d, key_id=key).agent is b
    )
    assert resolve("beta", "span_attr", "feedback", scope=a, directory=d, key_id=key).refused
    assert resolve("ghost", "span_attr", "feedback", scope=a, directory=d, key_id=key).refused
    assert resolve(None, "span_attr", "feedback", scope=a, directory=d, key_id=key).agent is a
    claim = resolve("ghost", "span_attr", "feedback", scope=None, directory=d, key_id=key).claim
    assert (
        claim is not None
        and claim.slug == unclaimed_slug("ghost")
        and len(claim.slug) == len("unclaimed/") + 8
    )
    default = resolve(None, "span_attr", "tool.call", scope=None, directory=d, key_id=key).claim
    assert default is not None and default.via == "api_key_default"
    assert (
        resolve(None, "span_attr", "observation.gap", scope=None, directory=d, key_id=key).agent
        is None
    )


def test_attrs_budget_keeps_required_and_payload() -> None:
    attrs = {
        "operation": "chat",
        "provider": "p",
        "request_model": "m",
        "status": "ok",
        "latency_ms": 1,
        "contributions": ["sdk"],
        "merge_state": "partial",
        "payload": {"ref": "r"},
        "finish_reasons": ["x" * 300] * 20,
        "conversation_id": "c" * 2000,
    }
    fitted, notes = fit_attrs("gen_ai.request", attrs, 1024)
    assert jsonb_size(fitted) <= 1024 and "payload" in fitted and fitted["merge_state"] == "partial"
    assert notes
    shortened, _ = fit_attrs("gen_ai.request", {**attrs, "provider": "p" * 5000}, 1024)
    assert len(shortened["provider"]) == 512
    with pytest.raises(ValueError):
        fit_attrs("gen_ai.request", attrs, 64)  # the required members alone exceed the budget


def test_ingest_block_fits_its_budget() -> None:
    block = ingest_block("scope/1", "0.1", [f"warning {i} " + "w" * 150 for i in range(50)], 1024)
    assert jsonb_size(block) <= 1024 and block["normaliser_version"] == "normaliser/1.0"


def test_row_attrs_round_trip() -> None:
    attrs = {"content_hashes": {"input": "a", "output": "b"}, "x": 1}
    stored = to_row_attrs(attrs)
    assert stored["content_hashes"] == {"input_sha256": "a", "output_sha256": "b"}
    assert from_row_attrs(stored) == attrs
    assert to_row_attrs({"x": 1}) == {"x": 1}


def test_strictest_capture_mode() -> None:
    assert strictest("full", "metadata") == "metadata"
    assert strictest("redacted", "full") == "redacted"
    assert strictest(None, "full") == "full"
    assert strictest(None, None) == "metadata"


def _span(attrs: dict) -> Span:
    return Span(TRACE, SPAN, b"", "s", 0, 1_000_000_000, 1_500_000_000, attrs, 0, "", ())


def test_legacy_openllmetry_span_is_mapped_with_warnings() -> None:
    cand = span_candidate(
        0,
        TENANT,
        _span(
            {
                "gen_ai.system": "OpenAI",
                "gen_ai.request.model": "m",
                "gen_ai.usage.prompt_tokens": 7,
                "gen_ai.prompt.0.role": "user",
                "gen_ai.prompt.0.content": "hi",
                "sibyl.bogus": 1,
            }
        ),
        Scope("openllmetry", "0.47"),
        {},
        "",
    )
    assert cand.event is not None and cand.event["type"] == "gen_ai.request"
    assert (
        cand.event["attrs"]["provider"] == "openai"
        and cand.event["attrs"]["usage"]["input_tokens"] == 7
    )
    assert cand.content is not None and b'"input_messages"' in cand.content.data
    assert any("legacy" in w for w in cand.warnings) and any(
        "unknown sibyl" in w for w in cand.warnings
    )
    assert cand.instrumentor == "openllmetry/0.47"


def test_openinference_llm_span() -> None:
    cand = span_candidate(
        0,
        TENANT,
        _span(
            {"openinference.span.kind": "LLM", "llm.model_name": "m", "llm.provider": "anthropic"}
        ),
        Scope(),
        {},
        "",
    )
    assert cand.event is not None and cand.event["attrs"]["provider"] == "anthropic"


def test_tool_span_without_name_is_missing_required() -> None:
    cand = span_candidate(
        0, TENANT, _span({"gen_ai.operation.name": "execute_tool"}), Scope(), {}, ""
    )
    assert cand.reject is not None and cand.reject.reason == "missing_required"


def test_pii_redactor_validates_matches() -> None:
    pii = PiiRedactor(
        b"s" * 32, ("email", "credit_card", "iban", "ip_address", "phone", "national_id")
    )
    text, fired = pii.redact(
        "mail a@b.co card 4111 1111 1111 1111 not 1234 5678 9012 3456 iban GB82 WEST 1234 5698"
        " 7654 32 ip 10.1.2.3"
    )
    assert (
        "a@b.co" not in text
        and "4111 1111 1111 1111" not in text
        and "GB82" not in text
        and "10.1.2.3" not in text
    )
    assert text.count("[PII_CREDIT_CARD:") == 1  # the Luhn-failing number is not called a card
    assert {"pii.email", "pii.credit_card", "pii.iban", "pii.ip_address"} <= fired
    assert pii.unimplemented == ()  # the shared sibyl_schemas.pii registry covers pii_standard
    ssn, hits = pii.redact("ssn 123-45-6789")
    assert "123-45-6789" not in ssn and hits == {"pii.national_id"}


def test_pii_redactor_token_is_unchanged_by_the_move_to_sibyl_schemas_pii() -> None:
    """Pinned output: the salted token ingest wrote before ``normalise/pii.py`` was folded into
    ``scrubbing`` (detection itself was already ``sibyl_schemas.pii``)."""
    pii = PiiRedactor(b"s" * 32, ("email", "secrets.openai_key"))
    digest = hashlib.sha256(b"s" * 32 + b"a@b.co").hexdigest()[:8]
    assert pii.redact("mail a@b.co now") == (f"mail [PII_EMAIL:{digest}] now", {"pii.email"})
    doc, fired = pii.redact_json({"k": ["a@b.co", 1, {"n": "x"}]})
    assert doc == {"k": [f"[PII_EMAIL:{digest}]", 1, {"n": "x"}]} and fired == {"pii.email"}
    assert PiiRedactor(b"s", ()).redact("a@b.co") == ("a@b.co", set())


def test_cached_response_is_compacted_under_16_kb() -> None:
    outcome = Outcome(
        "b",
        0,
        [
            Rejection(i, "schema_invalid", "d" * 400, "e" * 36, "t" * 32, "s" * 16)
            for i in range(1000)
        ],
        ["w"] * 50,
    )
    cached = _compact_for_cache(outcome.to_json())
    assert jsonb_size(cached) <= 16_384
    assert cached["rejected"] and "detail" not in cached["rejected"][0]
    restored = Outcome.from_json(cached)
    assert restored.replayed and events_response(restored)["replayed"] is True


def test_otlp_error_message_is_capped() -> None:
    outcome = Outcome(
        "b", 0, [Rejection(i, "missing_required", None, None, "t", "s") for i in range(150)]
    )
    count, message = otlp_partial(outcome)
    assert count == 150 and message.endswith(" +50 more")


async def test_backpressure_units() -> None:
    bp = Backpressure(InMemoryRateLimiter(clock=lambda: 0.0), IngestConfig(max_inflight=1))
    async with bp.slot():
        with pytest.raises(ProblemError) as caught:
            async with bp.slot():
                pass
        assert caught.value.code == "ingest_saturated"
    assert bp.inflight == 0
    await bp.tenant(TENANT, 1, 3, 0)  # heartbeats cost nothing
    await bp.tenant(TENANT, 1, 3, 3)
    with pytest.raises(ProblemError) as caught:
        await bp.tenant(TENANT, 1, 3, 1)
    assert caught.value.headers["X-Sibyl-Backpressure"] == "tenant_rate_limit"
    await bp.tenant(uuid4(), 1, 3, 10)  # one batch larger than the burst is capped, not starved
