"""Provider-neutral LLM adapter (D52): the three dialects over a fake transport, structured
output with one repair, retries, cost, and the egress allowlist. No network."""

from __future__ import annotations

import importlib.util
import json
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError
from sibyl_control.core.llm import (
    EgressPolicy,
    EgressRefused,
    LlmBadOutput,
    LlmClient,
    LlmConfigError,
    LlmHttpError,
    LlmMalformedResponse,
    LlmRefused,
    LlmRequest,
    LlmTimeout,
    LlmTransportError,
    Message,
    Price,
    Usage,
    cost_usd,
    estimate_tokens,
    extract_json,
    price_for,
)
from sibyl_control.core.llm.pricing import FALLBACK
from sibyl_schemas.models.sentinel import (
    HeldActionReview,
    SentinelTask,
    output_schema,
)


def _load(name: str, path: Path) -> Any:
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


fk = _load("sibyl_fake_llm", Path(__file__).resolve().parent / "fake_llm.py")
KEY = "sk-test-SECRET-0123456789"
REVIEW = {
    "severity": "warning",
    "summary": "Large transfer to a new payee",
    "advice": "needs_more_info",
    "reasoning": "First transfer to this payee.",
    "risks": ["new payee"],
    "confidence": "medium",
}
SCHEMA = output_schema(SentinelTask.HELD_ACTION_REVIEW)


async def _no_sleep(_: float) -> None:
    return None


def _client(fake: Any, model: str | None = None, **kw: Any) -> LlmClient:
    return LlmClient(fake.provider, KEY, model, transport=fake.transport(), sleep=_no_sleep, **kw)


def _req(**kw: Any) -> LlmRequest:
    return LlmRequest("You are Sentinel.", (Message("user", "Review this."),), **kw)


# --- dialects ---------------------------------------------------------------------------------


async def test_anthropic_request_shape_and_structured_output() -> None:
    fake = fk.FakeLlm("anthropic", json.dumps(REVIEW))
    client = _client(fake)
    assert client.model == "claude-fable-5-1"
    out = await client.complete_structured(
        _req(json_schema=SCHEMA, temperature=0.2), HeldActionReview.model_validate
    )
    assert out.value.advice == "needs_more_info"
    assert out.response.structured and out.calls == 1 and not out.repaired
    assert out.usage == Usage(120, 40)
    request = fake.requests[0]
    assert str(request.url) == "https://api.anthropic.com/v1/messages"
    assert request.headers["x-api-key"] == KEY
    assert request.headers["anthropic-version"] == "2023-06-01"
    body = fake.last_body()
    assert body["model"] == "claude-fable-5-1"
    assert body["system"] == "You are Sentinel."
    assert body["output_config"]["format"] == {"type": "json_schema", "schema": SCHEMA}
    assert "temperature" not in body  # current Claude models reject sampling parameters


async def test_anthropic_older_model_keeps_temperature() -> None:
    fake = fk.FakeLlm("anthropic", "hi")
    await _client(fake, "claude-haiku-4-5").complete(_req(temperature=0.3))
    assert fake.last_body()["temperature"] == 0.3


async def test_openai_request_shape() -> None:
    fake = fk.FakeLlm("openai", json.dumps(REVIEW))
    out = await _client(fake, "gpt-test-1").complete_structured(
        _req(json_schema=SCHEMA), HeldActionReview.model_validate
    )
    assert out.value.severity == "warning"
    request = fake.requests[0]
    assert str(request.url) == "https://api.openai.com/v1/chat/completions"
    assert request.headers["authorization"] == f"Bearer {KEY}"
    body = fake.last_body()
    assert body["messages"][0] == {"role": "system", "content": "You are Sentinel."}
    assert body["response_format"]["json_schema"]["strict"] is True
    assert body["max_completion_tokens"] == 4096


async def test_gemini_uses_json_mode_and_schema_in_the_instruction() -> None:
    fake = fk.FakeLlm("gemini", json.dumps(REVIEW))
    out = await _client(fake, "models/gemini-test-1").complete_structured(
        _req(json_schema=SCHEMA), HeldActionReview.model_validate
    )
    assert out.value.confidence == "medium"
    assert not out.response.structured
    request = fake.requests[0]
    assert str(request.url) == (
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-test-1:generateContent"
    )
    assert request.headers["x-goog-api-key"] == KEY
    body = fake.last_body()
    assert body["generationConfig"]["responseMimeType"] == "application/json"
    assert "JSON Schema" in body["systemInstruction"]["parts"][0]["text"]
    assert body["contents"][0]["role"] == "user"
    assert out.response.text == json.dumps(REVIEW)  # the thought part is dropped


@pytest.mark.parametrize("provider", ["openai", "gemini"])
def test_openai_and_gemini_require_an_explicit_model(provider: str) -> None:
    with pytest.raises(LlmConfigError):
        LlmClient(provider, KEY)


@pytest.mark.parametrize("model", ["../evil", "a b", "x" * 200, "gemini/../../v1"])
def test_model_ids_are_validated(model: str) -> None:
    with pytest.raises(LlmConfigError):
        LlmClient("gemini", KEY, model)


def test_unknown_provider_and_empty_key_are_refused() -> None:
    with pytest.raises(LlmConfigError):
        LlmClient("cohere", KEY, "m")
    with pytest.raises(LlmConfigError):
        LlmClient("anthropic", "")


def test_request_validation() -> None:
    with pytest.raises(ValueError):
        LlmRequest("s", ())
    with pytest.raises(ValueError):
        LlmRequest("s", (Message("assistant", "x"),))
    with pytest.raises(ValueError):
        _req(max_tokens=0)
    with pytest.raises(ValueError):
        _req(temperature=3)


# --- refusals and malformed answers -----------------------------------------------------------


async def test_refusals_raise_for_every_provider() -> None:
    fake = fk.FakeLlm("anthropic")
    fake.push(fk.Scripted(body=fk.anthropic_body("", stop="refusal")))
    with pytest.raises(LlmRefused):
        await _client(fake).complete(_req())
    fake = fk.FakeLlm("openai")
    fake.push(fk.Scripted(body=fk.openai_body(None, refusal="no")))
    with pytest.raises(LlmRefused):
        await _client(fake, "gpt-test-1").complete(_req())
    fake = fk.FakeLlm("gemini")
    fake.push(fk.Scripted(body=fk.gemini_body("", finish="SAFETY")))
    with pytest.raises(LlmRefused):
        await _client(fake, "gemini-test-1").complete(_req())
    fake.push(fk.Scripted(body={"promptFeedback": {"blockReason": "SAFETY"}}))
    with pytest.raises(LlmRefused):
        await _client(fake, "gemini-test-1").complete(_req())


@pytest.mark.parametrize("body", [[1], {"choices": []}, {"choices": [{"message": {}}]}])
async def test_malformed_bodies(body: Any) -> None:
    fake = fk.FakeLlm("openai")
    fake.push(fk.Scripted(body=body))
    with pytest.raises(LlmMalformedResponse):
        await _client(fake, "gpt-test-1").complete(_req())


async def test_non_json_body_is_malformed() -> None:
    fake = fk.FakeLlm("anthropic")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>")

    client = LlmClient("anthropic", KEY, transport=httpx.MockTransport(handler))
    with pytest.raises(LlmMalformedResponse):
        await client.complete(_req())
    assert fake.requests == []


# --- structured output repair -----------------------------------------------------------------


async def test_one_repair_then_success_sums_usage() -> None:
    fake = fk.FakeLlm("gemini")
    fake.push(fake.text("not json at all"), fake.text("```json\n" + json.dumps(REVIEW) + "\n```"))
    out = await _client(fake, "gemini-test-1").complete_structured(
        _req(json_schema=SCHEMA), HeldActionReview.model_validate
    )
    assert out.repaired and out.calls == 2 and out.usage == Usage(240, 80)
    repair = fake.bodies()[1]["contents"]
    assert [c["role"] for c in repair] == ["user", "model", "user"]
    assert "could not be used" in repair[-1]["parts"][0]["text"]


async def test_schema_violation_is_quoted_without_content_and_fails_after_one_repair() -> None:
    bad = {**REVIEW, "advice": "approve_everything"}
    fake = fk.FakeLlm("openai")
    fake.push(fake.text(json.dumps(bad)), fake.text(json.dumps(bad)))
    with pytest.raises(LlmBadOutput) as info:
        await _client(fake, "gpt-test-1").complete_structured(
            _req(json_schema=SCHEMA), HeldActionReview.model_validate
        )
    assert info.value.calls == 2 and info.value.usage == Usage(240, 80)
    repair_prompt = fake.bodies()[1]["messages"][-1]["content"]
    assert "advice" in repair_prompt and "approve_everything" not in repair_prompt
    assert len(fake.requests) == 2


async def test_repair_call_failure_is_bad_output() -> None:
    fake = fk.FakeLlm("anthropic")
    fake.push(fake.text("{"), fk.Scripted(status=400, body={"error": {"type": "invalid"}}))
    with pytest.raises(LlmBadOutput) as info:
        await _client(fake).complete_structured(
            _req(json_schema=SCHEMA), HeldActionReview.model_validate
        )
    assert info.value.calls == 1


async def test_structured_needs_a_schema() -> None:
    with pytest.raises(LlmConfigError):
        await _client(fk.FakeLlm()).complete_structured(_req(), HeldActionReview.model_validate)


def test_extract_json_and_lenient_outputs() -> None:
    assert extract_json(' ```\n{"a": 1}\n``` ') == {"a": 1}
    with pytest.raises(ValueError):
        extract_json("nope")
    long = {**REVIEW, "summary": "x" * 5000, "risks": ["r" * 900] * 20, "extra": 1}
    review = HeldActionReview.model_validate(long)
    assert len(review.summary) == 600 and len(review.risks) == 8 and len(review.risks[0]) == 400
    with pytest.raises(ValidationError):
        HeldActionReview.model_validate({**REVIEW, "severity": "doom"})


# --- retries ----------------------------------------------------------------------------------


async def test_retries_429_and_5xx_with_retry_after() -> None:
    delays: list[float] = []

    async def sleep(d: float) -> None:
        delays.append(d)

    fake = fk.FakeLlm("anthropic", "ok")
    fake.push(
        fk.Scripted(
            status=429, body={"error": {"type": "rate_limit_error"}}, headers={"retry-after": "3"}
        ),
        fk.Scripted(status=529, body={"error": {"type": "overloaded_error"}}),
    )
    client = LlmClient("anthropic", KEY, transport=fake.transport(), sleep=sleep, max_retries=2)
    out = await client.complete(_req())
    assert out.text == "ok" and out.attempts == 3
    assert delays[0] == 3.0 and 0 < delays[1] <= 1.0


async def test_retry_after_is_capped() -> None:
    delays: list[float] = []

    async def sleep(d: float) -> None:
        delays.append(d)

    fake = fk.FakeLlm("anthropic", "ok")
    fake.push(fk.Scripted(status=503, headers={"retry-after": "9999"}))
    await LlmClient("anthropic", KEY, transport=fake.transport(), sleep=sleep).complete(_req())
    assert delays == [30.0]


async def test_gives_up_after_max_retries() -> None:
    fake = fk.FakeLlm("anthropic")
    fake.push(*[fk.Scripted(status=500) for _ in range(3)])
    with pytest.raises(LlmHttpError) as info:
        await _client(fake, max_retries=2).complete(_req())
    assert info.value.status == 500 and len(fake.requests) == 3


async def test_client_errors_are_not_retried_and_never_leak_the_key() -> None:
    fake = fk.FakeLlm("openai")
    fake.push(fk.Scripted(status=401, body={"error": {"type": "invalid_api_key", "message": KEY}}))
    with pytest.raises(LlmHttpError) as info:
        await _client(fake, "gpt-test-1").complete(_req())
    assert len(fake.requests) == 1 and info.value.error_type == "invalid_api_key"
    assert KEY not in str(info.value) and KEY not in repr(_client(fake, "gpt-test-1"))


async def test_unsafe_error_types_are_dropped() -> None:
    fake = fk.FakeLlm("gemini")
    fake.push(fk.Scripted(status=400, body={"error": {"status": "bad <script>"}}))
    with pytest.raises(LlmHttpError) as info:
        await _client(fake, "gemini-test-1").complete(_req())
    assert info.value.error_type is None


async def test_transport_errors_and_timeouts_are_retried() -> None:
    fake = fk.FakeLlm("anthropic", "ok")
    fake.push(
        fk.Scripted(raise_exc=httpx.ConnectError("boom")),
        fk.Scripted(raise_exc=httpx.ReadTimeout("slow")),
    )
    assert (await _client(fake).complete(_req())).attempts == 3
    fake.push(*[fk.Scripted(raise_exc=httpx.ReadTimeout("slow")) for _ in range(3)])
    with pytest.raises(LlmTimeout):
        await _client(fake).complete(_req())
    fake.push(*[fk.Scripted(raise_exc=httpx.ConnectError("x")) for _ in range(3)])
    with pytest.raises(LlmTransportError):
        await _client(fake).complete(_req())


# --- egress -----------------------------------------------------------------------------------


def test_base_url_must_be_https_and_allowlisted() -> None:
    fake = fk.FakeLlm("openai")
    with pytest.raises(EgressRefused):
        LlmClient("openai", KEY, "m", base_url="http://api.openai.com", transport=fake.transport())
    with pytest.raises(EgressRefused):
        LlmClient(
            "openai", KEY, "m", base_url="https://u:p@api.openai.com", transport=fake.transport()
        )
    client = LlmClient(
        "openai", KEY, "m", base_url="https://llm.example.com/", transport=fake.transport()
    )
    assert "llm.example.com" in client.policy.allowed_hosts


def test_policy_check_rules() -> None:
    policy = EgressPolicy(dev_hosts=frozenset({"sibyl-sim"}))
    policy.check("https://api.anthropic.com/v1/messages")
    policy.check("http://sibyl-sim:8300/v1/messages")
    for bad in ("https://evil.example.com/", "ftp://api.openai.com/", "https:///x"):
        with pytest.raises(EgressRefused):
            policy.check(bad)


async def test_requests_to_other_hosts_are_refused_at_send_time() -> None:
    fake = fk.FakeLlm("anthropic", "ok")
    client = _client(fake)
    client.base_url = "https://evil.example.com"  # a tampered client still cannot leave
    with pytest.raises(EgressRefused):
        await client.complete(_req())
    assert fake.requests == []


async def test_connect_time_guard_refuses_private_addresses() -> None:
    async def private(host: str, port: int) -> list[str]:
        return ["10.0.0.7"]

    client = LlmClient(
        "anthropic",
        KEY,
        policy=EgressPolicy(resolver=private),
        sleep=_no_sleep,
        max_retries=0,
    )
    with pytest.raises(EgressRefused):
        await client.complete(_req())


# --- pricing ----------------------------------------------------------------------------------


def test_prices_and_costs() -> None:
    fable = price_for("anthropic", "claude-fable-5-1")
    assert (fable.input_per_mtok, fable.output_per_mtok) == (Decimal(10), Decimal(50))
    assert price_for("anthropic", "claude-haiku-4-5-latest").input_per_mtok == Decimal(1)
    assert price_for("openai", "gpt-unknown") is FALLBACK and FALLBACK.estimated
    custom = Price(Decimal("1"), Decimal("2"))
    assert price_for("openai", "gpt-x", override=custom) is custom
    assert cost_usd(Usage(1_000_000, 1_000_000), fable) == Decimal("60.000000")
    assert cost_usd(Usage(1, 0), fable) == Decimal("0.000010")
    assert cost_usd(Usage(1, 0), Price(Decimal("0.1"), Decimal(0))) == Decimal("0.000001")
    assert estimate_tokens("x" * 300) == 116
