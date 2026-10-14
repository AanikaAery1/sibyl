"""One deterministic test per chaos knob, through the HTTP surface the gateway sees."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from sibyl_sim.doubles import SimState
from sibyl_sim.doubles.responses import MALFORMED_ARGS, REFUSAL

CHAT = "/v1/chat/completions"
TOOLS = [{"type": "function", "function": {"name": "lookup_order", "parameters": {}}}]


def body(**extra: Any) -> dict[str, Any]:
    return {"model": "gpt-5-mini", "messages": [{"role": "user", "content": "quote A-1"}], **extra}


async def knobs(
    control: httpx.AsyncClient, double: str, patch: dict[str, Any], method: str = "PATCH"
) -> httpx.Response:
    response = await control.request(method, f"/_sim/doubles/{double}/knobs", json=patch)
    assert response.status_code == 200, response.text
    return response


async def statuses(doubles: httpx.AsyncClient, n: int, path: str = CHAT, **extra: Any) -> list[int]:
    return [(await doubles.post(path, json=body(**extra))).status_code for _ in range(n)]


# ------------------------------------------------------------------ determinism


async def test_same_seed_same_decisions(
    state: SimState, control: httpx.AsyncClient, doubles: httpx.AsyncClient
) -> None:
    await knobs(control, "openai-stub", {"error_rate": 0.3, "refusal_rate": 0.2})
    first = await statuses(doubles, 200)
    await control.post("/_sim/doubles/openai-stub/reset", json={"seed": 7})
    await knobs(control, "openai-stub", {"error_rate": 0.3, "refusal_rate": 0.2})
    assert await statuses(doubles, 200) == first
    await control.post("/_sim/doubles/openai-stub/reset", json={"seed": 8})
    await knobs(control, "openai-stub", {"error_rate": 0.3, "refusal_rate": 0.2})
    assert await statuses(doubles, 200) != first


async def test_one_knob_never_shifts_another(
    control: httpx.AsyncClient, doubles: httpx.AsyncClient
) -> None:
    async def refusals() -> list[bool]:
        out = []
        for _ in range(100):
            data = (await doubles.post(CHAT, json=body())).json()
            out.append(data["choices"][0]["message"]["content"] == REFUSAL)
        return out

    await knobs(control, "openai-stub", {"refusal_rate": 0.5})
    baseline = await refusals()
    await control.post("/_sim/doubles/openai-stub/reset", json={"seed": 7})
    await knobs(
        control, "openai-stub", {"refusal_rate": 0.5, "latency": {"dist": "uniform", "max_ms": 50}}
    )
    assert await refusals() == baseline


# ------------------------------------------------------------------ error rate / statuses


async def test_error_rate_and_status_codes(
    control: httpx.AsyncClient, doubles: httpx.AsyncClient
) -> None:
    await knobs(control, "openai-stub", {"error_rate": 0.25, "error_statuses": [500, 429]})
    codes = await statuses(doubles, 800)
    failures = [c for c in codes if c != 200]
    assert set(failures) == {500, 429}
    assert 150 <= len(failures) <= 250
    response = await doubles.post(CHAT, json=body())
    while response.status_code == 200:
        response = await doubles.post(CHAT, json=body())
    error = response.json()["error"]
    assert error["code"] in ("internal_error", "rate_limit_exceeded") and error["type"]


async def test_error_rate_one_is_always_failing(
    control: httpx.AsyncClient, doubles: httpx.AsyncClient
) -> None:
    await knobs(control, "openai-stub", {"error_rate": 1, "error_statuses": [502]})
    assert set(await statuses(doubles, 20)) == {502}


# ------------------------------------------------------------------ latency


@pytest.mark.parametrize(
    ("latency", "check"),
    [
        ({"dist": "fixed", "ms": 250}, lambda v: all(x == 0.25 for x in v)),
        (
            {"dist": "uniform", "min_ms": 100, "max_ms": 200},
            lambda v: all(0.1 <= x <= 0.2 for x in v) and len(set(v)) > 10,
        ),
        (
            {"dist": "normal", "mean_ms": 300, "stddev_ms": 50},
            lambda v: all(x >= 0 for x in v) and 0.27 < sum(v) / len(v) < 0.33,
        ),
        (
            {"dist": "lognormal", "median_ms": 400, "sigma": 0.5},
            lambda v: 0.3 < sorted(v)[len(v) // 2] < 0.5,
        ),
    ],
)
async def test_latency_distributions(
    control: httpx.AsyncClient,
    doubles: httpx.AsyncClient,
    sleeps: Any,
    latency: dict[str, Any],
    check: Any,
) -> None:
    await knobs(control, "openai-stub", {"latency": latency})
    await statuses(doubles, 200)
    assert check(sleeps.calls)


async def test_inter_chunk_gap_applies_to_streams(
    control: httpx.AsyncClient, doubles: httpx.AsyncClient, sleeps: Any
) -> None:
    await knobs(control, "openai-stub", {"inter_chunk_ms": 40})
    await doubles.post(CHAT, json=body(stream=True))
    assert sleeps.calls.count(0.04) >= 2


# ------------------------------------------------------------------ rate-limit ramp


async def test_rate_limit_ramp_then_429(
    control: httpx.AsyncClient, doubles: httpx.AsyncClient, clock: Any
) -> None:
    await knobs(
        control,
        "openai-stub",
        {
            "limit_requests": 1000,
            "ramp": {
                "start_headroom": 0.6,
                "end_headroom": 0.02,
                "ramp_s": 720,
                "retry_after_s": 15,
            },
        },
    )
    first = await doubles.post(CHAT, json=body())
    assert first.headers["x-ratelimit-remaining-requests"] == "600"
    assert first.headers["x-ratelimit-limit-requests"] == "1000"
    clock.advance(360)
    middle = await doubles.post(CHAT, json=body())
    assert middle.headers["x-ratelimit-remaining-requests"] == "310"
    clock.advance(360)
    limited = await doubles.post(CHAT, json=body())
    assert limited.status_code == 429 and limited.headers["retry-after"] == "15"
    assert limited.json()["error"]["type"] == "rate_limit_error"


async def test_ramp_restarts_when_set_again(
    control: httpx.AsyncClient, doubles: httpx.AsyncClient, clock: Any
) -> None:
    ramp = {"ramp": {"start_headroom": 1, "end_headroom": 0, "ramp_s": 100}}
    await knobs(control, "openai-stub", ramp)
    clock.advance(100)
    assert (await doubles.post(CHAT, json=body())).status_code == 429
    await knobs(control, "openai-stub", ramp)
    assert (await doubles.post(CHAT, json=body())).status_code == 200
    await knobs(control, "openai-stub", {"ramp": None})
    clock.advance(1000)
    ok = await doubles.post(CHAT, json=body())
    assert ok.headers["x-ratelimit-remaining-requests"] == "10000"


# ------------------------------------------------------------------ silent degradation


async def test_refusal_rate(control: httpx.AsyncClient, doubles: httpx.AsyncClient) -> None:
    await knobs(control, "openai-stub", {"refusal_rate": 1})
    choice = (await doubles.post(CHAT, json=body())).json()["choices"][0]
    assert choice["message"]["content"] == REFUSAL and choice["finish_reason"] == "stop"


async def test_truncation_rate_and_fraction(
    control: httpx.AsyncClient, doubles: httpx.AsyncClient
) -> None:
    normal = (await doubles.post(CHAT, json=body())).json()["choices"][0]["message"]["content"]
    await knobs(control, "openai-stub", {"truncation_rate": 1, "truncation_fraction": 0.3})
    choice = (await doubles.post(CHAT, json=body())).json()["choices"][0]
    assert choice["finish_reason"] == "length"
    assert len(choice["message"]["content"]) <= 0.3 * len(normal) + 2


async def test_schema_failure_needs_tools(
    control: httpx.AsyncClient, doubles: httpx.AsyncClient
) -> None:
    await knobs(control, "openai-stub", {"schema_failure_rate": 1})
    plain = (await doubles.post(CHAT, json=body())).json()["choices"][0]
    assert plain["finish_reason"] == "stop"
    choice = (await doubles.post(CHAT, json=body(tools=TOOLS))).json()["choices"][0]
    args = choice["message"]["tool_calls"][0]["function"]["arguments"]
    assert choice["finish_reason"] == "tool_calls" and args == MALFORMED_ARGS
    with pytest.raises(json.JSONDecodeError):
        json.loads(args)


async def test_tool_loop_repeats_the_same_call(
    control: httpx.AsyncClient, doubles: httpx.AsyncClient
) -> None:
    await knobs(control, "openai-stub", {"tool_loop": {"rate": 1}})
    calls = []
    for _ in range(5):
        msg = (await doubles.post(CHAT, json=body(tools=TOOLS))).json()["choices"][0]["message"]
        call = msg["tool_calls"][0]["function"]
        calls.append((call["name"], call["arguments"]))
    assert set(calls) == {("lookup_order", '{"order_id": "A-1"}')}
    await knobs(control, "openai-stub", {"tool_loop": {"rate": 1, "tool_name": "search"}})
    msg = (await doubles.post(CHAT, json=body(tools=TOOLS))).json()["choices"][0]["message"]
    assert msg["tool_calls"][0]["function"]["name"] == "search"


# ------------------------------------------------------------------ cost, outage, models


async def test_cost_per_token_and_token_multiplier(
    control: httpx.AsyncClient, doubles: httpx.AsyncClient
) -> None:
    base = (await doubles.post(CHAT, json=body())).json()["usage"]
    await knobs(
        control,
        "openai-stub",
        {
            "token_multiplier": 6,
            "cost_per_input_token_usd": 0.001,
            "cost_per_output_token_usd": 0.002,
        },
    )
    response = await doubles.post(CHAT, json=body())
    usage = response.json()["usage"]
    assert usage["completion_tokens"] == base["completion_tokens"] * 6
    expected = usage["prompt_tokens"] * 0.001 + usage["completion_tokens"] * 0.002
    assert float(response.headers["x-sim-cost-usd"]) == pytest.approx(expected)
    stats = (await control.get("/_sim/doubles/openai-stub")).json()
    assert stats["cost_usd"] == pytest.approx(expected)


async def test_outage_on_off(control: httpx.AsyncClient, doubles: httpx.AsyncClient) -> None:
    on = await control.post("/_sim/doubles/openai-stub/outage", json={"on": True})
    assert on.json()["knobs"]["outage"] is True
    response = await doubles.post(CHAT, json=body())
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "service_unavailable"
    assert (await doubles.get("/v1/models")).status_code == 503
    await control.post("/_sim/doubles/openai-stub/outage", json={"on": False})
    assert (await doubles.post(CHAT, json=body())).status_code == 200


async def test_missing_model_is_404(control: httpx.AsyncClient, doubles: httpx.AsyncClient) -> None:
    await knobs(control, "openai-stub", {"missing_models": ["gpt-5-mini"]})
    response = await doubles.post(CHAT, json=body())
    assert response.status_code == 404 and response.json()["error"]["code"] == "model_not_found"
    listed = [m["id"] for m in (await doubles.get("/v1/models")).json()["data"]]
    assert "gpt-5-mini" not in listed and "gpt-5.4" in listed


async def test_override_fails_one_credential_only(
    control: httpx.AsyncClient, doubles: httpx.AsyncClient
) -> None:
    await knobs(
        control,
        "openai-stub",
        {"overrides": [{"match": {"credential": "sk-sim-meridian"}, "knobs": {"outage": True}}]},
    )
    assert (await doubles.post(CHAT, json=body())).status_code == 503
    other = await doubles.post(CHAT, json=body(), headers={"Authorization": "Bearer sk-north"})
    assert other.status_code == 200
    shown = (await control.get("/_sim/doubles/openai-stub")).json()["knobs"]["overrides"]
    assert shown[0]["match"]["credential"] == "***"


async def test_override_by_model(control: httpx.AsyncClient, doubles: httpx.AsyncClient) -> None:
    await knobs(
        control,
        "openai-stub",
        {
            "overrides": [
                {"match": {"model": "gpt-5.4"}, "knobs": {"error_rate": 1, "error_statuses": [504]}}
            ]
        },
    )
    assert (await doubles.post(CHAT, json=body())).status_code == 200
    assert (await doubles.post(CHAT, json=body(model="gpt-5.4"))).status_code == 504
