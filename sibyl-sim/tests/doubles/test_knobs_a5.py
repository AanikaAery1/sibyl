"""Knobs for A-5 (tool calls with chosen arguments) and the silent model swap (S-31)."""

from __future__ import annotations

import json
from typing import Any

import httpx

CHAT = "/v1/chat/completions"
TOOLS = [{"type": "function", "function": {"name": "lookup_order", "parameters": {}}}]


def body(**extra: Any) -> dict[str, Any]:
    return {"model": "gpt-5-mini", "messages": [{"role": "user", "content": "quote A-1"}], **extra}


async def knobs(control: httpx.AsyncClient, patch: dict[str, Any]) -> None:
    response = await control.patch("/_sim/doubles/openai-stub/knobs", json=patch)
    assert response.status_code == 200, response.text


async def test_tool_loop_arguments_are_chosen_by_the_prompt(
    control: httpx.AsyncClient, doubles: httpx.AsyncClient
) -> None:
    choices = [{"amount": 2500}, {"amount": 25000}]
    await knobs(
        control, {"tool_loop": {"rate": 1, "tool_name": "payments.transfer", "arguments": choices}}
    )

    async def proposed(prompt: str) -> dict[str, Any]:
        msg = {"messages": [{"role": "user", "content": prompt}], "tools": TOOLS}
        data = (await doubles.post(CHAT, json=body(**msg))).json()
        call = data["choices"][0]["message"]["tool_calls"][0]["function"]
        assert call["name"] == "payments.transfer"
        return dict(json.loads(call["arguments"]))

    seen = [await proposed(f"pay invoice {n}") for n in range(12)]
    assert {s["amount"] for s in seen} == {2500, 25000}, "both cases come up"
    assert seen[3] == await proposed("pay invoice 3"), "same prompt, same proposal"


async def test_tool_loop_without_arguments_keeps_the_lookup_shape(
    control: httpx.AsyncClient, doubles: httpx.AsyncClient
) -> None:
    await knobs(control, {"tool_loop": {"rate": 1}})
    data = (await doubles.post(CHAT, json=body(tools=TOOLS))).json()
    call = data["choices"][0]["message"]["tool_calls"][0]["function"]
    assert json.loads(call["arguments"]) == {"order_id": "A-1"}


async def test_tool_loop_arguments_must_be_objects(control: httpx.AsyncClient) -> None:
    for bad in ({"rate": 1, "arguments": [1]}, {"rate": 1, "arguments": "x"}):
        resp = await control.patch("/_sim/doubles/openai-stub/knobs", json={"tool_loop": bad})
        assert resp.status_code == 422


async def test_served_model_and_fingerprint_swap_silently(
    control: httpx.AsyncClient, doubles: httpx.AsyncClient
) -> None:
    before = (await doubles.post(CHAT, json=body())).json()
    assert before["model"] == "gpt-5-mini" and "system_fingerprint" not in before
    await knobs(
        control,
        {"served_model": "gpt-4.1-mini-x", "system_fingerprint": "fp_x", "token_multiplier": 2.5},
    )
    after = await doubles.post(CHAT, json=body())
    doc = after.json()
    assert after.status_code == 200 and doc["model"] == "gpt-4.1-mini-x"
    assert doc["system_fingerprint"] == "fp_x"
    assert doc["usage"]["completion_tokens"] > before["usage"]["completion_tokens"]
    stream = await doubles.post(CHAT, json=body(stream=True))
    assert "fp_x" in stream.text and "gpt-4.1-mini-x" in stream.text
    for bad in ({"served_model": ""}, {"system_fingerprint": 7}):
        resp = await control.patch("/_sim/doubles/openai-stub/knobs", json=bad)
        assert resp.status_code == 422
