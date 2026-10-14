"""Lane SENTINEL scenarios (D52 Sibyl Sentinel): config, connectivity test, on-demand explain
and findings, built through the api on tenant A. A fake LLM transport is installed in the app's
lane state (no network); the owner configures Sentinel with a test key (step-up is fresh in the
contract world)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from sibyl_control.api.auth.common import LANE_STATE

from ._world_kit import REASON, Req, Scenario, _api
from .pg_world import ContractWorld

_FAKE = Path(__file__).resolve().parents[1] / "core" / "llm" / "fake_llm.py"
CONFIG: dict[str, Any] = {
    "enabled": True,
    "provider": "anthropic",
    "api_key": "sk-ant-contract-0123456789",
    "daily_budget_usd": "5",
    "sampling_rate": 0.1,
    "tasks": ["incident_explanation", "held_action_review"],
    "reason": REASON,
}
REVIEW = {
    "severity": "info",
    "summary": "Within the agent's purpose.",
    "advice": "approve",
    "reasoning": "Matches the declared purpose.",
    "risks": [],
    "confidence": "medium",
}


def _fake_module() -> Any:
    name = "sibyl_fake_llm"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, _FAKE)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


async def _no_sleep(_: float) -> None:
    return None


def _llm(w: ContractWorld) -> None:
    """Install the fake provider once per world (answers every task with a valid review)."""
    state = getattr(w.client.app.state, LANE_STATE, None)
    if state is None:
        state = {}
        setattr(w.client.app.state, LANE_STATE, state)
    if "sentinel_transport" not in state:
        fake = _fake_module().FakeLlm("anthropic", json.dumps(REVIEW))
        state["sentinel_transport"] = lambda policy: fake.transport()
        state["sentinel_client_kw"] = {"sleep": _no_sleep, "max_retries": 0}


def _if_match(w: ContractWorld) -> str:
    current = w.client.get("/api/v1/sentinel/config", headers=w.headers("owner"))
    return str(current.headers.get("etag") or "*")


def _configured(w: ContractWorld) -> None:
    _llm(w)
    headers = w.headers("owner", **{"If-Match": _if_match(w)})
    resp = w.client.put("/api/v1/sentinel/config", json=CONFIG, headers=headers)
    assert resp.status_code == 200, resp.text


def _held(w: ContractWorld) -> UUID:
    held = uuid4()
    w.admin.execute(
        "INSERT INTO sibyl.held_action (tenant_id, id, agent_id, call_id, tool, source,"
        " args_sha256, args_bytes, server_effect, reason, requested_by_key_id, hold_timeout_s,"
        " expires_at)"
        " VALUES ($1, $2, $3, $4, 'payments.transfer', 'sdk', $5, 20, 'escalate',"
        " 'needs a human', $6, 900, now() + interval '15 minutes')",
        w.a.id,
        held,
        next(iter(w.a.agents.values())),
        f"contract-{held.hex[:12]}",
        b"\x05" * 32,
        uuid4(),
    )
    return held


def _explain_body(w: ContractWorld) -> dict[str, Any]:
    return {"subject_kind": "held_action", "subject_id": str(_held(w))}


def _finding(w: ContractWorld) -> str:
    _configured(w)
    return str(_api(w, "POST", "/sentinel/explain", _explain_body(w)).json()["id"])


def _put(w: ContractWorld) -> Req:
    _llm(w)
    return Req("/sentinel/config", CONFIG, if_match=_if_match(w))


def _test(w: ContractWorld) -> Req:
    _configured(w)
    return Req("/sentinel/config/test")


def _explain(w: ContractWorld) -> Req:
    _configured(w)
    return Req("/sentinel/explain", _explain_body(w))


SENTINEL: dict[str, Scenario] = {
    "getSentinelConfig": lambda w: Req("/sentinel/config"),
    "putSentinelConfig": _put,
    "testSentinelConfig": _test,
    "listSentinelFindings": lambda w: Req("/sentinel/findings"),
    "getSentinelFinding": lambda w: Req(f"/sentinel/findings/{_finding(w)}"),
    "recordSentinelFeedback": lambda w: Req(
        f"/sentinel/findings/{_finding(w)}/feedback", {"feedback": "useful"}
    ),
    "explainWithSentinel": _explain,
}
