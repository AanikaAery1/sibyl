"""Lane EXTMON scenarios (D53 external monitors): monitors, their keys and webhooks, and findings,
built through the api on tenant A. Webhook deliveries go to a fake receiver installed in the
app's lane state (no network); the webhook URL is on the contract world's development host."""

from __future__ import annotations

from typing import Any

import httpx
from sibyl_control.api.auth.common import LANE_STATE

from ._world_kit import REASON, Req, Scenario, _api, agent, unique
from .pg_world import SIM_HOST, ContractWorld

HOOK_URL = f"http://{SIM_HOST}:8400/sibyl-hook"


def receiver(w: ContractWorld) -> list[httpx.Request]:
    """Install (once) a fake receiver answering 204; returns the requests it saw."""
    state = getattr(w.client.app.state, LANE_STATE, None)
    if state is None:
        state = {}
        setattr(w.client.app.state, LANE_STATE, state)
    if "webhook_seen" not in state:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(204)

        state["webhook_seen"] = seen
        state["webhook_transport"] = lambda policy: httpx.MockTransport(handler)
    requests: list[httpx.Request] = state["webhook_seen"]
    return requests


def monitor(w: ContractWorld, **fields: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"name": unique("monitor"), "kind": "mcp", "key_env": "test"}
    body.update(fields)
    created: dict[str, Any] = _api(w, "POST", "/monitors", body).json()
    return created


def webhook(w: ContractWorld, monitor_id: str) -> dict[str, Any]:
    body = {"url": HOOK_URL, "event_types": ["alert.fired", "run.failed"], "reason": REASON}
    created: dict[str, Any] = _api(w, "POST", f"/monitors/{monitor_id}/webhooks", body).json()
    return created


def finding_body(agent_id: str) -> dict[str, Any]:
    return {
        "kind": "semantic_drift",
        "subject_kind": "agent",
        "subject_id": agent_id,
        "severity": "warning",
        "summary": "The agent answers outside its declared purpose.",
        "recommendation": "Review the last ten runs.",
        "provider": "anthropic",
        "model": "claude-fable-5-1",
    }


def external_finding(w: ContractWorld) -> str:
    created = agent(w)
    resp = w.client.post(
        "/api/v1/findings", json=finding_body(created["id"]), headers=w.idem("monitor")
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


def _submit(w: ContractWorld) -> Req:
    created = agent(w)
    return Req("/findings", finding_body(created["id"]), who="monitor", agent_id=created["id"])


def _test(w: ContractWorld) -> Req:
    receiver(w)
    m = monitor(w)
    hook = webhook(w, m["id"])
    return Req(f"/monitors/{m['id']}/webhooks/{hook['id']}/test")


MONITORS: dict[str, Scenario] = {
    "createMonitor": lambda w: Req(
        "/monitors", {"name": unique("monitor"), "kind": "mcp", "key_env": "test", "reason": REASON}
    ),
    "listMonitors": lambda w: (monitor(w), Req("/monitors"))[1],
    "getMonitorSelf": lambda w: Req("/monitors/self", who="monitor"),
    "getMonitor": lambda w: Req(f"/monitors/{monitor(w)['id']}"),
    "updateMonitor": lambda w: Req(
        f"/monitors/{monitor(w)['id']}", {"state": "paused", "reason": REASON}, if_match='"1"'
    ),
    "revokeMonitor": lambda w: Req(f"/monitors/{monitor(w)['id']}/revoke", {"reason": REASON}),
    "issueMonitorKey": lambda w: Req(f"/monitors/{monitor(w)['id']}/keys", {"env": "test"}),
    "createMonitorWebhook": lambda w: Req(
        f"/monitors/{monitor(w)['id']}/webhooks",
        {"url": HOOK_URL, "event_types": ["action.held"], "reason": REASON},
    ),
    "testMonitorWebhook": _test,
    "submitFinding": _submit,
    "listFindings": lambda w: (external_finding(w), Req("/findings"))[1],
    "getFinding": lambda w: Req(f"/findings/{external_finding(w)}"),
    "recordFindingFeedback": lambda w: Req(
        f"/findings/{external_finding(w)}/feedback", {"feedback": "useful"}
    ),
}
