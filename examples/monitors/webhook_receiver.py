"""A signed-webhook receiver that turns Sibyl events into findings (FastAPI).

* verifies ``Sibyl-Signature`` over the raw body (``sibyl.monitor.verify_webhook``); a missing,
  stale or wrong signature is 400 and nothing else happens;
* de-duplicates by ``Sibyl-Event-Id`` (deliveries are retried, so they can arrive twice);
* ``run.failed`` -> an ``anomaly`` finding on the run; ``action.held`` for a tool listed in
  WATCHED_TOOLS -> ``needs_more_info`` advice on the held action (advisory only);
* everything else (``ping`` included) is acknowledged with 200.

Env: SIBYL_WEBHOOK_SECRET (the ``whsec_`` secret shown when the webhook was created),
SIBYL_API_URL, SIBYL_MONITOR_KEY, optional WATCHED_TOOLS (comma-separated tool names).

    uvicorn --factory examples.monitors.webhook_receiver:create_app --port 9000

Serve it over HTTPS (Sibyl only delivers to https URLs on public addresses).
"""

from __future__ import annotations

import os
from collections import OrderedDict
from typing import Any

try:  # FastAPI resolves the handler's annotation by name, so it must be a module global.
    from fastapi import Request
except ImportError:  # pragma: no cover - the module still imports without FastAPI
    Request = Any  # type: ignore[assignment,misc]

EVENT_ID_HEADER = "sibyl-event-id"
SEEN_MAX = 10_000


class SeenEvents:
    """A bounded set of delivered event ids (oldest forgotten first)."""

    def __init__(self, maximum: int = SEEN_MAX) -> None:
        self._ids: OrderedDict[str, None] = OrderedDict()
        self._max = maximum

    def add(self, event_id: str) -> bool:
        """True when the id is new."""
        if event_id in self._ids:
            return False
        self._ids[event_id] = None
        while len(self._ids) > self._max:
            self._ids.popitem(last=False)
        return True


async def handle_event(client: Any, event: dict[str, Any], watched_tools: frozenset[str]) -> str:
    """React to one verified event; returns what was done (for logs and tests)."""
    kind = event.get("type")
    data = event.get("data") if isinstance(event.get("data"), dict) else {}
    if kind == "run.failed" and data.get("run_id"):
        await client.submit_finding(
            kind="anomaly",
            subject_kind="run",
            subject_id=data["run_id"],
            severity="warning",
            summary="Run failed (seen by the webhook monitor).",
            body={"event_id": event.get("id"), "error_type": data.get("error_type")},
            provider="rules",
            idempotency_key=f"webhook:{event.get('id')}",
        )
        return "finding"
    if kind == "action.held" and data.get("held_action_id"):
        tool = str(data.get("tool") or "")
        if tool in watched_tools:
            await client.recommend_on_held_action(
                data["held_action_id"],
                "needs_more_info",
                f"Tool {tool[:80]} is on this monitor's watch list; check the arguments.",
                idempotency_key=f"webhook:{event.get('id')}",
            )
            return "advice"
    return "ignored"


def create_app(
    secret: str | None = None, client: Any = None, watched_tools: frozenset[str] | None = None
) -> Any:
    from fastapi import FastAPI, HTTPException
    from sibyl.monitor import AsyncClient, WebhookSignatureError, verify_webhook

    signing_secret = secret or os.environ.get("SIBYL_WEBHOOK_SECRET", "")
    if not signing_secret:
        raise RuntimeError("SIBYL_WEBHOOK_SECRET is not set")
    sibyl = client or AsyncClient.from_env()
    tools = watched_tools
    if tools is None:
        tools = frozenset(t.strip() for t in os.environ.get("WATCHED_TOOLS", "").split(",") if t)
    seen = SeenEvents()
    app = FastAPI(title="Sibyl webhook monitor")

    @app.post("/sibyl/webhook")
    async def receive(request: Request) -> dict[str, str]:
        raw = await request.body()
        try:
            event = verify_webhook(signing_secret, dict(request.headers), raw)
        except WebhookSignatureError:
            raise HTTPException(status_code=400, detail="invalid signature") from None
        event_id = request.headers.get(EVENT_ID_HEADER) or str(event.get("id") or "")
        if event_id and not seen.add(event_id):
            return {"status": "duplicate"}
        return {"status": await handle_event(sibyl, event, tools)}

    return app


def main() -> int:
    import uvicorn

    uvicorn.run(create_app(), host="127.0.0.1", port=int(os.environ.get("PORT", "9000")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
