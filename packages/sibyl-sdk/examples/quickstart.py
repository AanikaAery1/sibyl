"""Runnable SDK quickstart (API §8.3), offline by default.

    uv run python packages/sibyl-sdk/examples/quickstart.py            # local stub ingest
    SIBYL_API_KEY=sbl_... SIBYL_ENDPOINT=https://localhost:8445 \\
    SIBYL_API_URL=https://localhost:8443 uv run python .../quickstart.py --live

Offline it starts a loopback ingest + signed-snapshot stub, runs one task through a
stand-in OpenAI-shaped client, then prints what ingest received. With `--live` it talks to
your stack; swap `StandInOpenAI()` for `openai.OpenAI(base_url=<gateway>/v1)`.
"""

from __future__ import annotations

import sys
from datetime import timedelta
from typing import Any

import sibyl


class _Completions:
    def create(self, **kwargs: Any) -> dict[str, Any]:
        prompt = kwargs["messages"][-1]["content"]
        return {
            "id": "chatcmpl-local",
            "model": kwargs["model"],
            "usage": {"prompt_tokens": len(prompt) // 4, "completion_tokens": 12},
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": f"Draft quote for {prompt}"},
                }
            ],
        }


class StandInOpenAI:
    """Shaped like `openai.OpenAI` so `sibyl.instrument()` wraps it the same way."""

    def __init__(self) -> None:
        self.chat = type("Chat", (), {})()
        self.chat.completions = _Completions()


@sibyl.tool(side_effect="read")
def lookup_order(order_id: str) -> dict[str, str]:
    return {"id": order_id, "contact": "buyer@example.com", "tier": "B"}


@sibyl.tool(side_effect="external", name="send_email")
def send_email(to: str, body: str) -> None:
    return None


def run_quote(client: Any, rfq: dict[str, str]) -> None:
    with sibyl.agent(goal=f"Quote order {rfq['order_id']}") as run:
        order = lookup_order(rfq["order_id"])
        sibyl.checkpoint(
            {"rfq": rfq, "order": order},
            step="lookup_order",
            completed=["parse_rfq", "lookup_order"],
            pending=["price_quote", "send_quote"],
        )
        try:
            draft = client.chat.completions.create(
                model="gpt-5-mini",
                messages=[{"role": "user", "content": f"order {order['id']}"}],
            )
        except sibyl.SibylKilled:
            run.cancel("kill switch")
            raise
        except Exception as exc:
            packet = sibyl.handoff.packet(
                reason=f"Provider call failed while drafting the quote: {exc}",
                failure_mode="provider_outage",
                next_action="Review the order and send the quote manually.",
            )
            run.handoff(packet)
            return
        send_email(order["contact"], draft["choices"][0]["message"]["content"])
        run.outcome("success")


def main(argv: list[str]) -> int:
    live = "--live" in argv
    stub = None
    kwargs: dict[str, Any] = {
        "exporter": sibyl.ExporterConfig(schedule_delay=timedelta(milliseconds=100))
    }
    if live:
        sibyl.init(agent_id="quote-assistant", **kwargs)
    else:
        from sibyl._localstub import LocalIngest
        from sibyl.testing import TEST_KEY

        stub = LocalIngest().start()
        sibyl.init(
            TEST_KEY,
            endpoint=stub.url,
            agent_id="quote-assistant",
            policy=sibyl.PolicyConfig(
                public_key=stub.snapshots.signer.pin(), cache_dir=None if live else _tmpdir()
            ),
            **kwargs,
        )
    client = sibyl.instrument(StandInOpenAI())
    run_quote(client, {"order_id": "A-88213"})
    delivered = sibyl.flush(timedelta(seconds=5))
    snap = sibyl.policy.current()
    print(f"flushed={delivered} policy={snap.state if snap else 'none'}")
    if stub is not None:
        print(f"ingest received {len(stub.spans())} spans and {len(stub.events())} events:")
        for span in stub.spans():
            print(f"  span   {span['name']}")
        for event in stub.events():
            print(f"  event  {event['type']}")
    sibyl.shutdown()
    if stub is not None:
        stub.stop()
    return 0 if delivered else 1


def _tmpdir() -> str:
    import tempfile

    return tempfile.mkdtemp(prefix="sibyl-quickstart-")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
