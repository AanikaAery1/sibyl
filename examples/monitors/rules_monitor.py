"""A rules-only external monitor (no LLM): run it from cron every few minutes.

Rules
  * an agent in health band ``failed`` -> critical ``anomaly`` finding (opens a watch-only alert)
  * an agent in band ``degraded``      -> warning finding (no alert)
  * >= FAILED_RUNS_THRESHOLD failed runs of one agent in the last hour -> warning finding with
    ``raise_alert``

Idempotency keys are derived from (rule, agent, hour), so re-running within the hour never
duplicates a finding. Env: SIBYL_API_URL, SIBYL_MONITOR_KEY (a monitor key), optional
FAILED_RUNS_THRESHOLD (default 5).

    python examples/monitors/rules_monitor.py
"""

from __future__ import annotations

import os
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

DEFAULT_THRESHOLD = 5


@dataclass(frozen=True)
class Draft:
    """A finding the rules want to submit (kwargs for ``Client.submit_finding``)."""

    rule: str
    agent_id: str
    severity: str
    summary: str
    raise_alert: bool | None
    body: dict[str, Any] = field(default_factory=dict)

    def idempotency_key(self, now: datetime) -> str:
        return f"rules:{self.rule}:{self.agent_id}:{now.strftime('%Y%m%dT%H')}"


def _name(agent: Mapping[str, Any]) -> str:
    # Agent names come from the monitored fleet: untrusted, so clip them.
    return str(agent.get("name") or agent.get("slug") or agent.get("id"))[:80]


def evaluate(
    failed_agents: Iterable[Mapping[str, Any]],
    degraded_agents: Iterable[Mapping[str, Any]],
    failed_runs: Iterable[Mapping[str, Any]],
    *,
    threshold: int = DEFAULT_THRESHOLD,
) -> list[Draft]:
    """Pure rule evaluation over API pages (testable without a server)."""
    drafts = [
        Draft(
            "band_failed",
            str(a["id"]),
            "critical",
            f"Agent {_name(a)} is in band failed.",
            None,
            {"band": "failed"},
        )
        for a in failed_agents
    ]
    drafts += [
        Draft(
            "band_degraded",
            str(a["id"]),
            "warning",
            f"Agent {_name(a)} is degraded.",
            False,
            {"band": "degraded"},
        )
        for a in degraded_agents
    ]
    counts = Counter(str(r["agent_id"]) for r in failed_runs if r.get("agent_id"))
    drafts += [
        Draft(
            "failed_runs",
            agent,
            "warning",
            f"{n} failed runs in the last hour (threshold {threshold}).",
            True,
            {"failed_runs_1h": n, "threshold": threshold},
        )
        for agent, n in sorted(counts.items())
        if n >= threshold
    ]
    return drafts


def run_once(client: Any, *, now: datetime | None = None, threshold: int | None = None) -> int:
    """Fetch, evaluate and submit; returns the number of findings submitted."""
    from sibyl.monitor import paginate

    now = now or datetime.now(UTC)
    limit = threshold or int(os.environ.get("FAILED_RUNS_THRESHOLD", DEFAULT_THRESHOLD))
    drafts = evaluate(
        paginate(client.list_agents, band="failed", max_pages=10),
        paginate(client.list_agents, band="degraded", max_pages=10),
        paginate(client.list_runs, status="error", since=now - timedelta(hours=1), max_pages=20),
        threshold=limit,
    )
    for d in drafts:
        client.submit_finding(
            kind="anomaly",
            subject_kind="agent",
            subject_id=d.agent_id,
            severity=d.severity,
            summary=d.summary,
            body={"rule": d.rule, **d.body},
            raise_alert=d.raise_alert,
            provider="rules",
            idempotency_key=d.idempotency_key(now),
        )
    return len(drafts)


def main() -> int:
    from sibyl.monitor import Client

    with Client.from_env() as client:
        submitted = run_once(client)
    print(f"rules monitor: {submitted} finding(s) submitted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
