"""The alert loop's remainder on PG17: silence expiry, escalated wording, backlog SLI."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sibyl_control.core.outbox import InMemoryOutboxWriter
from sibyl_control.worker.alerts import LOOP, run_tenant, tick
from sibyl_control.worker.loops import LoopContext

NOW = datetime.now(UTC).replace(microsecond=0)


def alert(
    kit: Any,
    t: UUID,
    a: UUID,
    *,
    code: str = "error_rate",
    state: str = "open",
    silenced_until: datetime | None = None,
    escalation: int = 0,
    resolved_at: datetime | None = None,
    verdict: str | None = None,
    verdict_wanted: bool = False,
    what_to_do: str = "Check the provider.",
) -> UUID:
    rule = kit.in_tenant(
        t, "SELECT id FROM sibyl.alert_rule WHERE tenant_id = $1 AND code = $2", t, code
    )[0]["id"]
    label = None
    if verdict is not None:
        label = kit.in_tenant(
            t,
            "INSERT INTO sibyl.label (tenant_id, agent_id, kind, label_strength, judges_kind,"
            " judges_id, judged_as_of, labeller_kind, value) VALUES ($1, $2, 'alert_verdict',"
            " 'verdict', 'alert', 'x', now(), 'operator', $3::jsonb) RETURNING id",
            t,
            a,
            {"verdict": verdict},
        )[0]["id"]
    return kit.in_tenant(  # type: ignore[no-any-return]
        t,
        "INSERT INTO sibyl.alert (tenant_id, rule_id, scope, agent_id, severity, state, dedupe_key,"
        " what_to_do, summary, silenced_until, escalation_level, resolved_at, verdict,"
        " verdict_label_id, verdict_wanted, fired_count) VALUES ($1, $2, 'agent', $3, 'warning',"
        " $4,"
        " $5, $6, 's', $7, $8, $9, $10, $11, $12, 1) RETURNING id",
        t,
        rule,
        a,
        state,
        f"{code}:agent:{a}:{NOW.timestamp()}:{state}:{resolved_at}",
        what_to_do,
        silenced_until,
        escalation,
        resolved_at,
        verdict,
        label,
        verdict_wanted,
    )[0]["id"]


def run(kit: Any, t: UUID, now: datetime = NOW) -> tuple[Any, InMemoryOutboxWriter]:
    outbox = InMemoryOutboxWriter()

    async def go() -> Any:
        async with kit.worker.tenant_tx(t) as conn:
            return await run_tenant(conn, t, now, outbox)

    return kit.run(go()), outbox


def row(kit: Any, t: UUID, alert_id: UUID) -> Any:
    return kit.in_tenant(
        t, "SELECT * FROM sibyl.alert WHERE tenant_id = $1 AND id = $2", t, alert_id
    )[0]


def test_expired_silence_reopens_a_live_alert_without_a_new_row(akit: Any) -> None:
    t = akit.tenant()
    a = akit.agent(t)
    expired = alert(akit, t, a, state="acked", silenced_until=NOW - timedelta(seconds=1))
    pending = alert(
        akit, t, a, code="p95_latency", state="acked", silenced_until=NOW + timedelta(hours=1)
    )
    result, outbox = run(akit, t)
    assert result.reopened == [expired]
    r = row(akit, t, expired)
    assert (r["state"], r["fired_count"], r["silenced_until"]) == ("open", 2, None)
    assert row(akit, t, pending)["state"] == "acked"
    (sent,) = outbox.messages(t)
    assert (sent.event_type, sent.payload["cause"], sent.payload["state"]) == (
        "alert.updated",
        "silence_expired",
        "open",
    )
    assert akit.val("SELECT count(*) FROM sibyl.alert WHERE tenant_id = $1", t) == 2


def test_a_resolved_alert_only_drops_its_stale_silence(akit: Any) -> None:
    t = akit.tenant()
    a = akit.agent(t)
    done = alert(
        akit,
        t,
        a,
        state="resolved",
        resolved_at=NOW - timedelta(minutes=5),
        silenced_until=NOW - timedelta(minutes=1),
    )
    result, _ = run(akit, t)
    assert result.reopened == [] and result.silence_cleared == [done]
    r = row(akit, t, done)
    assert (r["state"], r["silenced_until"], r["fired_count"]) == ("resolved", None, 1)


def test_escalated_wording_once_per_level(akit: Any) -> None:
    t = akit.tenant()
    a = akit.agent(t)
    one = alert(akit, t, a, escalation=1)
    calm = alert(akit, t, a, code="p95_latency")
    result, _ = run(akit, t)
    assert result.escalated == [one]
    text = row(akit, t, one)["what_to_do"]
    assert text.startswith("Escalated (level 1): this is not transient")
    assert text.endswith("Check the provider.")
    again, _ = run(akit, t)
    assert again.escalated == []
    akit.in_tenant(t, "UPDATE sibyl.alert SET escalation_level = 2 WHERE id = $1", one)
    run(akit, t)
    text = row(akit, t, one)["what_to_do"]
    assert text.startswith("Escalated (level 2)") and text.count("Escalated") == 1
    assert row(akit, t, calm)["what_to_do"] == "Check the provider."


def test_unverdicted_backlog_sli(akit: Any) -> None:
    t = akit.tenant()
    a = akit.agent(t)
    alert(akit, t, a, state="resolved", resolved_at=NOW - timedelta(days=8))  # old, unverdicted
    alert(akit, t, a, state="resolved", resolved_at=NOW - timedelta(days=2), verdict_wanted=True)
    alert(akit, t, a, state="resolved", resolved_at=NOW - timedelta(days=9), verdict="tp")
    result, _ = run(akit, t)
    sli = result.backlog
    assert (sli.old_unverdicted, sli.resolved_30d, sli.unverdicted, sli.verdict_wanted) == (
        1,
        3,
        2,
        1,
    )
    assert sli.ratio == 1 / 3 and sli.breached
    assert sli.as_json()["banner"] is True


def test_empty_tenant_backlog_is_zero_and_quiet(akit: Any) -> None:
    t = akit.tenant()
    result, _ = run(akit, t)
    assert result.backlog.ratio == 0 and not result.backlog.breached


def test_loop_tick_runs_every_active_tenant(akit: Any) -> None:
    t = akit.tenant()
    a = akit.agent(t)
    expired = alert(
        akit, t, a, state="acked", silenced_until=datetime.now(UTC) - timedelta(minutes=1)
    )
    akit.run(tick(LoopContext(LOOP, akit.worker, None, logging.getLogger("t"))))
    assert row(akit, t, expired)["state"] == "open"
