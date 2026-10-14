"""S-05 / S-06 budgets are calibrated, not guessed (no PG needed).

qa-expert §2 rows S-05 ("scenario sets budget so this lands at t0+9 min") and S-06 ("spend
already at 0.97 at seed; normal traffic"): the crossing of the monthly budget is the onset label.
The spend that crosses it is the warm-up history plus the scenario's own calls, priced the way
ingest prices them (``sibyl seed`` model prices, USD per 1M tokens) with the token counts the
doubles answer. Everything here is seeded, so the curve is exact up to the double's reply
counter (a digit or two of reply text); a price, warm-up, traffic or chaos change that moves the
crossing off its label fails this test instead of the scenario.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal
from types import SimpleNamespace

import pytest
from sibyl_control.cli import seed
from sibyl_sim.actors.history import history_events
from sibyl_sim.actors.traffic import plan_arrivals
from sibyl_sim.doubles.responses import chat_message, usage_for
from sibyl_sim.scenarios.load import load
from sibyl_sim.scenarios.model import AgentRef, Scenario

SYSTEM = "You are a logistics support assistant."  # actors.agents.GatewayAgent.body
LANDING_S = 20.0  # the crossing lands at the onset label or within one scoring tick or two after
MID_MONTH = datetime(2026, 10, 14, 12, tzinfo=UTC)
HOUR_S, DAY_S = 3600, 86400


def _spec(ref: AgentRef) -> tuple[str, str]:
    tenant = next(t for t in seed.WORLD if t.slug == ref.tenant)
    agent = next(a for a in tenant.agents if a.slug == ref.slug)
    provider = next(p for p in tenant.providers if p.slug == agent.provider)
    return agent.provider, provider.models[0]


def _cost(model: str, tokens_in: int, tokens_out: int) -> Decimal:
    price_in, price_out = (Decimal(p) for p in seed.MODEL_PRICES[model])
    total = (tokens_in * price_in + tokens_out * price_out) / Decimal(1_000_000)
    return total.quantize(Decimal("0.00000001"), rounding=ROUND_HALF_UP)  # derive.cost


def _multiplier(s: Scenario, ref: AgentRef, double: str, t: float) -> float:
    value = 1.0
    for step in s.chaos:
        hits = step.kind == "double" and step.target == double and step.at <= t
        if hits and (not step.agents or ref in step.agents):
            value = float(step.patch.get("token_multiplier", value))
    return value


@dataclass(frozen=True)
class Spend:
    history: Decimal  # month-to-date at t=0: the whole warm-up
    last_hour: Decimal  # the warm-up's final hour: L4's long burn-rate window at t=0
    curve: tuple[tuple[float, Decimal], ...]  # (t, cumulative month-to-date) per scenario call


def spend(s: Scenario, ref: AgentRef) -> Spend:
    double, model = _spec(ref)
    tenant = SimpleNamespace(slug=ref.tenant, id=uuid.uuid4())
    agent = SimpleNamespace(slug=ref.slug, id=uuid.uuid4(), provider=double, model=model)
    minutes = s.warmup_agents.get(ref, s.warmup_min)
    priced = [
        (
            e["ts"],
            _cost(model, e["attrs"]["usage"]["input_tokens"], e["attrs"]["usage"]["output_tokens"]),
        )
        for e in history_events(tenant, agent, s.seed, s.id, minutes, MID_MONTH)
    ]
    hour_ago = (MID_MONTH - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
    history = sum((c for _, c in priced), Decimal(0))
    last_hour = sum((c for ts, c in priced if ts >= hour_ago), Decimal(0))
    profile = s.profile(s.tenant(ref.tenant).agents[ref.slug])
    total, curve = history, []
    for a in plan_arrivals(s.seed, s.id, ref, profile, duration_s=s.duration_s):
        request = {
            "messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": a.prompt},
            ]
        }
        multiplier = _multiplier(s, ref, double, a.t)
        decision = SimpleNamespace(
            seq=a.n + 1, behaviour="ok", knobs=SimpleNamespace(token_multiplier=multiplier)
        )
        message, _ = chat_message(double, request, decision)
        usage = usage_for(request, message, multiplier)
        total += _cost(model, usage["prompt_tokens"], usage["completion_tokens"])
        curve.append((a.t, total))
    return Spend(history, last_hour, tuple(curve))


def _onset(s: Scenario, ref: AgentRef) -> float:
    return next(lab.t for lab in s.labels if lab.agent == ref and lab.kind == "onset")


@pytest.mark.parametrize(("sid", "slug"), [("S-05", "email-drafter"), ("S-06", "billing-agent")])
def test_the_budget_is_crossed_at_the_onset_label(sid: str, slug: str) -> None:
    s = load(sid)
    ref = AgentRef("meridian", slug)
    budget = Decimal(s.budgets[ref])
    got = spend(s, ref)
    assert got.history < budget, sid  # R5 must not fire before t=0 (an FP before the onset)
    crossing = next(t for t, total in got.curve if total >= budget)
    onset = _onset(s, ref)
    assert onset <= crossing <= onset + LANDING_S, (sid, crossing, onset)
    # L4 (ML §4.1): month projected over budget at 24 h from the warm-up's own hourly burn, so
    # the prediction is up at the first evaluation, minutes before the breach (lead >= 5 min).
    projected_24h = (got.history + got.last_hour / HOUR_S * DAY_S) / budget
    assert projected_24h >= 1, (sid, projected_24h)


def test_s06_starts_at_097_of_its_budget_on_normal_traffic() -> None:
    s = load("S-06")
    ref = AgentRef("meridian", "billing-agent")
    ratio = spend(s, ref).history / Decimal(s.budgets[ref])
    assert Decimal("0.965") <= ratio <= Decimal("0.975"), ratio
    assert not any("token_multiplier" in step.patch for step in s.chaos)  # ML §8.2: normal traffic
