"""Scenario budgets: the monthly budget an agent runs under, set the way an admin would.

qa-expert §2 S-05: "scenario sets budget so this lands at t0+9 min"; S-06: "spend already at
0.97 at seed". `sibyl seed` gives every agent a tier budget (5000 / 1500 / 300 USD a month) that
an hour of warm-up and a 15-minute scenario cannot reach at real prices, so a scenario names its
own budget and the harness sets it right at t=0, after the warm-up (an L4 raised during the
warm-up would be cleared with the warm-up's frames and then held by its cooldown). It goes through
the real `PUT /agents/{id}/continuity-plan` as the tenant admin, If-Match on the plan read just
before, every other plan field unchanged: config, never a derived table (qa-expert §1 rule 1).
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

import httpx

from ..scenarios.model import AgentRef
from .world import World

API = "/api/v1"
PERSONA = "admin"
REASON = "sibyl-sim scenario budget (qa-expert section 2, S-05/S-06)"
CADENCE_REASON = "sibyl-sim scenario cadence (ML section 8.2, S-18 observation gap)"
# ContinuityPlanPut's writable fields; the read adds ids, versions and approval stamps.
PUT_FIELDS = (
    "rto_s",
    "rpo_s",
    "credential_mode",
    "degraded_mode",
    "inline_fallback",
    "preemptive_mode",
    "approval_timeout_s",
    "approval_timeout_policy",
    "fallback_chain_id",
    "on_call_user_id",
    "on_call_ref",
    "budget_usd_month",
    "max_inflight",
    "rps_limit",
    "drill_schedule",
    "expected_cadence_s",
)


async def apply_budgets(
    client: httpx.AsyncClient, api: str, world: World, budgets: Mapping[AgentRef, str]
) -> list[str]:
    """Set each agent's monthly budget; one note per change. Raises on any refusal."""
    notes = []
    for ref in sorted(budgets, key=str):
        old = await _put_plan(client, api, world, ref, "budget_usd_month", budgets[ref], REASON)
        notes.append(f"budget {ref}: {old} -> {budgets[ref]} USD/month")
    return notes


async def apply_cadences(
    client: httpx.AsyncClient, api: str, world: World, cadences: Mapping[AgentRef, int]
) -> list[str]:
    """Declare each agent's expected traffic cadence (R9 `heartbeat_missing` evaluates only
    on plans that declare one, ML section 3.3); one note per change. Raises on any refusal."""
    notes = []
    for ref in sorted(cadences, key=str):
        old = await _put_plan(
            client, api, world, ref, "expected_cadence_s", cadences[ref], CADENCE_REASON
        )
        notes.append(f"cadence {ref}: {old} -> {cadences[ref]} s")
    return notes


async def _put_plan(
    client: httpx.AsyncClient,
    api: str,
    world: World,
    ref: AgentRef,
    key: str,
    value: Any,
    reason: str,
) -> Any:
    """Change one plan field as the admin, If-Match on the read; returns the old value."""
    what = "budget" if key == "budget_usd_month" else key
    tenant = world.tenant(ref.tenant)
    url = f"{api}{API}/agents/{tenant.agent(ref.slug).id}/continuity-plan"
    auth = {"Authorization": f"Bearer {tenant.token(PERSONA)}"}
    got = await client.get(url, headers=auth)
    if got.status_code != 200:
        raise RuntimeError(f"{what} {ref}: plan read {got.status_code} {got.text[:200]}")
    plan: dict[str, Any] = got.json()
    body = {k: plan.get(k) for k in PUT_FIELDS} | {key: value, "reason": reason}
    headers = auth | {
        "If-Match": got.headers.get("etag", "*"),
        "Idempotency-Key": str(uuid.uuid4()),
    }
    put = await client.put(url, json=body, headers=headers)
    if put.status_code != 200:
        raise RuntimeError(f"{what} {ref}: plan update {put.status_code} {put.text[:200]}")
    return plan.get(key)
