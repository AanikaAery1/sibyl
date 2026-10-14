"""Lane DRIFT test kit (loaded as ``sibyl_drift_kit``): synthetic telemetry on the lane S world.

``Traffic`` writes ``gen_ai.request`` and ``tool.call`` events for one agent by direct SQL
(spread evenly over a time range, deterministic per seed); ``run`` executes the drift tick for
tenant A as ``sibyl_worker`` at a chosen ``now``.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sibyl_control.core.audit import PgAuditWriter
from sibyl_control.core.outbox import PgOutboxWriter
from sibyl_control.worker.drift.config import DriftConfig
from sibyl_control.worker.drift.runner import TenantResult, run_tenant

CFG = DriftConfig(
    baseline_min_samples=300,
    baseline_min_span=timedelta(minutes=30),
    eval_window=timedelta(hours=1),
    eval_every=timedelta(minutes=5),
    eval_min_samples=150,
    tool_min_samples=30,
    raise_after=2,
    clear_after=2,
    identity_clear_after=2,
)

_INSERT = """
INSERT INTO sibyl.events (tenant_id, event_id, ts, event_type, source, agent_id, task_id,
  emitter_id, seq, provider, model, response_model, status, error_class, latency_ms, tokens_in,
  tokens_out, policy_state, capture_mode, redaction_profile_hash, normaliser_version, attrs)
SELECT $1, gen_random_uuid(), r.ts, r.event_type, 'sdk', $2, r.task_id, 'drift-test',
       row_number() OVER (), r.provider, r.model, r.response_model, r.status, r.error_class,
       r.latency_ms, r.tokens_in, r.tokens_out, 'fresh', 'full', decode(repeat('00', 32), 'hex'),
       'normaliser/1.0', coalesce(r.attrs, '{}'::jsonb)
  FROM jsonb_to_recordset($3::jsonb) AS r(ts timestamptz, event_type text, task_id uuid,
       provider text, model text, response_model text, status text, error_class text,
       latency_ms integer, tokens_in integer, tokens_out integer, attrs jsonb)
"""


@dataclass(frozen=True)
class Profile:
    out_mu: float = 300
    refusal: float = 0.01
    errors: float = 0.02
    served: str = "gpt-4o-2024-08-06"
    fingerprint: str | None = "fp_a"
    tools: tuple[str, ...] = ("search", "fetch", "answer")


NORMAL = Profile()


def _spread(start: datetime, end: datetime, n: int) -> list[datetime]:
    step = (end - start) / max(n, 1)
    return [start + step * i for i in range(n)]


def gen_ai_rows(
    n: int,
    start: datetime,
    end: datetime,
    profile: Profile,
    *,
    seed: int,
    model: str = "gpt-4o",
    provider: str = "openai",
) -> list[dict[str, Any]]:
    rng = random.Random(seed)  # noqa: S311 (reproducible test data)
    rows = []
    for ts in _spread(start, end, n):
        failed = rng.random() < profile.errors
        finish = ["content_filter"] if rng.random() < profile.refusal else ["stop"]
        if rng.random() < 0.3:
            finish = ["tool_calls"]
        attrs: dict[str, Any] = {"finish_reasons": finish}
        if profile.fingerprint:
            attrs["system_fingerprint"] = profile.fingerprint
        rows.append(
            {
                "ts": ts.isoformat(),
                "event_type": "gen_ai.request",
                "provider": provider,
                "model": model,
                "response_model": profile.served,
                "status": "error" if failed else "ok",
                "error_class": "timeout" if failed else None,
                "latency_ms": max(1, int(rng.gauss(900, 150))),
                "tokens_in": max(1, int(rng.gauss(1200, 200))),
                "tokens_out": max(1, int(rng.gauss(profile.out_mu, profile.out_mu / 5))),
                "attrs": attrs,
            }
        )
    return rows


def tool_rows(tasks: int, start: datetime, end: datetime, profile: Profile) -> list[dict[str, Any]]:
    rows = []
    times = _spread(start, end, tasks * len(profile.tools))
    i = 0
    for _ in range(tasks):
        task = str(uuid4())
        for tool in profile.tools:
            rows.append(
                {
                    "ts": times[i].isoformat(),
                    "event_type": "tool.call",
                    "task_id": task,
                    "status": "ok",
                    "attrs": {"tool_name": tool, "schema_valid": True},
                }
            )
            i += 1
    return rows


@dataclass
class Traffic:
    s: Any  # SWorld
    on_b: bool = False  # tenant B instead of tenant A

    @property
    def tenant(self) -> UUID:
        return UUID(str((self.s.b if self.on_b else self.s.a).id))

    def now(self) -> datetime:
        value: datetime = self.s.val("SELECT date_trunc('second', now())")
        return value

    def agent(self) -> UUID:
        agent_id = uuid4()
        self.s.admin.execute(
            "INSERT INTO sibyl.agent (tenant_id, id, slug, name, kind, tier, fail_mode, lifecycle)"
            " VALUES ($1, $2, $3, $3, 'autonomous_agent', 2, 'closed', 'deployed')",
            self.tenant,
            agent_id,
            f"drift-{agent_id.hex[:10]}",
        )
        return agent_id

    def write(self, agent: UUID, rows: list[dict[str, Any]]) -> None:
        self.s.admin.execute(_INSERT, self.tenant, agent, json.dumps(rows))

    def period(
        self,
        agent: UUID,
        start: datetime,
        end: datetime,
        n: int,
        profile: Profile = NORMAL,
        *,
        seed: int,
        tasks: int = 40,
        model: str = "gpt-4o",
    ) -> None:
        self.write(agent, gen_ai_rows(n, start, end, profile, seed=seed, model=model))
        if tasks:
            self.write(agent, tool_rows(tasks, start, end, profile))

    def run(self, now: datetime, cfg: DriftConfig = CFG) -> TenantResult:
        async def go() -> TenantResult:
            async with self.s.worker_db.tenant_tx(self.tenant) as conn:
                return await run_tenant(
                    conn,
                    self.tenant,
                    now=now,
                    cfg=cfg,
                    outbox=PgOutboxWriter(),
                    audit=PgAuditWriter(),
                )

        result: TenantResult = self.s.run(go())
        return result

    def baselines(self, agent: UUID) -> list[Any]:
        return self.s.rows(
            "SELECT * FROM sibyl.drift_baseline WHERE tenant_id = $1 AND agent_id = $2"
            " ORDER BY created_at",
            self.tenant,
            agent,
        )

    def reports(self, agent: UUID) -> list[Any]:
        return self.s.rows(
            "SELECT * FROM sibyl.drift_report WHERE tenant_id = $1 AND agent_id = $2"
            " ORDER BY evaluated_at",
            self.tenant,
            agent,
        )

    def alerts(self, agent: UUID) -> list[Any]:
        return self.s.rows(
            "SELECT a.*, r.code, r.kind FROM sibyl.alert a JOIN sibyl.alert_rule r"
            " ON r.tenant_id = a.tenant_id AND r.id = a.rule_id"
            " WHERE a.tenant_id = $1 AND a.agent_id = $2 ORDER BY a.first_fired_at",
            self.tenant,
            agent,
        )


def make_traffic(sworld: Any, *, on_b: bool = False) -> Traffic:
    return Traffic(sworld, on_b)
