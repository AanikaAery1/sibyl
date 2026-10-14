"""Lane S test world: lane R's migrated PG17 world plus the worker role and incident fixtures.

Shared by ``tests/worker/{saga,approvals,failback,handoff}`` and
``tests/api/{incidents,approvals,killswitch,queue}`` (each conftest loads this file as
``sibyl_lane_s_world``). Adds:

* a ``Database`` connected as ``sibyl_worker`` on the world's event loop, so worker code runs
  under its real grants and RLS;
* session-backed principals (kill switches and step-up need real ``session`` rows);
* direct-SQL builders for agents with routing state, providers, models, continuity plans,
  approved chains, health snapshots, alerts and checkpoints.
"""

from __future__ import annotations

import importlib.util
import json
import secrets
import sys
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

import pytest
from sibyl_control.core.authz import (
    MembershipGrant,
    Principal,
    PrincipalKind,
    grants_for_api_key,
    grants_from_memberships,
)
from sibyl_control.core.db import Database
from sibyl_control.worker.saga.model import Env

_ROOT = Path(__file__).resolve().parents[2]  # services/control/tests


def _load(name: str, path: Path) -> Any:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


R = _load("sibyl_lane_r_harness", _ROOT / "api" / "registry" / "_harness.py")
FRESH = datetime.now(UTC) + timedelta(days=1)


def unique(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(4)}"


def _worker_dsn(name: str) -> str:
    parts = urlsplit(R.ADMIN_DSN)
    host = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, f"sibyl_worker@{host}", f"/{name}", "", ""))


@dataclass
class SWorld:
    w: Any  # lane R World
    worker_db: Database
    users: dict[str, UUID] = field(default_factory=dict)

    # --- plumbing -----------------------------------------------------------------------------
    @property
    def a(self) -> Any:
        return self.w.a

    @property
    def b(self) -> Any:
        return self.w.b

    @property
    def client(self) -> Any:
        return self.w.client

    @property
    def admin(self) -> Any:
        return self.w.admin

    def run(self, coro: Any) -> Any:
        return self.w.loop.run_until_complete(coro)

    def env(self, wid: str = "saga:test", **settings: Any) -> Env:
        """A worker ``Env``; ``settings`` overrides its Settings-derived gates (band, ramp)."""
        return Env(worker_id=wid, can_build_handoff=True, completion_audit=True, **settings)

    def idem(self, who: str, **extra: str) -> dict[str, str]:
        return self.w.idem(who, **extra)

    def post(self, who: str, path: str, body: Any = None, **headers: str) -> Any:
        return self.client.post("/api/v1" + path, json=body, headers=self.idem(who, **headers))

    def get(self, who: str, path: str, **params: Any) -> Any:
        return self.client.get("/api/v1" + path, params=params, headers=self.w.headers(who))

    def one(self, sql: str, *args: Any) -> Any:
        return self.admin.fetchrow(sql, *args)

    def val(self, sql: str, *args: Any) -> Any:
        return self.admin.fetchval(sql, *args)

    def rows(self, sql: str, *args: Any) -> list[Any]:
        return self.admin.fetch(sql, *args)

    def in_tenant(self, tenant: Any, sql: str, *args: Any) -> Any:
        return self.admin.in_tenant(tenant.id, sql, *args)

    def audit_actions(self, tenant: Any, since_seq: int = -1) -> list[str]:
        return [
            r["action"]
            for r in self.rows(
                "SELECT action FROM sibyl.audit_events WHERE tenant_id = $1 AND seq > $2"
                " ORDER BY seq",
                tenant.id,
                since_seq,
            )
        ]

    def head(self, tenant: Any) -> int:
        return int(
            self.val("SELECT seq FROM sibyl.audit_chain_head WHERE tenant_id = $1", tenant.id)
        )

    # --- principals ---------------------------------------------------------------------------
    def human(
        self,
        token: str,
        tenant: Any,
        roles: tuple[str, ...],
        *,
        user: UUID | None = None,
        group: UUID | None = None,
        step_up_at: datetime | None = FRESH,
    ) -> UUID:
        """A session-backed human principal; creates the user when ``user`` is None."""
        if user is None:
            user = uuid4()
            self.admin.execute(
                "INSERT INTO sibyl.app_user (tenant_id, id, oidc_issuer_id, subject, email,"
                " display_name, status) VALUES ($1, $2, $3, $4, $5, $6, 'active')",
                tenant.id,
                user,
                tenant.issuer_id,
                f"{tenant.slug}-{token}",
                f"{token}@{tenant.slug}.example.com",
                token.title(),
            )
        session = uuid4()
        self.admin.execute(
            "INSERT INTO sibyl.session (tenant_id, id, user_id, token_hash) VALUES ($1, $2, $3,"
            " $4)",
            tenant.id,
            session,
            user,
            secrets.token_bytes(32),
        )
        self.w.resolver.add(
            token,
            Principal(
                kind=PrincipalKind.SESSION,
                tenant_id=tenant.id,
                id=user,
                grants=grants_from_memberships(MembershipGrant(r, group) for r in roles),
                session_id=session,
                step_up_at=step_up_at,
                roles=frozenset(roles),
            ),
        )
        self.users[token] = user
        return user

    def key(self, token: str, tenant: Any, scopes: Sequence[str], *, env: str = "live") -> UUID:
        """A real ``api_key`` row (kill switches reference it) plus its principal."""
        key_id = uuid4()
        self.admin.execute(
            "INSERT INTO sibyl.api_key (tenant_id, id, name, env, prefix, secret_hash, scopes,"
            " expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, now() + interval '30 days')",
            tenant.id,
            key_id,
            token,
            env,
            secrets.token_hex(6),
            secrets.token_bytes(32),
            list(scopes),
        )
        self.w.resolver.add(
            token,
            Principal(
                PrincipalKind.API_KEY, tenant.id, key_id, grants_for_api_key(frozenset(scopes))
            ),
        )
        return key_id

    # --- registry -----------------------------------------------------------------------------
    def provider(self, tenant: Any | None = None) -> UUID:
        tenant = tenant or self.a
        pid = uuid4()
        name = unique("prov")
        self.admin.execute(
            "INSERT INTO sibyl.provider (tenant_id, id, slug, name, provider_kind, dialect,"
            " base_url, is_known_provider) VALUES ($1, $2, $3, $3, 'openai', 'openai_compatible',"
            " $4, true)",
            tenant.id,
            pid,
            name,
            f"https://api.{name}.example.com/v1",
        )
        return pid

    def model(self, provider: UUID, tenant: Any | None = None, *, allowed: bool = True) -> UUID:
        tenant = tenant or self.a
        mid = uuid4()
        self.in_tenant(
            tenant,
            "INSERT INTO sibyl.model (tenant_id, id, provider_id, model_name, is_allowed)"
            " VALUES ($1, $2, $3, $4, $5)",
            tenant.id,
            mid,
            provider,
            unique("model"),
            allowed,
        )
        return mid

    def agent(
        self,
        tenant: Any | None = None,
        *,
        tier: int = 2,
        group: UUID | None = None,
        tags: Sequence[str] = (),
        model: UUID | None = None,
        register: bool = True,
        owner: UUID | None = None,
    ) -> UUID:
        tenant = tenant or self.a
        agent = uuid4()
        self.admin.execute(
            "INSERT INTO sibyl.agent (tenant_id, id, slug, name, kind, tier, fail_mode, lifecycle,"
            " agent_group_id, tags, owner_user_id) VALUES ($1, $2, $3, $3, 'autonomous_agent', $4,"
            " 'closed', 'deployed', $5, $6, $7)",
            tenant.id,
            agent,
            unique("agent"),
            tier,
            group,
            list(tags),
            owner,
        )
        if model is not None:
            version = uuid4()
            self.admin.execute(
                "INSERT INTO sibyl.agent_version (tenant_id, id, agent_id, version_no,"
                " primary_model_id, source) VALUES ($1, $2, $3, 1, $4, 'api')",
                tenant.id,
                version,
                agent,
                model,
            )
            self.admin.execute(
                "UPDATE sibyl.agent SET current_version_id = $3 WHERE tenant_id = $1 AND id = $2",
                tenant.id,
                agent,
                version,
            )
        if register:
            self.in_tenant(
                tenant,
                "SELECT * FROM sibyl.routing_apply($1, $2, NULL, NULL, 'active', NULL, 'register',"
                " 'system', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, $3,"
                " 'route.changed', NULL, NULL, NULL, NULL)",
                tenant.id,
                agent,
                f"register:{agent}",
            )
        return agent

    def plan(self, agent: UUID, tenant: Any | None = None, **fields: Any) -> None:
        tenant = tenant or self.a
        cols = {"credential_mode": "passthrough", "approval_timeout_policy": "hold", **fields}
        names = ", ".join(cols)
        marks = ", ".join(f"${i + 3}" for i in range(len(cols)))
        self.in_tenant(
            tenant,
            f"INSERT INTO sibyl.continuity_plan (tenant_id, agent_id, rto_s, rpo_s,"  # noqa: S608
            f" inline_fallback, preemptive_mode, {names}) VALUES ($1, $2, NULL, NULL, NULL, NULL,"
            f" {marks}) ON CONFLICT (tenant_id, agent_id) DO NOTHING",
            tenant.id,
            agent,
            *cols.values(),
        )

    def chain(
        self, agent: UUID, steps: Sequence[dict[str, Any]], tenant: Any | None = None
    ) -> dict[str, UUID]:
        """An approved chain (requester owner, approver security_admin) wired into the plan;
        returns ``{kind or label: step_id}``."""
        tenant = tenant or self.a
        users = tenant.users
        chain = uuid4()
        version = self.val(
            "SELECT coalesce(max(version_no), 0) + 1 FROM sibyl.fallback_chain"
            " WHERE tenant_id = $1 AND agent_id = $2",
            tenant.id,
            agent,
        )
        self.admin.execute(
            "INSERT INTO sibyl.fallback_chain (tenant_id, id, agent_id, version_no,"
            " requested_by_user_id) VALUES ($1, $2, $3, $4, $5)",
            tenant.id,
            chain,
            agent,
            version,
            users["owner"],
        )
        out: dict[str, UUID] = {}
        for position, step in enumerate(steps):
            sid = uuid4()
            self.admin.execute(
                "INSERT INTO sibyl.fallback_step (tenant_id, id, chain_id, position, kind,"
                " provider_id, model_id, backup_agent_id, credential_id, risk)"
                " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                tenant.id,
                sid,
                chain,
                position,
                step["kind"],
                step.get("provider_id"),
                step.get("model_id"),
                step.get("backup_agent_id"),
                step.get("credential_id"),
                step.get("risk", "low"),
            )
            out[step.get("label", step["kind"])] = sid
        self.admin.execute(
            "UPDATE sibyl.fallback_chain SET status = 'retired', retired_at = now()"
            " WHERE tenant_id = $1 AND agent_id = $2 AND status = 'approved'",
            tenant.id,
            agent,
        )
        self.admin.execute(
            "UPDATE sibyl.fallback_chain SET status = 'approved', approved_by_user_id = $3,"
            " approved_at = now() WHERE tenant_id = $1 AND id = $2",
            tenant.id,
            chain,
            users["approver"],
        )
        self.in_tenant(
            tenant,
            "UPDATE sibyl.continuity_plan SET fallback_chain_id = $3 WHERE tenant_id = $1"
            " AND agent_id = $2",
            tenant.id,
            agent,
            chain,
        )
        out["chain"] = chain
        return out

    # --- health & alerts ------------------------------------------------------------------------
    def snapshot(
        self, agent: UUID, band: str, tenant: Any | None = None, *, ago_s: int = 0
    ) -> UUID:
        tenant = tenant or self.a
        sid = self.val("SELECT sibyl.uuidv7()")
        score = {"healthy": 95, "watch": 80, "degraded": 55, "failed": 10}[band]
        self.admin.execute(
            "INSERT INTO sibyl.health_snapshot (tenant_id, evaluated_at, id, agent_id, score, band,"
            " provisional, events_seen, observation_coverage, scoring_config_id, policy_version,"
            " routing_state_at, window_start, window_end, grain_s)"
            " VALUES ($1, now() - make_interval(secs => $5), $2, $3, $4, $6, false, 100, 1,"
            " $7, 1, 'active', now() - interval '5 minutes', now(), 300)",
            tenant.id,
            sid,
            agent,
            score,
            ago_s,
            band,
            uuid4(),
        )
        return sid

    def rule_id(self, code: str, tenant: Any | None = None) -> UUID:
        tenant = tenant or self.a
        return self.val(
            "SELECT id FROM sibyl.alert_rule WHERE tenant_id = $1 AND code = $2", tenant.id, code
        )

    def alert(
        self,
        agent: UUID,
        tenant: Any | None = None,
        *,
        code: str = "error_rate",
        band: str = "failed",
        fired_ago_s: int = 120,
        severity: str = "critical",
        incident: UUID | None = None,
        snapshot_ago_s: int = 0,
    ) -> UUID:
        tenant = tenant or self.a
        snapshot = self.snapshot(agent, band, tenant, ago_s=snapshot_ago_s)
        alert = uuid4()
        self.admin.execute(
            "INSERT INTO sibyl.alert (tenant_id, id, rule_id, scope, agent_id, severity,"
            " dedupe_key, first_fired_at, what_to_do, health_snapshot_id, summary,"
            " provider_incident_id, suppressed_by_incident)"
            " VALUES ($1, $2, $3, 'agent', $4, $5, $6, now() - make_interval(secs => $7),"
            " 'fail over', $8, 'test alert', $9::uuid, $9::uuid IS NOT NULL)",
            tenant.id,
            alert,
            self.rule_id(code, tenant),
            agent,
            severity,
            f"{code}:agent:{agent}:{uuid4().hex[:6]}",
            fired_ago_s,
            snapshot,
            incident,
        )
        return alert

    def provider_incident(
        self, provider: UUID, agents: Sequence[UUID], tenant: Any | None = None
    ) -> UUID:
        tenant = tenant or self.a
        iid = uuid4()
        self.admin.execute(
            "INSERT INTO sibyl.provider_incident (tenant_id, id, provider_id, severity, rule_codes,"
            " affected_agent_ids, summary) VALUES ($1, $2, $3, 'critical', '{error_rate}', $4,"
            " 'provider outage')",
            tenant.id,
            iid,
            provider,
            list(agents),
        )
        return iid

    def provider_status(
        self, provider: UUID, status: str, tenant: Any | None = None, *, ago_s: int = 0
    ) -> None:
        tenant = tenant or self.a
        self.admin.execute(
            "INSERT INTO sibyl.provider_status (tenant_id, provider_id, source, status,"
            " observed_at)"
            " VALUES ($1, $2, 'status_feed', $3, now() - make_interval(secs => $4))",
            tenant.id,
            provider,
            status,
            ago_s,
        )

    def checkpoint(
        self,
        agent: UUID,
        task: UUID,
        tenant: Any | None = None,
        *,
        seq: int = 1,
        side_effects: Sequence[Mapping[str, Any]] = (),
    ) -> UUID:
        tenant = tenant or self.a
        cid = self.val("SELECT sibyl.uuidv7()")
        doc = {
            "schema": "sibyl-checkpoint/1",
            "checkpoint_id": str(cid),
            "tenant_id": str(tenant.id),
            "agent_id": str(agent),
            "task_id": str(task),
            "seq": seq,
            "step_index": 1,
            "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "goal": "Reconcile invoice batch 42 against the ledger",
            "state_bytes": 2,
            "state_schema": "json",
            "completed_steps": [
                {
                    "index": 0,
                    "step": "fetch_invoices",
                    "started_at": "2026-10-11T09:00:00Z",
                    "ended_at": "2026-10-11T09:00:02Z",
                    "assumed": False,
                }
            ],
            "pending_steps": [
                {"index": 1, "step": "post_ledger", "description": "Post the batch to the ledger"}
            ],
            "side_effects": [dict(e) for e in side_effects],
            "redaction": {
                "capture_mode": "redacted",
                "profile": {"id": "secrets_only", "version": 1, "secrets_scrubbed": 0},
            },
            "provenance": {
                "sdk_version": "0.1.0",
                "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
                "span_id": "00f067aa0ba902b7",
            },
        }
        self.admin.execute(
            "INSERT INTO sibyl.checkpoint (tenant_id, id, agent_id, task_id, seq, step_index,"
            " state_bytes, state, state_schema, doc, capture_mode, redaction_profile_hash)"
            " VALUES ($1, $2, $3, $4, $5, 1, 2, '{}'::jsonb, 'json', $6::jsonb, 'redacted', $7)",
            tenant.id,
            cid,
            agent,
            task,
            seq,
            json.dumps(doc),
            b"\x00" * 32,
        )
        return cid

    # --- reads --------------------------------------------------------------------------------
    def routing(self, agent: UUID, tenant: Any | None = None) -> Any:
        tenant = tenant or self.a
        return self.one(
            "SELECT * FROM sibyl.routing_state WHERE tenant_id = $1 AND agent_id = $2",
            tenant.id,
            agent,
        )

    def saga(self, failover_id: UUID | str, tenant: Any | None = None) -> Any:
        tenant = tenant or self.a
        return self.one(
            "SELECT * FROM sibyl.failover WHERE tenant_id = $1 AND id = $2",
            tenant.id,
            UUID(str(failover_id)),
        )

    def sagas(self, agent: UUID, tenant: Any | None = None) -> list[Any]:
        tenant = tenant or self.a
        return self.rows(
            "SELECT * FROM sibyl.failover WHERE tenant_id = $1 AND agent_id = $2 ORDER BY"
            " created_at",
            tenant.id,
            agent,
        )

    def results(self, failover_id: Any, tenant: Any | None = None) -> dict[str, Any]:
        raw = self.saga(failover_id, tenant)["step_results"]
        return json.loads(raw) if isinstance(raw, str) else dict(raw)


@pytest.fixture(scope="module")
def sworld(world: Any) -> Iterator[SWorld]:
    db = world.loop.run_until_complete(
        Database.connect(_worker_dsn(world.db_name), min_size=1, max_size=4)
    )
    s = SWorld(world, db)
    for tenant in (world.a, world.b):
        for role, user in tenant.users.items():
            roles = ("security_admin",) if role == "approver" else (role,)
            token = role if tenant is world.a else f"{role}-b"
            group = tenant.group_id if role == "engineer" else None
            s.human(token, tenant, roles, user=user, group=group)
    s.human("owner2", world.a, ("owner",))
    try:
        yield s
    finally:
        world.loop.run_until_complete(db.close())
