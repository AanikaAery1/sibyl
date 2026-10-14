"""The shared DB-backed contract world (G0 reconciliation item 9, INT-1 item 6).

One migrated PG17 database per test session (``sibyl_contract_<hex>`` on ``SIBYL_PG_ADMIN_DSN``,
dropped at the end) and the full api (``create_app``) wired like production: the real principal
chain (console sessions and peppered ``sbl_`` API keys, ``build_principal_resolver``), the real
``Database``, ``PgIdempotencyStore`` and the Pg audit/outbox writers. Audit rows are read back
from ``sibyl.audit_events``, so "the route wrote only its declared actions" is checked on the
real hash chain, not on a recorder.

Two tenants (A = the subject of every scenario, B = the foreign owner) are seeded with the lane
A/V kit (``tests/api/auth/kit.py``): an OIDC issuer, a user per role with a live, stepped-up
session, three agent groups and three agents. On top of that: a second security admin
(``approver``, four-eyes), a user with no role in A (``nobody``), the sim double host, a snapshot
signing key, a published ``audit_anchor`` signing key (``anchor_signer``: scenarios write real
signed anchors with the worker's own ``write_anchor``), and API keys created through the api
itself (``keys``: every machine scope but break-glass; ``bound``: the same scopes bound to the
``bound`` agent; ``keys-b`` in tenant B; D53 monitor keys registered through ``POST /monitors``:
``monitor`` watching every group, ``monitor-g1`` watching group g1 and its child g2). Payload blobs
live in an in-memory ``BlobStore``; SSE streams end after a short lifetime so a 2xx stream
terminates.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import secrets
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import asyncpg
from sibyl_control.api.sse.stream import StreamConfig
from sibyl_control.core.authz import KEY_SCOPES, MONITOR_SCOPES
from sibyl_control.core.blob.base import BlobNotFound
from sibyl_control.core.crypto.signing import Ed25519Signer
from sibyl_control.core.db import _init_connection
from sibyl_control.core.ratelimit import RateDecision, RatePolicy
from sibyl_control.migrate.config import ConnSpec, MigrateConfig
from sibyl_control.migrate.runner import apply

SNAP_ENV = "SIBYL_TEST_CONTRACT_SNAPSHOT_SEED"
SNAP_KID = "snap-contract-1"
ANCHOR_ENV = "SIBYL_TEST_CONTRACT_ANCHOR_SEED"
ANCHOR_KID = "anchor-contract-1"
SIM_HOST = "sibyl-sim"
SESSION_ROLES = ("owner", "admin", "security_admin", "engineer", "operator", "auditor", "viewer")
MACHINE_SCOPES = sorted(KEY_SCOPES - {"killswitch:pull"} - MONITOR_SCOPES)
"""Every machine scope a plain key can hold (monitor scopes are monitor-bound, D53)."""


def load_kit() -> Any:
    """The lane A/V kit, as the module name its own suites use (one shared module object)."""
    name = "sibyl_lane_a_kit"
    if name not in sys.modules:
        path = Path(__file__).resolve().parents[1] / "api" / "auth" / "kit.py"
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


kit = load_kit()


class Unlimited:
    """Rate limiter that never refuses (the generated suites are not rate-limit tests; the
    scenarios' setup traffic would otherwise trip the per-principal write quotas)."""

    def _ok(self, policy: RatePolicy) -> RateDecision:
        return RateDecision(True, policy, policy.quota, 0, 0)

    async def hit(self, key: str, policy: RatePolicy, cost: int = 1) -> RateDecision:
        return self._ok(policy)

    async def peek(self, key: str, policy: RatePolicy) -> RateDecision:
        return self._ok(policy)


class MemoryBlob:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    async def put(self, key: str, data: bytes, *, content_type: str = "") -> None:
        self.objects[key] = data

    async def get(self, key: str) -> bytes:
        if key not in self.objects:
            raise BlobNotFound(key)
        return self.objects[key]

    async def delete(self, key: str) -> None:
        self.objects.pop(key, None)

    async def exists(self, key: str) -> bool:
        return key in self.objects


class Admin:
    """The kit's superuser connection plus the registry harness's ``in_tenant`` helper."""

    def __init__(self, conn: Any) -> None:
        self.conn = conn

    def execute(self, sql: str, *args: Any) -> Any:
        return self.conn.execute(sql, *args)

    def fetch(self, sql: str, *args: Any) -> list[Any]:
        return self.conn.fetch(sql, *args)

    def fetchrow(self, sql: str, *args: Any) -> Any:
        return self.conn.fetchrow(sql, *args)

    def fetchval(self, sql: str, *args: Any) -> Any:
        return self.conn.fetchval(sql, *args)

    def in_tenant(self, tenant_id: UUID, sql: str, *args: Any) -> Any:
        with self.conn.tx(tenant_id):
            return self.conn.fetch(sql, *args)

    def tx(self, tenant: UUID | None = None) -> Any:
        return self.conn.tx(tenant)


@dataclass
class Tenant:
    id: UUID
    slug: str
    issuer_id: UUID
    users: dict[str, UUID]
    groups: dict[str, UUID]
    agents: dict[str, UUID]


@dataclass
class ContractWorld:
    db: Any  # kit.LaneDb
    lane: Any  # kit.Lane
    admin: Admin
    a: Tenant
    b: Tenant
    blob: MemoryBlob
    anchor_signer: Ed25519Signer
    tokens: dict[str, str] = field(default_factory=dict)
    key_ids: dict[str, UUID] = field(default_factory=dict)
    monitor_ids: dict[str, UUID] = field(default_factory=dict)

    @property
    def client(self) -> Any:
        return self.lane.client

    def headers(self, token: str, **extra: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.tokens[token]}", **extra}

    def idem(self, who: str = "owner", **extra: str) -> dict[str, str]:
        return self.headers(who, **{"Idempotency-Key": str(uuid4()), **extra})

    def audit_head(self, tenant: UUID) -> int:
        return int(kit.audit_head(self.db, tenant))

    def audit_since(self, tenant: UUID, seq: int) -> list[str]:
        return list(kit.audit_actions(self.db, tenant, seq))

    def refresh_step_up(self) -> None:
        """Keep every session freshly stepped up (the suite may outlive the 5-minute window)."""
        with self.admin.tx():
            self.admin.execute(
                "UPDATE sibyl.session SET step_up_at = now() WHERE revoked_at IS NULL"
                " AND step_up_at IS NOT NULL"
            )


# --- database ---------------------------------------------------------------------------------


def _create_db() -> Any:
    loop = asyncio.new_event_loop()
    name = f"sibyl_contract_{secrets.token_hex(6)}"
    loop.run_until_complete(kit._admin_exec(f'CREATE DATABASE "{name}"'))
    spec = ConnSpec(dsn=kit.ADMIN_DSN, user=None, database=name)
    migrate = ConnSpec(dsn=kit.ADMIN_DSN, user="sibyl_migrate", database=name)
    loop.run_until_complete(apply(MigrateConfig(migrate=migrate, admin=spec)))

    async def dev_host() -> None:
        conn = await asyncpg.connect(**migrate.kwargs())
        try:
            await conn.execute(
                "INSERT INTO sibyl.base_url_dev_host (host, note) VALUES ($1, 'contract world')"
                " ON CONFLICT DO NOTHING",
                SIM_HOST,
            )
        finally:
            await conn.close()

    loop.run_until_complete(dev_host())
    raw = loop.run_until_complete(asyncpg.connect(**spec.kwargs()))
    loop.run_until_complete(_init_connection(raw))
    return kit.LaneDb(name, loop, kit.Conn(loop, raw))


def _drop_db(db: Any) -> None:
    db.admin.close()
    db.loop.run_until_complete(kit._admin_exec(f'DROP DATABASE IF EXISTS "{db.name}" WITH (FORCE)'))
    db.loop.close()


def _tenant(db: Any) -> Tenant:
    w = kit.world(db)
    users = dict(w.users)
    users["approver"] = kit.add_user(db, w.tenant, w.issuer_id, roles=("security_admin",))
    kit.add_capture_policy(db, w.tenant, users["owner"])
    agents = dict(w.agents)
    agents["bound"] = kit.add_agent(db, w.tenant, "agent-bound")
    return Tenant(w.tenant, w.slug, w.issuer_id, users, dict(w.groups), agents)


def _signing_key(db: Any, kid: str, purpose: str, env: str) -> Ed25519Signer:
    seed = secrets.token_bytes(32)
    os.environ[env] = seed.hex()
    signer = Ed25519Signer.from_seed(kid, seed)
    with db.admin.tx():
        db.admin.execute(
            "INSERT INTO sibyl.signing_key (kid, purpose, public_key, private_key_ref)"
            " VALUES ($1, $2, $3, $4)",
            kid,
            purpose,
            signer.public_key_raw,
            f"env:{env}",
        )
    return signer


def _session(db: Any, tenant: UUID, user: UUID) -> str:
    token: str = kit.add_session(db, tenant, user, step_up_at=datetime.now(UTC))
    return token


def _api_key(world: ContractWorld, name: str, agent: UUID | None, who: str = "owner") -> None:
    body: dict[str, Any] = {"name": f"contract-{name}", "env": "test", "scopes": MACHINE_SCOPES}
    if agent is not None:
        body["agent_id"] = str(agent)
    resp = world.client.post("/api/v1/api-keys", json=body, headers=world.idem(who))
    assert resp.status_code == 201, resp.text
    created = resp.json()
    world.tokens[name] = created["secret"]
    world.key_ids[name] = UUID(created["id"] if "id" in created else created["key"]["id"])


def _monitor_key(world: ContractWorld, name: str, groups: list[UUID] | None = None) -> None:
    body: dict[str, Any] = {
        "name": f"contract-{name}",
        "kind": "api",
        "key_env": "test",
        "all_groups": groups is None,
        "group_ids": [str(g) for g in groups or []],
    }
    resp = world.client.post("/api/v1/monitors", json=body, headers=world.idem("owner"))
    assert resp.status_code == 201, resp.text
    created = resp.json()
    world.tokens[name] = created["api_key"]["secret"]
    world.key_ids[name] = UUID(created["api_key"]["id"])
    world.monitor_ids[name] = UUID(created["id"])


@contextmanager
def contract_world() -> Iterator[ContractWorld]:
    db = _create_db()
    try:
        a, b = _tenant(db), _tenant(db)
        _signing_key(db, SNAP_KID, "snapshot", SNAP_ENV)
        anchor_signer = _signing_key(db, ANCHOR_KID, "audit_anchor", ANCHOR_ENV)
        blob = MemoryBlob()
        fast_sse = StreamConfig(heartbeat_s=0.05, poll_s=0.05, max_lifetime_s=0.3)
        with kit.lane_app(db, extra_state={"blob": blob, "sse_config": fast_sse}) as lane:
            lane.services.rate_limiter = Unlimited()
            world = ContractWorld(db, lane, Admin(db.admin), a, b, blob, anchor_signer)
            for role in SESSION_ROLES:
                world.tokens[role] = _session(db, a.id, a.users[role])
            world.tokens["approver"] = _session(db, a.id, a.users["approver"])
            world.tokens["nobody"] = _session(db, a.id, a.users["nobody"])
            world.tokens["owner-b"] = _session(db, b.id, b.users["owner"])
            _api_key(world, "keys", None)
            _api_key(world, "bound", a.agents["bound"])
            _api_key(world, "keys-b", None, who="owner-b")
            _monitor_key(world, "monitor")
            _monitor_key(world, "monitor-g1", [a.groups["g1"]])
            yield world
    finally:
        os.environ.pop(SNAP_ENV, None)
        os.environ.pop(ANCHOR_ENV, None)
        _drop_db(db)


def stale(minutes: int = 6) -> datetime:
    return datetime.now(UTC) - timedelta(minutes=minutes)
