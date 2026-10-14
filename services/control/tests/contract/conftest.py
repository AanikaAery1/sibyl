"""Shared harnesses for the generated contract suites (authz red wall, audit completeness).

* ``harness``: the app with no database, principals from ``StaticTokenResolver`` and in-memory
  audit/outbox writers. Guard-level cases (401, scope 403, key-only/session-only, break-glass,
  stale step-up) are decided before any handler runs, so they need nothing more.
* ``contract_world`` (session-scoped, ``pg_world``): a migrated PG17 with two seeded tenants and
  the production principal chain, for the cases that need real objects (foreign-tenant 404,
  group / bound-agent / job-owner 404, audit rows on a 2xx). Requests come from ``scenarios``.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sibyl_control.api.app import create_app
from sibyl_control.api.deps import Services, StaticTokenResolver
from sibyl_control.core.audit import InMemoryAuditWriter
from sibyl_control.core.authz import (
    KEY_SCOPES,
    MONITOR_SCOPES,
    STEP_UP_WINDOW,
    MembershipGrant,
    Principal,
    PrincipalKind,
    grants_for_api_key,
    grants_from_memberships,
)
from sibyl_control.core.idempotency import InMemoryIdempotencyStore
from sibyl_control.core.outbox import InMemoryOutboxWriter

from . import pg_world

TENANT_A = UUID("01927000-0000-7000-8000-00000000000a")
TENANT_B = UUID("01927000-0000-7000-8000-00000000000b")
GROUP_A = UUID("01927000-0000-7000-8000-0000000000a1")
BOUND_AGENT_A = UUID("01927000-0000-7000-8000-0000000000a2")


def _human(
    tenant: UUID,
    roles: tuple[str, ...],
    *,
    step_up_at: datetime | None,
    group: UUID | None = None,
) -> Principal:
    return Principal(
        kind=PrincipalKind.SESSION,
        tenant_id=tenant,
        id=uuid4(),
        grants=grants_from_memberships(MembershipGrant(r, group) for r in roles),
        session_id=uuid4(),
        step_up_at=step_up_at,
        roles=frozenset(roles),
    )


def _key(tenant: UUID, scopes: frozenset[str], agent: UUID | None = None) -> Principal:
    return Principal(
        kind=PrincipalKind.API_KEY,
        tenant_id=tenant,
        id=uuid4(),
        grants=grants_for_api_key(scopes),
        bound_agent_id=agent,
    )


def make_tokens(now: datetime) -> dict[str, Principal]:
    """Principals keyed by bearer token. ``now`` is the test's own clock (test review F16): a
    fresh step-up is fresh for the whole test however long the suite has been running."""
    stale = now - STEP_UP_WINDOW - timedelta(minutes=1)
    return {
        "owner-a": _human(TENANT_A, ("owner",), step_up_at=now),
        "owner-a-stale": _human(TENANT_A, ("owner",), step_up_at=stale),
        "owner-b": _human(TENANT_B, ("owner",), step_up_at=now),
        "nobody-a": _human(TENANT_A, (), step_up_at=now),
        "engineer-group-a": _human(TENANT_A, ("engineer",), step_up_at=now, group=GROUP_A),
        "keys-a": _key(TENANT_A, KEY_SCOPES - {"killswitch:pull"} - MONITOR_SCOPES),
        "bound-key-a": _key(
            TENANT_A, KEY_SCOPES - {"killswitch:pull"} - MONITOR_SCOPES, BOUND_AGENT_A
        ),
        "breakglass-a": _key(TENANT_A, frozenset({"killswitch:pull"})),
    }


@pytest.fixture
def now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
def tokens(now: datetime) -> dict[str, Principal]:
    return make_tokens(now)


@dataclass
class Harness:
    client: TestClient
    audit: InMemoryAuditWriter
    outbox: InMemoryOutboxWriter
    principals: StaticTokenResolver


@pytest.fixture
def harness(tokens: dict[str, Principal], now: datetime) -> Iterator[Harness]:
    audit = InMemoryAuditWriter()
    outbox = InMemoryOutboxWriter()
    principals = StaticTokenResolver(tokens)
    services = Services(
        principals=principals,
        audit=audit,
        outbox=outbox,
        idempotency=InMemoryIdempotencyStore(),
        clock=lambda: now,
    )
    with TestClient(create_app(services=services), raise_server_exceptions=False) as client:
        yield Harness(client, audit, outbox, principals)


@pytest.fixture(scope="session")
def contract_world() -> Iterator[pg_world.ContractWorld]:
    if not pg_world.kit.available():
        pytest.skip(f"PostgreSQL 17 not reachable at {pg_world.kit.ADMIN_DSN} (make db-up)")
    with pg_world.contract_world() as world:
        yield world


@pytest.fixture
def cworld(contract_world: pg_world.ContractWorld) -> pg_world.ContractWorld:
    contract_world.refresh_step_up()
    return contract_world
