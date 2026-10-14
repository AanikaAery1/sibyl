"""Monitor-bound API keys in the kernel (D53): scope validation, the resolver narrowing a key to
its monitor's watched groups, and failing closed when the monitor is revoked or unreadable."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sibyl_control.api.deps import ApiKeyResolver
from sibyl_control.core.apikeys import KeyRecord, generate_api_key, validate_key_scopes
from sibyl_control.core.monitor_keys import (
    MonitorBinding,
    descendants,
    load_binding,
    monitor_grants,
)
from sibyl_control.core.problems import ProblemError

PEPPER = b"p" * 32
TENANT = uuid4()


def test_validate_key_scopes_keeps_monitor_scopes_on_monitor_keys() -> None:
    monitor = uuid4()
    with pytest.raises(ProblemError, match="monitor"):
        validate_key_scopes({"monitor:read"}, agent_id=None, env="live")
    with pytest.raises(ProblemError):
        validate_key_scopes(
            {"monitor:read", "agents:read"}, agent_id=None, env="live", monitor_id=monitor
        )
    with pytest.raises(ProblemError):
        validate_key_scopes({"findings:write"}, agent_id=uuid4(), env="live", monitor_id=monitor)
    scopes = validate_key_scopes(
        {"monitor:read", "findings:write"}, agent_id=None, env="test", monitor_id=monitor
    )
    assert scopes == {"monitor:read", "findings:write"}


def test_descendants_follow_children_and_survive_cycles() -> None:
    root, child, grandchild, other = uuid4(), uuid4(), uuid4(), uuid4()
    edges: dict[UUID, UUID | None] = {root: None, child: root, grandchild: child, other: None}
    assert descendants([root], edges) == {root, child, grandchild}
    assert descendants([child], {**edges, root: grandchild}) == {child, grandchild, root}
    assert descendants([], edges) == frozenset()


class _Conn:
    def __init__(self, row: dict[str, Any] | None, groups: list[dict[str, Any]]) -> None:
        self.row, self.groups = row, groups

    async def fetchrow(self, sql: str, *args: Any) -> Any:
        return self.row

    async def fetch(self, sql: str, *args: Any) -> Any:
        return self.groups


def test_load_binding_expands_watched_groups() -> None:
    g1, g2 = uuid4(), uuid4()
    narrow = _Conn(
        {"state": "active", "all_groups": False, "group_ids": [g1]},
        [{"id": g1, "parent_group_id": None}, {"id": g2, "parent_group_id": g1}],
    )
    binding = asyncio.run(load_binding(narrow, TENANT, uuid4()))
    assert binding is not None and binding.group_ids == {g1, g2} and binding.usable
    wide = _Conn({"state": "paused", "all_groups": True, "group_ids": []}, [])
    binding = asyncio.run(load_binding(wide, TENANT, uuid4()))
    assert binding is not None and binding.group_ids is None and binding.usable
    assert asyncio.run(load_binding(_Conn(None, []), TENANT, uuid4())) is None
    revoked = MonitorBinding(uuid4(), "revoked", None)
    assert not revoked.usable
    grants = monitor_grants({"monitor:read"}, MonitorBinding(uuid4(), "active", frozenset({g1})))
    assert grants["monitor:read"].group_ids == {g1}


class _Request:
    def __init__(self, token: str) -> None:
        self.headers = {"authorization": f"Bearer {token}"}
        self.state = type("State", (), {})()


def _resolver(binding: MonitorBinding | None, *, with_lookup: bool = True) -> tuple[Any, str]:
    generated = generate_api_key("live", PEPPER)
    monitor = binding.monitor_id if binding else uuid4()
    record = KeyRecord(
        tenant_id=TENANT,
        id=uuid4(),
        env="live",
        secret_hash=generated.secret_hash,
        scopes=frozenset({"monitor:read", "findings:write"}),
        expires_at=datetime.now(UTC) + timedelta(days=1),
        monitor_id=monitor,
    )

    async def lookup(prefix: str) -> KeyRecord | None:
        return record if prefix == generated.prefix else None

    async def monitors(tenant: UUID, monitor_id: UUID) -> MonitorBinding | None:
        assert (tenant, monitor_id) == (TENANT, monitor)
        return binding

    resolver = ApiKeyResolver(lookup, PEPPER, monitors=monitors if with_lookup else None)
    return resolver, generated.plaintext


def test_the_resolver_narrows_a_monitor_key_to_its_groups() -> None:
    group = uuid4()
    binding = MonitorBinding(uuid4(), "paused", frozenset({group}))
    resolver, token = _resolver(binding)
    principal = asyncio.run(resolver.resolve(_Request(token)))
    assert principal.monitor_id == binding.monitor_id
    assert {g.group_ids for g in principal.grants.values()} == {frozenset({group})}
    assert principal.bound_agent_id is None


@pytest.mark.parametrize(
    ("binding", "with_lookup"),
    [
        (MonitorBinding(uuid4(), "revoked", None), True),
        (None, True),  # the monitor is gone
        (MonitorBinding(uuid4(), "active", None), False),  # e.g. ingest: no monitor lookup
    ],
)
def test_the_resolver_fails_closed(binding: MonitorBinding | None, with_lookup: bool) -> None:
    resolver, token = _resolver(binding, with_lookup=with_lookup)
    request = _Request(token)
    with pytest.raises(ProblemError) as caught:
        asyncio.run(resolver.resolve(request))
    assert caught.value.status == 401
    assert request.state.key_reject_reason == "monitor_unavailable"
    assert token not in str(caught.value)
