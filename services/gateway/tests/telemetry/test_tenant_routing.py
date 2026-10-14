"""B-03: a gateway fronting several tenants (R26) posts each tenant's telemetry with that
tenant's own ingest key. Ingest files events under the key's tenant, so one shared key would
file every other tenant's calls, prompts metadata included, in the first tenant: an isolation
leak. An event whose tenant has no key is dropped and counted (fail closed), never posted under
another tenant's key."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

import httpx
import pytest
from sibyl_gateway.config import GatewayConfig
from sibyl_gateway.runtime import ingest_router
from sibyl_gateway.telemetry.queue import HttpIngestSink, TelemetryQueue, UnroutableTelemetry

A, B, C = (str(UUID(int=n)) for n in (1, 2, 3))


def key(env: str, prefix: str) -> str:
    return f"sbl_{env}_{prefix}_" + "x" * 43


GW_A, GW_B = key("live", "aaaaaaaaaaaa"), key("live", "bbbbbbbbbbbb")
IN_A, IN_B = key("live", "iaaaaaaaaaaa"), key("live", "ibbbbbbbbbbb")


def ev(tenant: str | None, n: int) -> dict[str, Any]:
    return {"tenant_id": tenant, "n": n}


# ---- configuration -------------------------------------------------------------------------


def test_ingest_keys_pair_with_tenant_keys_in_order() -> None:
    cfg = GatewayConfig.from_env(
        {
            "SIBYL_GATEWAY_TENANT_KEYS": f"{GW_A},{GW_B}",
            "SIBYL_INGEST_KEYS": f"{IN_A},{IN_B}",
        }
    )
    assert cfg.ingest_routes() == {"aaaaaaaaaaaa": IN_A, "bbbbbbbbbbbb": IN_B}
    assert not [p for p in cfg.problems() if "INGEST" in p]
    assert IN_A not in repr(cfg) and IN_B not in repr(cfg)


def test_a_single_ingest_key_serves_a_single_tenant_gateway() -> None:
    cfg = GatewayConfig(tenant_keys=(GW_A,), ingest_key=IN_A)
    assert cfg.ingest_routes() == {"aaaaaaaaaaaa": IN_A}
    assert not [p for p in cfg.problems() if "INGEST" in p]


def test_one_ingest_key_for_several_tenants_routes_only_the_first() -> None:
    cfg = GatewayConfig(tenant_keys=(GW_A, GW_B), ingest_key=IN_A)
    assert cfg.ingest_routes() == {"aaaaaaaaaaaa": IN_A}
    assert any("SIBYL_INGEST_KEYS" in p and "dropped" in p for p in cfg.problems())


def test_mismatched_ingest_key_count_is_a_problem_and_never_shifts_keys() -> None:
    cfg = GatewayConfig(tenant_keys=(GW_A, GW_B), ingest_keys=(IN_A,))
    assert cfg.ingest_routes() == {"aaaaaaaaaaaa": IN_A}
    assert any("SIBYL_INGEST_KEYS" in p for p in cfg.problems())


def test_without_ingest_keys_each_tenant_posts_with_its_own_gateway_key() -> None:
    cfg = GatewayConfig(tenant_keys=(GW_A, GW_B))
    assert cfg.ingest_routes() == {"aaaaaaaaaaaa": GW_A, "bbbbbbbbbbbb": GW_B}


# ---- routing a tenant to its key ------------------------------------------------------------


class Doc:
    def __init__(self, *tenants: str) -> None:
        self.tenants = frozenset(UUID(t) for t in tenants)


class Store:
    def __init__(self, docs: dict[str, Doc]) -> None:
        self.docs = docs

    def documents(self) -> dict[str, Doc]:
        return self.docs


def test_router_follows_the_verified_snapshot_that_carries_the_tenant() -> None:
    store = Store({"aaaaaaaaaaaa": Doc(A), "bbbbbbbbbbbb": Doc(B)})
    route = ingest_router(store, {"aaaaaaaaaaaa": IN_A, "bbbbbbbbbbbb": IN_B})
    assert route(A) == IN_A and route(B) == IN_B
    assert route(C) is None and route(None) is None and route("not-a-uuid") is None


# ---- sink and queue -------------------------------------------------------------------------


async def test_a_mixed_batch_is_posted_per_tenant_with_each_tenants_key() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(202)

    keys = {A: IN_A, B: IN_B}
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        queue = TelemetryQueue(HttpIngestSink("http://ingest/", keys.get, client), max_retries=3)
        for i, tenant in enumerate([A, B, A, C, B]):
            queue.offer(ev(tenant, i))
        await queue.flush()
    posted = {
        r.headers["authorization"]: [e["n"] for e in json.loads(r.content)["events"]] for r in seen
    }
    assert posted == {f"Bearer {IN_A}": [0, 2], f"Bearer {IN_B}": [1, 4]}
    # tenant C has no key: dropped and counted, never retried, never sent with A's or B's key
    assert queue.stats.sent == 4 and queue.stats.dropped == 1 and queue.stats.unroutable == 1
    assert queue.stats.failed_batches == 0


async def test_unroutable_tenant_raises_from_the_sink() -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(202))) as c:
        sink = HttpIngestSink("http://ingest/", {A: IN_A}.get, c)
        with pytest.raises(UnroutableTelemetry):
            await sink([ev(B, 1)])
        assert IN_A not in repr(sink)
