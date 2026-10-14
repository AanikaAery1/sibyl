"""Key-set chain across rotations (B10), on its own throw-away database.

A gateway ``KeyChain`` pinned to the genesis key follows ``GET /api/v1/policy/keys?since=0``
through a pre-published rotation and through an unannounced one (the service issues the
announcement itself), and verifies snapshots signed by the new key, while a snapshot signed by
the outgoing key still verifies during the overlap. Without ``since`` the route serves only the
latest set; with no usable private key for the signer the chain needs, nothing is fabricated.
"""

from __future__ import annotations

import asyncio
import json
import secrets
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import asyncpg
import httpx
import pytest
from sibyl_control.api.app import create_app
from sibyl_control.api.deps import Services, StaticTokenResolver
from sibyl_control.api.snapshot import SnapshotService, router
from sibyl_control.api.snapshot.keys import SignerResolver
from sibyl_control.core.crypto.signing import Ed25519Signer
from sibyl_control.core.db import Database
from sibyl_control.migrate.config import ConnSpec, MigrateConfig
from sibyl_control.migrate.runner import apply
from sibyl_gateway.policy.keychain import KeyChain

from .conftest import ADMIN_DSN, Unlimited, _admin, _dsn

KEYS = "/api/v1/policy/keys"


@dataclass
class Rig:
    db_name: str
    seeds: dict[str, bytes]


@pytest.fixture(scope="module")
def rig() -> Iterator[Rig]:
    name = f"sibyl_g_rot_{secrets.token_hex(5)}"
    try:
        asyncio.run(_admin(f'CREATE DATABASE "{name}"'))
    except (OSError, asyncpg.PostgresError):
        pytest.skip(f"PostgreSQL 17 not reachable at {ADMIN_DSN} (make db-up)")
    try:
        spec = ConnSpec(dsn=ADMIN_DSN, database=name)
        migrate = ConnSpec(dsn=ADMIN_DSN, user="sibyl_migrate", database=name)
        asyncio.run(apply(MigrateConfig(migrate=migrate, admin=spec)))
        yield Rig(name, {})
    finally:
        asyncio.run(_admin(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))


@dataclass
class Api:
    client: httpx.AsyncClient
    service: SnapshotService
    admin: asyncpg.Connection
    rig: Rig

    async def add_key(self, kid: str, state: str, **cols: object) -> Ed25519Signer:
        seed = secrets.token_bytes(32)
        self.rig.seeds[kid] = seed
        signer = Ed25519Signer.from_seed(kid, seed)
        await self.admin.execute(
            "INSERT INTO sibyl.signing_key (kid, purpose, public_key, private_key_ref, state,"
            " activated_at) VALUES ($1, 'snapshot', $2, $3, $4, now())",
            kid,
            signer.public_key_raw,
            f"env:SEED_{kid.upper().replace('-', '_')}",
            state,
        )
        return signer

    async def rotate(self, old: str, new: str) -> None:
        await self.admin.execute(
            "UPDATE sibyl.signing_key SET state = 'retiring',"
            " retiring_until = now() + interval '1 day' WHERE kid = $1",
            old,
        )
        await self.admin.execute(
            "UPDATE sibyl.signing_key SET state = 'active', activated_at = now() WHERE kid = $1",
            new,
        )

    async def chain(self, since: int = 0) -> dict:
        resp = await self.client.get(KEYS, params={"since": since})
        assert resp.status_code == 200, resp.text
        return json.loads(resp.content)

    async def latest(self) -> dict:
        resp = await self.client.get(KEYS)
        assert resp.status_code == 200, resp.text
        return json.loads(resp.content)


@pytest.fixture
async def api(rig: Rig) -> AsyncIterator[Api]:
    db = await Database.connect(_dsn(rig.db_name, "sibyl_app"), min_size=1, max_size=2)
    admin = await asyncpg.connect(_dsn(rig.db_name, None))
    environ = _Environ(rig)
    service = SnapshotService(db, resolver=SignerResolver(environ))
    services = Services(principals=StaticTokenResolver({}), db=db, rate_limiter=Unlimited())
    app = create_app(services, include=lambda a: a.include_router(router))
    app.state.snapshot_service = service
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://api") as client:
            yield Api(client, service, admin, rig)
    finally:
        await admin.close()
        await db.close()


class _Environ(dict):  # type: ignore[type-arg]
    """``env:SEED_<KID>`` lookups served from the rig's seeds (hex)."""

    def __init__(self, rig: Rig) -> None:
        super().__init__()
        self._rig = rig

    def _kid(self, name: str) -> str | None:
        for kid in self._rig.seeds:
            if name == f"SEED_{kid.upper().replace('-', '_')}":
                return kid
        return None

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and self._kid(name) is not None

    def __getitem__(self, name: str) -> str:
        kid = self._kid(name)
        if kid is None:
            raise KeyError(name)
        return self._rig.seeds[kid].hex()


def _follow(pin: dict, documents: list[dict], now: datetime) -> KeyChain:
    chain = KeyChain.from_pin_json(json.dumps(pin))
    for doc in documents:
        chain.accept(json.dumps(doc), now=now, persist=False)
    return chain


async def test_genesis_is_self_signed_and_stable(api: Api) -> None:
    await api.add_key("k1", "active")
    first = await api.latest()
    assert first["kid"] == "k1" and first["body"]["sequence"] == 1
    assert first["body"]["next_key"] is None
    assert await api.latest() == first  # nothing changed: no new set
    page = await api.chain(0)
    assert page == {"data": [first], "latest_sequence": 1}
    assert (await api.chain(1))["data"] == []


async def test_pre_published_rotation_is_followed_from_the_pin(api: Api) -> None:
    genesis = (await api.chain(0))["data"][0]
    pin = genesis["body"]["keys"][0]
    k2 = await api.add_key("k2", "next")
    announced = await api.latest()
    assert announced["kid"] == "k1" and announced["body"]["next_key"]["kid"] == "k2"
    await api.rotate("k1", "k2")
    rotated = await api.latest()
    assert rotated["kid"] == "k1"  # signed by the previous set's active key
    assert [(k["kid"], k.get("status")) for k in rotated["body"]["keys"]] == [
        ("k2", "active"),
        ("k1", "retiring"),
    ]
    now = datetime.now(UTC)
    chain = _follow(pin, (await api.chain(0))["data"], now)
    assert chain.sequence == rotated["body"]["sequence"]
    # snapshots signed by the new key verify; so do k1's during the overlap, not after it
    keys = chain.verification_keys(now)
    assert "k2" in keys and "k1" in keys
    assert "k1" not in chain.verification_keys(now + timedelta(days=2))
    assert k2.kid == "k2"


async def test_an_unannounced_rotation_is_announced_by_the_service(api: Api) -> None:
    before = (await api.latest())["body"]["sequence"]
    current = next(
        k["kid"] for k in (await api.latest())["body"]["keys"] if k["status"] == "active"
    )
    await api.add_key("k3", "retired")  # inserted, then activated without a `next` phase
    await api.admin.execute("UPDATE sibyl.signing_key SET state = 'retired' WHERE kid = 'k1'")
    await api.rotate(current, "k3")
    page = await api.chain(before)
    assert [d["body"]["sequence"] for d in page["data"]] == [before + 1, before + 2]
    announce, rotation = page["data"]
    assert announce["kid"] == current and announce["body"]["next_key"]["kid"] == "k3"
    assert rotation["kid"] == current
    assert rotation["body"]["keys"][0]["kid"] == "k3"
    genesis = (await api.chain(0))["data"][0]
    chain = _follow(genesis["body"]["keys"][0], (await api.chain(0))["data"], datetime.now(UTC))
    assert chain.sequence == page["latest_sequence"]


async def test_no_set_is_fabricated_without_the_chain_signer(api: Api) -> None:
    latest = await api.latest()
    active = next(k["kid"] for k in latest["body"]["keys"] if k["status"] == "active")
    await api.add_key("k4", "retired")
    api.rig.seeds.pop(active)  # the chain's signer loses its private key
    try:
        await api.rotate(active, "k4")
        assert await api.latest() == latest
        assert (await api.chain(latest["body"]["sequence"]))["data"] == []
    finally:
        await api.admin.execute("UPDATE sibyl.signing_key SET state = 'retired' WHERE kid = 'k4'")


async def test_since_is_validated(api: Api) -> None:
    assert (await api.client.get(KEYS, params={"since": -1})).status_code == 422
    assert (await api.client.get(KEYS, params={"since": "x"})).status_code == 422
