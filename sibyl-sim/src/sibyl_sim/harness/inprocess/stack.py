"""The in-process stack: every product service on an ephemeral localhost port, one event loop.

    doubles (https, fixed port: the seeded base URLs name it) + sim control (http)
    api      (sibyl_app pool)      FastAPI app from `create_app`, persona tokens chained
    ingest   (sibyl_ingest pool)   `assemble()` + `create_app()`, plus the call_merge flusher
    worker   (sibyl_worker pool)   the product `LoopRunner` over `LOOPS`
    gateway                         `build_gateway()`: signed snapshots from the api, events
                                    to ingest, upstream to the doubles through the dev CA

Each run gets a fresh clone of the template database, dropped at `stop()`. Nothing here is
reachable from outside 127.0.0.1. Actors and the oracle receive only `Endpoints` + `World`.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import shutil
import socket
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import asyncpg
import uvicorn
from pydantic import SecretStr
from sibyl_control.core.blob.fs import FsBlobStore
from sibyl_control.core.db import Database
from sibyl_control.ingest.app import assemble
from sibyl_control.ingest.app import create_app as create_ingest_app
from sibyl_control.ingest.flusher import run_flusher
from sibyl_control.worker.loops import LoopContext
from sibyl_control.worker.main import LoopRunner
from sibyl_gateway.config import GatewayConfig
from sibyl_gateway.runtime import build_gateway

from ...doubles import tls
from ...doubles.app import control_app, doubles_app
from ...doubles.state import SimState, build_state
from ..world import Endpoints, World
from . import database as pg
from . import sessions
from .build import DEFAULT_DOUBLES_PORT, SIM_HOST, ensure_template, pinned_key_json, sdk_pin
from .control import build_api_app, control_settings
from .loops import HarnessWorkerSettings, SwitchableLimiter, harness_specs
from .secrets import DEV_SECRETS

log = logging.getLogger("sibyl_sim.harness")
STARTUP_TIMEOUT_S = 30.0
CONNECTIONS_PER_STACK = 12  # api 4 + ingest 4 + worker 3 + the SSE LISTEN hub


# B38: the oldest event beyond each tenant's rollup cursor (the rollup reads below the cluster's
# commit horizon, R60, so open transactions elsewhere on the cluster stall it).
_DATA_LAG_SQL = """
SELECT coalesce(max(extract(epoch FROM now() - u.oldest)), 0)
  FROM sibyl.consumer_offsets o
 CROSS JOIN LATERAL (
   SELECT min(e.received_at) AS oldest FROM sibyl.events e
    WHERE e.tenant_id = o.tenant_id AND (e.xid, e.event_id) > (o.last_xid, o.last_id)) u
 WHERE o.consumer_group = 'rollup' AND o.topic = 'events'
"""
START_ATTEMPTS = 4
START_WAIT_S = 20.0


async def start_with_retry(
    stack: Any, *, attempts: int = START_ATTEMPTS, wait_s: float = START_WAIT_S
) -> Any:
    """``stack.start()``, waiting out a cluster with no connection slots left (the dev cluster's
    ``max_connections`` is shared with every lane's CI); any other failure is raised at once.
    A failed start has already stopped itself (``InProcessStack.start``)."""
    for attempt in range(1, attempts + 1):
        try:
            return await stack.start()
        except asyncpg.TooManyConnectionsError:
            if attempt == attempts:
                raise
            log.warning("no Postgres connection slots; retrying the stack in %.0f s", wait_s)
            await asyncio.sleep(wait_s)
    raise AssertionError("unreachable")  # pragma: no cover


@dataclass(frozen=True)
class StackOptions:
    doubles_port: int = DEFAULT_DOUBLES_PORT
    sim_seed: int = 1
    eval_tick_s: float | None = None  # dev-only SIBYL_EVAL_TICK_S equivalent (R45)
    status_poll_s: float | None = None
    gateway_poll_s: float = 5.0
    gateway: Literal["shared", "per_tenant"] = "shared"
    keep_db: bool = False
    drift: Mapping[str, float] | None = None  # scaled DriftConfig for this run (S-31)


def _bind(port: int = 0) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((SIM_HOST, port))
    except OSError as exc:
        sock.close()
        raise RuntimeError(f"cannot bind {SIM_HOST}:{port} ({exc})") from None
    sock.listen(128)
    sock.setblocking(False)
    return sock


@dataclass
class _Served:
    name: str
    server: uvicorn.Server
    task: asyncio.Task[None]
    url: str


async def _serve(
    name: str, app: Any, sock: socket.socket, *, lifespan: str = "off", tls_: Any = None
) -> _Served:
    port = sock.getsockname()[1]
    config = uvicorn.Config(
        app,
        lifespan=lifespan,  # type: ignore[arg-type]
        log_level="warning",
        access_log=False,
        server_header=False,
        ssl_certfile=str(tls_.cert_path) if tls_ else None,
        ssl_keyfile=str(tls_.key_path) if tls_ else None,
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve(sockets=[sock]), name=f"sibyl-sim-{name}")
    loop = asyncio.get_running_loop()
    deadline = loop.time() + STARTUP_TIMEOUT_S
    while not server.started:
        if task.done():
            task.result()
            raise RuntimeError(f"{name} exited during startup")
        if loop.time() > deadline:
            raise RuntimeError(f"{name} did not start within {STARTUP_TIMEOUT_S} s")
        await asyncio.sleep(0.02)
    scheme = "https" if tls_ else "http"
    return _Served(name, server, task, f"{scheme}://{SIM_HOST}:{port}")


@dataclass
class InProcessStack:
    options: StackOptions = field(default_factory=StackOptions)
    world: World | None = None
    endpoints: Endpoints | None = None
    sim: SimState | None = None
    limiter: SwitchableLimiter = field(default_factory=SwitchableLimiter)
    database: str = ""
    _served: list[_Served] = field(default_factory=list)
    _pools: list[Database] = field(default_factory=list)
    _tasks: list[asyncio.Task[Any]] = field(default_factory=list)
    _stop: asyncio.Event = field(default_factory=asyncio.Event)
    _tmp: Path | None = None
    runner: LoopRunner | None = None
    gateways: list[Any] = field(default_factory=list)
    _api_app: Any = None
    _probe: Any = None  # B38: one read-only admin connection for the data-lag probe

    # ------------------------------------------------------------------ lifecycle

    async def start(self) -> InProcessStack:
        if not await pg.available():
            raise RuntimeError(f"PostgreSQL not reachable at {pg.admin_dsn()} (make db-up)")
        opts = self.options
        # a retried start (start_with_retry) begins from a clean lifecycle
        self._stop, self.gateways, self.runner = asyncio.Event(), [], None
        world = await ensure_template(doubles_port=opts.doubles_port)
        self.database = await pg.clone(world.template)
        self._tmp = Path(tempfile.mkdtemp(prefix="sibyl-sim-run-"))
        try:
            await self._boot(world)
        except BaseException:
            await self.stop()
            raise
        return self

    async def _boot(self, world: World) -> None:
        assert self._tmp is not None
        opts, secrets_ = self.options, DEV_SECRETS
        dsns = pg.RoleDsns.for_database(self.database)
        certs = tls.generate(self._tmp / "tls", tls.DEFAULT_HOSTS)
        self.sim = build_state(seed=opts.sim_seed, admin_token="")
        self.sim.ca_path = str(certs.ca_path)
        doubles = await _serve(
            "doubles", doubles_app(self.sim), _bind(opts.doubles_port), tls_=certs
        )
        sim_control = await _serve("sim-control", control_app(self.sim), _bind())
        self._served += [doubles, sim_control]

        settings = control_settings(dsns.app, secrets_, self._tmp / "blob")
        api_db = await self._pool(dsns.app, "sibyl-sim-api")
        world = await sessions.mint(dsns.admin, world)
        self._api_app = build_api_app(api_db, settings, secrets_, None)
        api = await _serve("api", self._api_app, _bind())
        ingest_db = await self._pool(dsns.ingest, "sibyl-sim-ingest")
        ingest_settings = control_settings(dsns.ingest, secrets_, self._tmp / "blob")
        assembled = assemble(
            ingest_db,
            ingest_settings,
            store=FsBlobStore(self._tmp / "blob"),
            limiter=self.limiter,
        )
        ingest = await _serve("ingest", create_ingest_app(assembled), _bind())
        self._served += [api, ingest]
        self._tasks.append(
            asyncio.create_task(run_flusher(ingest_db, assembled.cfg, self._stop), name="flusher")
        )
        await self._start_worker(dsns.worker, str(certs.ca_path))
        gateway = await self._start_gateways(world, api.url, ingest.url, str(certs.ca_path))
        self.world = world
        self.endpoints = Endpoints(
            api=api.url,
            ingest=ingest.url,
            gateway=gateway,
            sim_control=sim_control.url,
            doubles=doubles.url,
            ca_file=str(certs.ca_path),
            sdk_pin=sdk_pin(secrets_),
        )
        await self._wait_gateway_ready(gateway)

    async def _pool(self, dsn: str, name: str, max_size: int = 4) -> Database:
        """Small pools: the dev cluster (max_connections 100) is shared with every lane."""
        db = await Database.connect(dsn, min_size=1, max_size=max_size, application_name=name)
        self._pools.append(db)
        return db

    async def _start_worker(self, dsn: str, ca_file: str) -> None:
        opts = self.options
        db = await self._pool(dsn, "sibyl-sim-worker", max_size=3)
        assert self._tmp is not None
        ledger_key = self._tmp / "ledger-signing.key"
        ledger_key.write_bytes(DEV_SECRETS.ledger_seed)
        ledger_key.chmod(0o600)
        settings = HarnessWorkerSettings(
            pg_dsn=SecretStr(dsn),
            kek=SecretStr(DEV_SECRETS.kek_b64),
            kek_id=DEV_SECRETS.kek_id,
            key_pepper=SecretStr(DEV_SECRETS.pepper.hex()),
            scrub_salt=SecretStr(DEV_SECRETS.scrub_salt.hex()),
            subject_salt=SecretStr(DEV_SECRETS.subject_salt.hex()),
            anchor_signing_key=SecretStr(DEV_SECRETS.anchor_seed.hex()),
            ledger_signing_key_file=str(ledger_key),
            blob_root=str(self._tmp / "blob"),
            upstream_ca_file=ca_file,  # Sentinel's LLM calls reach sentinel-stub on the doubles
            sim_ca_file=ca_file,
            sim_dev_hosts=(SIM_HOST,),
            sim_drift=dict(opts.drift) if opts.drift else None,
        )
        wlog = logging.getLogger("sibyl.worker")
        specs = harness_specs(
            eval_tick_s=opts.eval_tick_s, status_poll_s=opts.status_poll_s, drift=opts.drift
        )
        self.runner = LoopRunner(specs, lambda spec: LoopContext(spec.name, db, settings, wlog))
        self._tasks.append(asyncio.create_task(self.runner.run(self._stop), name="worker"))

    async def _start_gateways(self, world: World, api: str, ingest: str, ca: str) -> str:
        assert self._tmp is not None
        chaos = [t for t in world.tenants.values() if t.gateway_key]
        groups = [chaos] if self.options.gateway == "shared" else [[t] for t in chaos]
        urls: list[str] = []
        for n, group in enumerate(groups):
            config = GatewayConfig(
                gateway_id=f"sim-gw-{n}",
                env="live",
                control_url=api,
                ingest_url=ingest,
                tenant_keys=tuple(t.gateway_key for t in group),
                # B-03: one ingest key per fronted tenant, paired with its gateway key
                # (SIBYL_INGEST_KEYS), so every tenant's telemetry is filed in its own tenant;
                # S-21/S-22 keep probing that isolation through the shared gateway.
                ingest_keys=tuple(t.ingest_key for t in group),
                pepper=DEV_SECRETS.pepper,
                pinned_key_json=pinned_key_json(DEV_SECRETS),
                snapshot_dir=self._tmp / f"gw-{n}",
                scrub_salt=DEV_SECRETS.scrub_salt.hex().encode(),
                dev_hosts=(SIM_HOST,),
                poll_s=self.options.gateway_poll_s,
                upstream_ca_file=ca,
            )
            (self._tmp / f"gw-{n}").mkdir(exist_ok=True)
            app = build_gateway(config)
            self.gateways.append(app)
            served = await _serve(f"gateway-{n}", app, _bind(), lifespan="on")
            self._served.append(served)
            urls.append(served.url)
        return urls[0]

    async def _wait_gateway_ready(self, url: str) -> None:
        import httpx

        loop = asyncio.get_running_loop()
        deadline = loop.time() + STARTUP_TIMEOUT_S
        async with httpx.AsyncClient(trust_env=False) as client:
            while True:
                with contextlib.suppress(httpx.HTTPError):
                    if (await client.get(f"{url}/readyz")).status_code == 200:
                        return
                if loop.time() > deadline:
                    raise RuntimeError("gateway never received a verified snapshot")
                await asyncio.sleep(0.25)

    async def stop(self) -> None:
        self._stop.set()
        for served in reversed(self._served):
            served.server.should_exit = True
        for served in reversed(self._served):
            with contextlib.suppress(Exception):
                await asyncio.wait_for(served.task, 10)
        for task in self._tasks:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(task, 15)
        await self._stop_sse_hub()
        probe, self._probe = self._probe, None
        if probe is not None:
            with contextlib.suppress(Exception):
                await probe.close()
        for db in self._pools:
            with contextlib.suppress(Exception):
                await db.close()
        self._served, self._tasks, self._pools = [], [], []
        if self.database and not self.options.keep_db:
            with contextlib.suppress(Exception):
                await pg.drop(self.database)
        if self._tmp is not None:
            shutil.rmtree(self._tmp, ignore_errors=True)

    async def _stop_sse_hub(self) -> None:
        """The api's LISTEN hub is lazy and has no lifespan here (`build_app` stops it)."""
        from sibyl_control.api.auth.common import LANE_STATE

        lane = getattr(getattr(self._api_app, "state", None), LANE_STATE, None) or {}
        hub = lane.get("sse_hub")
        if hub is not None:
            with contextlib.suppress(Exception):
                await hub.stop()

    # ------------------------------------------------------------------ harness-side chaos

    def pause_ingest(self, tenant_id: str, seconds: float) -> None:
        """S-19: ingest's own backpressure answers `tenant_rate_limit` for `seconds`."""
        self.limiter.pause(tenant_id, datetime.now(UTC) + timedelta(seconds=seconds))

    def resume_ingest(self, tenant_id: str) -> None:
        self.limiter.resume(tenant_id)

    def loop_status(self) -> dict[str, Any]:
        return self.runner.status() if self.runner else {}

    async def data_lag_s(self) -> float | None:
        """B38: age in seconds of the oldest committed event the rollup has not read yet,
        across tenants (0 when it is caught up). A read of the product's own cursor and events,
        as the cluster admin; nothing is written."""
        if not self.database:
            return None
        if self._probe is None:
            self._probe = await asyncpg.connect(
                pg.dsn_for(self.database), server_settings={"application_name": "sibyl-sim-lag"}
            )
        value = await self._probe.fetchval(_DATA_LAG_SQL)
        return float(value or 0.0)

    def loop_intervals(self) -> dict[str, float]:
        """Nominal interval of every worker loop (B38: the tick-lag meter's calibration)."""
        return {s.name: float(s.interval_s) for s in self.runner.specs} if self.runner else {}


__all__ = ["InProcessStack", "StackOptions", "replace"]
