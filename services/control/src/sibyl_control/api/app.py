"""App factory for the control-plane api container. No lane edits this file (ROADMAP §4.1).

``create_app(services=...)`` builds a pure app (tests inject in-memory services).
``build_app()`` is the process entrypoint: settings from env, asyncpg pool opened in the lifespan,
API-key principals resolved via ``sibyl.api_key_lookup``; lane A chains its session/OIDC resolver
in front of the key resolver at G1.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from ..core.db import Database
from ..core.idempotency import PgIdempotencyStore
from ..core.problems import ProblemError, install_problem_handlers
from ..core.settings import Settings
from .contract import API_PREFIX, load_document
from .deps import Services
from .middleware import RequestContextMiddleware
from .routers import include_all

API_VERSION = "v1.0"  # v1.<migration>; the migrate lane stamps the migration number at G0
OPENAPI_URL = f"{API_PREFIX}/openapi.json"
INFRA_PATHS: frozenset[str] = frozenset({"/healthz", "/readyz", OPENAPI_URL})


def _infra_routes(app: FastAPI) -> None:
    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    async def readyz(request: Request) -> dict[str, str]:
        services: Services = request.app.state.services
        if services.db is None:
            raise ProblemError("database_unavailable", "no database configured")
        try:
            await services.db.ping()
        except Exception:
            raise ProblemError("database_unavailable") from None
        return {"status": "ready"}

    @app.get(OPENAPI_URL, include_in_schema=False)
    async def openapi_document() -> JSONResponse:
        return JSONResponse(load_document())


def create_app(
    services: Services | None = None,
    *,
    settings: Settings | None = None,
    lifespan: Any = None,
    include: Callable[[FastAPI], None] = include_all,
) -> FastAPI:
    """``include`` mounts the routers; tests pass a narrower one to exercise single handlers."""
    app = FastAPI(
        title="Sibyl Control Plane API",
        version=API_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.services = services or Services(settings=settings)
    install_problem_handlers(app)
    include(app)
    _infra_routes(app)
    origins = (settings.console_origins if settings else []) or []
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=[
                "authorization",
                "content-type",
                "idempotency-key",
                "if-match",
                "if-none-match",
                "x-request-id",
                "x-sibyl-tenant",
            ],
        )
    trusted = settings.trusted_networks() if settings else ()
    app.add_middleware(RequestContextMiddleware, api_version=API_VERSION, trusted_proxies=trusted)
    return app


def build_app(settings: Settings | None = None) -> FastAPI:
    """Production factory (``uvicorn --factory sibyl_control.api.app:build_app``)."""
    settings = settings or Settings()
    services = Services(settings=settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        settings.require_secrets("api")  # fail fast, before the pool opens
        db = await Database.connect(
            settings.dsn(),
            min_size=settings.db_pool_min,
            max_size=settings.db_pool_max,
            application_name="sibyl-api",
            command_timeout=settings.db_command_timeout_s,
        )
        services.db = db
        services.idempotency = PgIdempotencyStore(db)
        # API key -> console session -> OIDC bearer JWT (lane A); require_secrets guarantees the
        # pepper is present, so the chain is always the production one.
        from sibyl_control.api.auth.common import LANE_STATE
        from sibyl_control.api.auth.principals import build_principal_resolver

        services.principals = build_principal_resolver(services, settings)
        try:
            yield
        finally:
            lane = getattr(app.state, LANE_STATE, None) or {}
            hub = lane.get("sse_hub")
            if hub is not None:
                await hub.stop()
            await db.close()

    return create_app(services, settings=settings, lifespan=lifespan)
