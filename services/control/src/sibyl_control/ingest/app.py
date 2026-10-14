"""Ingest app (API.md §4): ``POST /v1/otlp/traces``, ``POST /v1/otlp/logs``, ``POST /v1/events``.

``create_app(services)`` builds a pure app; with no services every ingest route answers 503
(the contract-mount test imports it this way). ``build_app()`` is the process factory: settings
from the environment (``require_secrets("ingest")``), an asyncpg pool as ``sibyl_ingest``, the
BlobStore, the KEK-backed DEK provider and the ``call_merge`` flusher in the lifespan.
Only these three routes exist; ``GET`` on them is 405. No CORS.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import asyncpg
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from sibyl_schemas.scrub import SecretsScrubber

from ..api.deps import ApiKeyResolver, Services, pg_key_lookup, write_denial
from ..api.middleware import RequestContextMiddleware
from ..core.audit import PgAuditWriter
from ..core.authz import Principal
from ..core.blob.base import BlobStore
from ..core.crypto.deks import PgDekProvider
from ..core.crypto.envelope import LocalKek
from ..core.db import Database
from ..core.problems import ProblemError, install_problem_handlers
from ..core.ratelimit import InMemoryRateLimiter
from ..core.settings import Settings
from . import otlp
from .backpressure import Backpressure
from .body import check_declared_length, inflate, read_capped
from .config import (
    AGENT_HEADER,
    BATCH_ID_HEADER,
    CAPTURE_OWNER_HEADER,
    REPLAYED_HEADER,
    SCHEMA_HEADER,
    IngestConfig,
)
from .flusher import run_flusher
from .normalise.fields import as_uuid
from .normalise.logs import log_candidate
from .normalise.scrubbing import Scrubber
from .normalise.semconv import span_candidate
from .normalise.wire_events import event_candidate, parse_batch
from .payloads import PayloadSealer
from .service import BatchRequest, IngestPrincipal, IngestService, events_response, otlp_partial

INGEST_VERSION = "v1.0"
INGEST_SCOPE = "ingest:write"
HANDOFF_SCOPE = "handoff:write"


@dataclass
class IngestServices:
    service: IngestService | None = None
    resolver: Any = None
    kernel: Services = field(default_factory=Services)
    db: Database | None = None
    cfg: IngestConfig = field(default_factory=IngestConfig)


def _state(request: Request) -> IngestServices:
    services: IngestServices = request.app.state.ingest
    return services


async def _principal(
    request: Request, services: IngestServices
) -> tuple[IngestPrincipal, Principal]:
    if services.resolver is None:
        raise ProblemError("database_unavailable", "ingest is not configured")
    principal: Principal | None = await services.resolver.resolve(request)
    if principal is None:
        raise ProblemError("unauthenticated")
    if not principal.has(INGEST_SCOPE):
        await write_denial(services.kernel, request, principal, INGEST_SCOPE)
        raise ProblemError("forbidden", "the key lacks ingest:write")
    record_env = getattr(request.state, "key_env", None)
    settings = services.kernel.settings
    env = record_env or (settings.env if settings else "live")
    return (
        IngestPrincipal(
            principal.tenant_id, principal.id, env, principal.scopes, principal.bound_agent_id
        ),
        principal,
    )


def _batch_id(request: Request) -> str | None:
    raw = request.headers.get(BATCH_ID_HEADER)
    if raw is None:
        return None
    value = as_uuid(raw.strip())
    if value is None or value[14] != "7":
        raise ProblemError("validation_failed", "X-Sibyl-Batch-Id must be a UUIDv7")
    return value


async def _body(request: Request, cfg: IngestConfig) -> bytes:
    check_declared_length(request.headers.get("content-length"), cfg)
    raw = await read_capped(request.stream(), cfg.max_body_bytes)
    return inflate(raw, request.headers.get("content-encoding"), cfg)


_DB_DOWN = (
    OSError,
    ConnectionError,
    asyncpg.exceptions.ConnectionDoesNotExistError,
    asyncpg.exceptions.CannotConnectNowError,
    asyncpg.exceptions.TooManyConnectionsError,
    asyncpg.exceptions.InterfaceError,
)


async def _run(
    request: Request,
    route: str,
    build: Callable[[IngestPrincipal, bytes], tuple[list[Any], tuple[str, ...]]],
) -> tuple[Any, IngestPrincipal]:
    try:
        return await _run_inner(request, route, build)
    except _DB_DOWN as exc:
        retry = _state(request).cfg.db_retry_after_s
        raise ProblemError(
            "database_unavailable",
            f"database unreachable ({type(exc).__name__})",
            extensions={"retry_after_s": retry},
            headers={"Retry-After": str(retry)},
        ) from None


async def _run_inner(
    request: Request,
    route: str,
    build: Callable[[IngestPrincipal, bytes], tuple[list[Any], tuple[str, ...]]],
) -> tuple[Any, IngestPrincipal]:
    services = _state(request)
    if services.service is None:
        raise ProblemError("database_unavailable", "ingest is not configured")
    principal, kernel_principal = await _principal(request, services)
    await services.service.bp.key(principal.key_id)
    body = await _body(request, services.cfg)
    candidates, warnings = build(principal, body)
    if (
        any(c.event is not None and c.event.get("type") == "handoff.requested" for c in candidates)
        and HANDOFF_SCOPE not in principal.scopes
    ):
        await write_denial(services.kernel, request, kernel_principal, HANDOFF_SCOPE)
        raise ProblemError("forbidden", "handoff.requested events need handoff:write")
    req = BatchRequest(
        route=route,
        principal=principal,
        candidates=candidates,
        batch_id=_batch_id(request),
        agent_header=(request.headers.get(AGENT_HEADER) or "").strip()[:200] or None,
        capture_owner=request.headers.get(CAPTURE_OWNER_HEADER),
        request_id=_request_uuid(request),
        decode_warnings=warnings,
    )
    try:
        outcome = await services.service.ingest(req)
    except ProblemError as exc:
        if exc.audit_denied:
            await write_denial(services.kernel, request, kernel_principal, INGEST_SCOPE)
        raise
    return outcome, principal


def _request_uuid(request: Request) -> UUID | None:
    value = getattr(request.state, "request_id", None)
    parsed = as_uuid(value) if value else None
    return UUID(parsed) if parsed else None


def _decode_errors(exc: otlp.OtlpDecodeError) -> ProblemError:
    if isinstance(exc, otlp.TooManyItems):
        return ProblemError("batch_too_large", str(exc))
    if "content type" in str(exc):
        return ProblemError("unsupported_media_type", str(exc))
    return ProblemError("validation_failed", str(exc)[:300])


def _otlp_response(request: Request, outcome: Any, encode: Callable[..., bytes]) -> Response:
    protobuf = otlp.media_type(request.headers.get("content-type")) == otlp.PROTOBUF
    rejected, message = otlp_partial(outcome)
    body = encode(rejected, message, protobuf=protobuf)
    headers = {REPLAYED_HEADER: "true"} if outcome.replayed else {}
    return Response(
        body, status_code=200, media_type=otlp.PROTOBUF if protobuf else otlp.JSON, headers=headers
    )


def _routes(app: FastAPI) -> None:
    @app.post("/v1/otlp/traces", operation_id="ingestOtlpTraces")
    async def ingest_traces(request: Request) -> Response:
        def build(principal: IngestPrincipal, body: bytes) -> tuple[list[Any], tuple[str, ...]]:
            try:
                batch = otlp.decode_traces(
                    body,
                    content_type=request.headers.get("content-type"),
                    max_items=_state(request).cfg.max_spans,
                )
            except otlp.OtlpDecodeError as exc:
                raise _decode_errors(exc) from None
            out, index = [], 0
            for rs in batch.resources:
                for ss in rs.scopes:
                    for span in ss.spans:
                        out.append(
                            span_candidate(
                                index,
                                principal.tenant_id,
                                span,
                                ss.scope,
                                rs.resource,
                                ss.schema_url or rs.schema_url,
                            )
                        )
                        index += 1
            return out, batch.warnings

        outcome, _ = await _run(request, "traces", build)
        return _otlp_response(request, outcome, otlp.encode_traces_response)

    @app.post("/v1/otlp/logs", operation_id="ingestOtlpLogs")
    async def ingest_logs(request: Request) -> Response:
        def build(principal: IngestPrincipal, body: bytes) -> tuple[list[Any], tuple[str, ...]]:
            try:
                batch = otlp.decode_logs(
                    body,
                    content_type=request.headers.get("content-type"),
                    max_items=_state(request).cfg.max_log_records,
                )
            except otlp.OtlpDecodeError as exc:
                raise _decode_errors(exc) from None
            out, index = [], 0
            for rl in batch.resources:
                for sl in rl.scopes:
                    for record in sl.records:
                        out.append(
                            log_candidate(index, principal.tenant_id, record, sl.scope, rl.resource)
                        )
                        index += 1
            return out, batch.warnings

        outcome, _ = await _run(request, "logs", build)
        return _otlp_response(request, outcome, otlp.encode_logs_response)

    @app.post("/v1/events", operation_id="ingestEvents", status_code=202)
    async def ingest_events(request: Request) -> JSONResponse:
        content_type = (request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ProblemError("unsupported_media_type", "POST /v1/events takes application/json")

        def build(principal: IngestPrincipal, body: bytes) -> tuple[list[Any], tuple[str, ...]]:
            elements = parse_batch(body, request.headers.get(SCHEMA_HEADER), _state(request).cfg)
            return [event_candidate(i, e, principal.tenant_id) for i, e in enumerate(elements)], ()

        outcome, _ = await _run(request, "events", build)
        headers = {REPLAYED_HEADER: "true"} if outcome.replayed else {}
        return JSONResponse(events_response(outcome), status_code=202, headers=headers)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    async def readyz(request: Request) -> dict[str, str]:
        db = _state(request).db
        if db is None:
            raise ProblemError("database_unavailable", "no database configured")
        try:
            await db.ping()
        except Exception:
            raise ProblemError("database_unavailable") from None
        return {"status": "ready"}


def create_app(services: IngestServices | None = None, *, lifespan: Any = None) -> FastAPI:
    app = FastAPI(
        title="Sibyl Ingest",
        version=INGEST_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.ingest = services or IngestServices()
    install_problem_handlers(app)
    _routes(app)
    app.add_middleware(RequestContextMiddleware, api_version=INGEST_VERSION)
    return app


class _EnvRecordingResolver:
    """Wraps the kernel resolver; remembers the key's env (``sbl_<env>_…``) for env checks."""

    def __init__(self, inner: ApiKeyResolver) -> None:
        self._inner = inner

    async def resolve(self, request: Request) -> Principal | None:
        principal = await self._inner.resolve(request)
        header = request.headers.get("authorization", "")
        token = header.partition(" ")[2].strip()
        if principal is not None and token.startswith("sbl_"):
            request.state.key_env = token.split("_", 2)[1]
        return principal


def _blob_store(settings: Settings) -> BlobStore:
    if settings.blob_backend == "s3":
        from ..core.blob.s3 import S3BlobStore, S3Config

        return S3BlobStore(S3Config.from_env())
    from ..core.blob.fs import FsBlobStore

    return FsBlobStore(settings.blob_root)


def _scrub_salt(settings: Settings) -> bytes:
    assert settings.scrub_salt is not None
    value = settings.scrub_salt.get_secret_value()
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raw = value.encode()
    return raw


def assemble(
    db: Database,
    settings: Settings,
    *,
    store: BlobStore | None = None,
    cfg: IngestConfig | None = None,
    limiter: Any = None,
) -> IngestServices:
    """Wire the services for a connected pool (used by ``build_app`` and the tests)."""
    cfg = cfg or IngestConfig()
    assert settings.kek is not None
    kek = LocalKek.from_env(settings.kek_id, settings.kek.get_secret_value())
    deks = PgDekProvider(db, kek, ttl_s=cfg.dek_cache_ttl_s)
    salt = _scrub_salt(settings)
    scrubber = Scrubber(SecretsScrubber(salt), salt)
    sealer = PayloadSealer(store or _blob_store(settings), deks)
    service = IngestService(
        db, sealer, deks, scrubber, Backpressure(limiter or InMemoryRateLimiter(), cfg), cfg
    )
    resolver = _EnvRecordingResolver(
        ApiKeyResolver(pg_key_lookup(db), settings.pepper(), expected_env=settings.env)
    )
    kernel = Services(db=db, audit=PgAuditWriter(), settings=settings)
    return IngestServices(service=service, resolver=resolver, kernel=kernel, db=db, cfg=cfg)


def build_app(settings: Settings | None = None) -> FastAPI:
    """Production factory (``uvicorn --factory sibyl_control.ingest.app:build_app``)."""
    settings = settings or Settings()
    settings.require_secrets("ingest")
    holder = IngestServices()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        db = await Database.connect(
            settings.dsn(),
            min_size=settings.db_pool_min,
            max_size=settings.db_pool_max,
            application_name="sibyl-ingest",
        )
        assembled = assemble(db, settings)
        app.state.ingest = assembled
        stop = asyncio.Event()
        flusher = asyncio.create_task(run_flusher(db, assembled.cfg, stop))
        try:
            yield
        finally:
            stop.set()
            await flusher
            await db.close()

    return create_app(holder, lifespan=lifespan)
