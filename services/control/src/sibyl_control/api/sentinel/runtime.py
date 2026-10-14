"""Plumbing shared by the Sentinel routes: the LLM client for the request's tenant and a write
runner that makes the model call *after* the Idempotency-Key claim and *outside* the database
transaction.

``run_after_claim`` is ``registry._kit.run_write(idempotent=True)`` with a prelude: claim the
key (a replay returns the stored response without calling the model again), run the prelude
(the model call, no transaction held), then the write transaction (audit lock, rows, audit,
idempotency record). Any failure abandons the claim.

Tests and demos substitute the network by putting a ``sentinel_transport`` factory
(``EgressPolicy -> httpx transport``) and optional ``sentinel_client_kw`` in the app's lane state.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from fastapi.responses import Response

from ...core.idempotency import (
    IDEMPOTENCY_HEADER,
    REPLAY_HEADER,
    PgIdempotencyStore,
    Replay,
    begin_or_raise,
    require_key,
)
from ...core.llm import LlmClient, LlmError
from ...core.problems import ProblemError
from ...worker.sentinel.config import (
    KeyUnavailable,
    SentinelConfig,
    build_client,
    egress_policy,
    load_config,
    open_key,
)
from ...worker.sentinel.content import payload_reader
from ...worker.sentinel.gather import ContentReader
from ..auth.common import lane_state
from ..auth.runtime import kek_for
from ..deps import AuthContext, idempotency_fingerprint, idempotency_principal_kind
from ..reads.payloads import blob_store
from ..registry._kit import Outcome, _execute, _replayed, _stored, require_db, services_of


@dataclass(frozen=True)
class Session:
    cfg: SentinelConfig
    client: LlmClient


def _state(ctx: AuthContext) -> dict[str, Any]:
    assert ctx.request is not None
    return lane_state(ctx.request)


def content_reader(ctx: AuthContext) -> ContentReader:
    request = ctx.request
    assert request is not None
    return payload_reader(lambda: blob_store(request), kek_for(request))


async def open_session(conn: Any, ctx: AuthContext, *, require_enabled: bool) -> Session:
    """Config + client for the tenant; 409 ``not_active`` when Sentinel cannot run."""
    cfg = await load_config(conn, ctx.tenant_id)
    if cfg is None or not cfg.has_key:
        raise ProblemError("not_active", "Sentinel is not configured with an API key")
    if require_enabled and not cfg.enabled:
        raise ProblemError("not_active", "Sentinel is not enabled for this tenant")
    assert ctx.request is not None
    try:
        api_key = await open_key(conn, kek_for(ctx.request), ctx.tenant_id)
    except KeyUnavailable:
        raise ProblemError(
            "service_unavailable", "the vaulted Sentinel key cannot be opened"
        ) from None
    policy = await egress_policy(conn, services_of(ctx).settings)
    state = _state(ctx)
    try:
        client = build_client(
            cfg,
            api_key,
            policy,
            state.get("sentinel_transport"),
            **dict(state.get("sentinel_client_kw") or {}),
        )
    except LlmError as exc:
        raise ProblemError("service_unavailable", f"Sentinel client refused: {exc.code}") from None
    finally:
        del api_key
    return Session(cfg, client)


async def run_after_claim[T](
    ctx: AuthContext,
    prelude: Callable[[], Awaitable[T]],
    work: Callable[[Any, T], Awaitable[Outcome]],
) -> Response:
    services = services_of(ctx)
    db = require_db(services)
    request = ctx.request
    principal = ctx.principal
    assert request is not None and principal is not None
    key = require_key(request.headers.get(IDEMPOTENCY_HEADER))
    store = services.idempotency
    if store is None:
        raise ProblemError("service_unavailable", "idempotency store not configured")
    claim = await begin_or_raise(
        store,
        ctx.tenant_id,
        principal.id,
        f"{request.method} {request.url.path}",
        key,
        idempotency_fingerprint(request, await request.body()),
        principal_kind=idempotency_principal_kind(principal),
    )
    if isinstance(claim, Replay):
        _replayed(ctx)
        stored = claim.response
        return Response(
            stored.body,
            status_code=stored.status,
            headers={**stored.headers, REPLAY_HEADER: "true"},
        )
    token = claim.token
    try:
        prepared = await prelude()

        async def body(conn: Any) -> Outcome:
            return await work(conn, prepared)

        result = await _execute(db, ctx, body, store, token)
    except BaseException:
        await store.abandon(token)
        raise
    response = result.to_response()
    if not isinstance(store, PgIdempotencyStore):
        await store.complete(token, _stored(result, response))
    return response
