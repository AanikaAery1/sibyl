"""snapshot API module (lane G): the gateway's control routes (API.md §5.13).

``GET /api/v1/policy/snapshot``     signed ``sibyl.policy_snapshot/1``, one tenant per key
``GET /api/v1/policy/credentials``  sealed vaulted credentials for that snapshot (D11)
``GET /api/v1/policy/keys``         signed key set (security M6); ``?since=n`` the chain after n
                                    (B10); the latest set is also at
``GET /.well-known/sibyl-keys.json``

Route-level authz comes from ``guard(operationId)``; the snapshot's ``bound_agent`` object rule
is evaluated through the guard context. None of these routes writes audit rows (contract
``x-sibyl-audit: never``). The ``SnapshotService`` lives on ``app.state.snapshot_service``
(tests inject one; production builds it lazily from ``Services``).
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import Response
from sibyl_schemas.canonical import canonicalize

from ...core.problems import ProblemError
from .._stubs import stub_router
from ..contract import API_PREFIX
from ..deps import AuthContext, get_services, guard
from .builder import GATEWAY_SCOPE, SnapshotScope
from .credentials import parse_ids
from .sealing import SEAL_HEADER, parse_seal_key
from .service import SnapshotService

__all__ = ["SnapshotService", "router"]

_router = APIRouter()
GZIP_MIN_BYTES = 1024
MAX_SEQUENCE = 9007199254740991


def snapshot_service(request: Request) -> SnapshotService:
    service: SnapshotService | None = getattr(request.app.state, "snapshot_service", None)
    if service is None:
        services = get_services(request)
        service = SnapshotService.from_settings(services.db, services.settings)
        if services.db is not None:
            request.app.state.snapshot_service = service
    return service


def _bound_agent(ctx: AuthContext) -> UUID | None:
    agent_filter = getattr(ctx, "agent_filter", None)  # contracts-v1.1 kernel marks the rule
    if callable(agent_filter):
        result: UUID | None = agent_filter()
        return result
    return ctx.principal.bound_agent_id if ctx.principal is not None else None


def _matches(if_none_match: str | None, version: int) -> bool:
    if not if_none_match:
        return False
    tags = {tag.strip().removeprefix("W/") for tag in if_none_match.split(",")}
    return f'"{version}"' in tags or "*" in tags


@_router.get(API_PREFIX + "/policy/snapshot", operation_id="getPolicySnapshot")
async def get_policy_snapshot(
    request: Request,
    ctx: Annotated[AuthContext, Depends(guard("getPolicySnapshot"))],
    agent_id: Annotated[UUID | None, Query()] = None,
    if_none_match: Annotated[str | None, Header()] = None,
    accept_encoding: Annotated[str | None, Header()] = None,
) -> Response:
    bound = _bound_agent(ctx)
    if agent_id is not None and bound is not None and agent_id != bound:
        raise ProblemError("not_found")
    principal = ctx.principal
    assert principal is not None
    scope = SnapshotScope(
        tenant_id=principal.tenant_id,
        agent_id=agent_id or bound,
        include_keys=GATEWAY_SCOPE in principal.scopes,
        require_agent=agent_id is not None,
    )
    issued = await snapshot_service(request).snapshot(scope)
    headers = {
        "ETag": f'"{issued.version}"',
        "X-Sibyl-Snapshot-Kid": issued.kid,
        "X-Sibyl-Snapshot-Signature": issued.signature,
        "X-Sibyl-Snapshot-Version": str(issued.version),
        "Cache-Control": "max-age=60",
        "Vary": "Accept-Encoding",
    }
    if _matches(if_none_match, issued.version):
        return Response(status_code=304, headers=headers)
    if "gzip" in (accept_encoding or "").lower() and len(issued.raw) > GZIP_MIN_BYTES:
        headers["Content-Encoding"] = "gzip"
        return Response(issued.gz, media_type="application/json", headers=headers)
    return Response(issued.raw, media_type="application/json", headers=headers)


@_router.get(API_PREFIX + "/policy/credentials", operation_id="getPolicyCredentials")
async def get_policy_credentials(
    request: Request,
    ctx: Annotated[AuthContext, Depends(guard("getPolicyCredentials"))],
    ids: Annotated[str, Query()],
) -> Response:
    principal = ctx.principal
    assert principal is not None
    seal_key = parse_seal_key(request.headers.get(SEAL_HEADER))
    scope = SnapshotScope(principal.tenant_id, principal.bound_agent_id, include_keys=False)
    bundle = await snapshot_service(request).credentials(scope, parse_ids(ids), seal_key)
    return Response(
        canonicalize(bundle), media_type="application/json", headers={"Cache-Control": "no-store"}
    )


async def _key_set(request: Request, since: int | None = None) -> Response:
    service = snapshot_service(request)
    document: dict[str, Any] = (
        await service.key_set() if since is None else await service.key_chain(since)
    )
    return Response(
        canonicalize(document),
        media_type="application/json",
        headers={"Cache-Control": "max-age=300" if since is None else "no-cache"},
    )


@_router.get(API_PREFIX + "/policy/keys", operation_id="getPolicyKeys")
async def get_policy_keys(
    request: Request,
    ctx: Annotated[AuthContext, Depends(guard("getPolicyKeys"))],
    since: Annotated[int | None, Query(ge=0, le=MAX_SEQUENCE)] = None,
) -> Response:
    """The latest signed key set; with ``?since=<sequence>`` every set issued after it (B10)."""
    return await _key_set(request, since)


@_router.get("/.well-known/sibyl-keys.json", operation_id="getWellKnownKeys")
async def get_well_known_keys(
    request: Request, ctx: Annotated[AuthContext, Depends(guard("getWellKnownKeys"))]
) -> Response:
    return await _key_set(request)


router = stub_router("snapshot", _router)
