"""``/monitors``: register, list, read, update (pause/resume, groups), revoke, issue keys.

* Tenant-wide admins (``monitors:admin``) write; ``sentinel:read`` holders read. A monitor key
  reads its own monitor at ``GET /monitors/self``.
* Registration issues the first monitor-bound key unless ``issue_key`` is false; the secret is in
  the 201 response once (an Idempotency-Key replay carries ``secret: null``).
* A revoked monitor is terminal: its keys are revoked and its webhooks disabled in the same
  transaction, and every later write is 409.
* Monitors are advisory: nothing here reaches an enforcement table.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.responses import Response
from sibyl_schemas.models.monitor import (
    MonitorCreate,
    MonitorKeyCreate,
    MonitorPatch,
    MonitorRevoke,
)

from ...core.apikeys import generate_api_key, validate_expiry, validate_key_scopes
from ...core.authz import MONITOR_SCOPES
from ...core.etag import check_if_match, etag_for_version
from ...core.problems import ProblemError
from ..auth.common import Outcome as Written
from ..auth.common import actor_record, human_reason, iso, principal_of, run_mutation
from ..contract import API_PREFIX
from ..deps import AuthContext, Services, get_services, guard
from ..keys import key_view
from ..registry._kit import Outcome, PageQuery, keyset_page, run_read
from .views import MONITOR_COLUMNS, hydrate

BASE = API_PREFIX + "/monitors"
RESOURCE = "monitor"
router = APIRouter()
_GET_SQL = (
    f"SELECT {MONITOR_COLUMNS} FROM sibyl.monitor"  # noqa: S608 (constant columns)
    " WHERE tenant_id = $1 AND id = $2"
)
_LIST_SQL = f"SELECT {MONITOR_COLUMNS} FROM sibyl.monitor WHERE tenant_id = $1"  # noqa: S608
_NAME_TAKEN_SQL = (
    "SELECT EXISTS (SELECT 1 FROM sibyl.monitor WHERE tenant_id = $1 AND lower(name) = lower($2)"
    " AND state <> 'revoked' AND id IS DISTINCT FROM $3)"
)
_OWNER_SQL = (
    "SELECT EXISTS (SELECT 1 FROM sibyl.app_user WHERE tenant_id = $1 AND id = $2"
    " AND status = 'active')"
)
_GROUPS_SQL = "SELECT count(*) FROM sibyl.agent_group WHERE tenant_id = $1 AND id = ANY($2::uuid[])"
_INSERT_SQL = f"""
INSERT INTO sibyl.monitor (tenant_id, name, kind, description, owner_user_id, all_groups,
  group_ids, rate_limit_per_min, created_by_user_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING {MONITOR_COLUMNS}
"""  # noqa: S608 (constant columns)
_KEY_INSERT_SQL = """
INSERT INTO sibyl.api_key (tenant_id, monitor_id, name, env, prefix, secret_hash, scopes,
  expires_at, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, name, env, prefix, scopes, agent_id, monitor_id, status, expires_at, last_used_at,
  last_used_ip_hash, rotated_from_id, rotation_grace_until, created_by, created_at
"""
_REVOKE_SQL = f"""
UPDATE sibyl.monitor SET state = 'revoked', revoked_at = now(), revoked_by_user_id = $3,
       revoke_reason = $4, version = version + 1
 WHERE tenant_id = $1 AND id = $2
RETURNING {MONITOR_COLUMNS}
"""  # noqa: S608 (constant columns)
_REVOKE_KEYS_SQL = """
UPDATE sibyl.api_key SET status = 'revoked', revoked_at = now(), revoked_by = $3,
       revoke_reason = $4
 WHERE tenant_id = $1 AND monitor_id = $2 AND status IN ('active', 'rotating')
RETURNING id
"""
_DISABLE_WEBHOOKS_SQL = """
UPDATE sibyl.monitor_webhook SET state = 'disabled', disabled_reason = 'monitor revoked'
 WHERE tenant_id = $1 AND monitor_id = $2 AND state = 'enabled'
RETURNING id
"""
_PATCHABLE = ("name", "description", "state", "owner_user_id", "rate_limit_per_min")


# --- helpers ----------------------------------------------------------------------------------


def _pepper(services: Services) -> bytes:
    if services.settings is None or services.settings.key_pepper is None:
        raise ProblemError("service_unavailable", "SIBYL_KEY_PEPPER is not set")
    return services.settings.pepper()


def _key_env(services: Services, requested: str | None) -> str:
    """The deployment's env (a key the deployment would refuse is never issued)."""
    expected = services.settings.env if services.settings is not None else None
    env = requested or expected or "live"
    if expected is not None and env != expected:
        raise ProblemError(
            "validation_failed",
            f"this deployment accepts only {expected} keys (env_mismatch)",
            extensions={
                "errors": [{"pointer": "/env", "code": "env_mismatch", "message": expected}]
            },
        )
    return env


async def _check_owner(conn: Any, tenant: UUID, owner: UUID) -> None:
    if not await conn.fetchval(_OWNER_SQL, tenant, owner):
        raise ProblemError("validation_failed", "owner_user_id is not an active user")


async def _check_groups(conn: Any, tenant: UUID, groups: list[UUID]) -> None:
    if groups and await conn.fetchval(_GROUPS_SQL, tenant, groups) != len(set(groups)):
        raise ProblemError("validation_failed", "group_ids names an unknown agent group")


async def _check_name(conn: Any, tenant: UUID, name: str, monitor_id: UUID | None) -> None:
    if await conn.fetchval(_NAME_TAKEN_SQL, tenant, name, monitor_id):
        raise ProblemError("conflict", "an active monitor already has this name")


async def load_monitor(conn: Any, tenant: UUID, monitor_id: UUID, *, lock: bool = False) -> Any:
    row = await conn.fetchrow(_GET_SQL + (" FOR UPDATE" if lock else ""), tenant, monitor_id)
    if row is None:
        raise ProblemError("not_found")
    return row


async def issue_key(
    conn: Any,
    ctx: AuthContext,
    services: Services,
    monitor: Any,
    *,
    name: str,
    env: str,
    expires_at: datetime,
    reason: str,
) -> tuple[dict[str, Any], Any]:
    """Insert one monitor-bound key; returns its view (with the one-time secret) and receipt."""
    principal = principal_of(ctx)
    scopes = validate_key_scopes(MONITOR_SCOPES, agent_id=None, env=env, monitor_id=monitor["id"])
    generated = generate_api_key(env, _pepper(services))
    row = await conn.fetchrow(
        _KEY_INSERT_SQL,
        principal.tenant_id,
        monitor["id"],
        name,
        env,
        generated.prefix,
        generated.secret_hash,
        sorted(scopes),
        expires_at,
        principal.id,
    )
    receipt = await services.audit.append(
        conn,
        principal.tenant_id,
        actor_record(
            ctx,
            "api_key.created",
            resource_type="api_key",
            resource_id=row["id"],
            resource_ref=row["prefix"],
            detail={
                "key_id": str(row["id"]),
                "prefix": row["prefix"],
                "scopes": sorted(row["scopes"]),
                "agent_id": None,
                "grace_until": None,
                "env": row["env"],
                "monitor_id": str(monitor["id"]),
                "expires_at": iso(row["expires_at"]),
            },
            reason=reason,
        ),
    )
    return key_view(row) | {"secret": generated.plaintext}, receipt


async def _view(conn: Any, tenant: UUID, row: Any) -> dict[str, Any]:
    return (await hydrate(conn, tenant, [row]))[0]


# --- reads ------------------------------------------------------------------------------------


@router.get(BASE)
async def list_monitors(
    ctx: Annotated[AuthContext, Depends(guard("listMonitors"))],
    state: Annotated[str | None, Query(pattern="^(active|paused|revoked)$")] = None,
    kind: Annotated[str | None, Query(pattern="^(mcp|webhook|api)$")] = None,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    page = PageQuery.of(limit, cursor, state=state, kind=kind)

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = _LIST_SQL
        for column, value in (("state", state), ("kind", kind)):
            if value is not None:
                args.append(value)
                sql += f" AND {column} = ${len(args)}"
        outcome = await keyset_page(
            conn, ctx, select=sql, args=args, page=page, descending=True, serialize=lambda r: r
        )
        outcome.body["data"] = await hydrate(conn, ctx.tenant_id, outcome.body["data"])
        return outcome

    return await run_read(ctx, work)


@router.get(BASE + "/self")
async def get_monitor_self(
    ctx: Annotated[AuthContext, Depends(guard("getMonitorSelf"))],
) -> Response:
    monitor_id = principal_of(ctx).monitor_id
    if monitor_id is None:  # pragma: no cover - the guard admits monitor:read keys only
        raise ProblemError("not_found")

    async def work(conn: Any) -> Outcome:
        row = await load_monitor(conn, ctx.tenant_id, monitor_id)
        return Outcome(await _view(conn, ctx.tenant_id, row))

    return await run_read(ctx, work)


@router.get(BASE + "/{monitor_id}")
async def get_monitor(
    monitor_id: UUID, ctx: Annotated[AuthContext, Depends(guard("getMonitor"))]
) -> Response:
    async def work(conn: Any) -> Outcome:
        row = await load_monitor(conn, ctx.tenant_id, monitor_id)
        etag = etag_for_version(row["version"])
        return Outcome(await _view(conn, ctx.tenant_id, row), etag=etag)

    return await run_read(ctx, work)


# --- writes -----------------------------------------------------------------------------------


@router.post(BASE)
async def create_monitor(
    request: Request,
    body: MonitorCreate,
    ctx: Annotated[AuthContext, Depends(guard("createMonitor"))],
) -> Response:
    principal = principal_of(ctx)
    services = get_services(request)
    reason = human_reason(request, body.reason, ctx.op.operation_id)
    owner = body.owner_user_id or principal.id
    groups = list(body.group_ids)
    env = _key_env(services, body.key_env) if body.issue_key else None
    expires_at = validate_expiry(body.key_expires_at, now=ctx.now) if body.issue_key else None
    if body.issue_key:
        _pepper(services)  # 503 before any write when the pepper is missing

    async def mutate(conn: Any) -> Written:
        tenant = principal.tenant_id
        await _check_owner(conn, tenant, owner)
        await _check_groups(conn, tenant, groups)
        await _check_name(conn, tenant, body.name, None)
        row = await conn.fetchrow(
            _INSERT_SQL,
            tenant,
            body.name,
            body.kind.value,
            body.description,
            owner,
            body.all_groups,
            groups,
            body.rate_limit_per_min,
            principal.id,
        )
        receipt = await services.audit.append(
            conn,
            tenant,
            actor_record(
                ctx,
                "monitor.registered",
                resource_type=RESOURCE,
                resource_id=row["id"],
                resource_ref=row["name"],
                detail={
                    "monitor_id": str(row["id"]),
                    "name": row["name"],
                    "kind": row["kind"],
                    "all_groups": row["all_groups"],
                    "group_ids": [str(g) for g in row["group_ids"]],
                    "owner_user_id": str(owner),
                    "rate_limit_per_min": row["rate_limit_per_min"],
                    "issue_key": body.issue_key,
                },
                reason=reason,
            ),
        )
        key: dict[str, Any] | None = None
        if body.issue_key:
            assert env is not None and expires_at is not None
            key, receipt = await issue_key(
                conn,
                ctx,
                services,
                row,
                name=f"{body.name[:70]} key",
                env=env,
                expires_at=expires_at,
                reason=reason,
            )
        view = await _view(conn, tenant, row)
        headers = {"Location": f"{BASE}/{row['id']}"}
        return Written(
            201,
            view | {"api_key": key},
            headers=headers,
            receipt=receipt,
            replay_body=view | {"api_key": None if key is None else key | {"secret": None}},
        )

    return await run_mutation(request, ctx, mutate, idempotent=True)


def _changes(row: Any, body: MonitorPatch) -> dict[str, dict[str, Any]]:
    fields = body.model_dump(exclude_unset=True, exclude={"reason"}, mode="json")
    changes: dict[str, dict[str, Any]] = {}
    for name in _PATCHABLE:
        if name in fields:
            before = row[name]
            before = str(before) if isinstance(before, UUID) else before
            if fields[name] != before:
                changes[name] = {"before": before, "after": fields[name]}
    if "all_groups" in fields:
        before_groups = sorted(str(g) for g in row["group_ids"] or ())
        after_groups = sorted(fields["group_ids"] or [])
        if fields["all_groups"] != row["all_groups"] or before_groups != after_groups:
            changes["watch"] = {
                "before": {"all_groups": row["all_groups"], "group_ids": before_groups},
                "after": {"all_groups": fields["all_groups"], "group_ids": after_groups},
            }
    return changes


@router.patch(BASE + "/{monitor_id}")
async def update_monitor(
    request: Request,
    monitor_id: UUID,
    body: MonitorPatch,
    ctx: Annotated[AuthContext, Depends(guard("updateMonitor"))],
) -> Response:
    principal = principal_of(ctx)
    services = get_services(request)
    reason = human_reason(request, body.reason, ctx.op.operation_id)

    async def mutate(conn: Any) -> Written:
        tenant = principal.tenant_id
        row = await load_monitor(conn, tenant, monitor_id, lock=True)
        check_if_match(request.headers.get("if-match"), etag_for_version(row["version"]))
        if row["state"] == "revoked":
            raise ProblemError("invalid_transition", "the monitor is revoked")
        changes = _changes(row, body)
        if not changes:
            view = await _view(conn, tenant, row)
            return Written(200, view, headers={"ETag": etag_for_version(row["version"])})
        if "owner_user_id" in changes:
            await _check_owner(conn, tenant, UUID(changes["owner_user_id"]["after"]))
        if "name" in changes:
            await _check_name(conn, tenant, changes["name"]["after"], monitor_id)
        sets: list[str] = []
        args: list[Any] = [tenant, monitor_id]
        for name in _PATCHABLE:
            if name in changes:
                args.append(getattr(body, name))
                sets.append(f"{name} = ${len(args)}")
        if "watch" in changes:
            groups = list(body.group_ids or [])
            await _check_groups(conn, tenant, groups)
            args += [body.all_groups, groups]
            sets += [f"all_groups = ${len(args) - 1}", f"group_ids = ${len(args)}::uuid[]"]
        updated = await conn.fetchrow(
            f"UPDATE sibyl.monitor SET {', '.join(sets)}, version = version + 1"  # noqa: S608
            f" WHERE tenant_id = $1 AND id = $2 RETURNING {MONITOR_COLUMNS}",
            *args,
        )
        receipt = await services.audit.append(
            conn,
            tenant,
            actor_record(
                ctx,
                "monitor.updated",
                resource_type=RESOURCE,
                resource_id=monitor_id,
                resource_ref=updated["name"],
                detail={"monitor_id": str(monitor_id), "change": changes},
                reason=reason,
            ),
        )
        etag = {"ETag": etag_for_version(updated["version"])}
        return Written(200, await _view(conn, tenant, updated), headers=etag, receipt=receipt)

    return await run_mutation(request, ctx, mutate, idempotent=False)


@router.post(BASE + "/{monitor_id}/revoke")
async def revoke_monitor(
    request: Request,
    monitor_id: UUID,
    body: MonitorRevoke,
    ctx: Annotated[AuthContext, Depends(guard("revokeMonitor"))],
) -> Response:
    principal = principal_of(ctx)
    services = get_services(request)

    async def mutate(conn: Any) -> Written:
        tenant = principal.tenant_id
        row = await load_monitor(conn, tenant, monitor_id, lock=True)
        if row["state"] == "revoked":
            raise ProblemError("invalid_transition", "the monitor is already revoked")
        keys = await conn.fetch(_REVOKE_KEYS_SQL, tenant, monitor_id, principal.id, body.reason)
        hooks = await conn.fetch(_DISABLE_WEBHOOKS_SQL, tenant, monitor_id)
        updated = await conn.fetchrow(_REVOKE_SQL, tenant, monitor_id, principal.id, body.reason)
        receipt = await services.audit.append(
            conn,
            tenant,
            actor_record(
                ctx,
                "monitor.revoked",
                resource_type=RESOURCE,
                resource_id=monitor_id,
                resource_ref=updated["name"],
                detail={
                    "monitor_id": str(monitor_id),
                    "keys_revoked": len(keys),
                    "key_ids": [str(k["id"]) for k in keys],
                    "webhooks_disabled": len(hooks),
                    "previous_state": row["state"],
                },
                reason=body.reason,
            ),
        )
        return Written(200, await _view(conn, tenant, updated), receipt=receipt)

    return await run_mutation(request, ctx, mutate, idempotent=True)


@router.post(BASE + "/{monitor_id}/keys")
async def issue_monitor_key(
    request: Request,
    monitor_id: UUID,
    ctx: Annotated[AuthContext, Depends(guard("issueMonitorKey"))],
    body: Annotated[MonitorKeyCreate | None, Body()] = None,
) -> Response:
    spec = body or MonitorKeyCreate()
    principal = principal_of(ctx)
    services = get_services(request)
    env = _key_env(services, spec.env)
    expires_at = validate_expiry(spec.expires_at, now=ctx.now)
    _pepper(services)
    reason = human_reason(request, spec.reason, ctx.op.operation_id)

    async def mutate(conn: Any) -> Written:
        row = await load_monitor(conn, principal.tenant_id, monitor_id, lock=True)
        if row["state"] == "revoked":
            raise ProblemError("not_active", "the monitor is revoked")
        key, receipt = await issue_key(
            conn,
            ctx,
            services,
            row,
            name=spec.name or f"{row['name'][:70]} key",
            env=env,
            expires_at=expires_at,
            reason=reason,
        )
        return Written(201, key, receipt=receipt, replay_body=key | {"secret": None})

    return await run_mutation(request, ctx, mutate, idempotent=True)
