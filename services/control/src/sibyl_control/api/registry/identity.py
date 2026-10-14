"""Agent identity: allowed tools/models/providers and enforcement (API.md §5.4).

ETag = ``"<identity_version>"`` (``"0"`` before the first write). A group-limited
``identity:write`` grant (engineer G) may only narrow: any added entry, or ``block → observe``,
is 403 ``identity_widen_forbidden``. Changing ``enforcement`` needs a fresh step-up.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Response

from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ._kit import (
    Outcome,
    audit,
    deny,
    load_agent,
    op_reason,
    policy_changed,
    refuse,
    require_if_match,
    run_read,
    run_write,
    user_id,
)
from .models import AgentIdentityPut
from .views import identity_etag, identity_view, tools_hash

router = APIRouter()
IDENTITY = API_PREFIX + "/agents/{agent_id}/identity"


async def _current(
    conn: Any, tenant_id: UUID, agent_id: UUID, *, lock: bool
) -> dict[str, Any] | None:
    row = await conn.fetchrow(
        "SELECT * FROM sibyl.agent_identity WHERE tenant_id = $1 AND agent_id = $2"  # noqa: S608
        + (" FOR UPDATE" if lock else ""),
        tenant_id,
        agent_id,
    )
    return dict(row) if row is not None else None


@router.get(IDENTITY, operation_id="getAgentIdentity")
async def get_identity(
    agent_id: UUID, ctx: Annotated[AuthContext, Depends(guard("getAgentIdentity"))]
) -> Response:
    async def work(conn: Any) -> Outcome:
        await load_agent(conn, ctx, agent_id)
        row = await _current(conn, ctx.tenant_id, agent_id, lock=False)
        view = identity_view(agent_id, row)
        return Outcome(view, etag=identity_etag(view["identity_version"]))

    return await run_read(ctx, work)


def _providers(values: list[str]) -> list[UUID]:
    out: list[UUID] = []
    errors = []
    for index, value in enumerate(values):
        try:
            out.append(UUID(value))
        except ValueError:
            errors.append(
                {
                    "pointer": f"/allowed_providers/{index}",
                    "code": "uuid",
                    "message": "provider ids are UUIDs",
                }
            )
    if errors:
        raise ProblemError("validation_failed", extensions={"errors": errors})
    return out


def _diff(before: list[Any], after: list[Any]) -> tuple[list[str], list[str]]:
    old, new = {str(v) for v in before}, {str(v) for v in after}
    return sorted(new - old), sorted(old - new)


@router.put(IDENTITY, operation_id="putAgentIdentity")
async def put_identity(
    agent_id: UUID,
    body: AgentIdentityPut,
    ctx: Annotated[AuthContext, Depends(guard("putAgentIdentity"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        agent = await load_agent(conn, ctx, agent_id, lock=True)
        current = await _current(conn, ctx.tenant_id, agent_id, lock=True)
        before = identity_view(agent_id, current)
        require_if_match(
            ctx,
            identity_etag(before["identity_version"]),
            allow_star_create=False,
            body=before,
        )
        providers = _providers(body.allowed_providers)
        if providers:
            known = await conn.fetchval(
                "SELECT count(*) FROM sibyl.provider WHERE tenant_id = $1 AND id = ANY($2::uuid[])",
                ctx.tenant_id,
                providers,
            )
            if known != len(set(providers)):
                raise ProblemError("validation_failed", "allowed_providers names unknown providers")
        added: dict[str, list[str]] = {}
        removed: dict[str, list[str]] = {}
        for name, values in (
            ("tools", body.allowed_tools),
            ("models", body.allowed_models),
            ("providers", [str(p) for p in providers]),
        ):
            added[name], removed[name] = _diff(before[f"allowed_{name}"], values)
        enforcement_changed = body.enforcement != before["enforcement"]
        widened = any(added.values()) or (enforcement_changed and body.enforcement == "observe")
        ctx.object_rule_checked("narrow_only")
        grant = ctx.grant
        if widened and grant is not None and grant.group_ids is not None:
            raise await refuse(ctx, "identity_widen_forbidden")
        try:
            ctx.step_up_if(enforcement_changed)
        except ProblemError as exc:
            raise await deny(ctx, exc) from None
        version = before["identity_version"] + 1
        row = await conn.fetchrow(
            "INSERT INTO sibyl.agent_identity AS i (tenant_id, agent_id, allowed_tools,"
            " allowed_models, allowed_providers, enforcement, identity_version, tools_hash,"
            " updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
            " ON CONFLICT (tenant_id, agent_id) DO UPDATE"
            " SET allowed_tools = EXCLUDED.allowed_tools,"
            " allowed_models = EXCLUDED.allowed_models,"
            " allowed_providers = EXCLUDED.allowed_providers, enforcement = EXCLUDED.enforcement,"
            " identity_version = EXCLUDED.identity_version, tools_hash = EXCLUDED.tools_hash,"
            " updated_by = EXCLUDED.updated_by RETURNING *",
            ctx.tenant_id,
            agent_id,
            sorted(set(body.allowed_tools)),
            sorted(set(body.allowed_models)),
            providers,
            body.enforcement,
            version,
            tools_hash(body.allowed_tools),
            user_id(ctx),
        )
        receipt = await audit(
            conn,
            ctx,
            "agent_identity.changed",
            resource_type="agent_identity",
            resource_id=row["id"],
            resource_ref=agent["slug"],
            reason=op_reason(ctx, body.reason),
            detail={
                "agent_id": str(agent_id),
                "identity_version": version,
                "added": added,
                "removed": removed,
                "widened": widened,
                "enforcement": {"before": before["enforcement"], "after": body.enforcement},
            },
        )
        await policy_changed(
            conn, ctx, aggregate_kind="agent", aggregate_id=agent_id, agent_id=agent_id
        )
        view = identity_view(agent_id, dict(row))
        return Outcome(view, etag=identity_etag(version), receipt=receipt)

    return await run_write(ctx, work, idempotent=False)
