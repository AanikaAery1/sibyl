"""Provider credential routes (API.md §5.5, D11, R55; security-auditor §2.3, T1).

Secrets are sealed under the tenant ``credential`` DEK (``vault.seal_secret``, AAD bound to the
credential id) and stored as ciphertext + nonce; reads go through ``provider_credential_meta``
and return metadata only. The plaintext is never logged, echoed, audited or put in the outbox.
Every change emits ``policy_changed`` so the snapshot's credential bundle is rebuilt.
``verifyProviderCredential`` enqueues a ``credential_probe`` job (B14) and answers 202 with its id;
the worker probes through its SSRF guard and writes the audit rows.
"""

from __future__ import annotations

import hashlib
from typing import Annotated, Any
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sibyl_schemas.values import JobKind

from ...core.jobs import Requester, enqueue_job
from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import (
    JSON,
    Outcome,
    PageQuery,
    audit,
    jsonable,
    keyset_page,
    op_reason,
    policy_changed,
    run_read,
    run_write,
    services_of,
    user_id,
)
from ..registry.ssrf import check_base_url
from .models import ProviderCredentialCreate, ProviderCredentialRotate, ReasonBody
from .vault import kek_from_settings, seal_secret

BASE = API_PREFIX + "/provider-credentials"
RESOURCE = "provider_credential"
HINT_MIN_SECRET_CHARS = 12
MASKED_HINT = "****"
META_FIELDS: tuple[str, ...] = (
    "id",
    "name",
    "provider_id",
    "purpose",
    "base_url",
    "allowlist_basis",
    "auth_scheme",
    "secret_hint",
    "status",
    "key_version",
    "expires_at",
    "last_used_at",
    "last_verified_at",
)
_META_SQL = "SELECT * FROM sibyl.provider_credential_meta WHERE tenant_id = $1 AND id = $2"

router = APIRouter()


def meta(row: Any) -> JSON:
    """``ProviderCredentialMeta``: never ciphertext, nonce or secret hash."""
    out: JSON = {name: jsonable(row[name]) for name in META_FIELDS}
    hint = out["secret_hint"]
    out["secret_hint"] = hint.strip() if isinstance(hint, str) else MASKED_HINT
    return out


def secret_hint(secret: str) -> str:
    return secret[-4:] if len(secret) >= HINT_MIN_SECRET_CHARS else MASKED_HINT


def _audit_detail(row: Any, **extra: Any) -> JSON:
    return {
        "credential_id": row["id"],
        "provider_id": row["provider_id"],
        "base_url": row["base_url"],
        "allowlist_basis": row["allowlist_basis"],
        "key_version": row["key_version"],
        **extra,
    }


async def _insert(
    conn: Any,
    ctx: AuthContext,
    *,
    provider_id: UUID,
    name: str,
    purpose: str,
    base_url: str,
    allowlist_basis: str,
    auth_scheme: str,
    secret: str,
    rotated_from_id: UUID | None = None,
) -> Any:
    """Seal ``secret`` to a fresh credential id and insert the row; returns its meta row."""
    kek = kek_from_settings(services_of(ctx).settings)
    credential_id: UUID = await conn.fetchval("SELECT sibyl.uuidv7()")
    blob, key_id = await seal_secret(conn, kek, ctx.tenant_id, credential_id, secret)
    await conn.execute(
        "INSERT INTO sibyl.provider_credential (tenant_id, id, provider_id, name, purpose,"
        " base_url, allowlist_basis, auth_scheme, ciphertext, nonce, tenant_key_id, key_version,"
        " secret_sha256, secret_hint, created_by, rotated_from_id)"
        " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
        ctx.tenant_id,
        credential_id,
        provider_id,
        name,
        purpose,
        base_url,
        allowlist_basis,
        auth_scheme,
        blob.ciphertext,
        blob.nonce,
        key_id,
        blob.key_version,
        hashlib.sha256(secret.encode()).digest(),
        secret_hint(secret),
        user_id(ctx),
        rotated_from_id,
    )
    return await conn.fetchrow(_META_SQL, ctx.tenant_id, credential_id)


async def _locked(conn: Any, ctx: AuthContext, credential_id: UUID) -> Any:
    row = await conn.fetchrow(
        "SELECT id, provider_id, name, purpose, base_url, allowlist_basis, auth_scheme, status,"
        " key_version FROM sibyl.provider_credential WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        ctx.tenant_id,
        credential_id,
    )
    if row is None:
        raise ProblemError("not_found")
    return row


async def _refuse_outside_demo(conn: Any, ctx: AuthContext, base_url: str) -> None:
    """R55: with ``SIBYL_DEMO=1`` only the allowlisted sibyl-sim doubles may hold credentials.

    Decided before any DNS lookup, so demo mode never resolves a real provider name.
    """
    settings = services_of(ctx).settings
    if settings is None or not settings.demo:
        return
    host = (urlsplit(base_url).hostname or "").lower().rstrip(".")
    dev_hosts = await conn.fetchval("SELECT sibyl.base_url_dev_hosts()")
    if host not in set(dev_hosts or ()):
        raise ProblemError("demo_mode", "demo mode accepts credentials for sibyl-sim doubles only")


@router.get(BASE)
async def list_provider_credentials(
    ctx: Annotated[AuthContext, Depends(guard("listProviderCredentials"))],
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query()] = None,
    provider_id: Annotated[UUID | None, Query()] = None,
    status: Annotated[str | None, Query(max_length=20)] = None,
) -> Any:
    page = PageQuery.of(limit, cursor, provider_id=provider_id, status=status)
    groups = ctx.group_filter()

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = "SELECT m.* FROM sibyl.provider_credential_meta m WHERE m.tenant_id = $1"
        if provider_id is not None:
            args.append(provider_id)
            sql += f" AND m.provider_id = ${len(args)}"
        if status is not None:
            args.append(status)
            sql += f" AND m.status = ${len(args)}"
        if groups is not None:
            # A group-limited reader sees the credentials its group's agents fall back to.
            args.append(list(groups))
            sql += (
                " AND EXISTS (SELECT 1 FROM sibyl.fallback_step s"  # noqa: S608 (constants only)
                " JOIN sibyl.fallback_chain c ON c.tenant_id = s.tenant_id AND c.id = s.chain_id"
                " JOIN sibyl.agent a ON a.tenant_id = c.tenant_id AND a.id = c.agent_id"
                " WHERE s.tenant_id = m.tenant_id AND s.credential_id = m.id"
                f" AND a.agent_group_id = ANY(${len(args)}::uuid[]))"
            )
        return await keyset_page(
            conn,
            ctx,
            select=sql,
            args=args,
            page=page,
            keys=("m.created_at", "m.id"),
            serialize=meta,
        )

    return await run_read(ctx, work)


@router.post(BASE, status_code=201)
async def create_provider_credential(
    body: ProviderCredentialCreate,
    ctx: Annotated[AuthContext, Depends(guard("createProviderCredential"))],
) -> Any:
    kek_from_settings(services_of(ctx).settings)  # 503 before claiming the idempotency key

    async def work(conn: Any) -> Outcome:
        exists = await conn.fetchval(
            "SELECT 1 FROM sibyl.provider WHERE tenant_id = $1 AND id = $2",
            ctx.tenant_id,
            body.provider_id,
        )
        if exists is None:
            raise ProblemError(
                "validation_failed",
                "provider_id does not name a provider of this tenant",
                extensions={
                    "errors": [
                        {
                            "pointer": "/provider_id",
                            "code": "unknown",
                            "message": "unknown provider",
                        }
                    ]
                },
            )
        await _refuse_outside_demo(conn, ctx, body.base_url)
        checked = await check_base_url(conn, body.base_url)
        row = await _insert(
            conn,
            ctx,
            provider_id=body.provider_id,
            name=body.name,
            purpose=body.purpose,
            base_url=checked.url,
            allowlist_basis=checked.basis,
            auth_scheme=body.auth_scheme,
            secret=body.secret.get_secret_value(),
        )
        receipt = await audit(
            conn,
            ctx,
            "credential.created",
            resource_type=RESOURCE,
            resource_id=row["id"],
            reason=op_reason(ctx, body.reason),
            detail=_audit_detail(row),
        )
        await policy_changed(
            conn, ctx, aggregate_kind=RESOURCE, aggregate_id=row["id"], agent_id=None
        )
        return Outcome(
            meta(row), status=201, receipt=receipt, headers={"Location": f"{BASE}/{row['id']}"}
        )

    return await run_write(ctx, work, idempotent=True)


@router.post(BASE + "/{credential_id}/rotate", status_code=201)
async def rotate_provider_credential(
    credential_id: UUID,
    body: ProviderCredentialRotate,
    ctx: Annotated[AuthContext, Depends(guard("rotateProviderCredential"))],
) -> Any:
    kek_from_settings(services_of(ctx).settings)

    async def work(conn: Any) -> Outcome:
        old = await _locked(conn, ctx, credential_id)
        if old["status"] != "active":
            raise ProblemError("not_active", f"the credential is {old['status']}")
        row = await _insert(
            conn,
            ctx,
            provider_id=old["provider_id"],
            name=old["name"],
            purpose=old["purpose"],
            base_url=old["base_url"],
            allowlist_basis=old["allowlist_basis"],
            auth_scheme=old["auth_scheme"],
            secret=body.secret.get_secret_value(),
            rotated_from_id=old["id"],
        )
        await conn.execute(
            "UPDATE sibyl.provider_credential SET status = 'rotating',"
            " rotation_grace_until = now() + make_interval(secs => $3)"
            " WHERE tenant_id = $1 AND id = $2",
            ctx.tenant_id,
            old["id"],
            body.grace_s,
        )
        receipt = await audit(
            conn,
            ctx,
            "credential.rotated",
            resource_type=RESOURCE,
            resource_id=row["id"],
            reason=op_reason(ctx, body.reason),
            detail=_audit_detail(row, rotated_from_id=old["id"], grace_s=body.grace_s),
        )
        await policy_changed(
            conn, ctx, aggregate_kind=RESOURCE, aggregate_id=row["id"], agent_id=None
        )
        return Outcome(
            meta(row), status=201, receipt=receipt, headers={"Location": f"{BASE}/{row['id']}"}
        )

    return await run_write(ctx, work, idempotent=True)


@router.post(BASE + "/{credential_id}/revoke")
async def revoke_provider_credential(
    credential_id: UUID,
    body: ReasonBody,
    ctx: Annotated[AuthContext, Depends(guard("revokeProviderCredential"))],
) -> Any:
    async def work(conn: Any) -> Outcome:
        old = await _locked(conn, ctx, credential_id)
        if old["status"] in ("revoked", "shredded"):
            raise ProblemError("already_revoked")
        await conn.execute(
            "UPDATE sibyl.provider_credential SET status = 'revoked', ciphertext = NULL,"
            " nonce = NULL, revoked_at = now(), revoke_reason = $3"
            " WHERE tenant_id = $1 AND id = $2",
            ctx.tenant_id,
            old["id"],
            body.reason,
        )
        row = await conn.fetchrow(_META_SQL, ctx.tenant_id, old["id"])
        receipt = await audit(
            conn,
            ctx,
            "credential.revoked",
            resource_type=RESOURCE,
            resource_id=row["id"],
            reason=body.reason,
            detail=_audit_detail(row, previous_status=old["status"]),
        )
        await policy_changed(
            conn, ctx, aggregate_kind=RESOURCE, aggregate_id=row["id"], agent_id=None
        )
        return Outcome(meta(row), receipt=receipt)

    return await run_write(ctx, work, idempotent=True)


@router.post(BASE + "/{credential_id}/verify", status_code=202)
async def verify_provider_credential(
    credential_id: UUID,
    ctx: Annotated[AuthContext, Depends(guard("verifyProviderCredential"))],
) -> Any:
    """Enqueue a ``credential_probe`` job (B14); at most one is open per credential, so a repeat
    while it is in flight answers with the same job id."""
    principal = ctx.principal
    assert principal is not None

    async def work(conn: Any) -> Outcome:
        exists = await conn.fetchval(
            "SELECT 1 FROM sibyl.provider_credential WHERE tenant_id = $1 AND id = $2",
            ctx.tenant_id,
            credential_id,
        )
        if exists is None:
            raise ProblemError("not_found")
        job = await enqueue_job(
            conn,
            services_of(ctx).outbox,
            ctx.tenant_id,
            kind=JobKind.CREDENTIAL_PROBE,
            requester=Requester.of(principal),
            params={"credential_id": credential_id},
            subject=(RESOURCE, credential_id),
        )
        return Outcome(
            {"job_id": str(job.id)},
            status=202,
            headers={"Location": f"{API_PREFIX}/jobs/{job.id}"},
        )

    return await run_write(ctx, work, idempotent=True)
