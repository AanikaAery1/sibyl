"""``/sentinel/config``: read it, set it (step-up; the key is sealed and write-only), test it.

* ``PUT`` validates the provider/model pair, vets an optional ``base_url`` exactly like a provider
  credential (``sibyl.is_allowlisted_base_url()`` plus a resolver check), seals a new key under
  the tenant ``credential`` DEK bound to a fresh ``credential_id`` (a config without a new key
  keeps the vaulted one), creates the watch-only ``sentinel_finding`` alert rule when Sentinel is
  on, and audits ``sentinel.config_changed`` (never the key).
* ``POST /test`` makes one tiny call with the vaulted key (after the Idempotency-Key claim, no
  transaction held), records it in today's usage and audits ``sentinel.config_tested``.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated, Any
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends
from sibyl_schemas.models.sentinel import SentinelConfigPut

from ...core.etag import etag_for_version
from ...core.llm import LlmError, LlmHttpError, LlmRequest, Message, Usage, cost_usd, price_for
from ...core.problems import ProblemError
from ...worker.sentinel import budget
from ...worker.sentinel.config import CONFIG_COLUMNS, seal_key
from ...worker.sentinel.findings import ensure_alert_rule
from ..auth.runtime import kek_for
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import (
    Outcome,
    audit,
    op_reason,
    require_if_match,
    run_read,
    run_write,
    services_of,
    user_id,
)
from ..registry.ssrf import check_base_url
from .runtime import Session, open_session, run_after_claim
from .views import config_view, money

BASE = API_PREFIX + "/sentinel/config"
RESOURCE = "sentinel_config"
TEST_MAX_TOKENS = 64
UNSAVED_VERSION = 0
"""ETag ``"0"`` before the first save (saved versions start at 1), so If-Match is uniform."""
router = APIRouter()

_SELECT_SQL = f"SELECT {CONFIG_COLUMNS} FROM sibyl.sentinel_config WHERE tenant_id = $1"  # noqa: S608
_LOCK_SQL = _SELECT_SQL + " FOR UPDATE"
_UPSERT_SQL = """
INSERT INTO sibyl.sentinel_config (tenant_id, enabled, provider, model, base_url, credential_id,
  ciphertext, nonce, tenant_key_id, key_version, key_hint, key_updated_at, daily_budget_usd,
  sampling_rate, tasks, price_in_usd_per_mtok, price_out_usd_per_mtok, updated_by_user_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
ON CONFLICT (tenant_id) DO UPDATE SET
  enabled = EXCLUDED.enabled, provider = EXCLUDED.provider, model = EXCLUDED.model,
  base_url = EXCLUDED.base_url,
  credential_id = CASE WHEN EXCLUDED.ciphertext IS NULL THEN sentinel_config.credential_id
                       ELSE EXCLUDED.credential_id END,
  ciphertext = coalesce(EXCLUDED.ciphertext, sentinel_config.ciphertext),
  nonce = coalesce(EXCLUDED.nonce, sentinel_config.nonce),
  tenant_key_id = coalesce(EXCLUDED.tenant_key_id, sentinel_config.tenant_key_id),
  key_version = coalesce(EXCLUDED.key_version, sentinel_config.key_version),
  key_hint = coalesce(EXCLUDED.key_hint, sentinel_config.key_hint),
  key_updated_at = coalesce(EXCLUDED.key_updated_at, sentinel_config.key_updated_at),
  daily_budget_usd = EXCLUDED.daily_budget_usd, sampling_rate = EXCLUDED.sampling_rate,
  tasks = EXCLUDED.tasks, price_in_usd_per_mtok = EXCLUDED.price_in_usd_per_mtok,
  price_out_usd_per_mtok = EXCLUDED.price_out_usd_per_mtok,
  updated_by_user_id = EXCLUDED.updated_by_user_id, version = sentinel_config.version + 1
"""


def _today() -> Any:
    return datetime.now(UTC).date()


def key_hint(secret: str) -> str:
    return secret[-4:] if len(secret) >= 12 else "****"


async def _view(conn: Any, tenant: UUID) -> tuple[dict[str, Any], str | None]:
    """The view and its ETag (``"<version>"``; ``"0"`` before the first write)."""
    row = await conn.fetchrow(_SELECT_SQL, tenant)
    etag = etag_for_version(UNSAVED_VERSION if row is None else row["version"])
    return config_view(row, await budget.today(conn, tenant, _today())), etag


@router.get(BASE)
async def get_sentinel_config(
    ctx: Annotated[AuthContext, Depends(guard("getSentinelConfig"))],
) -> Any:
    async def work(conn: Any) -> Outcome:
        view, etag = await _view(conn, ctx.tenant_id)
        return Outcome(view, etag=etag)

    return await run_read(ctx, work)


def _check_if_match(ctx: AuthContext, current: Any) -> None:
    """The first write accepts ``*`` or ``"0"`` (the ETag GET returns before any save); later
    writes need the saved version's ETag."""
    if current is None:
        header = ctx.request.headers.get("if-match") if ctx.request is not None else None
        star = header is not None and header.strip() == "*"
        tag = None if star else etag_for_version(UNSAVED_VERSION)
        require_if_match(ctx, tag, allow_star_create=True)
        return
    require_if_match(
        ctx,
        etag_for_version(current["version"]),
        allow_star_create=True,
        body=config_view(current, None),
    )


def _invalid(pointer: str, message: str) -> ProblemError:
    return ProblemError(
        "validation_failed",
        message,
        extensions={"errors": [{"pointer": pointer, "code": "invalid", "message": message}]},
    )


async def _vet_base_url(conn: Any, url: str | None) -> str | None:
    if url is None:
        return None
    if urlsplit(url).username or urlsplit(url).password:
        raise _invalid("/base_url", "credentials in a URL are refused")
    return (await check_base_url(conn, url)).url


@router.put(BASE)
async def put_sentinel_config(
    body: SentinelConfigPut,
    ctx: Annotated[AuthContext, Depends(guard("putSentinelConfig"))],
) -> Any:
    assert ctx.request is not None
    kek = kek_for(ctx.request)  # 503 before any write when the vault is not configured
    tenant = ctx.tenant_id
    secret = body.api_key.get_secret_value() if body.api_key is not None else None
    model = body.resolved_model()

    async def work(conn: Any) -> Outcome:
        current = await conn.fetchrow(_LOCK_SQL, tenant)
        _check_if_match(ctx, current)
        has_key = current is not None and current["key_version"] is not None
        if body.enabled and secret is None and not has_key:
            raise _invalid("/api_key", "an API key is required to enable Sentinel")
        base_url = await _vet_base_url(conn, body.base_url)
        credential_id: UUID = await conn.fetchval("SELECT sibyl.uuidv7()")
        cipher = nonce = key_id = version = hint = changed_at = None
        if secret is not None:
            blob, key_id = await seal_key(conn, kek, tenant, credential_id, secret)
            cipher, nonce, version = blob.ciphertext, blob.nonce, blob.key_version
            hint, changed_at = key_hint(secret), datetime.now(UTC)
        await conn.execute(
            _UPSERT_SQL,
            tenant,
            body.enabled,
            body.provider.value,
            model,
            base_url,
            credential_id,
            cipher,
            nonce,
            key_id,
            version,
            hint,
            changed_at,
            Decimal(body.daily_budget_usd),
            Decimal(str(body.sampling_rate)),
            [t.value for t in body.tasks],
            None if body.price_in_usd_per_mtok is None else Decimal(body.price_in_usd_per_mtok),
            None if body.price_out_usd_per_mtok is None else Decimal(body.price_out_usd_per_mtok),
            user_id(ctx),
        )
        if body.enabled:
            await ensure_alert_rule(conn, tenant)
        receipt = await audit(
            conn,
            ctx,
            "sentinel.config_changed",
            resource_type=RESOURCE,
            resource_id=tenant,
            reason=op_reason(ctx, body.reason),
            detail={
                "enabled": body.enabled,
                "provider": body.provider.value,
                "model": model,
                "tasks": [t.value for t in body.tasks],
                "daily_budget_usd": body.daily_budget_usd,
                "sampling_rate": str(body.sampling_rate),
                "credential_changed": secret is not None,
                "base_url": base_url,
            },
        )
        view, etag = await _view(conn, tenant)
        return Outcome(view, etag=etag, receipt=receipt)

    return await run_write(ctx, work, idempotent=False)


@router.post(BASE + "/test")
async def test_sentinel_config(
    ctx: Annotated[AuthContext, Depends(guard("testSentinelConfig"))],
) -> Any:
    db = services_of(ctx).db
    tenant = ctx.tenant_id

    async def prelude() -> tuple[Session, dict[str, Any], Usage]:
        assert db is not None
        async with db.tenant_tx(tenant, readonly=True) as conn:
            session = await open_session(conn, ctx, require_enabled=False)
        req = LlmRequest(
            "You are a connectivity check.",
            (Message("user", "Reply with the single word OK."),),
            max_tokens=TEST_MAX_TOKENS,
        )
        started = time.monotonic()
        result: dict[str, Any] = {"ok": True, "http_status": 200, "error": None}
        usage = Usage()
        try:
            answer = await session.client.complete(req)
            usage = answer.usage
        except LlmError as exc:
            status = exc.status if isinstance(exc, LlmHttpError) else 0
            result = {"ok": False, "http_status": status, "error": exc.code}
        result["latency_ms"] = int((time.monotonic() - started) * 1000)
        return session, result, usage

    async def work(conn: Any, pre: tuple[Session, dict[str, Any], Usage]) -> Outcome:
        session, result, usage = pre
        price = price_for(session.cfg.provider, session.client.model, override=session.cfg.price)
        cost = cost_usd(usage, price)
        await budget.settle(
            conn,
            tenant,
            _today(),
            budget.Settlement(Decimal(0), cost, usage, 1, False, not result["ok"]),
        )
        receipt = await audit(
            conn,
            ctx,
            "sentinel.config_tested",
            resource_type=RESOURCE,
            resource_id=tenant,
            detail={
                "provider": session.cfg.provider,
                "model": session.client.model,
                "ok": result["ok"],
                "http_status": result["http_status"],
                "error": result["error"],
                "latency_ms": result["latency_ms"],
                "cost_usd": str(cost),
            },
        )
        body = {
            **result,
            "provider": session.cfg.provider,
            "model": session.client.model,
            "cost_usd": money(cost),
        }
        return Outcome(body, receipt=receipt)

    return await run_after_claim(ctx, prelude, work)
