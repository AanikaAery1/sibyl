"""One Sentinel analysis: prepare the prompt, reserve budget, call the model (outside any
transaction), then settle and write the finding.

Shared by the worker loop (scheduled, actor ``system``) and ``POST /sentinel/explain``
(on demand, actor the requesting human). Nothing here can reach an enforcement route or table:
the only writes are ``sentinel_usage``, ``sentinel_finding``, the audit row and (worker only)
a watch-only alert.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any, Final, Literal
from uuid import UUID

from sibyl_schemas.models.sentinel import OUTPUT_MODELS
from sibyl_schemas.values import SentinelTask

from ...core.audit import AuditActor, AuditRecord, AuditWriter
from ...core.llm import (
    LlmBadOutput,
    LlmClient,
    LlmError,
    LlmRequest,
    Price,
    Usage,
    cost_usd,
    price_for,
)
from . import budget
from .config import SentinelConfig
from .findings import FindingDraft, Subject, audit_finding, insert_finding
from .prompts import build_request, prompt_sha256, prompt_text

SYSTEM_ACTOR: Final = AuditActor("system", None, None, None)
Status = Literal["created", "duplicate", "skipped_budget", "failed"]


@dataclass(frozen=True)
class Prepared:
    task: SentinelTask
    request: LlmRequest
    price: Price
    estimate: Decimal
    prompt_sha256: bytes
    data_meta: dict[str, Any]


@dataclass(frozen=True)
class CallResult:
    value: dict[str, Any] | None
    usage: Usage
    calls: int
    model: str
    error_code: str | None = None

    @property
    def ok(self) -> bool:
        return self.value is not None


@dataclass(frozen=True)
class Outcome:
    status: Status
    finding: dict[str, Any] | None = None
    error_code: str | None = None
    cost_usd: Decimal = Decimal(0)
    extra: dict[str, Any] = field(default_factory=dict)


def utc_day(now: datetime) -> date:
    return now.astimezone(UTC).date()


def prepare(
    task: SentinelTask, data: dict[str, Any], cfg: SentinelConfig, client: LlmClient
) -> Prepared:
    req = build_request(task, data)
    price = price_for(cfg.provider, client.model, override=cfg.price)
    estimate = budget.estimate_cost(prompt_text(req), req.max_tokens, price)
    meta = {
        "content_included": bool(data.get("content_included")),
        "capture_mode": data.get("capture_mode", "metadata"),
        "prompt_chars": len(prompt_text(req)),
    }
    return Prepared(
        task, req, price, estimate, prompt_sha256(cfg.provider, client.model, req), meta
    )


async def reserve(
    db: Any,
    audit: AuditWriter,
    tenant: UUID,
    cfg: SentinelConfig,
    prepared: Prepared,
    day: date,
    actor: AuditActor,
) -> bool:
    """Reserve the worst-case cost; on refusal count the skip and audit the first one."""
    async with db.tenant_tx(tenant) as conn:
        if await budget.reserve(conn, tenant, day, cfg.daily_budget_usd, prepared.estimate):
            return True
    async with db.tenant_tx(tenant) as conn:
        await conn.execute("SELECT sibyl.audit_lock($1)", tenant)
        first, spent = await budget.record_budget_skip(conn, tenant, day)
        if first:
            await audit.append(
                conn,
                tenant,
                AuditRecord(
                    action="sentinel.budget_exhausted",
                    resource_type="sentinel_config",
                    resource_id=tenant,
                    detail={
                        "day": day.isoformat(),
                        "spent_usd": str(spent),
                        "daily_budget_usd": str(cfg.daily_budget_usd),
                        "task": prepared.task.value,
                    },
                    **actor.fields(),
                ),
            )
    return False


async def call(client: LlmClient, prepared: Prepared) -> CallResult:
    model = OUTPUT_MODELS[prepared.task]
    try:
        out = await client.complete_structured(prepared.request, model.model_validate)
    except LlmBadOutput as exc:
        return CallResult(None, exc.usage, exc.calls, client.model, exc.code)
    except LlmError as exc:
        return CallResult(None, Usage(), 1, client.model, exc.code)
    value = out.value.model_dump(mode="json")
    return CallResult(value, out.usage, out.calls, out.response.model or client.model)


def settlement(prepared: Prepared, result: CallResult, *, finding: bool) -> budget.Settlement:
    actual = cost_usd(result.usage, prepared.price)
    return budget.Settlement(
        prepared.estimate, actual, result.usage, result.calls, finding, not result.ok
    )


def draft(
    cfg: SentinelConfig,
    subject: Subject,
    prepared: Prepared,
    result: CallResult,
    *,
    trigger: str,
    requested_by: UUID | None = None,
) -> FindingDraft:
    assert result.value is not None
    return FindingDraft(
        subject=subject,
        output=result.value,
        provider=cfg.provider,
        model=result.model,
        prompt_sha256=prepared.prompt_sha256,
        tokens_in=result.usage.input_tokens,
        tokens_out=result.usage.output_tokens,
        cost_usd=cost_usd(result.usage, prepared.price),
        cost_estimated=prepared.price.estimated,
        calls=result.calls,
        trigger=trigger,
        requested_by=requested_by,
        data_meta=prepared.data_meta,
    )


async def finish_scheduled(
    db: Any,
    audit: AuditWriter,
    outbox: Any,
    tenant: UUID,
    cfg: SentinelConfig,
    subject: Subject,
    prepared: Prepared,
    result: CallResult,
    day: date,
    *,
    alert: bool,
) -> Outcome:
    """Worker path: settle, write the finding, audit it, maybe raise the watch-only alert."""
    from .findings import raise_alert, should_alert

    async with db.tenant_tx(tenant) as conn:
        await conn.execute("SELECT sibyl.audit_lock($1)", tenant)
        if not result.ok:
            await budget.settle(conn, tenant, day, settlement(prepared, result, finding=False))
            return Outcome("failed", error_code=result.error_code)
        row = await insert_finding(
            conn, tenant, draft(cfg, subject, prepared, result, trigger="scheduled")
        )
        await budget.settle(
            conn, tenant, day, settlement(prepared, result, finding=row is not None)
        )
        if row is None:
            return Outcome("duplicate")
        await audit_finding(conn, audit, tenant, row, SYSTEM_ACTOR)
        if alert and should_alert(subject.kind, result.value or {}):
            row["alert_id"] = await raise_alert(conn, outbox, tenant, row)
        return Outcome("created", row, cost_usd=Decimal(row["cost_usd"]))
