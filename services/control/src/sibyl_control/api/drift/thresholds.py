"""``/drift/thresholds`` (wave 4 HARDEN): read and replace the tenant's drift thresholds.

* ``GET`` (``drift:read``, every role): each tunable value with its effective value, the
  deployment default, its source (``tenant`` | ``default``) and its accepted range. ETag
  ``"<version>"``, ``"0"`` before the first save (mirrors ``/sentinel/config``).
* ``PUT`` (``drift:write``: Owner, Admin, Security admin; If-Match; reason): replaces the whole
  override set. A null or omitted value uses the deployment default, so a body with only a
  reason resets every value; the row is kept (all NULL) so the version keeps counting. Ranges
  are checked by the body model (``THRESHOLD_BOUNDS``); each statistic's effective watch must be
  below its effective drift (422 ``validation_failed`` naming the field). Audited
  ``drift.thresholds_updated`` with the before and after overrides (thresholds as decimal
  strings, the audit chain is canonical JSON without floats). No outbox event: drift is
  watch-only and the drift loop reads the row on its next tick.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sibyl_schemas.models.drift import THRESHOLD_BOUNDS, DriftThresholdsPut

from ...core.etag import etag_for_version
from ...core.problems import ProblemError
from ...worker.drift.config import (
    DEFAULT_CONFIG,
    TUNABLE_FEATURES,
    TenantThresholds,
    resolve_pair,
    tunable_values,
)
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import (
    JSON,
    Outcome,
    audit,
    jsonable,
    require_if_match,
    run_read,
    run_write,
    user_id,
)

PATH = API_PREFIX + "/drift/thresholds"
RESOURCE = "drift_thresholds"
UNSAVED_VERSION = 0
"""ETag ``"0"`` before the first save (saved versions start at 1), so If-Match is uniform."""
NAMES = tuple(THRESHOLD_BOUNDS)
router = APIRouter()

_SELECT_SQL = "SELECT * FROM sibyl.drift_thresholds WHERE tenant_id = $1"
_LOCK_SQL = _SELECT_SQL + " FOR UPDATE"
_COLUMNS = ", ".join(NAMES)
_SETS = ", ".join(f"{name} = EXCLUDED.{name}" for name in NAMES)
_UPSERT_SQL = (
    f"INSERT INTO sibyl.drift_thresholds (tenant_id, {_COLUMNS}, updated_by_user_id)"  # noqa: S608
    f" VALUES ($1, {', '.join(f'${i}' for i in range(2, len(NAMES) + 2))}, ${len(NAMES) + 2})"
    f" ON CONFLICT (tenant_id) DO UPDATE SET {_SETS},"
    " updated_by_user_id = EXCLUDED.updated_by_user_id,"
    " version = drift_thresholds.version + 1"
)


def thresholds_view(row: Mapping[str, Any] | None) -> JSON:
    tuned = TenantThresholds.from_row(row)
    defaults = tunable_values(DEFAULT_CONFIG)
    effective = tuned.effective(DEFAULT_CONFIG)
    overridden = set(tuned.overridden)
    values = {
        name: {
            "value": effective[name],
            "default": defaults[name],
            "source": "tenant" if name in overridden else "default",
            "minimum": THRESHOLD_BOUNDS[name][0],
            "maximum": THRESHOLD_BOUNDS[name][1],
        }
        for name in NAMES
    }
    return {
        "values": values,
        "version": UNSAVED_VERSION if row is None else int(row["version"]),
        "updated_at": None if row is None else jsonable(row["updated_at"]),
        "updated_by_user_id": None if row is None else jsonable(row["updated_by_user_id"]),
        "watch_only": True,
    }


def _etag(row: Mapping[str, Any] | None) -> str:
    return etag_for_version(UNSAVED_VERSION if row is None else row["version"])


@router.get(PATH)
async def get_drift_thresholds(
    ctx: Annotated[AuthContext, Depends(guard("getDriftThresholds"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        row = await conn.fetchrow(_SELECT_SQL, ctx.tenant_id)
        return Outcome(thresholds_view(row), etag=_etag(row))

    return await run_read(ctx, work)


def _check_if_match(ctx: AuthContext, current: Mapping[str, Any] | None) -> None:
    """The first write accepts ``*`` or ``"0"`` (the ETag GET returns before any save); later
    writes need the saved version's ETag (412 with the current view otherwise)."""
    if current is None:
        header = ctx.request.headers.get("if-match") if ctx.request is not None else None
        star = header is not None and header.strip() == "*"
        tag = None if star else etag_for_version(UNSAVED_VERSION)
        require_if_match(ctx, tag, allow_star_create=True)
        return
    require_if_match(ctx, _etag(current), allow_star_create=True, body=thresholds_view(current))


def _audited(values: Mapping[str, float | int | None]) -> dict[str, str | int | None]:
    """Audit details are canonical JSON (no floats): thresholds as decimal strings."""
    return {k: v if v is None or isinstance(v, int) else str(v) for k, v in values.items()}


def _check_pairs(body: DriftThresholdsPut) -> None:
    """Each statistic's effective watch (override else default) must stay below its drift."""
    errors = []
    for stat, features in TUNABLE_FEATURES.items():
        watch, drift = getattr(body, f"{stat}_watch"), getattr(body, f"{stat}_drift")
        default = DEFAULT_CONFIG.threshold(features[0])
        if resolve_pair(watch, drift, default) is not None:
            continue
        name = f"{stat}_watch" if watch is not None else f"{stat}_drift"
        effective_watch = default.watch if watch is None else watch
        effective_drift = default.drift if drift is None else drift
        message = (
            f"{stat}: watch ({effective_watch}) must be below drift ({effective_drift});"
            " a value you leave null uses the deployment default"
        )
        errors.append({"pointer": f"/{name}", "code": "invalid", "message": message})
    if errors:
        raise ProblemError("validation_failed", errors[0]["message"], extensions={"errors": errors})


@router.put(PATH)
async def put_drift_thresholds(
    body: DriftThresholdsPut,
    ctx: Annotated[AuthContext, Depends(guard("putDriftThresholds"))],
) -> Response:
    tenant: UUID = ctx.tenant_id
    after = body.overrides()

    async def work(conn: Any) -> Outcome:
        current = await conn.fetchrow(_LOCK_SQL, tenant)
        _check_if_match(ctx, current)
        _check_pairs(body)
        before = TenantThresholds.from_row(current).as_dict()
        await conn.execute(_UPSERT_SQL, tenant, *(after[name] for name in NAMES), user_id(ctx))
        receipt = await audit(
            conn,
            ctx,
            "drift.thresholds_updated",
            resource_type=RESOURCE,
            resource_id=tenant,
            reason=body.reason.strip(),
            detail={"before": _audited(before), "after": _audited(after)},
        )
        row = await conn.fetchrow(_SELECT_SQL, tenant)
        return Outcome(thresholds_view(row), etag=_etag(row), receipt=receipt)

    return await run_write(ctx, work, idempotent=False)
