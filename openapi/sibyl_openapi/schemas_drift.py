"""D51 model drift schemas (lane DRIFT): baselines, reports, the fleet summary, the reset body.

Enumerations render the ``sibyl_schemas`` value sets inline (single source); the pydantic
twins live in ``sibyl_schemas.models.drift``.
"""

from __future__ import annotations

from enum import Enum

from sibyl_schemas import values as sv
from sibyl_schemas.models import drift as dm

from .dsl import (
    N_TS,
    N_UUID,
    REASON,
    TS,
    UUID,
    Schema,
    array,
    body_obj,
    boolean,
    enum,
    free_object,
    integer,
    nullable,
    obj,
    ref,
    string,
)


def _number() -> Schema:
    return {"type": "number"}


def _provider() -> Schema:
    return string(maxLength=64)


def _model() -> Schema:
    return string(minLength=1, maxLength=256)


def _enum(values: type[Enum]) -> Schema:
    return enum(*(str(m.value) for m in values))


def _verdict() -> Schema:
    return _enum(sv.DriftVerdict)


def _state() -> Schema:
    return _enum(sv.DriftBaselineState)


def _summary_props() -> dict[str, Schema]:
    return {
        "id": UUID,
        "baseline_id": UUID,
        "evaluated_at": TS,
        "verdict": _verdict(),
        "behaviour_evaluated": boolean(description="at least one feature had enough samples"),
        "identity_changed": boolean(),
        "max_ratio": _number(),
        "sample_count": integer(minimum=0),
    }


def _reports() -> dict[str, Schema]:
    summary_required = tuple(_summary_props())
    return {
        "DriftContributor": obj(
            {"label": string(), "baseline": _number(), "window": _number()},
            ("label", "baseline", "window"),
        ),
        "DriftFeatureResult": obj(
            {
                "feature": _enum(sv.DriftFeature),
                "statistic": _enum(sv.DriftStatistic),
                "status": enum("ok", "insufficient_samples", "invalid_baseline"),
                "value": nullable(_number()),
                "noise_floor": _number(),
                "excess": nullable(_number()),
                "watch": _number(),
                "drift": _number(),
                "verdict": _verdict(),
                "n_baseline": integer(minimum=0),
                "n_window": integer(minimum=0),
                "contributors": array(ref("DriftContributor"), maxItems=3),
            },
            ("feature", "statistic", "status", "value", "watch", "drift", "verdict"),
            description="psi: population stability index over the baseline's decile bins;"
            " js: Jensen-Shannon divergence (base 2). The verdict compares the excess over the"
            " sampling noise floor with the watch / drift thresholds",
        ),
        "DriftIdentityFinding": obj(
            {
                "kind": _enum(sv.DriftIdentityChange),
                "value": string(maxLength=128),
                "count": integer(minimum=1),
                "requested_model": string(),
            },
            ("kind", "value", "count", "requested_model"),
        ),
        "DriftReportSummary": obj(_summary_props(), summary_required),
        "DriftReport": obj(
            {
                **_summary_props(),
                "agent_id": UUID,
                "provider": _provider(),
                "model": _model(),
                "window_start": TS,
                "window_end": TS,
                "tool_sample_count": integer(minimum=0),
                "features": array(ref("DriftFeatureResult")),
                "identity": array(ref("DriftIdentityFinding"), maxItems=64),
                "config": free_object("windows, minimum samples and hysteresis used"),
            },
            (*summary_required, "agent_id", "provider", "model", "features", "identity"),
        ),
    }


def _baselines() -> dict[str, Schema]:
    return {
        "DriftBaseline": obj(
            {
                "id": UUID,
                "agent_id": UUID,
                "provider": _provider(),
                "model": _model(),
                "state": _state(),
                "window_start": TS,
                "window_end": N_TS,
                "sample_count": integer(minimum=0),
                "tool_sample_count": integer(minimum=0),
                "frozen_at": N_TS,
                "served_models": array(string(), maxItems=64),
                "fingerprints": array(string(), maxItems=64),
                "features": free_object(
                    "frozen distributions per feature (numeric: edges + probs; categorical:"
                    " probs); empty while collecting"
                ),
                "reset_by_user_id": N_UUID,
                "reset_reason": nullable(string()),
                "supersedes": N_UUID,
                "superseded_by": N_UUID,
                "superseded_at": N_TS,
                "last_evaluated_at": N_TS,
                "created_at": TS,
            },
            ("id", "agent_id", "provider", "model", "state", "window_start", "sample_count"),
        ),
        "DriftAlertRef": obj(
            {
                "id": UUID,
                "rule": enum("silent_drift", "model_change"),
                "severity": ref("AlertSeverity"),
                "state": ref("AlertState"),
                "first_fired_at": TS,
                "summary": string(),
            },
            ("id", "rule", "severity", "state", "first_fired_at"),
        ),
        "DriftKeySummary": obj(
            {
                "baseline_id": UUID,
                "agent_id": UUID,
                "agent_name": string(),
                "provider": _provider(),
                "model": _model(),
                "state": _state(),
                "frozen_at": N_TS,
                "sample_count": integer(minimum=0),
                "report_id": N_UUID,
                "evaluated_at": N_TS,
                "verdict": nullable(_verdict()),
                "identity_changed": boolean(),
                "max_ratio": nullable(_number()),
                "drifting_features": array(_enum(sv.DriftFeature)),
                "created_at": TS,
            },
            ("baseline_id", "agent_id", "provider", "model", "state", "verdict"),
        ),
        "FleetDriftSummary": obj(
            {
                key: integer(minimum=0)
                for key in (
                    "baselines",
                    "collecting",
                    "frozen",
                    "drift",
                    "watch",
                    "identity_changed",
                    "open_alerts",
                )
            },
            ("baselines", "collecting", "frozen", "drift", "watch", "identity_changed"),
        ),
        "AgentDrift": obj(
            {
                "agent_id": UUID,
                "baselines": array(ref("DriftBaseline")),
                "latest": array(ref("DriftReport")),
                "history": array(ref("DriftReportSummary"), maxItems=48),
                "open_alerts": array(ref("DriftAlertRef")),
            },
            ("agent_id", "baselines", "latest", "history", "open_alerts"),
        ),
        "DriftBaselineReset": body_obj(
            {
                "provider": _provider(),
                "model": _model(),
                "since": TS,
                "reason": REASON,
            },
            ("reason",),
            description="supersede the agent's current baselines (or the one for provider /"
            " model) and collect again from since (default now; a past since re-freezes on"
            " recent traffic at the next drift tick)",
        ),
        "DriftBaselineResetResult": obj(
            {
                "agent_id": UUID,
                "superseded": array(UUID),
                "baselines": array(ref("DriftBaseline")),
            },
            ("agent_id", "superseded", "baselines"),
        ),
    }


def _bounded(name: str) -> Schema:
    low, high = dm.THRESHOLD_BOUNDS[name]
    kind: Schema = integer() if isinstance(low, int) else _number()
    return nullable({**kind, "minimum": low, "maximum": high})


def _thresholds() -> dict[str, Schema]:
    names = tuple(dm.THRESHOLD_BOUNDS)
    return {
        "DriftThresholdValue": obj(
            {
                "value": _number(),
                "default": _number(),
                "source": enum("tenant", "default"),
                "minimum": _number(),
                "maximum": _number(),
            },
            ("value", "default", "source", "minimum", "maximum"),
            description="the effective value (the tenant override, else the deployment"
            " default), the default and the accepted inclusive range",
        ),
        "DriftThresholds": obj(
            {
                "values": obj(
                    {name: ref("DriftThresholdValue") for name in names},
                    names,
                ),
                "version": integer(minimum=0, description="0 before the first save"),
                "updated_at": N_TS,
                "updated_by_user_id": N_UUID,
                "watch_only": boolean(),
            },
            ("values", "version", "watch_only"),
        ),
        "DriftThresholdsPut": body_obj(
            {**{name: _bounded(name) for name in names}, "reason": REASON},
            ("reason",),
            description="the tenant's whole override set: a null or omitted value uses the"
            " deployment default (a body with only reason resets every value); each"
            " statistic's effective watch must stay below its effective drift",
        ),
    }


def drift_schemas() -> dict[str, Schema]:
    return {**_reports(), **_baselines(), **_thresholds()}
