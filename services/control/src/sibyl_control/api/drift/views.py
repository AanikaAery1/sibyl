"""Row -> document mapping for the drift API (``sibyl_schemas.models.drift`` shapes)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from sibyl_schemas.models import drift as dm


def _list(value: Any) -> list[Any]:
    return list(value or [])


def baseline(row: Mapping[str, Any]) -> dict[str, Any]:
    doc = dm.DriftBaseline(
        id=row["id"],
        agent_id=row["agent_id"],
        provider=row["provider"],
        model=row["model"],
        state=row["state"],
        window_start=row["window_start"],
        window_end=row["window_end"],
        sample_count=row["sample_count"],
        tool_sample_count=row["tool_sample_count"],
        frozen_at=row["frozen_at"],
        served_models=_list(row["served_models"]),
        fingerprints=_list(row["fingerprints"]),
        features=dict(row["features"] or {}),
        reset_by_user_id=row["reset_by_user_id"],
        reset_reason=row["reset_reason"],
        supersedes=row["supersedes"],
        superseded_by=row["superseded_by"],
        superseded_at=row["superseded_at"],
        last_evaluated_at=row["last_evaluated_at"],
        created_at=row["created_at"],
    )
    return doc.model_dump(mode="json")


def report_summary(row: Mapping[str, Any]) -> dict[str, Any]:
    return dm.DriftReportSummary(
        id=row["id"],
        baseline_id=row["baseline_id"],
        evaluated_at=row["evaluated_at"],
        verdict=row["verdict"],
        behaviour_evaluated=row["behaviour_evaluated"],
        identity_changed=row["identity_changed"],
        max_ratio=float(row["max_ratio"]),
        sample_count=row["sample_count"],
    ).model_dump(mode="json")


def report(row: Mapping[str, Any]) -> dict[str, Any]:
    return dm.DriftReport(
        id=row["id"],
        baseline_id=row["baseline_id"],
        agent_id=row["agent_id"],
        provider=row["provider"],
        model=row["model"],
        evaluated_at=row["evaluated_at"],
        window_start=row["window_start"],
        window_end=row["window_end"],
        sample_count=row["sample_count"],
        tool_sample_count=row["tool_sample_count"],
        verdict=row["verdict"],
        behaviour_evaluated=row["behaviour_evaluated"],
        identity_changed=row["identity_changed"],
        max_ratio=float(row["max_ratio"]),
        features=[dm.DriftFeatureResult.model_validate(f) for f in _list(row["features"])],
        identity=[dm.DriftIdentityFinding.model_validate(i) for i in _list(row["identity"])],
        config=dict(row["config"] or {}),
    ).model_dump(mode="json")


def drifting(features: Sequence[Mapping[str, Any]] | None) -> list[str]:
    return [str(f["feature"]) for f in features or () if f.get("verdict") == "drift"]


def key_summary(row: Mapping[str, Any]) -> dict[str, Any]:
    return dm.DriftKeySummary(
        baseline_id=row["id"],
        agent_id=row["agent_id"],
        agent_name=row["agent_name"],
        provider=row["provider"],
        model=row["model"],
        state=row["state"],
        frozen_at=row["frozen_at"],
        sample_count=row["sample_count"],
        report_id=row["report_id"],
        evaluated_at=row["evaluated_at"],
        verdict=row["verdict"],
        identity_changed=bool(row["identity_changed"]),
        max_ratio=None if row["max_ratio"] is None else float(row["max_ratio"]),
        drifting_features=drifting(row["features"]),
        created_at=row["created_at"],
    ).model_dump(mode="json")


def alert_ref(row: Mapping[str, Any]) -> dict[str, Any]:
    return dm.DriftAlertRef(
        id=row["id"],
        rule=row["code"],
        severity=row["severity"],
        state=row["state"],
        first_fired_at=row["first_fired_at"],
        summary=row["summary"],
    ).model_dump(mode="json")


def summary(row: Mapping[str, Any]) -> dict[str, Any]:
    return dm.FleetDriftSummary(
        **{key: int(row[key] or 0) for key in dm.FleetDriftSummary.model_fields}
    ).model_dump(mode="json")
