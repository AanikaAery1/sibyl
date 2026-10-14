"""Lane S request plumbing: the saga ``Env`` takes its gates from ``Settings``, and the saga actor
comes from ``core.audit.audit_actor`` (G0-4 / G0-6)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from sibyl_control.api.deps import Services
from sibyl_control.api.incidents.common import actor_of, api_env
from sibyl_control.core.authz import Principal, PrincipalKind
from sibyl_control.core.settings import Settings


def _ctx(settings: Settings | None, principal: Principal | None = None) -> Any:
    services = Services(settings=settings)
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(services=services)), state=SimpleNamespace()
    )
    return SimpleNamespace(request=request, principal=principal)


def test_api_env_takes_band_ramp_and_demo_from_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIBYL_PREDICTED_AUTOMATION_BAND", "0.60")
    monkeypatch.setenv("SIBYL_FAILBACK_RAMP", "1")
    default = api_env(_ctx(None))  # no Settings on the app: the Settings defaults, no env read
    assert (default.automation_band, default.failback_ramp, default.demo_mode) == (
        "0.90",
        False,
        False,
    )
    tuned = api_env(_ctx(Settings(predicted_automation_band="0.60", failback_ramp=True, demo=True)))
    assert (tuned.automation_band, tuned.failback_ramp, tuned.demo_mode) == ("0.60", True, True)
    assert tuned.worker_id == "api" and tuned.can_build_handoff is False


def test_actor_of_attributes_keys_as_api_key_and_humans_with_their_session() -> None:
    tenant, key_id, user, session = uuid4(), uuid4(), uuid4(), uuid4()
    key = actor_of(_ctx(None, Principal(PrincipalKind.API_KEY, tenant, key_id)))
    assert (key.kind, key.key_id, key.user_id, key.session_id) == ("api_key", key_id, None, None)
    assert key.audit_fields() == {
        "actor_type": "api_key",
        "actor_id": None,
        "actor_key_id": key_id,
        "actor_session_id": None,
    }
    human = actor_of(_ctx(None, Principal(PrincipalKind.SESSION, tenant, user, session_id=session)))
    assert (human.kind, human.user_id, human.session_id, human.key_id) == (
        "human",
        user,
        session,
        None,
    )


def test_incident_health_evidence_strips_engine_bookkeeping() -> None:
    """B-04: the incident's health evidence shows the snapshot's rules, never the engine's
    ``_hysteresis`` / ``_clamp`` rows (ML.md §3.6)."""
    from datetime import UTC, datetime

    from sibyl_control.api.incidents.views import _health_view

    rule = {"rule": "error_rate", "penalty": 40, "explanation": "errors"}
    row = {
        "id": uuid4(),
        "score": 0,
        "band": "failed",
        "evaluated_at": datetime(2026, 10, 14, tzinfo=UTC),
        "factors": [
            rule,
            {"rule": "_hysteresis", "band": "failed"},
            {"rule": "_clamp", "penalty": 5},
        ],
    }
    view = _health_view(row)
    assert view is not None and view["factors"] == [rule]
