"""B-09: a pending hold is reported with ``decided_at: null``; the SDK must accept it."""

from __future__ import annotations

from sibyl_schemas.action_gate import HeldActionStatus

HELD_ID = "0192aaaa-0000-7000-8000-000000000001"


def test_pending_hold_with_null_decided_at_parses() -> None:
    status = HeldActionStatus.model_validate(
        {
            "held_action_id": HELD_ID,
            "state": "pending",
            "expires_at": "2026-10-12T10:00:00Z",
            "decided_at": None,
            "reason": None,
        }
    )
    assert status.decided_at is None
    assert status.reason is None


def test_decided_hold_keeps_timestamp() -> None:
    status = HeldActionStatus.model_validate(
        {"held_action_id": HELD_ID, "state": "approved", "decided_at": "2026-10-12T10:00:00Z"}
    )
    assert status.decided_at is not None
