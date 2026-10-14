"""verify_webhook: good, tampered, stale, rotated secrets, header lookup."""

from __future__ import annotations

import json

import pytest
from sibyl.monitor import WEBHOOK_EVENT_TYPES, WebhookSignatureError, verify_webhook
from sibyl_schemas.webhook_signature import signature_header

SECRET = "whsec_" + "a" * 43
OTHER = "whsec_" + "b" * 43
NOW = 1_800_000_000
BODY = json.dumps({"type": "run.failed", "data": {"run_id": "r1"}}).encode()


def _sig(secret: str = SECRET, body: bytes = BODY, ts: int = NOW) -> str:
    return signature_header(secret, body, timestamp=ts)


def test_valid_signature_returns_event() -> None:
    event = verify_webhook(SECRET, {"Sibyl-Signature": _sig()}, BODY, now=NOW)
    assert event["type"] == "run.failed"
    assert verify_webhook(SECRET, {"sibyl-signature": _sig()}, BODY, now=NOW + 10)
    assert verify_webhook(SECRET, _sig(), BODY, now=NOW)


def test_rotated_secrets() -> None:
    assert verify_webhook([OTHER, SECRET], _sig(), BODY, now=NOW)
    with pytest.raises(WebhookSignatureError):
        verify_webhook([OTHER], _sig(), BODY, now=NOW)


@pytest.mark.parametrize(
    ("header", "body", "now"),
    [
        (None, BODY, NOW),
        ("garbage", BODY, NOW),
        (_sig(), BODY + b" ", NOW),
        (_sig(OTHER), BODY, NOW),
        (_sig(), BODY, NOW + 301),
        (_sig(), BODY, NOW - 301),
    ],
)
def test_rejections(header: str | None, body: bytes, now: int) -> None:
    with pytest.raises(WebhookSignatureError) as info:
        verify_webhook(SECRET, header, body, now=now)
    assert SECRET not in str(info.value)


def test_missing_header_in_mapping_and_non_object_body() -> None:
    with pytest.raises(WebhookSignatureError):
        verify_webhook(SECRET, {"X-Other": "1"}, BODY, now=NOW)
    for raw in (b"[1]", b"not json"):
        with pytest.raises(WebhookSignatureError):
            verify_webhook(SECRET, _sig(body=raw), raw, now=NOW)


def test_event_types_exported() -> None:
    assert {"alert.fired", "run.failed", "action.held", "ping"} <= WEBHOOK_EVENT_TYPES
