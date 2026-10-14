"""Verify a Sibyl monitor webhook delivery (``Sibyl-Signature: t=<unix>,v1=<hex>``)."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any, Final

from sibyl_schemas import values as sv
from sibyl_schemas.webhook_signature import (
    SIGNATURE_HEADER,
    SIGNATURE_TOLERANCE_S,
    SignatureError,
    verify,
)

from ._errors import WebhookSignatureError

WEBHOOK_EVENT_TYPES: Final = frozenset(str(e.value) for e in sv.WebhookEventType)
"""Every ``Sibyl-Event-Type`` a delivery may carry (``ping`` is the test delivery)."""


def _signature(headers_or_signature: Mapping[str, str] | str | None) -> str | None:
    if headers_or_signature is None or isinstance(headers_or_signature, str):
        return headers_or_signature
    wanted = SIGNATURE_HEADER.lower()
    for name, value in headers_or_signature.items():
        if name.lower() == wanted:
            return value
    return None


def verify_webhook(
    secret: str | bytes | Iterable[str | bytes],
    headers_or_signature: Mapping[str, str] | str | None,
    body: bytes,
    *,
    tolerance_s: int = SIGNATURE_TOLERANCE_S,
    now: float | None = None,
) -> dict[str, Any]:
    """Check the signature over the **raw** request body, then return the JSON event.

    ``secret`` may be several secrets while one is being rotated. Raises
    ``WebhookSignatureError`` (missing, malformed, stale or mismatched signature, or a body
    that is not a JSON object). The secret never appears in the error.
    """
    try:
        verify(secret, _signature(headers_or_signature), body, tolerance_s=tolerance_s, now=now)
    except SignatureError as exc:
        raise WebhookSignatureError(str(exc)) from None
    try:
        event = json.loads(body)
    except ValueError:
        raise WebhookSignatureError("the webhook body is not JSON") from None
    if not isinstance(event, dict):
        raise WebhookSignatureError("the webhook body is not a JSON object")
    return event
