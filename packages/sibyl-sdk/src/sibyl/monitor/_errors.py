"""Errors raised by the monitor client. None of them ever carries the monitor key."""

from __future__ import annotations

from typing import Any


class MonitorError(Exception):
    """Base class of every ``sibyl.monitor`` error."""


class MonitorConfigError(MonitorError, ValueError):
    """Missing or malformed configuration (``SIBYL_API_URL``, ``SIBYL_MONITOR_KEY``)."""


class WebhookSignatureError(MonitorError, ValueError):
    """A webhook delivery whose ``Sibyl-Signature`` is missing, stale or does not match."""


class MonitorApiError(MonitorError):
    """An RFC 9457 problem returned by the Sibyl control plane.

    ``code`` is the problem code (the last segment of ``type``, e.g. ``not_found``,
    ``rate_limited``, ``not_active``); ``retry_after`` is set on 429 / 503 when the server sent
    ``Retry-After``.
    """

    def __init__(
        self,
        status: int,
        code: str,
        title: str | None = None,
        detail: str | None = None,
        *,
        retry_after: float | None = None,
        request_id: str | None = None,
        extensions: dict[str, Any] | None = None,
    ) -> None:
        self.status = status
        self.code = code
        self.title = title
        self.detail = detail
        self.retry_after = retry_after
        self.request_id = request_id
        self.extensions = dict(extensions or {})
        super().__init__(self._message())

    def _message(self) -> str:
        text = f"Sibyl API {self.status} {self.code}"
        if self.detail:
            text += f": {self.detail}"
        elif self.title:
            text += f": {self.title}"
        return text

    def __repr__(self) -> str:
        return f"MonitorApiError(status={self.status}, code={self.code!r})"
