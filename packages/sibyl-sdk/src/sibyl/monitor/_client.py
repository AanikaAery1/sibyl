"""``sibyl.monitor.Client`` (sync) and ``AsyncClient``: an external monitor's view of Sibyl.

Both speak to the control plane with a monitor-bound key (``monitor:read`` +
``findings:write``): metadata reads within the monitor's watched agent groups, and advisory
findings. The key lives in a private attribute and never appears in a repr, an error or a log
line. TLS verification is always on (``ca_file`` adds a CA bundle; ``SSL_CERT_FILE`` is honoured).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping
from typing import Any
from uuid import UUID

import httpx

from . import _routes as r
from ._http import (
    DEFAULT_TIMEOUT_S,
    JSON,
    MAX_PAGES,
    Page,
    Req,
    build,
    check_key,
    finding_body,
    from_env,
    headers,
    key_hint,
    normalise_base_url,
    parse,
    recommendation_fields,
    submit,
    tls_verify,
)

Id = UUID | str


class _Secret:
    """Holds the key; its repr is masked so tracebacks and ``vars()`` never show it."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"<secret {key_hint(self._value)}>"


class _Base:
    def __init__(self, api_url: str, api_key: str) -> None:
        self.base_url = normalise_base_url(api_url)
        self._key = _Secret(check_key(api_key))
        self.key_hint = key_hint(self._key.reveal())

    def _headers(self) -> dict[str, str]:
        return headers(self._key.reveal())

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base_url={self.base_url!r}, key={self.key_hint!r})"


def _finding(
    kind: str,
    subject_kind: str,
    severity: str,
    summary: str,
    subject_id: Id | None,
    extra: Mapping[str, Any],
) -> JSON:
    return finding_body(
        kind=kind,
        subject_kind=subject_kind,
        severity=severity,
        summary=summary,
        subject_id=str(subject_id) if subject_id is not None else None,
        **extra,
    )


class Client(_Base):
    """Synchronous monitor client. Use as a context manager or call ``close()``."""

    def __init__(
        self,
        api_url: str,
        api_key: str,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
        ca_file: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        super().__init__(api_url, api_key)
        self._http = httpx.Client(
            base_url=self.base_url,
            headers=self._headers(),
            timeout=timeout,
            verify=tls_verify(ca_file),
            follow_redirects=False,
            transport=transport,
        )

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None, **kw: Any) -> Client:
        """``SIBYL_API_URL`` + ``SIBYL_MONITOR_KEY``."""
        url, key = from_env(environ)
        return cls(url, key, **kw)

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    def _send(self, req: Req) -> Any:
        return parse(self._http.request(req.method, req.path, **build(req)))

    # reads
    def list_agents(self, *, limit: int | None = None, cursor: str | None = None, **f: Any) -> Page:
        result: Page = self._send(r.list_agents(limit, cursor, f))
        return result

    def get_agent(self, agent_id: Id) -> JSON:
        result: JSON = self._send(r.get_agent(agent_id))
        return result

    def get_fleet_health(self, **f: Any) -> JSON:
        result: JSON = self._send(r.get_fleet_health(f))
        return result

    def get_health(self, agent_id: Id, *, verbose: bool | None = None) -> JSON:
        result: JSON = self._send(r.get_health(agent_id, verbose))
        return result

    def list_runs(self, *, limit: int | None = None, cursor: str | None = None, **f: Any) -> Page:
        result: Page = self._send(r.list_runs(limit, cursor, f))
        return result

    def get_run(self, run_id: Id) -> JSON:
        result: JSON = self._send(r.get_run(run_id))
        return result

    def get_drift(self, agent_id: Id, *, since: Any = None, limit: int | None = None) -> JSON:
        result: JSON = self._send(r.get_drift(agent_id, since, limit))
        return result

    def list_alerts(self, *, limit: int | None = None, cursor: str | None = None, **f: Any) -> Page:
        result: Page = self._send(r.list_alerts(limit, cursor, f))
        return result

    def get_alert(self, alert_id: Id) -> JSON:
        result: JSON = self._send(r.get_alert(alert_id))
        return result

    def list_incidents(
        self, *, limit: int | None = None, cursor: str | None = None, **f: Any
    ) -> Page:
        result: Page = self._send(r.list_incidents(limit, cursor, f))
        return result

    def get_incident(self, incident_id: Id) -> JSON:
        result: JSON = self._send(r.get_incident(incident_id))
        return result

    def list_held_actions(
        self, *, limit: int | None = None, cursor: str | None = None, **f: Any
    ) -> Page:
        result: Page = self._send(r.list_held_actions(limit, cursor, f))
        return result

    def get_held_action(self, held_action_id: Id) -> JSON:
        result: JSON = self._send(r.get_held_action(held_action_id))
        return result

    def list_findings(
        self, *, limit: int | None = None, cursor: str | None = None, **f: Any
    ) -> Page:
        result: Page = self._send(r.list_findings(limit, cursor, f))
        return result

    def get_finding(self, finding_id: Id) -> JSON:
        result: JSON = self._send(r.get_finding(finding_id))
        return result

    def whoami(self) -> JSON:
        """The monitor this key is bound to (``GET /monitors/self``)."""
        result: JSON = self._send(r.get_monitor_self())
        return result

    # writes (advisory)
    def submit_finding(
        self,
        *,
        kind: str,
        subject_kind: str,
        severity: str,
        summary: str,
        subject_id: Id | None = None,
        idempotency_key: str | None = None,
        **extra: Any,
    ) -> JSON:
        """POST /findings. ``extra``: body, recommendation, advice, confidence, provider, model,
        raise_alert. Validated client-side; a fresh Idempotency-Key unless one is given."""
        body = _finding(kind, subject_kind, severity, summary, subject_id, extra)
        result: JSON = self._send(submit(body, idempotency_key))
        return result

    def recommend_on_held_action(
        self,
        held_action_id: Id,
        advice: str,
        recommendation: str,
        *,
        severity: str = "warning",
        summary: str | None = None,
        idempotency_key: str | None = None,
        **extra: Any,
    ) -> JSON:
        """An advisory ``held_action_review`` finding; it never decides the hold."""
        fields = recommendation_fields(
            held_action_id, advice, recommendation, summary, severity, extra
        )
        body = finding_body(**fields)
        result: JSON = self._send(submit(body, idempotency_key))
        return result


class AsyncClient(_Base):
    """Asynchronous monitor client (same methods as ``Client``, awaited)."""

    def __init__(
        self,
        api_url: str,
        api_key: str,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
        ca_file: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(api_url, api_key)
        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            headers=self._headers(),
            timeout=timeout,
            verify=tls_verify(ca_file),
            follow_redirects=False,
            transport=transport,
        )

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None, **kw: Any) -> AsyncClient:
        url, key = from_env(environ)
        return cls(url, key, **kw)

    async def __aenter__(self) -> AsyncClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _send(self, req: Req) -> Any:
        return parse(await self._http.request(req.method, req.path, **build(req)))

    async def list_agents(
        self, *, limit: int | None = None, cursor: str | None = None, **f: Any
    ) -> Page:
        result: Page = await self._send(r.list_agents(limit, cursor, f))
        return result

    async def get_agent(self, agent_id: Id) -> JSON:
        result: JSON = await self._send(r.get_agent(agent_id))
        return result

    async def get_fleet_health(self, **f: Any) -> JSON:
        result: JSON = await self._send(r.get_fleet_health(f))
        return result

    async def get_health(self, agent_id: Id, *, verbose: bool | None = None) -> JSON:
        result: JSON = await self._send(r.get_health(agent_id, verbose))
        return result

    async def list_runs(
        self, *, limit: int | None = None, cursor: str | None = None, **f: Any
    ) -> Page:
        result: Page = await self._send(r.list_runs(limit, cursor, f))
        return result

    async def get_run(self, run_id: Id) -> JSON:
        result: JSON = await self._send(r.get_run(run_id))
        return result

    async def get_drift(self, agent_id: Id, *, since: Any = None, limit: int | None = None) -> JSON:
        result: JSON = await self._send(r.get_drift(agent_id, since, limit))
        return result

    async def list_alerts(
        self, *, limit: int | None = None, cursor: str | None = None, **f: Any
    ) -> Page:
        result: Page = await self._send(r.list_alerts(limit, cursor, f))
        return result

    async def get_alert(self, alert_id: Id) -> JSON:
        result: JSON = await self._send(r.get_alert(alert_id))
        return result

    async def list_incidents(
        self, *, limit: int | None = None, cursor: str | None = None, **f: Any
    ) -> Page:
        result: Page = await self._send(r.list_incidents(limit, cursor, f))
        return result

    async def get_incident(self, incident_id: Id) -> JSON:
        result: JSON = await self._send(r.get_incident(incident_id))
        return result

    async def list_held_actions(
        self, *, limit: int | None = None, cursor: str | None = None, **f: Any
    ) -> Page:
        result: Page = await self._send(r.list_held_actions(limit, cursor, f))
        return result

    async def get_held_action(self, held_action_id: Id) -> JSON:
        result: JSON = await self._send(r.get_held_action(held_action_id))
        return result

    async def list_findings(
        self, *, limit: int | None = None, cursor: str | None = None, **f: Any
    ) -> Page:
        result: Page = await self._send(r.list_findings(limit, cursor, f))
        return result

    async def get_finding(self, finding_id: Id) -> JSON:
        result: JSON = await self._send(r.get_finding(finding_id))
        return result

    async def whoami(self) -> JSON:
        """The monitor this key is bound to (``GET /monitors/self``)."""
        result: JSON = await self._send(r.get_monitor_self())
        return result

    async def submit_finding(
        self,
        *,
        kind: str,
        subject_kind: str,
        severity: str,
        summary: str,
        subject_id: Id | None = None,
        idempotency_key: str | None = None,
        **extra: Any,
    ) -> JSON:
        body = _finding(kind, subject_kind, severity, summary, subject_id, extra)
        result: JSON = await self._send(submit(body, idempotency_key))
        return result

    async def recommend_on_held_action(
        self,
        held_action_id: Id,
        advice: str,
        recommendation: str,
        *,
        severity: str = "warning",
        summary: str | None = None,
        idempotency_key: str | None = None,
        **extra: Any,
    ) -> JSON:
        fields = recommendation_fields(
            held_action_id, advice, recommendation, summary, severity, extra
        )
        body = finding_body(**fields)
        result: JSON = await self._send(submit(body, idempotency_key))
        return result


def paginate(
    list_method: Callable[..., Page], *, max_pages: int = MAX_PAGES, **kwargs: Any
) -> Iterator[JSON]:
    """Yield every item of a ``Client.list_*`` method, following ``next_cursor`` (bounded)."""
    cursor: str | None = kwargs.pop("cursor", None)
    for _ in range(max_pages):
        page = list_method(cursor=cursor, **kwargs)
        yield from page.get("data") or []
        cursor = page.get("next_cursor")
        if not page.get("has_more") or not cursor:
            return


async def apaginate(
    list_method: Callable[..., Awaitable[Page]], *, max_pages: int = MAX_PAGES, **kwargs: Any
) -> AsyncIterator[JSON]:
    """``paginate`` for ``AsyncClient.list_*`` methods."""
    cursor: str | None = kwargs.pop("cursor", None)
    for _ in range(max_pages):
        page = await list_method(cursor=cursor, **kwargs)
        for item in page.get("data") or []:
            yield item
        cursor = page.get("next_cursor")
        if not page.get("has_more") or not cursor:
            return
