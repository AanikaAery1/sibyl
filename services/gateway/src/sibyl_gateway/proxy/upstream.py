"""The single outbound HTTP client: timeouts on every phase, no redirects, no env proxies,
connect-time SSRF guard. ``ttfb_s`` is the read timeout (API §3.5: 504 ``upstream_timeout``)."""

from __future__ import annotations

import ssl
from collections.abc import Iterable
from dataclasses import dataclass

import httpcore
import httpx

from .ssrf import GuardedBackend, is_allowlisted_base_url


@dataclass(frozen=True)
class UpstreamSettings:
    connect_s: float = 5.0
    ttfb_s: float = 60.0
    write_s: float = 30.0
    pool_s: float = 5.0
    max_connections: int = 512
    max_keepalive: int = 128
    dev_hosts: tuple[str, ...] = ()
    ca_file: str | None = None


class GuardedTransport(httpx.AsyncHTTPTransport):
    def __init__(self, settings: UpstreamSettings) -> None:
        verify: ssl.SSLContext | bool = True
        if settings.ca_file:
            verify = ssl.create_default_context(cafile=settings.ca_file)
        super().__init__(verify=verify, trust_env=False)
        context = verify if isinstance(verify, ssl.SSLContext) else httpx.create_ssl_context()
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=context,
            max_connections=settings.max_connections,
            max_keepalive_connections=settings.max_keepalive,
            keepalive_expiry=30.0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=GuardedBackend(settings.dev_hosts),
        )


class UpstreamClient:
    def __init__(
        self,
        settings: UpstreamSettings | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings or UpstreamSettings()
        s = self.settings
        self.http = httpx.AsyncClient(
            transport=transport or GuardedTransport(s),
            timeout=httpx.Timeout(
                connect=s.connect_s, read=s.ttfb_s, write=s.write_s, pool=s.pool_s
            ),
            follow_redirects=False,
            trust_env=False,
        )

    def allowed(self, base_url: str) -> bool:
        return is_allowlisted_base_url(base_url, self.settings.dev_hosts)

    def build(self, url: str, headers: Iterable[tuple[str, str]], content: bytes) -> httpx.Request:
        return self.http.build_request("POST", url, headers=list(headers), content=content)

    async def send(self, request: httpx.Request) -> httpx.Response:
        return await self.http.send(request, stream=True, follow_redirects=False)

    async def aclose(self) -> None:
        await self.http.aclose()
