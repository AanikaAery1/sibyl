"""OIDC relying-party client: discovery, JWKS, code exchange (PKCE), token verification.

Sibyl is an RP only (ADR-8). Discovery and JWKS are fetched server-side through
``rewrite`` (``Settings.oidc_internal``: public dex URL → in-network URL) and cached; the
discovery document's ``issuer`` must equal the configured ``issuer_url`` exactly. An unknown
``kid`` triggers at most one JWKS refresh per ``REFRESH_COOLDOWN_S`` (key rotation without a
refetch storm). Every failure is an ``OidcError`` whose ``cause`` goes to ``access.login_failed``.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx

from .jose import JoseError, has_key_for, parse_compact, validate_claims, verify_signature

METADATA_TTL_S = 3600
REFRESH_COOLDOWN_S = 30
HTTP_TIMEOUT_S = 5.0
MAX_DOC_BYTES = 256 * 1024


class OidcError(Exception):
    def __init__(self, cause: str) -> None:
        super().__init__(cause)
        self.cause = cause


@dataclass(frozen=True)
class ProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


@dataclass
class _Cached:
    value: Any
    fetched: float


def _identity(url: str) -> str:
    return url


class OidcClient:
    def __init__(
        self,
        http: httpx.AsyncClient,
        *,
        rewrite: Callable[[str], str] = _identity,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._http = http
        self._rewrite = rewrite
        self._clock = clock
        self._meta: dict[str, _Cached] = {}
        self._jwks: dict[str, _Cached] = {}
        self._forced: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _get_json(self, url: str) -> dict[str, Any]:
        try:
            resp = await self._http.get(self._rewrite(url), timeout=HTTP_TIMEOUT_S)
        except httpx.HTTPError:
            raise OidcError("issuer_unreachable") from None
        if resp.status_code != 200 or len(resp.content) > MAX_DOC_BYTES:
            raise OidcError("issuer_bad_response")
        try:
            doc = resp.json()
        except ValueError:
            raise OidcError("issuer_bad_response") from None
        if not isinstance(doc, dict):
            raise OidcError("issuer_bad_response")
        return doc

    async def metadata(self, issuer_url: str) -> ProviderMetadata:
        cached = self._meta.get(issuer_url)
        if cached is not None and self._clock() - cached.fetched < METADATA_TTL_S:
            meta: ProviderMetadata = cached.value
            return meta
        doc = await self._get_json(issuer_url.rstrip("/") + "/.well-known/openid-configuration")
        if doc.get("issuer") != issuer_url:
            raise OidcError("issuer_mismatch")
        try:
            meta = ProviderMetadata(
                issuer=doc["issuer"],
                authorization_endpoint=str(doc["authorization_endpoint"]),
                token_endpoint=str(doc["token_endpoint"]),
                jwks_uri=str(doc["jwks_uri"]),
            )
        except KeyError:
            raise OidcError("issuer_bad_response") from None
        self._meta[issuer_url] = _Cached(meta, self._clock())
        return meta

    async def jwks(self, issuer_url: str, *, refresh: bool = False) -> Mapping[str, Any]:
        cached = self._jwks.get(issuer_url)
        now = self._clock()
        fresh = cached is not None and now - cached.fetched < METADATA_TTL_S
        last_forced = self._forced.get(issuer_url)
        cooling = last_forced is not None and now - last_forced < REFRESH_COOLDOWN_S
        if cached is not None and ((fresh and not refresh) or (refresh and cooling)):
            keys: Mapping[str, Any] = cached.value
            return keys
        async with self._lock:
            if refresh:
                self._forced[issuer_url] = now
            meta = await self.metadata(issuer_url)
            doc = await self._get_json(meta.jwks_uri)
            if not isinstance(doc.get("keys"), list):
                raise OidcError("issuer_bad_response")
            self._jwks[issuer_url] = _Cached(doc, self._clock())
            return doc

    async def exchange_code(
        self,
        meta: ProviderMetadata,
        *,
        code: str,
        verifier: str,
        redirect_uri: str,
        client_id: str,
        client_secret: str | None,
    ) -> dict[str, Any]:
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": redirect_uri,
        }
        auth: tuple[str, str] | None = None
        if client_secret:
            auth = (client_id, client_secret)
        else:
            form["client_id"] = client_id
        try:
            resp = await self._http.post(
                self._rewrite(meta.token_endpoint),
                data=form,
                auth=auth,  # type: ignore[arg-type]
                headers={"Accept": "application/json"},
                timeout=HTTP_TIMEOUT_S,
            )
        except httpx.HTTPError:
            raise OidcError("issuer_unreachable") from None
        if resp.status_code != 200:
            raise OidcError("token_exchange_failed")
        try:
            tokens = resp.json()
        except ValueError:
            raise OidcError("token_exchange_failed") from None
        if not isinstance(tokens, dict) or not isinstance(tokens.get("id_token"), str):
            raise OidcError("no_id_token")
        return tokens

    async def verify(
        self,
        token: str,
        *,
        issuer_url: str,
        audience: str,
        now: datetime,
        nonce: str | None = None,
        max_lifetime_s: int | None = None,
    ) -> dict[str, Any]:
        """Verify signature (JWKS of ``issuer_url``) and claims; returns the claims."""
        try:
            compact = parse_compact(token)
            jwks = await self.jwks(issuer_url)
            if not has_key_for(compact, jwks):
                jwks = await self.jwks(issuer_url, refresh=True)
            verify_signature(compact, jwks)
            validate_claims(
                compact.claims,
                issuer=issuer_url,
                audience=audience,
                now=now,
                nonce=nonce,
                max_lifetime_s=max_lifetime_s,
            )
        except JoseError as exc:
            raise OidcError(exc.cause) from None
        return compact.claims
