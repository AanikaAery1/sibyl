"""S3-API BlobStore (``SIBYL_BLOB_BACKEND=s3``): AWS S3, MinIO, Ceph RGW, R2, moto.

Speaks the S3 REST API directly over ``httpx`` (BSD-3) with AWS Signature Version 4, so no
provider SDK is involved (D14). Calls used: PutObject (``If-None-Match: *`` for create-only
writes), GetObject, HeadObject, DeleteObject, ListObjectsV2 and query-string presigned GETs.
Every request signs its payload hash. Idempotent calls retry transient failures (5xx, 429,
connection errors); a create-only PUT whose response was lost is reconciled on retry by
comparing the stored ``x-amz-meta-sha256`` with ours. Error messages never carry credentials,
response bodies or object contents. Objects are already encrypted by the caller.

Configuration (``S3Config.from_env``): ``SIBYL_S3_ENDPOINT``, ``SIBYL_S3_BUCKET``,
``SIBYL_S3_REGION``, ``SIBYL_S3_ACCESS_KEY_ID``, ``SIBYL_S3_SECRET_ACCESS_KEY``, optional
``SIBYL_S3_SESSION_TOKEN``, ``SIBYL_S3_PREFIX``, ``SIBYL_S3_PATH_STYLE`` (default true) and
``SIBYL_S3_ALLOW_HTTP`` (plain http is otherwise allowed only to loopback).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final
from urllib.parse import quote, unquote, urlencode, urlsplit
from xml.etree import ElementTree

import httpx

from .base import BlobError, BlobExists, BlobInfo, BlobNotFound, validate_key

EMPTY_SHA256: Final = hashlib.sha256(b"").hexdigest()
UNSIGNED_PAYLOAD: Final = "UNSIGNED-PAYLOAD"
MAX_PRESIGN_S: Final = 7 * 24 * 3600
_ALGORITHM: Final = "AWS4-HMAC-SHA256"
_SERVICE: Final = "s3"
_S3_NS: Final = "{http://s3.amazonaws.com/doc/2006-03-01/}"
_RETRYABLE: Final = frozenset({429, 500, 502, 503, 504})
_TRUE: Final = frozenset({"1", "true", "yes", "on"})


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class S3Config:
    endpoint_url: str
    bucket: str
    region: str
    access_key_id: str
    secret_access_key: str = field(repr=False)
    session_token: str | None = field(default=None, repr=False)
    key_prefix: str = ""
    path_style: bool = True
    allow_http: bool = False
    timeout_s: float = 10.0
    max_attempts: int = 3

    def __post_init__(self) -> None:
        parts = urlsplit(self.endpoint_url)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise ValueError("S3 endpoint must be an absolute http(s) URL")
        if parts.scheme == "http" and not (self.allow_http or _is_loopback(parts.hostname)):
            raise ValueError("S3 endpoint must use https (plain http only for loopback)")
        if not self.bucket or "/" in self.bucket:
            raise ValueError("S3 bucket name is required and has no '/'")
        if self.key_prefix:
            validate_key(self.key_prefix.rstrip("/") or "x/")
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> S3Config:
        def need(name: str) -> str:
            value = env.get(name, "")
            if not value:
                raise ValueError(f"{name} is not set")
            return value

        return cls(
            endpoint_url=need("SIBYL_S3_ENDPOINT"),
            bucket=need("SIBYL_S3_BUCKET"),
            region=env.get("SIBYL_S3_REGION", "us-east-1"),
            access_key_id=need("SIBYL_S3_ACCESS_KEY_ID"),
            secret_access_key=need("SIBYL_S3_SECRET_ACCESS_KEY"),
            session_token=env.get("SIBYL_S3_SESSION_TOKEN") or None,
            key_prefix=env.get("SIBYL_S3_PREFIX", ""),
            path_style=env.get("SIBYL_S3_PATH_STYLE", "true").lower() in _TRUE,
            allow_http=env.get("SIBYL_S3_ALLOW_HTTP", "false").lower() in _TRUE,
        )


# -- Signature Version 4 ---------------------------------------------------------------------


def _uri_encode(value: str, *, keep_slash: bool) -> str:
    return quote(value, safe="-_.~/" if keep_slash else "-_.~")


def _canonical_query(query: str) -> str:
    pairs: list[tuple[str, str]] = []
    for item in query.split("&") if query else []:
        name, _, value = item.partition("=")
        pairs.append(
            (
                _uri_encode(unquote(name), keep_slash=False),
                _uri_encode(unquote(value), keep_slash=False),
            )
        )
    return "&".join(f"{k}={v}" for k, v in sorted(pairs))


def _signing_key(secret: str, day: str, region: str) -> bytes:
    key = hmac.new(f"AWS4{secret}".encode(), day.encode(), hashlib.sha256).digest()
    for part in (region, _SERVICE, "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    return key


def _signature(
    method: str,
    url: str,
    headers: Mapping[str, str],
    payload_hash: str,
    *,
    config: S3Config,
    amz_date: str,
    query_override: str | None = None,
) -> tuple[str, str, str]:
    """Return (signed header names, credential scope, hex signature)."""
    parts = urlsplit(url)
    host = parts.netloc
    canonical_headers = {"host": host}
    canonical_headers.update({k.lower(): " ".join(str(v).split()) for k, v in headers.items()})
    names = sorted(canonical_headers)
    signed = ";".join(names)
    query = parts.query if query_override is None else query_override
    canonical = "\n".join(
        [
            method.upper(),
            _uri_encode(unquote(parts.path) or "/", keep_slash=True),
            _canonical_query(query),
            "".join(f"{n}:{canonical_headers[n]}\n" for n in names),
            signed,
            payload_hash,
        ]
    )
    day = amz_date[:8]
    scope = f"{day}/{config.region}/{_SERVICE}/aws4_request"
    to_sign = "\n".join(
        [_ALGORITHM, amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()]
    )
    key = _signing_key(config.secret_access_key, day, config.region)
    return signed, scope, hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()


def sigv4_authorization(
    method: str,
    url: str,
    headers: Mapping[str, str],
    payload_hash: str,
    *,
    config: S3Config,
    amz_date: str,
) -> str:
    """The ``Authorization`` header for a request; ``headers`` excludes ``host``."""
    signed, scope, sig = _signature(
        method, url, headers, payload_hash, config=config, amz_date=amz_date
    )
    return (
        f"{_ALGORITHM} Credential={config.access_key_id}/{scope},"
        f"SignedHeaders={signed},Signature={sig}"
    )


def presign_get_url(url: str, *, config: S3Config, amz_date: str, expires_s: int) -> str:
    if not 1 <= expires_s <= MAX_PRESIGN_S:
        raise ValueError("presigned URLs expire within 1 s .. 7 days")
    day = amz_date[:8]
    params = {
        "X-Amz-Algorithm": _ALGORITHM,
        "X-Amz-Credential": f"{config.access_key_id}/{day}/{config.region}/{_SERVICE}/aws4_request",
        "X-Amz-Date": amz_date,
        "X-Amz-Expires": str(expires_s),
        "X-Amz-SignedHeaders": "host",
    }
    if config.session_token:
        params["X-Amz-Security-Token"] = config.session_token
    query = urlencode(params, quote_via=quote, safe="-_.~")
    _signed, _scope, sig = _signature(
        "GET", url, {}, UNSIGNED_PAYLOAD, config=config, amz_date=amz_date, query_override=query
    )
    return f"{url}?{query}&X-Amz-Signature={sig}"


def _amz_now() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


# -- adapter -----------------------------------------------------------------------------------


class S3BlobStore:
    def __init__(
        self,
        config: S3Config,
        *,
        client: httpx.AsyncClient | None = None,
        retry_backoff_s: float = 0.2,
    ) -> None:
        self.config = config
        self._client = client
        self._own_client = client is None
        self._backoff = retry_backoff_s

    async def aclose(self) -> None:
        if self._own_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.config.timeout_s, follow_redirects=False, trust_env=False
            )
        return self._client

    def _bucket_url(self) -> str:
        parts = urlsplit(self.config.endpoint_url)
        base = f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"
        if self.config.path_style:
            return f"{base}/{self.config.bucket}"
        if parts.netloc.startswith(f"{self.config.bucket}."):
            return base
        return f"{parts.scheme}://{self.config.bucket}.{parts.netloc}{parts.path.rstrip('/')}"

    def object_url(self, key: str) -> str:
        full = self.config.key_prefix + key
        return f"{self._bucket_url()}/{_uri_encode(full, keep_slash=True)}"

    async def _send(
        self,
        method: str,
        url: str,
        *,
        body: bytes = b"",
        headers: Mapping[str, str] | None = None,
        op: str,
    ) -> httpx.Response:
        last: str = "no attempt"
        for attempt in range(self.config.max_attempts):
            if attempt:
                await asyncio.sleep(self._backoff * attempt)
            payload_hash = hashlib.sha256(body).hexdigest()
            amz_date = _amz_now()
            signed = {
                **(headers or {}),
                "x-amz-content-sha256": payload_hash,
                "x-amz-date": amz_date,
            }
            if self.config.session_token:
                signed["x-amz-security-token"] = self.config.session_token
            auth = sigv4_authorization(
                method, url, signed, payload_hash, config=self.config, amz_date=amz_date
            )
            try:
                response = await self._http().request(
                    method, url, content=body, headers={**signed, "authorization": auth}
                )
            except httpx.TransportError as exc:
                last = type(exc).__name__
                continue
            if response.status_code in _RETRYABLE:
                last = f"HTTP {response.status_code}"
                continue
            return response
        raise BlobError(f"s3 {op} failed after {self.config.max_attempts} attempts ({last})")

    @staticmethod
    def _fail(op: str, response: httpx.Response) -> BlobError:
        return BlobError(f"s3 {op} failed: HTTP {response.status_code}")

    async def put(
        self, key: str, data: bytes, *, content_type: str, if_absent: bool = True
    ) -> BlobInfo:
        url = self.object_url(validate_key(key))
        digest = hashlib.sha256(data).hexdigest()
        headers = {"content-type": content_type, "x-amz-meta-sha256": digest}
        if if_absent:
            headers["if-none-match"] = "*"
        response = await self._send("PUT", url, body=data, headers=headers, op="put")
        if response.status_code in (409, 412) and if_absent:
            existing = await self.head(key)
            if existing is not None and existing.sha256 == digest:
                return existing  # our own earlier attempt landed; its response was lost
            raise BlobExists(key)
        if not 200 <= response.status_code < 300:
            raise self._fail("put", response)
        return BlobInfo(key, len(data), digest, content_type)

    async def get(self, key: str) -> bytes:
        response = await self._send("GET", self.object_url(validate_key(key)), op="get")
        if response.status_code == 404:
            raise BlobNotFound(key)
        if response.status_code != 200:
            raise self._fail("get", response)
        return response.content

    async def head(self, key: str) -> BlobInfo | None:
        response = await self._send("HEAD", self.object_url(validate_key(key)), op="head")
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise self._fail("head", response)
        return BlobInfo(
            key,
            int(response.headers.get("content-length", "0")),
            response.headers.get("x-amz-meta-sha256", ""),
            response.headers.get("content-type", "application/octet-stream"),
        )

    async def delete(self, key: str) -> bool:
        if await self.head(key) is None:
            return False
        response = await self._send("DELETE", self.object_url(key), op="delete")
        if response.status_code not in (200, 204, 404):
            raise self._fail("delete", response)
        return response.status_code != 404

    async def list_prefix(self, prefix: str, *, limit: int = 1000) -> list[str]:
        if prefix:
            validate_key(prefix.rstrip("/") or "x/")
        full_prefix = self.config.key_prefix + prefix
        keys: list[str] = []
        token: str | None = None
        while len(keys) < limit:
            params = {
                "list-type": "2",
                "prefix": full_prefix,
                "max-keys": str(min(1000, limit - len(keys))),
            }
            if token:
                params["continuation-token"] = token
            query = urlencode(sorted(params.items()), quote_via=quote, safe="-_.~")
            url = f"{self._bucket_url()}/?{query}"
            response = await self._send("GET", url, op="list")
            if response.status_code != 200:
                raise self._fail("list", response)
            page, token = _parse_list(response.content)
            keys.extend(k[len(self.config.key_prefix) :] for k in page)
            if token is None:
                break
        return sorted(keys)[:limit]

    async def presigned_get(self, key: str, *, expires_s: int) -> str | None:
        return presign_get_url(
            self.object_url(validate_key(key)),
            config=self.config,
            amz_date=_amz_now(),
            expires_s=expires_s,
        )


def _parse_list(body: bytes) -> tuple[list[str], str | None]:
    # The endpoint is operator-configured, not user input; expat refuses external entities.
    root = ElementTree.fromstring(body)  # noqa: S314
    keys = [el.text or "" for el in root.iter(f"{_S3_NS}Key")]
    truncated = (root.findtext(f"{_S3_NS}IsTruncated") or "false") == "true"
    token = root.findtext(f"{_S3_NS}NextContinuationToken") if truncated else None
    return keys, token
