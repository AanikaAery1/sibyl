"""A small in-process S3 double for ``httpx.MockTransport``.

Implements the five calls the adapter makes (PUT with ``If-None-Match: *``, GET, HEAD, DELETE,
ListObjectsV2 with continuation) and rejects any request whose SigV4 signature, date scope or
payload hash is wrong. Faults can be injected per method to exercise retries.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit
from xml.sax.saxutils import escape

import httpx
from sibyl_control.core.blob.s3 import EMPTY_SHA256, S3Config, sigv4_authorization


@dataclass
class StoredObject:
    data: bytes
    content_type: str
    meta: dict[str, str]


@dataclass
class FakeS3:
    config: S3Config
    page_size: int = 1000
    objects: dict[str, StoredObject] = field(default_factory=dict)
    faults: dict[str, list[int]] = field(default_factory=dict)
    requests: list[httpx.Request] = field(default_factory=list)
    on_put: Callable[[str], None] | None = None

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        pending = self.faults.get(request.method)
        if pending:
            return httpx.Response(pending.pop(0))
        if not self._authorised(request):
            return httpx.Response(403, text="<Error><Code>SignatureDoesNotMatch</Code></Error>")
        path = urlsplit(str(request.url)).path
        bucket, _, key = path.lstrip("/").partition("/")
        if bucket != self.config.bucket:
            return httpx.Response(404, text="<Error><Code>NoSuchBucket</Code></Error>")
        if not key:
            return self._list(request)
        handler = {"PUT": self._put, "GET": self._get, "HEAD": self._head, "DELETE": self._delete}
        return handler[request.method](request, key)

    def _authorised(self, request: httpx.Request) -> bool:
        auth = request.headers.get("authorization")
        if auth is None:
            return False
        body = request.content
        claimed = request.headers.get("x-amz-content-sha256")
        if claimed != hashlib.sha256(body).hexdigest():
            return False
        signed = auth.split("SignedHeaders=")[1].split(",")[0].split(";")
        headers = {name: request.headers[name] for name in signed if name != "host"}
        expected = sigv4_authorization(
            request.method,
            str(request.url),
            headers,
            claimed,
            config=self.config,
            amz_date=request.headers["x-amz-date"],
        )
        return expected == auth

    def _put(self, request: httpx.Request, key: str) -> httpx.Response:
        if request.headers.get("if-none-match") == "*" and key in self.objects:
            return httpx.Response(412, text="<Error><Code>PreconditionFailed</Code></Error>")
        meta = {
            k[len("x-amz-meta-") :]: v
            for k, v in request.headers.items()
            if k.startswith("x-amz-meta-")
        }
        self.objects[key] = StoredObject(request.content, request.headers["content-type"], meta)
        if self.on_put is not None:
            self.on_put(key)
        return httpx.Response(
            200,
            headers={
                "etag": f'"{hashlib.md5(request.content, usedforsecurity=False).hexdigest()}"'
            },
        )

    def _headers(self, obj: StoredObject) -> dict[str, str]:
        out = {"content-type": obj.content_type, "content-length": str(len(obj.data))}
        out.update({f"x-amz-meta-{k}": v for k, v in obj.meta.items()})
        return out

    def _get(self, request: httpx.Request, key: str) -> httpx.Response:
        obj = self.objects.get(key)
        if obj is None:
            return httpx.Response(404, text="<Error><Code>NoSuchKey</Code></Error>")
        return httpx.Response(200, content=obj.data, headers=self._headers(obj))

    def _head(self, request: httpx.Request, key: str) -> httpx.Response:
        obj = self.objects.get(key)
        if obj is None:
            return httpx.Response(404)
        return httpx.Response(200, headers=self._headers(obj))

    def _delete(self, request: httpx.Request, key: str) -> httpx.Response:
        self.objects.pop(key, None)
        return httpx.Response(204)

    def _list(self, request: httpx.Request) -> httpx.Response:
        query = dict(parse_qsl(urlsplit(str(request.url)).query))
        assert query.get("list-type") == "2"
        prefix = query.get("prefix", "")
        limit = min(int(query.get("max-keys", "1000")), self.page_size)
        keys = sorted(k for k in self.objects if k.startswith(prefix))
        start = query.get("continuation-token")
        if start:
            keys = [k for k in keys if k > start]
        page, rest = keys[:limit], keys[limit:]
        contents = "".join(f"<Contents><Key>{escape(k)}</Key></Contents>" for k in page)
        token = f"<NextContinuationToken>{escape(page[-1])}</NextContinuationToken>" if rest else ""
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            f"<IsTruncated>{'true' if rest else 'false'}</IsTruncated>{contents}{token}"
            "</ListBucketResult>"
        )
        return httpx.Response(200, text=xml, headers={"content-type": "application/xml"})


__all__ = ["EMPTY_SHA256", "FakeS3"]
