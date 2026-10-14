"""A tiny real-HTTP ingest + snapshot stub for contract tests and the offline example.

It speaks the ingest contract (API §4): gzip JSON in, `200` for OTLP, `202`
`sibyl-ingest-response/1` for `/v1/events`, `X-Sibyl-Replayed: true` for a repeated
`X-Sibyl-Batch-Id` (batch dedupe, §4.3), and serves the signed snapshot and key set.
Response bodies come from the recorded `sibyl-schemas` ingest fixtures. Loopback only.
"""

from __future__ import annotations

import gzip
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx
from sibyl_schemas.golden import load_fixture

from sibyl.testing import OffsetClock, SnapshotServer


class LocalIngest:
    def __init__(self, clock: OffsetClock | None = None) -> None:
        self.clock = clock or OffsetClock()
        self.snapshots = SnapshotServer(self.clock)
        self.received: list[dict[str, Any]] = []
        self.seen_batches: dict[str, dict[str, Any]] = {}
        self.fail_next: list[int] = []
        self._lock = threading.Lock()
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                return None

            def do_GET(self) -> None:
                route = {
                    "/api/v1/policy/snapshot": stub.snapshots.snapshot_route,
                    "/api/v1/policy/keys": stub.snapshots.keys_route,
                    "/.well-known/sibyl-keys.json": stub.snapshots.keys_route,
                }.get(self.path.split("?", 1)[0])
                if route is None:
                    self._reply(404, b"")
                    return
                request = httpx.Request("GET", self.path, headers=dict(self.headers))
                response = route(request)
                self._reply(response.status_code, response.content, dict(response.headers))

            def do_POST(self) -> None:
                length = int(self.headers.get("content-length", "0"))
                raw = self.rfile.read(length)
                if self.headers.get("content-encoding") == "gzip":
                    raw = gzip.decompress(raw)
                stub._post(self, json.loads(raw) if raw else None)

            def _reply(
                self, status: int, body: bytes, headers: dict[str, str] | None = None
            ) -> None:
                self.send_response(status)
                for key, value in (headers or {}).items():
                    if key.lower() not in (
                        "content-length",
                        "content-encoding",
                        "transfer-encoding",
                    ):
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._handler = Handler
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host!s}:{port}"

    def start(self) -> LocalIngest:
        self._thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def _post(self, handler: Any, body: Any) -> None:
        batch_id = handler.headers.get("x-sibyl-batch-id", "")
        with self._lock:
            if self.fail_next:
                status = self.fail_next.pop(0)
                handler._reply(status, b"", {"Retry-After": "0"})
                return
            replay = batch_id in self.seen_batches
            if not replay:
                self.received.append(
                    {"path": handler.path, "headers": dict(handler.headers), "body": body}
                )
        if handler.path == "/v1/events":
            response = dict(load_fixture("ingest", "valid/response_replayed.json"))
            response.update(
                {
                    "batch_id": batch_id,
                    "accepted": len(body["events"]),
                    "rejected": [],
                    "replayed": replay,
                }
            )
            payload = json.dumps(response).encode()
            headers = {"Content-Type": "application/json"}
            if replay:
                headers["X-Sibyl-Replayed"] = "true"
            with self._lock:
                self.seen_batches[batch_id] = response
            handler._reply(202, payload, headers)
            return
        with self._lock:
            self.seen_batches[batch_id] = {}
        handler._reply(
            200,
            b"{}",
            {
                "Content-Type": "application/json",
                **({"X-Sibyl-Replayed": "true"} if replay else {}),
            },
        )

    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                e for r in self.received if r["path"] == "/v1/events" for e in r["body"]["events"]
            ]

    def spans(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                s
                for r in self.received
                if r["path"] == "/v1/otlp/traces"
                for rs in r["body"]["resourceSpans"]
                for ss in rs["scopeSpans"]
                for s in ss["spans"]
            ]
