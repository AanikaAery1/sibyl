"""Test helpers for applications using the SDK: a recording in-memory ingest and an
advanceable clock. No pytest dependency; nothing here touches the network."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sibyl_schemas.canonical import canonicalize

TEST_KEY = "sbl_test_Bd3Fg5Hj7Kl9_" + "A" * 43
"""A syntactically valid, obviously fake `test` key (prefix of the fixture agent key)."""
AGENT_UUID = "0192767f-0000-7000-8000-00000000c011"
TENANT_UUID = "0192767f-0000-7000-8000-00000000a001"


class OffsetClock:
    """Real time plus an offset the test can advance (threads keep making progress)."""

    def __init__(self) -> None:
        self.offset = 0.0

    def time(self) -> float:
        return time.time() + self.offset

    def monotonic(self) -> float:
        return time.monotonic() + self.offset

    def advance(self, seconds: float) -> None:
        self.offset += seconds


@dataclass
class Recorded:
    method: str
    path: str
    headers: dict[str, str]
    body: Any


Responder = Callable[[httpx.Request], httpx.Response]


@dataclass
class Ingest:
    """httpx MockTransport that records decoded requests and answers from a script."""

    requests: list[Recorded] = field(default_factory=list)
    script: list[Responder] = field(default_factory=list)
    default: Responder = field(default=lambda req: httpx.Response(200, json={}))
    routes: dict[str, Responder] = field(default_factory=dict)
    """Per-path responders (GET snapshot/keys); POSTs fall through to `script`/`default`."""
    lock: threading.Lock = field(default_factory=threading.Lock)

    def handler(self, request: httpx.Request) -> httpx.Response:
        raw = request.content
        if request.headers.get("content-encoding") == "gzip":
            raw = gzip.decompress(raw)
        body = json.loads(raw) if raw and request.method == "POST" else None
        with self.lock:
            self.requests.append(
                Recorded(request.method, request.url.path, dict(request.headers), body)
            )
            route = self.routes.get(request.url.path)
            if route is not None:
                return route(request)
            if request.method != "POST":
                return httpx.Response(404)
            responder = self.script.pop(0) if self.script else self.default
        return responder(request)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def posts(self, path: str) -> list[Recorded]:
        with self.lock:
            return [r for r in self.requests if r.path == path and r.method == "POST"]

    def spans(self) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for req in self.posts("/v1/otlp/traces"):
            for rs in req.body["resourceSpans"]:
                for ss in rs["scopeSpans"]:
                    found.extend(ss["spans"])
        return found

    def events(self) -> list[dict[str, Any]]:
        return [e for req in self.posts("/v1/events") for e in req.body["events"]]

    def logs(self) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for req in self.posts("/v1/otlp/logs"):
            for rl in req.body["resourceLogs"]:
                for sl in rl["scopeLogs"]:
                    found.extend(sl["logRecords"])
        return found


def attrs(span_or_log: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for kv in span_or_log["attributes"]:
        value = kv["value"]
        ((kind, raw),) = value.items()
        if kind == "intValue":
            raw = int(raw)
        elif kind == "arrayValue":
            raw = [next(iter(v.values())) for v in raw["values"]]
        out[kv["key"]] = raw
    return out


def wait_for(predicate: Callable[[], bool], timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


# ---------------------------------------------------------------- signed snapshots


def test_signing_seed(n: int = 1) -> bytes:
    """The public TEST-ONLY seeds behind the `sibyl-schemas` snapshot vectors."""
    text = f"sibyl-test-vector-snapshot-key-{n} (TEST ONLY, never deploy)"
    return hashlib.sha256(text.encode("utf-8")).digest()


test_signing_seed.__test__ = False  # type: ignore[attr-defined]  # not a pytest test


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class SnapshotSigner:
    """Signs `sibyl.policy_snapshot/1` bodies and key sets with a TEST key (never deploy)."""

    def __init__(self, n: int = 1, kid: str = "snap-2026-10-v1") -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(test_signing_seed(n))
        self.kid = kid
        raw = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public_key = _b64u(raw)

    def sign(self, data: bytes) -> str:
        return _b64u(self._key.sign(data))

    def detached(self, body: dict[str, Any]) -> tuple[bytes, dict[str, str]]:
        raw = canonicalize({**body, "kid": self.kid})
        return raw, {"X-Sibyl-Snapshot-Kid": self.kid, "X-Sibyl-Snapshot-Signature": self.sign(raw)}

    def envelope(self, body: dict[str, Any]) -> bytes:
        signed = {**body, "kid": self.kid}
        doc = {
            "kid": self.kid,
            "alg": "Ed25519",
            "sig": self.sign(canonicalize(signed)),
            "body": signed,
        }
        return json.dumps(doc).encode("utf-8")

    def key(self, **extra: Any) -> dict[str, Any]:
        return {"kid": self.kid, "alg": "Ed25519", "public_key": self.public_key, **extra}

    def key_set(
        self,
        sequence: int,
        keys: list[dict[str, Any]],
        next_key: dict[str, Any] | None,
        issued_at: str,
    ) -> bytes:
        body = {"sequence": sequence, "issued_at": issued_at, "keys": keys, "next_key": next_key}
        doc = {
            "kid": self.kid,
            "alg": "Ed25519",
            "sig": self.sign(canonicalize(body)),
            "body": body,
        }
        return json.dumps(doc).encode("utf-8")

    def pin(self) -> str:
        return f"{self.kid}:{self.public_key}"


def _rfc3339(epoch: float) -> str:
    from datetime import UTC, datetime

    moment = datetime.fromtimestamp(epoch, tz=UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


class SnapshotServer:
    """Serves signed snapshots (detached form, ETag/304) and a signed key set for tests.

    Starts from the `sibyl-schemas` golden snapshot body; `publish()` re-signs it with a
    higher version, `issued_at = clock.time()` and an optional mutation of the agent."""

    AGENT = AGENT_UUID

    def __init__(self, clock: OffsetClock, signer: SnapshotSigner | None = None) -> None:
        from sibyl_schemas.golden import load_fixture

        self.clock = clock
        self.signer = signer or SnapshotSigner()
        self.body: dict[str, Any] = load_fixture("snapshot", "valid/snapshot_body.json")
        self.version = int(self.body["version"])
        self.raw = b""
        self.headers: dict[str, str] = {}
        self.down = False
        self.polls = 0
        self.key_sets: list[bytes] = []  # empty: a self-signed genesis by `signer` on demand
        self.key_since: list[int] = []
        self.publish()

    @property
    def tenant(self) -> dict[str, Any]:
        return dict(next(iter(self.body["tenants"].values())))

    def agent(self) -> dict[str, Any]:
        block = next(iter(self.body["tenants"].values()))
        return dict(block["agents"][self.AGENT])

    def publish(
        self,
        *,
        state: str | None = None,
        fail_mode: str | None = None,
        capture: str | None = None,
        kill_switch: str | None = None,
        scopes: list[str] | None = None,
        issued_offset: float = 0.0,
        action_policies: list[dict[str, Any]] | None = None,
        dangling_policy_ref: bool = False,
    ) -> int:
        body = json.loads(json.dumps(self.body))
        block = next(iter(body["tenants"].values()))
        agent = block["agents"][self.AGENT]
        if state is not None:
            agent["route"]["state"] = state
        if fail_mode is not None:
            agent["fail_mode"] = fail_mode
        if capture is not None:
            agent["capture"]["mode"] = capture
        if scopes is not None:
            block["api_keys"]["Bd3Fg5Hj7Kl9"]["scopes"] = scopes
        if action_policies is not None:
            block["action_policies"] = {p["policy_id"]: p for p in action_policies}
            agent["action_policies"] = [p["policy_id"] for p in action_policies]
        if dangling_policy_ref:
            agent["action_policies"] = [
                *agent.get("action_policies", []),
                "0192767f-0000-7000-8000-0000000acfff",
            ]
        block["kill_switches"] = (
            []
            if kill_switch is None
            else [
                {
                    "kill_switch_id": "0192f0d1-0000-7000-8000-000000000001",
                    "scope_kind": kill_switch,
                    "scope_id": self.AGENT if kill_switch == "agent" else None,
                    "pulled_at": _rfc3339(self.clock.time()),
                }
            ]
        )
        self.version += 1
        issued = self.clock.time() + issued_offset
        body.update(
            {
                "version": self.version,
                "issued_at": _rfc3339(issued),
                "expires_at": _rfc3339(issued + body["ttl_s"]),
            }
        )
        self.body = body
        self.raw, self.headers = self.signer.detached(body)
        return self.version

    def snapshot_route(self, request: httpx.Request) -> httpx.Response:
        self.polls += 1
        if self.down:
            return httpx.Response(503)
        if request.headers.get("if-none-match") == f'"{self.version}"':
            return httpx.Response(304)
        headers = {**self.headers, "ETag": f'"{self.version}"', "Content-Type": "application/json"}
        return httpx.Response(200, content=self.raw, headers=headers)

    def keys_route(self, request: httpx.Request) -> httpx.Response:
        """The latest key set; with `?since=n` the `KeySetChain` after n (B10)."""
        if not self.key_sets:
            genesis = self.signer.key_set(
                1, [self.signer.key(status="active")], None, _rfc3339(self.clock.time() - 60)
            )
            self.key_sets = [genesis]
        docs = [json.loads(raw) for raw in self.key_sets]
        since = request.url.params.get("since")
        if since is None:
            payload: Any = docs[-1]
        else:
            self.key_since.append(int(since))
            after = [d for d in docs if d["body"]["sequence"] > int(since)]
            payload = {"data": after, "latest_sequence": docs[-1]["body"]["sequence"]}
        content = json.dumps(payload).encode("utf-8")
        return httpx.Response(200, content=content, headers={"Content-Type": "application/json"})

    def install(self, ingest: Ingest) -> None:
        ingest.routes["/api/v1/policy/snapshot"] = self.snapshot_route
        ingest.routes["/api/v1/policy/keys"] = self.keys_route
        ingest.routes["/.well-known/sibyl-keys.json"] = self.keys_route


# ---------------------------------------------------------------- Action Gate control plane


@dataclass
class FakeActionApi:
    """`POST /api/v1/held-actions`, `GET /api/v1/held-actions/{id}` and
    `POST /api/v1/action-decisions` for tests (idempotent per call id, like the real API).

    `decide` sets what a hold resolves to after `decide_after` polls (`None` = never);
    `cap_values` seeds counters; `fail` makes every call answer 503."""

    decide: str | None = "approved"
    decide_after: int = 1
    cap_values: dict[str, Decimal] = field(default_factory=dict)
    fail: bool = False
    holds: dict[str, dict[str, Any]] = field(default_factory=dict)
    decisions: dict[str, dict[str, Any]] = field(default_factory=dict)
    polls: dict[str, int] = field(default_factory=dict)
    _ingest: Ingest | None = None

    def install(self, ingest: Ingest) -> None:
        self._ingest = ingest
        ingest.routes["/api/v1/held-actions"] = self.create_hold
        ingest.routes["/api/v1/action-decisions"] = self.check_and_increment

    def create_hold(self, request: httpx.Request) -> httpx.Response:
        if self.fail:
            return httpx.Response(503)
        body = json.loads(request.content)
        existing = next((h for h in self.holds.values() if h["call_id"] == body["call_id"]), None)
        if existing is not None:
            return httpx.Response(201, json=self._status(existing))
        held_id = f"0192f0e1-0000-7000-8000-{len(self.holds) + 1:012d}"
        hold = {**body, "held_action_id": held_id, "state": "pending"}
        self.holds[held_id] = hold
        self.polls[held_id] = 0
        if self._ingest is not None:
            self._ingest.routes[f"/api/v1/held-actions/{held_id}"] = self.get_hold
        return httpx.Response(201, json=self._status(hold))

    def get_hold(self, request: httpx.Request) -> httpx.Response:
        held_id = request.url.path.rsplit("/", 1)[1]
        hold = self.holds[held_id]
        self.polls[held_id] += 1
        if self.decide is not None and self.polls[held_id] >= self.decide_after:
            hold["state"] = self.decide
        return httpx.Response(200, json=self._status(hold))

    def check_and_increment(self, request: httpx.Request) -> httpx.Response:
        if self.fail:
            return httpx.Response(503)
        body = json.loads(request.content)
        if body["call_id"] in self.decisions:
            return httpx.Response(200, json=self.decisions[body["call_id"]])
        key = body["counter_key"]
        current = self.cap_values.get(key, Decimal(0))
        within = current + Decimal(body["increment"]) <= Decimal(body["max"])
        if within:
            current += Decimal(body["increment"])
            self.cap_values[key] = current
        result = {"call_id": body["call_id"], "within_cap": within, "counter_value": str(current)}
        self.decisions[body["call_id"]] = result
        return httpx.Response(200, json=result)

    @staticmethod
    def _status(hold: dict[str, Any]) -> dict[str, Any]:
        return {"held_action_id": hold["held_action_id"], "state": hold["state"]}
