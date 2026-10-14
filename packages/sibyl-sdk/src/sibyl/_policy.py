"""Kill-switch poll of the signed snapshot and the per-call policy check (API §8.4).

Every `poll_interval` (20 s) the SDK GETs `/api/v1/policy/snapshot` with `If-None-Match`,
verifies it against keys pinned (or trusted on first use at the genesis) and followed along the
signed rotation chain via `/api/v1/policy/keys?since=<sequence>` (B10, B18),
refuses lower versions, caches the raw snapshot to disk and derives freshness from
`issued_at + ttl`, grace, then `max_stale`. A cached `killed` persists through staleness
until a fresh snapshot says otherwise. The poll never runs on the caller's thread.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import threading
import weakref
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import httpx
from sibyl_schemas.values import SnapshotRejectCause

from sibyl._config import FORBIDDEN_SDK_SCOPES, Settings
from sibyl._errors import SibylKilled, SibylPolicyUnavailable
from sibyl._ids import SYSTEM_CLOCK, Clock, is_uuid
from sibyl._keys import KeySetRejected, KeySetVerifier, parse_pin
from sibyl._keysync import KEYS_PATH, ChainFetchError, follow_chain
from sibyl._lanes import retry_after_seconds
from sibyl._snapshot import (
    PolicySnapshot,
    SnapshotRejected,
    VerifiedSnapshot,
    agent_view,
    verify_snapshot,
)

log = logging.getLogger("sibyl")

SNAPSHOT_PATH: Final = "/api/v1/policy/snapshot"
DECISION_INTERVAL_S: Final = 60.0
KEY_REFRESH_MIN_S: Final = 60.0

Decision = dict[str, Any]
_LIVE: weakref.WeakSet[PolicyManager] = weakref.WeakSet()


class PolicyManager:
    def __init__(
        self,
        settings: Settings,
        *,
        clock: Clock = SYSTEM_CLOCK,
        transport: httpx.BaseTransport | None = None,
        emit_decision: Callable[[Decision], None] = lambda decision: None,
        on_forbidden_key: Callable[[str], None] = lambda reason: None,
    ) -> None:
        self._s = settings
        self._cfg = settings.policy
        self._clock = clock
        self._transport = transport
        self._emit = emit_decision
        self._on_forbidden = on_forbidden_key
        self._cache_dir = Path(self._cfg.cache_dir or Path.home() / ".sibyl" / "policy")
        self._callbacks: list[Callable[[PolicySnapshot], None]] = []
        self._verified: VerifiedSnapshot | None = None
        self._snapshot: PolicySnapshot | None = None
        self._keys: KeySetVerifier | None = None
        self._last_decision: dict[str, float] = {}
        self._last_key_fetch = -1e18
        self._warned_none = False
        self.rejections: dict[str, int] = {}
        self._setup_threading()
        _LIVE.add(self)
        self._load_pin()
        self._load_cache()

    def _setup_threading(self) -> None:
        self._lock = threading.RLock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._http: httpx.Client | None = None

    def _after_fork_in_child(self) -> None:
        running = self._thread is not None
        self._setup_threading()
        if running:
            self.start()

    # ------------------------------------------------------------------ public

    def current(self) -> PolicySnapshot | None:
        return self._snapshot

    def on_change(self, callback: Callable[[PolicySnapshot], None]) -> Callable[[], None]:
        with self._lock:
            self._callbacks.append(callback)

        def unsubscribe() -> None:
            with self._lock, suppress(ValueError):
                self._callbacks.remove(callback)

        return unsubscribe

    def check(self) -> None:
        """Kill beats everything; fail-closed agents stop when no usable snapshot exists."""
        snap = self._snapshot
        now = self._clock.time()
        if snap is None:
            mode = self._s.fail_mode or "open"
            if mode == "closed":
                self._decide("reject_closed", "none", "closed", "no snapshot ever received")
                raise SibylPolicyUnavailable(self._s.agent_ref, "unavailable")
            if not self._warned_none:
                self._warned_none = True
                log.warning("sibyl: no policy snapshot yet; proceeding fail-open")
            return
        if snap.state == "killed" and self._cfg.enforce_kill_switch:
            self._decide(
                "reject_killed",
                _decision_state(snap, now),
                snap.fail_mode,
                snap.kill_reason or "killed",
            )
            raise SibylKilled(snap.agent_id, snap.policy_version, snap.kill_reason or "killed")
        freshness = snap.freshness_at(now)
        if freshness in ("expired", "unavailable"):
            if snap.fail_mode == "closed":
                self._decide(
                    "reject_closed", _decision_state(snap, now), "closed", f"snapshot {freshness}"
                )
                raise SibylPolicyUnavailable(snap.agent_id, freshness)
            self._decide(
                "forward_stale",
                _decision_state(snap, now),
                "open",
                f"snapshot {freshness}; proceeding fail-open",
            )

    def policy_attributes(self) -> dict[str, Any]:
        """`sibyl.policy.*` span attributes for the current call."""
        snap = self._snapshot
        now = self._clock.time()
        if snap is None:
            return {
                "sibyl.policy.state": "unavailable",
                "sibyl.policy.fail_mode": self._s.fail_mode or "open",
            }
        return {
            "sibyl.policy.state": snap.freshness_at(now),
            "sibyl.policy.version": snap.policy_version,
            "sibyl.policy.fail_mode": snap.fail_mode,
            "sibyl.policy.snapshot_age_s": round(snap.age_s(now), 3),
        }

    def start(self) -> None:
        if not self._cfg.enabled or self._thread is not None:
            return
        thread = threading.Thread(target=self._run, name="sibyl-policy", daemon=True)
        self._thread = thread
        thread.start()

    def stop(self, timeout: float = 1.0) -> None:
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
        if self._http is not None:
            self._http.close()
        _LIVE.discard(self)

    # ------------------------------------------------------------------ poll

    def _run(self) -> None:
        interval = self._cfg.poll_interval.total_seconds()
        while not self._stop.is_set():
            wait = interval
            try:
                wait = self.poll_once() or interval
            except Exception:  # the poller must never die
                log.exception("sibyl: policy poll failed")
            self._wake.wait(timeout=wait)
            self._wake.clear()

    def _client(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(
                base_url=self._s.api_endpoint,
                timeout=10.0,
                transport=self._transport,
                follow_redirects=False,
            )
        return self._http

    def poll_once(self) -> float | None:
        """One poll; returns an override for the next wait (Retry-After), else None."""
        if self._keys is None and not self._refresh_keys():
            return None
        headers = {"Authorization": f"Bearer {self._s.api_key}", "Accept": "application/json"}
        if self._verified is not None:
            headers["If-None-Match"] = f'"{self._verified.version}"'
        params = {}
        agent_uuid = self._agent_uuid()
        if agent_uuid:
            params["agent_id"] = agent_uuid
        try:
            response = self._client().get(SNAPSHOT_PATH, params=params, headers=headers)
        except httpx.HTTPError as exc:
            log.debug("sibyl: snapshot poll failed: %s", type(exc).__name__)
            return None
        if response.status_code == 304:
            return None
        if response.status_code == 429:
            return retry_after_seconds(response.headers, self._clock.time())
        if response.status_code != 200:
            if response.status_code in (401, 403):
                log.error("sibyl: snapshot poll refused (HTTP %s)", response.status_code)
            return None
        self.ingest(response.content, response.headers)
        return None

    def ingest(self, raw: bytes, headers: Any, *, from_cache: bool = False) -> bool:
        """Verify and apply one snapshot response; returns whether it was accepted."""
        held = 0 if from_cache or self._verified is None else self._verified.version
        try:
            verified = self._verify(raw, headers, held)
        except SnapshotRejected as rejected:
            cause = rejected.cause.value
            self.rejections[cause] = self.rejections.get(cause, 0) + 1
            if rejected.cause is not SnapshotRejectCause.NON_MONOTONIC:
                log.warning("sibyl: policy snapshot rejected (%s)", cause)
            return False
        view = agent_view(
            verified,
            agent_ref=self._s.agent_ref,
            key_prefix=self._s.key.prefix,
            max_stale_s=self._cfg.max_stale.total_seconds(),
        )
        if not from_cache:
            # persist, then publish: whatever a caller can see survives a restart or a crash
            self._write_cache(verified, headers)
        with self._lock:
            previous = self._snapshot
            self._verified = verified
            if view is not None:
                self._snapshot = view
            callbacks = list(self._callbacks)
        if view is None:
            log.warning("sibyl: agent %r not found in the policy snapshot", self._s.agent_ref)
            return True
        forbidden = FORBIDDEN_SDK_SCOPES.intersection(view.key_scopes)
        if forbidden:
            self._on_forbidden(f"API key carries {sorted(forbidden)}; the SDK refuses it")
        if previous is None or (previous.state, previous.policy_version) != (
            view.state,
            view.policy_version,
        ):
            for callback in callbacks:
                try:
                    callback(view)
                except Exception:
                    log.exception("sibyl: policy.on_change callback failed")
        return True

    def _verify(self, raw: bytes, headers: Any, held: int) -> VerifiedSnapshot:
        keys = self._keys
        if keys is None:
            raise SnapshotRejected(SnapshotRejectCause.UNKNOWN_KID)
        now = self._clock.time()
        try:
            return verify_snapshot(raw, headers, keys, held_version=held, now=now)
        except SnapshotRejected as rejected:
            # A new kid may follow a rotation we have not fetched yet: refresh once.
            if rejected.cause is not SnapshotRejectCause.UNKNOWN_KID or not self._refresh_keys():
                raise
            assert self._keys is not None
            return verify_snapshot(raw, headers, self._keys, held_version=held, now=now)

    # ------------------------------------------------------------------ keys

    def _load_pin(self) -> None:
        """A configured pin starts the chain; stored chain state is reused only when it grew
        from the same origin (the configured pin, or trust-on-first-use without one)."""
        self._origin: dict[str, Any] | str = "tofu"
        if self._cfg.public_key:
            pinned = parse_pin(self._cfg.public_key)
            self._origin = pinned
            self._keys = KeySetVerifier(pinned)
        stored = self._cache_dir / "keys.json"
        if not stored.is_file():
            return
        try:
            state = json.loads(stored.read_text("utf-8"))
            if state.get("origin") == self._origin:
                self._keys = KeySetVerifier.from_state(state["verifier"])
        except (OSError, ValueError, KeyError, IndexError, TypeError):
            log.warning("sibyl: ignoring unreadable pinned key state %s", stored)

    def _save_keys(self) -> None:
        if self._keys is not None:
            state = {"origin": self._origin, "verifier": self._keys.state()}
            self._persist(self._cache_dir / "keys.json", json.dumps(state))

    def _refresh_keys(self) -> bool:
        """Catch the key-set chain up from the held sequence (`?since=`, B10, B18); True when
        new sets were adopted. A rejected delivery leaves the verifier as it was."""
        now_mono = self._clock.monotonic()
        if now_mono - self._last_key_fetch < KEY_REFRESH_MIN_S:
            return False
        self._last_key_fetch = now_mono
        if self._keys is not None and self._keys.is_static:
            return False
        now = datetime.fromtimestamp(self._clock.time(), tz=UTC)
        try:
            keys, adopted = follow_chain(self._fetch_key_page, self._keys, now=now)
        except ChainFetchError as exc:
            log.debug("sibyl: key set fetch failed: %s", exc)
            return False
        except KeySetRejected as rejected:
            log.warning(
                "sibyl: signing key set chain rejected (%s at member %s)",
                rejected.cause.value,
                rejected.index,
            )
            return False
        if adopted == 0 or keys is None:
            return False
        self._keys = keys
        self._save_keys()
        return True

    def _fetch_key_page(self, since: int) -> bytes:
        """The public key route (no API key sent): one `KeySetChain` page."""
        try:
            response = self._client().get(
                KEYS_PATH, params={"since": since}, headers={"Accept": "application/json"}
            )
        except httpx.HTTPError as exc:
            raise ChainFetchError(type(exc).__name__) from None
        if response.status_code != 200:
            raise ChainFetchError(f"HTTP {response.status_code}")
        return response.content

    # ------------------------------------------------------------------ cache

    def _cache_file(self) -> Path:
        name = self._s.agent_ref or f"key-{self._s.key.prefix}"
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name)
        return self._cache_dir / f"{safe}.json"

    def _write_cache(self, verified: VerifiedSnapshot, headers: Any) -> None:
        record = {
            "form": verified.form,
            "kid": verified.kid,
            "sig": verified.sig,
            "raw": base64.b64encode(verified.raw).decode("ascii"),
        }
        self._persist(self._cache_file(), json.dumps(record))

    def _load_cache(self) -> None:
        path = self._cache_file()
        if self._keys is None or not path.is_file():
            return
        try:
            record = json.loads(path.read_text("utf-8"))
            raw = base64.b64decode(record["raw"])
        except (OSError, ValueError, KeyError):
            return
        headers: dict[str, str] = {}
        if record.get("form") == "detached":
            headers = {
                "x-sibyl-snapshot-kid": record["kid"],
                "x-sibyl-snapshot-signature": record["sig"],
            }
        self.ingest(raw, headers, from_cache=True)

    def _persist(self, path: Path, text: str) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(text, "utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except OSError as exc:
            log.debug("sibyl: could not write %s: %s", path, exc)

    # ------------------------------------------------------------------ helpers

    def _agent_uuid(self) -> str | None:
        if self._snapshot is not None:
            return str(self._snapshot.agent_id)
        ref = self._s.agent_ref
        return ref if ref and is_uuid(ref) else None

    def _decide(self, action: str, state: str, fail_mode: str, reason: str) -> None:
        now = self._clock.monotonic()
        if now - self._last_decision.get(action, -1e18) < DECISION_INTERVAL_S:
            return
        self._last_decision[action] = now
        decision: Decision = {
            "action": action,
            "state": state,
            "fail_mode": fail_mode,
            "reason": reason[:200],
        }
        snap = self._snapshot
        if snap is not None:
            decision["snapshot_issued_at"] = snap.issued_at
        try:
            self._emit(decision)
        except Exception:
            log.exception("sibyl: could not emit policy.decision")


def _decision_state(snap: PolicySnapshot, now: float) -> str:
    return snap.freshness_at(now)


def _reinit_after_fork() -> None:
    for manager in list(_LIVE):
        manager._after_fork_in_child()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reinit_after_fork)
