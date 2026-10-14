"""Signed key-set rotation chain (security M6, ``sibyl.policy_snapshot/1`` ``$defs/key_set``).

The gateway is configured with ONE pinned key (``SIBYL_SNAPSHOT_PINNED_KEY``) and follows the
chain the api publishes at ``/api/v1/policy/keys`` through the shared follower in
``sibyl_schemas.keyset`` (B33): it owns every check and its order (``KeySetRejectCause``:
malformed, unknown_signer, signer_expired, bad_signature, non_monotonic, sequence_gap,
chain_broken), the catch-up staging and the snapshot key selection (every key the accepted set
lists, active or retiring, not past ``not_after``). This module adds only what is the
gateway's own: a lock around the follower, persisting the accepted documents and replaying
them from the pin on start (trust on disk is always re-derived, never read back), and the
``PinnedKeySet`` the snapshot store verifies with.

Catch-up (B10): ``stage()`` verifies a ``?since=<sequence>`` delivery in order on top of the
current state and ``commit()`` adopts it whole; ``keysync.follow_chain`` drives this over HTTP.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from sibyl_schemas.canonical import CanonicalizationError, canonicalize, parse_json_strict
from sibyl_schemas.keyset import (
    ChainFollower,
    ChainKey,
    ChainStage,
    KeySetRejected,
    parse_ts,
)

from .verify import KeySetError, PinnedKey, PinnedKeySet

__all__ = ["ChainKey", "ChainStage", "KeyChain", "KeySetRejected"]

log = logging.getLogger("sibyl.gateway.policy")


class KeyChain:
    """Pinned first key + the accepted rotation chain; thread-safe around the shared follower."""

    def __init__(self, pinned: ChainKey, *, state_dir: Path | None = None) -> None:
        self._follower = ChainFollower(pinned)
        self._dir = state_dir
        self._lock = threading.Lock()

    @classmethod
    def from_pin_json(cls, text: str, *, state_dir: Path | None = None) -> KeyChain:
        try:
            return cls(ChainKey.from_entry(json.loads(text)), state_dir=state_dir)
        except (ValueError, TypeError) as exc:
            raise KeySetError(f"pinned key unusable: {exc}") from None

    @property
    def sequence(self) -> int:
        return self._follower.sequence

    def verification_keys(self, now: datetime) -> PinnedKeySet:
        usable = self._follower.listed_keys(now) or [self._follower.pinned]
        return PinnedKeySet(PinnedKey(k.kid, k.public_key, k.status) for k in usable)

    def accept(self, raw: str | bytes, *, now: datetime, persist: bool = True) -> int:
        """Verify and adopt one key set; returns its sequence or raises ``KeySetRejected``."""
        with self._lock:
            self._follower.accept(raw, now=now)
            sequence = self._follower.sequence
        if persist:
            self._persist()
        return sequence

    def stage(self) -> ChainStage:
        """Start verifying a ``?since=<sequence>`` delivery on top of the current state."""
        return self._follower.stage()

    def commit(self, stage: ChainStage, *, persist: bool = True) -> int:
        """Adopt a fully verified stage (refused if the chain moved since it was started)."""
        with self._lock:
            sequence = self._follower.commit(stage)
        if persist:
            self._persist()
        return sequence

    def accept_chain(
        self, documents: Sequence[str | bytes], *, now: datetime, persist: bool = True
    ) -> int:
        """Verify ``documents`` in order from the current state, all or nothing (B10)."""
        stage = self.stage()
        for raw in documents:
            stage.accept(raw, now=now)
        return self.commit(stage, persist=persist)

    def is_current(self, raw: str | bytes) -> bool:
        """The document is the set already accepted last (a re-fetch, not a new delivery).

        Needed because after a rotation the current set's signer is no longer an active key,
        so re-verifying it would report ``unknown_signer`` on every poll."""
        accepted = self._follower.chain_state.accepted
        if not accepted:
            return False
        try:
            return canonicalize(parse_json_strict(raw)) == canonicalize(
                parse_json_strict(accepted[-1])
            )
        except (CanonicalizationError, ValueError, RecursionError):
            return False

    def _persist(self) -> None:
        if self._dir is None:
            return
        try:
            self._dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            target = self._dir / "keysets.json"
            tmp = target.with_suffix(f".tmp{os.getpid()}")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(list(self._follower.chain_state.accepted), handle)
            os.replace(tmp, target)
        except OSError:
            log.exception("could not persist the key-set chain")

    def replay(self) -> int:
        """Re-verify the persisted chain from the pin (each set checked at its own issue time)."""
        if self._dir is None or not (self._dir / "keysets.json").is_file():
            return 0
        try:
            documents = json.loads((self._dir / "keysets.json").read_text("utf-8"))
        except (OSError, ValueError):
            return 0
        replayed = 0
        for text in documents if isinstance(documents, list) else []:
            try:
                issued = parse_ts(json.loads(text)["body"]["issued_at"])
                self.accept(text, now=issued, persist=False)
                replayed += 1
            except (KeySetRejected, ValueError, KeyError, TypeError) as exc:
                log.warning("persisted key set ignored: %s", exc)
                break
        return replayed
