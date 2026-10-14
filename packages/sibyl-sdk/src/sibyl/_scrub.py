"""Per-content-part scrub pipeline (API §8.4).

(1) the unconditional secrets floor from `sibyl_schemas.scrub` (cannot be disabled or
reordered) → (2) user hooks in order → (3) the capture-mode gate. A hook exception is
counted and downgrades that part to `metadata`: never ship unscrubbed on hook failure.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal
from uuid import UUID

from sibyl_schemas.scrub import PROFILE_HASH, PROFILE_ID, PROFILE_VERSION, SecretsScrubber

from sibyl._types import CaptureMode

log = logging.getLogger("sibyl")

ScrubPart = Literal[
    "input_messages",
    "output_messages",
    "system_instructions",
    "tool_definitions",
    "tool_args",
    "tool_result",
    "state",
    "comment",
]


@dataclass(frozen=True)
class ScrubContext:
    part: ScrubPart
    agent_id: UUID | None
    task_id: UUID | None
    call_id: UUID | None


ScrubHook = Callable[[str, ScrubContext], str]


@dataclass(frozen=True)
class ScrubbedPart:
    """`text` is None when the part may not ship (metadata mode or hook failure)."""

    text: str | None
    sha256: str
    chars: int
    secrets_scrubbed: int
    rules: tuple[str, ...]
    mode: CaptureMode
    hook_failed: bool


def _hook_name(hook: ScrubHook) -> str:
    return str(getattr(hook, "__name__", type(hook).__name__))


class ScrubPipeline:
    def __init__(self, salt: bytes, hooks: Sequence[ScrubHook] = ()) -> None:
        self._secrets = SecretsScrubber(salt=salt)
        self._hooks = tuple(hooks)
        self._lock = threading.Lock()
        self._hook_errors = 0

    @property
    def scrubber(self) -> SecretsScrubber:
        """The unconditional secrets floor (Action Gate scrubs held-action arguments with it)."""
        return self._secrets

    @property
    def hook_errors(self) -> int:
        return self._hook_errors

    @property
    def profile_hash(self) -> str:
        return PROFILE_HASH

    def run(self, text: str, ctx: ScrubContext, mode: CaptureMode) -> ScrubbedPart:
        floor = self._secrets.scrub(text, ctx.part)
        rules = list(floor.rules_fired)
        current = floor.text
        failed = False
        for hook in self._hooks:
            try:
                current = hook(current, ctx)
            except Exception:  # a user hook must never break the app or leak content
                with self._lock:
                    self._hook_errors += 1
                log.warning("sibyl: scrub hook %s failed; part downgraded", _hook_name(hook))
                failed = True
                current = floor.text
                break
            if not isinstance(current, str):
                failed = True
                current = floor.text
                break
            rules.append(f"sdk.hook:{_hook_name(hook)}")
        effective: CaptureMode = "metadata" if failed else mode
        digest = hashlib.sha256(current.encode("utf-8")).hexdigest()
        return ScrubbedPart(
            text=None if effective == "metadata" else current,
            sha256=digest,
            chars=len(current),
            secrets_scrubbed=floor.secrets_scrubbed,
            rules=tuple(rules),
            mode=effective,
            hook_failed=failed,
        )

    def run_json(self, value: Any, ctx: ScrubContext, mode: CaptureMode) -> ScrubbedPart:
        return self.run(to_json(value), ctx, mode)


def to_json(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, default=_jsonable, ensure_ascii=False, separators=(",", ":"))


def _jsonable(value: Any) -> Any:
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return dump(mode="json")
    if isinstance(value, (set, frozenset, tuple)):
        return list(value)
    return str(value)


def redaction_record(secrets_scrubbed: int, rules: Sequence[str]) -> dict[str, Any]:
    """`sibyl-event/1` `redaction_profile` for SDK-emitted events."""
    return {
        "id": PROFILE_ID,
        "version": PROFILE_VERSION,
        "rules_fired": sorted(set(rules)),
        "secrets_scrubbed": secrets_scrubbed,
        "emitter_profile_hash": PROFILE_HASH,
    }
