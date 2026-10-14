"""A-4 (ACTION-GATE §4): never auto-resume side-effecting work.

A task whose latest checkpoint records a side effect that is not explicitly ``idempotent: true``
must not be continued on a new route (or handed back to the agent) automatically: replaying it
could pay twice, mail twice, write twice. Such a task goes to the operator queue with its
side-effect ledger instead.

Only an explicit boolean ``idempotent: true`` counts. An ``idempotency_key`` alone does not: the
new route (another model, provider or agent) need not reuse the key. Anything malformed fails
closed (treated as a non-idempotent ``unknown`` side effect).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .packet import HOLD_NEXT_ACTION, TaskInput

__all__ = ["HOLD_NEXT_ACTION", "is_idempotent", "ledger", "ledger_of", "unsafe_to_resume"]
MAX_KIND = 64
MAX_TEXT = 256
_OPTIONAL_TEXT = ("target", "idempotency_key", "evidence_span_id")


def is_idempotent(effect: Any) -> bool:
    return isinstance(effect, Mapping) and effect.get("idempotent") is True


def _recorded(task: TaskInput) -> Sequence[Any]:
    doc = task.checkpoint_doc
    if not isinstance(doc, Mapping):
        return ()
    effects = doc.get("side_effects")
    if effects is None:
        return ()
    if isinstance(effects, list):
        return effects
    return ("malformed",)  # not a list: fail closed


def unsafe_to_resume(task: TaskInput) -> bool:
    """True when any recorded side effect of the task is not explicitly idempotent."""
    return any(not is_idempotent(e) for e in _recorded(task))


def _entry(task: TaskInput, effect: Any) -> dict[str, Any]:
    raw: Mapping[str, Any] = effect if isinstance(effect, Mapping) else {}
    out: dict[str, Any] = {
        "task_id": str(task.task_id),
        "checkpoint_id": None if task.checkpoint_id is None else str(task.checkpoint_id),
        "checkpoint_seq": task.checkpoint_seq,
        "kind": str(raw.get("kind") or "unknown")[:MAX_KIND],
        "at": None if raw.get("at") is None else str(raw["at"])[:MAX_KIND],
        "assumed": raw.get("assumed") is True,
        "idempotent": is_idempotent(raw),
    }
    for name in _OPTIONAL_TEXT:
        if raw.get(name) is not None:
            out[name] = str(raw[name])[:MAX_TEXT]
    if isinstance(raw.get("reversible"), bool):
        out["reversible"] = raw["reversible"]
    return out


def ledger(task: TaskInput) -> list[dict[str, Any]]:
    """Every recorded side effect of the task, with its idempotency verdict and call reference."""
    return [_entry(task, e) for e in _recorded(task)]


def ledger_of(tasks: Sequence[TaskInput]) -> list[dict[str, Any]]:
    return [entry for task in tasks for entry in ledger(task)]
