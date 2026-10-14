"""`feedback()` and `outcome()`: ground-truth labels on `/v1/events` (telemetry lane)."""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Literal
from uuid import UUID

from sibyl import _state
from sibyl._emit import envelope, scrub_text
from sibyl._ids import uuid7
from sibyl._run import current_run
from sibyl._scrub import redaction_record
from sibyl._types import Outcome

if TYPE_CHECKING:
    from sibyl._run import AgentRun

COMMENT_TYPE = "text/plain; charset=utf-8"


def feedback(
    score: float,
    *,
    scale: str = "thumbs",
    target: Literal["trace", "task", "call", "packet"] = "task",
    target_id: str | UUID | None = None,
    rater: Literal["end_user", "operator"] = "end_user",
    comment: str | None = None,
    tags: Sequence[str] = (),
) -> UUID:
    """Scores outside [-1, 1] are clamped; the original value is kept as `raw_value`."""
    feedback_id = uuid7()
    client = _state.get()
    run = current_run()
    if target_id is None and run is not None:
        target_id = run.trace_id if target == "trace" else run.task_id
    if client is None or target_id is None:
        _state.warn_once("feedback", "feedback() needs init() and a target (or a current run)")
        return feedback_id
    clamped = max(-1.0, min(1.0, float(score)))
    attrs: dict[str, Any] = {
        "feedback_id": str(feedback_id),
        "target": {"kind": target, "id": str(target_id)},
        "score": clamped,
        "scale": scale[:64],
        "rater": rater,
    }
    if clamped != score:
        attrs["raw_value"] = float(score)
    if tags:
        attrs["tags"] = [str(tag)[:64] for tag in tags][:32]
    event = envelope(
        client,
        "feedback",
        attrs,
        task_id=str(run.task_id) if run else None,
        trace_id=run.trace_id if run else None,
    )
    if comment:
        mode = client.capture_mode
        text, secrets, rules = scrub_text(client, comment, "comment", mode=mode)
        event["redaction_profile"] = redaction_record(secrets, rules)
        if text is not None:
            attrs["payload_inline"] = {
                "encoding": "utf8",
                "data": text,
                "content_type": COMMENT_TYPE,
                "parts": ["comment"],
            }
    client.emit_event(event)
    return feedback_id


def emit_outcome(
    run: AgentRun, outcome: Outcome, *, reason: str | None = None, rework: bool | None = None
) -> None:
    client = run.client or _state.get()
    if client is None:
        return
    attrs: dict[str, Any] = {
        "outcome": outcome,
        "declared_by": "sdk",
        "metrics": {
            "steps": run.steps,
            "tool_calls": run.tool_calls,
            "model_calls": run.model_calls,
            "duration_ms": round((time.time() - run.started_at) * 1000, 3),
        },
    }
    if reason:
        text, _, _ = scrub_text(client, reason, "comment", mode="full", task_id=run.task_id)
        attrs["reason"] = (text or "")[:500]
    if rework is not None:
        attrs["rework"] = rework
    client.emit_event(
        envelope(
            client,
            "task.outcome",
            attrs,
            task_id=str(run.task_id),
            trace_id=run.trace_id,
            span_id=run.span_id,
        )
    )


def outcome(
    outcome: Outcome,
    *,
    reason: str | None = None,
    rework: bool | None = None,
    run: AgentRun | None = None,
) -> None:
    run = run or current_run()
    if run is None:
        _state.warn_once("outcome", "outcome() outside sibyl.agent() is ignored")
        return
    emit_outcome(run, outcome, reason=reason, rework=rework)
