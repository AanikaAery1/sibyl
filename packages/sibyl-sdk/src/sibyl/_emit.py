"""Event envelopes and the worker-thread finalizers (identity late binding, deferred scrub).

Content is scrubbed on the exporter thread, not the caller's: the caller pays O(1) per span.
A part the scrubber refuses (`ScrubInputTooLarge`, > 16 Mi chars) drops the whole event or
span with a counter; it is never passed through unscrubbed.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Final

from sibyl_schemas.scrub import PROFILE_HASH, PROFILE_ID, PROFILE_VERSION, ScrubInputTooLarge

from sibyl._ids import NIL_UUID, rfc3339, uuid7
from sibyl._scrub import ScrubContext, ScrubPart, redaction_record, to_json
from sibyl._spans import Span
from sibyl._types import CaptureMode

if TYPE_CHECKING:
    from sibyl._client import Client

log = logging.getLogger("sibyl")

DEFERRED: Final = "_deferred"
HASH_KEYS: Final[dict[str, str]] = {
    "input_messages": "input",
    "output_messages": "output",
    "system_instructions": "system",
    "tool_args": "args",
    "tool_result": "result",
    "tool_definitions": "tools",
}
DeferredBuilder = Callable[[], dict[str, Any] | None]
"""Runs on the worker; returns `{"attrs": {...}, "redaction_profile": {...}}` or None."""


def envelope(
    client: Client,
    event_type: str,
    attrs: dict[str, Any],
    *,
    task_id: str | None = None,
    call_id: str | None = None,
    trace_id: str | None = None,
    span_id: str | None = None,
    capture_mode: CaptureMode | None = None,
    deferred: DeferredBuilder | None = None,
) -> dict[str, Any]:
    """A `sibyl-event/1` wire envelope; `tenant_id`/`agent_id` bind on the worker."""
    event: dict[str, Any] = {
        "schema": "sibyl-event/1",
        "event_id": str(uuid7(client.clock.time())),
        "type": event_type,
        "tenant_id": None,
        "agent_id": None,
        "task_id": task_id,
        "call_id": call_id,
        "ts": rfc3339(client.clock.time()),
        "source": "sdk",
        "emitter_id": client.emitter_id,
        "seq": client.next_seq(),
        "capture_mode": capture_mode or client.capture_mode,
        "redaction_profile": redaction_record(0, ()),
        "policy_state": client.policy_state(),
        "attrs": attrs,
    }
    if trace_id:
        event["trace_id"] = trace_id
    if span_id:
        event["span_id"] = span_id
    if deferred is not None:
        event[DEFERRED] = deferred
    return event


def finalize_event(client: Client, event: dict[str, Any]) -> dict[str, Any] | None:
    deferred: DeferredBuilder | None = event.pop(DEFERRED, None)
    if event["tenant_id"] is None:
        event["tenant_id"] = str(client.tenant_id) if client.tenant_id else NIL_UUID
    if event["agent_id"] is None:
        event["agent_id"] = str(client.agent_id) if client.agent_id else NIL_UUID
    if deferred is None:
        return event
    try:
        patch = deferred()
    except ScrubInputTooLarge:
        log.warning("sibyl: %s dropped: content exceeds the scrub size cap", event["type"])
        return None
    except Exception:
        log.exception("sibyl: could not build %s", event["type"])
        return None
    if patch is None:
        return None
    event["attrs"] = {**event["attrs"], **patch.get("attrs", {})}
    if "redaction_profile" in patch:
        event["redaction_profile"] = patch["redaction_profile"]
    if "capture_mode" in patch:
        event["capture_mode"] = patch["capture_mode"]
    return event


def finalize_span(client: Client, span: Span) -> bool:
    """Scrub deferred content into attributes; stamp `sibyl.redaction.*`."""
    mode = str(span.attributes.get("sibyl.capture.mode", client.capture_mode))
    ctx_ids = (
        client.agent_id,
        _uuid_attr(span, "sibyl.task_id"),
        _uuid_attr(span, "sibyl.call_id"),
    )
    secrets = 0
    rules: list[str] = []
    for attribute, part, value in span.content:
        ctx = ScrubContext(
            part=part,  # type: ignore[arg-type]
            agent_id=ctx_ids[0],
            task_id=ctx_ids[1],
            call_id=ctx_ids[2],
        )
        try:
            scrubbed = client.scrub.run(to_json(value), ctx, mode)  # type: ignore[arg-type]
        except ScrubInputTooLarge:
            log.warning("sibyl: span %s dropped: content exceeds the scrub size cap", span.name)
            return False
        secrets += scrubbed.secrets_scrubbed
        rules.extend(scrubbed.rules)
        key = HASH_KEYS.get(part, part)
        span.attributes[f"sibyl.content_hash.{key}"] = scrubbed.sha256
        if part == "output_messages":
            span.attributes["sibyl.output_chars"] = scrubbed.chars
        if scrubbed.text is not None:
            span.attributes[attribute] = scrubbed.text
    span.content.clear()
    span.attributes.update(
        {
            "sibyl.redaction.profile": PROFILE_ID,
            "sibyl.redaction.version": PROFILE_VERSION,
            "sibyl.redaction.rules": sorted(set(rules)) or ["secrets.*"],
            "sibyl.redaction.secrets_scrubbed": secrets,
            "sibyl.redaction.emitter_profile_hash": PROFILE_HASH,
        }
    )
    return True


def scrub_text(
    client: Client, text: str, part: ScrubPart, *, mode: CaptureMode, task_id: Any = None
) -> tuple[str | None, int, list[str]]:
    """Scrub on the caller's thread (short strings only: reasons, goals, comments)."""
    ctx = ScrubContext(part=part, agent_id=client.agent_id, task_id=task_id, call_id=None)
    scrubbed = client.scrub.run(text, ctx, mode)
    return scrubbed.text, scrubbed.secrets_scrubbed, list(scrubbed.rules)


def _uuid_attr(span: Span, key: str) -> Any:
    from uuid import UUID

    value = span.attributes.get(key)
    try:
        return UUID(str(value)) if value else None
    except ValueError:
        return None
