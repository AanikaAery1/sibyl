"""``sibyl-event/1`` documents the gateway emits (wire form, ``sibyl-event-wire/1``).

``gen_ai.request`` for every call (refusals included, so they count in the health score),
``agent.discovered`` for provisional agents and ``policy.decision`` for degraded-policy paths.
Content leaves only under ``capture_mode`` ``full``/``redacted`` and always after the
unconditional secrets scrub (D12); ``metadata`` carries no content and no content hashes.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sibyl_schemas.scrub import PROFILE_ID, PROFILE_VERSION, ScrubField, SecretsScrubber

from ..routing.decide import provisional_agent_id

MAX_INLINE_BYTES = 256 * 1024
CONTENT_TYPE = "application/vnd.sibyl.genai-content+json"
_HEX64 = frozenset("0123456789abcdef")
# Gateway operation -> GenAiOperation (OTel gen_ai.operation.name); Anthropic Messages is chat.
_OPERATION = {"embeddings": "embeddings", "gemini.generate_content": "generate_content"}


def uuid7() -> UUID:
    ms = time.time_ns() // 1_000_000
    raw = bytearray(ms.to_bytes(6, "big") + os.urandom(10))
    raw[6] = (raw[6] & 0x0F) | 0x70
    raw[8] = (raw[8] & 0x3F) | 0x80
    return UUID(bytes=bytes(raw))


def iso_ms(ts: datetime) -> str:
    ts = ts.astimezone(UTC)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def parse_traceparent(value: str | None) -> tuple[str, str | None]:
    """(trace_id, parent span id) from W3C ``traceparent``; a fresh trace when absent/invalid."""
    parts = (value or "").strip().split("-")
    if len(parts) == 4 and len(parts[1]) == 32 and len(parts[2]) == 16:
        trace, span = parts[1].lower(), parts[2].lower()
        if set(trace) <= _HEX64 and set(span) <= _HEX64 and trace != "0" * 32:
            return trace, span
    return secrets.token_hex(16), None


@dataclass
class CallRecord:
    """Everything one proxied (or refused) call contributes to its ``gen_ai.request`` event."""

    tenant_id: UUID
    agent_id: UUID | str
    operation: str
    provider: str
    request_model: str
    status: str
    started: float
    ended: float
    route: str
    capture_mode: str
    policy_state: str
    policy_version: int | None
    fail_mode: str | None
    profile_hash: str = ""
    call_id: UUID = field(default_factory=uuid7)
    task_id: str | None = None
    traceparent: str | None = None
    http_status: int | None = None
    error_type: str | None = None
    ttfb_ms: float | None = None
    streamed: bool = False
    response_model: str | None = None
    response_id: str | None = None
    system_fingerprint: str | None = None  # frozen attr (WAVE3); OpenAI only
    usage: dict[str, Any] | None = None
    finish_reasons: list[str] | None = None
    ratelimit: dict[str, int] | None = None  # upstream rate-limit headers (proxy.ratelimit)
    attempts: int = 1
    inline_fallback_used: bool = False
    from_target: dict[str, str] | None = None
    to_target: dict[str, str] | None = None
    request_body: bytes | None = field(default=None, repr=False)
    response_body: bytes | None = field(default=None, repr=False)
    snapshot_age_s: float | None = None


class EventFactory:
    def __init__(self, gateway_id: str, scrubber: SecretsScrubber) -> None:
        self.gateway_id = gateway_id
        self.emitter_id = f"gateway:{gateway_id}:{os.getpid()}"[:128]
        self._scrubber = scrubber
        self._seq = 0

    @property
    def scrubber(self) -> SecretsScrubber:
        """The secrets floor (the Action Gate scrubs held-action arguments with it)."""
        return self._scrubber

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _envelope(
        self, kind: str, tenant: UUID, agent: UUID | str | None, ts: datetime, **extra: Any
    ) -> dict[str, Any]:
        trace, parent = parse_traceparent(extra.pop("traceparent", None))
        event: dict[str, Any] = {
            "schema": "sibyl-event/1",
            "event_id": str(uuid7()),
            "type": kind,
            "tenant_id": str(tenant),
            "agent_id": None if agent is None else str(_agent_uuid(tenant, agent)),
            "task_id": extra.pop("task_id", None),
            "call_id": extra.pop("call_id", None),
            "trace_id": trace,
            "span_id": secrets.token_hex(8),
            "ts": iso_ms(ts),
            "source": "gateway",
            "emitter_id": self.emitter_id,
            "seq": self._next_seq(),
        }
        if parent is not None:
            event["parent_span_id"] = parent
        event.update(extra)
        return event

    def gen_ai_request(self, rec: CallRecord) -> dict[str, Any]:
        attrs: dict[str, Any] = {
            "operation": _OPERATION.get(rec.operation, "chat"),
            "provider": rec.provider or "unknown",
            "request_model": rec.request_model or "unknown",
            "status": rec.status,
            "latency_ms": round(max(0.0, (rec.ended - rec.started) * 1000), 3),
            "streamed": rec.streamed,
            "route": _route(rec),
            "contributions": ["gateway"],
            "merge_state": "partial",
        }
        for name in (
            "http_status",
            "error_type",
            "response_model",
            "response_id",
            "system_fingerprint",
        ):
            value = getattr(rec, name)
            if value is not None:
                attrs[name] = value
        if rec.ttfb_ms is not None:
            attrs["ttfb_ms"] = round(rec.ttfb_ms, 3)
        if rec.usage:
            attrs["usage"] = rec.usage
        if rec.finish_reasons:
            attrs["finish_reasons"] = rec.finish_reasons
        if rec.ratelimit:
            attrs["ratelimit"] = rec.ratelimit
        if rec.attempts > 1 or rec.inline_fallback_used:
            retry: dict[str, Any] = {"attempt": rec.attempts}
            retry["inline_fallback_used"] = rec.inline_fallback_used
            if rec.to_target:
                retry["fallback_target"] = rec.to_target
            attrs["retry"] = retry
        profile = self._capture(rec, attrs)
        policy: dict[str, Any] = {"state": rec.policy_state, "policy_version": rec.policy_version}
        policy["fail_mode"] = rec.fail_mode
        if rec.snapshot_age_s is not None:
            policy["snapshot_age_s"] = rec.snapshot_age_s
        return self._envelope(
            "gen_ai.request",
            rec.tenant_id,
            rec.agent_id,
            datetime.fromtimestamp(rec.ended, UTC),
            traceparent=rec.traceparent,
            task_id=_uuid_or_none(rec.task_id),
            call_id=str(rec.call_id),
            capture_mode=rec.capture_mode,
            redaction_profile=profile,
            policy_state=policy,
            attrs=attrs,
        )

    def _capture(self, rec: CallRecord, attrs: dict[str, Any]) -> dict[str, Any]:
        profile: dict[str, Any] = {
            "id": PROFILE_ID,
            "version": PROFILE_VERSION,
            "rules_fired": [],
            "secrets_scrubbed": 0,
        }
        if len(rec.profile_hash) == 64 and set(rec.profile_hash) <= _HEX64:
            profile["profile_hash"] = rec.profile_hash
        if rec.capture_mode == "metadata":
            return profile
        parts: dict[str, str] = {}
        fired: set[str] = set()
        hashes: dict[str, str] = {}
        for part, raw, scrub_field in (
            ("input_messages", rec.request_body, ScrubField.INPUT_MESSAGES),
            ("output_messages", rec.response_body, ScrubField.OUTPUT_MESSAGES),
        ):
            if not raw:
                continue
            text = raw.decode("utf-8", errors="replace")
            result = self._scrubber.scrub(text, scrub_field)
            profile["secrets_scrubbed"] += result.secrets_scrubbed
            fired.update(result.rules_fired)
            parts[part] = result.text
            hashes["input" if part == "input_messages" else "output"] = hashlib.sha256(
                result.text.encode()
            ).hexdigest()
        profile["rules_fired"] = sorted(fired)
        if hashes:
            attrs["content_hashes"] = hashes
        data = json.dumps(parts, ensure_ascii=False, separators=(",", ":"))
        if parts and len(data.encode()) <= MAX_INLINE_BYTES:
            attrs["payload_inline"] = {
                "encoding": "utf8",
                "data": data,
                "content_type": CONTENT_TYPE,
                "parts": sorted(parts),
            }
        return profile

    def agent_discovered(
        self,
        tenant: UUID,
        slug: str,
        *,
        candidate: str,
        candidate_hash: str,
        via: str,
        fail_mode: str,
        call_id: UUID | None,
        traceparent: str | None,
        policy_version: int | None,
        policy_state: str = "fresh",
    ) -> dict[str, Any]:
        agent_id = _agent_uuid(tenant, slug)
        attrs: dict[str, Any] = {
            "discovered_via": via,
            "candidate": candidate[:256],
            "candidate_hash": candidate_hash,
            "resolved_agent_id": str(agent_id),
            "fail_mode_applied": fail_mode,
        }
        if call_id is not None:
            attrs["first_call_id"] = str(call_id)
        return self._metadata_event(
            "agent.discovered",
            tenant,
            agent_id,
            attrs,
            traceparent,
            policy_state,
            policy_version,
            fail_mode,
        )

    def policy_decision(
        self,
        tenant: UUID,
        agent: UUID | str,
        *,
        action: str,
        state: str,
        fail_mode: str,
        reason: str,
        http_status: int | None,
        policy_version: int | None,
    ) -> dict[str, Any]:
        attrs: dict[str, Any] = {
            "action": action,
            "state": state if state != "unavailable" else "none",
            "fail_mode": fail_mode,
            "reason": reason[:200],
        }
        if http_status is not None:
            attrs["http_status_returned"] = http_status
        return self._metadata_event(
            "policy.decision", tenant, agent, attrs, None, state, policy_version, fail_mode
        )

    def _metadata_event(
        self,
        kind: str,
        tenant: UUID,
        agent: UUID | str,
        attrs: dict[str, Any],
        traceparent: str | None,
        state: str,
        policy_version: int | None,
        fail_mode: str | None,
    ) -> dict[str, Any]:
        return self._envelope(
            kind,
            tenant,
            agent,
            datetime.now(UTC),
            traceparent=traceparent,
            capture_mode="metadata",
            redaction_profile={
                "id": PROFILE_ID,
                "version": PROFILE_VERSION,
                "rules_fired": [],
                "secrets_scrubbed": 0,
            },
            policy_state={"state": state, "policy_version": policy_version, "fail_mode": fail_mode},
            attrs=attrs,
        )


def _route(rec: CallRecord) -> dict[str, Any]:
    route: dict[str, Any] = {"decision": rec.route}
    if rec.from_target:
        route["from"] = rec.from_target
    if rec.to_target:
        route["to"] = rec.to_target
    return route


def _uuid_or_none(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(UUID(value))
    except ValueError:
        return None


def _agent_uuid(tenant: UUID, agent: UUID | str) -> UUID:
    if isinstance(agent, UUID):
        return agent
    try:
        return UUID(agent)
    except ValueError:
        return provisional_agent_id(tenant, agent)
