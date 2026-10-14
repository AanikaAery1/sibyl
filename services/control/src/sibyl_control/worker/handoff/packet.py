"""Control-plane assembly of ``sibyl-handoff/1`` packets (API.md §9).

``checkpoint`` fidelity when the task has a checkpoint (goal, completed and pending steps, side
effects, redaction state copied from the checkpoint document, never its ``state``), otherwise
``request_only`` (no pending steps). Content stays as payload references so the erasure cascade
covers packets (D17). The deadline is ``created_at + rto_s`` (D23); accountability comes from the
registry and the continuity plan. Every packet is validated against the frozen schema before it
is stored; a checkpoint document that does not validate degrades to ``request_only``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sibyl_schemas.jsonschema import iter_errors

from ...core.canonical import canonicalize

SCHEMA = "sibyl-handoff/1"
RULE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,40}$")
UUIDV7_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
DEFAULT_PROFILE = {"id": "secrets_only", "version": 1, "rules_fired": [], "secrets_scrubbed": 0}
DEFAULT_NEXT_ACTION = "Review the task, finish it by hand and record the outcome."
HOLD_NEXT_ACTION = (
    "Side effects were already recorded that are not safe to repeat. Check the side-effect "
    "ledger before you continue or return this task."
)
# ``sibyl-handoff/1`` side effects take exactly these members; a checkpoint may carry more
# (e.g. ``idempotent``, A-4), which the packet drops so it still validates.
SIDE_EFFECT_KEYS = frozenset(
    {
        "kind",
        "target",
        "at",
        "idempotency_key",
        "reversible",
        "idempotent",
        "assumed",
        "evidence_span_id",
    }
)


@dataclass(frozen=True)
class TaskInput:
    """One in-flight task and its latest checkpoint (``doc`` minus ``state``), if any."""

    task_id: UUID
    checkpoint_id: UUID | None = None
    checkpoint_seq: int | None = None
    checkpoint_at: datetime | None = None
    checkpoint_doc: Mapping[str, Any] | None = None
    capture_mode: str | None = None
    first_input: Mapping[str, Any] | None = None  # payload_refs row of the task's first request
    trace_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class PacketContext:
    tenant_id: UUID
    agent_id: UUID
    agent_name: str
    tier: int
    rto_s: int
    failure_mode: str
    trigger_kind: str  # rule | operator | approval_timeout
    rule_code: str | None
    alert_id: UUID | None
    health_snapshot_id: UUID | None
    policy_version: int
    transition_id: UUID | None
    owner: str
    on_call: str | None
    business_process: str | None
    reason: str


@dataclass(frozen=True)
class BuiltPacket:
    packet: dict[str, Any]
    sha256: bytes
    fidelity: str
    next_action: str
    summary: str
    deadline_at: datetime


def iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def packet_digest(packet: Mapping[str, Any]) -> bytes:
    """sha256 over RFC 8785 bytes; documents with floats fall back to sorted compact JSON."""
    try:
        raw = canonicalize(packet)
    except (TypeError, ValueError):
        raw = json.dumps(packet, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).digest()


def _plain_language(ctx: PacketContext) -> str:
    rule = f" (rule {ctx.rule_code})" if ctx.rule_code else ""
    text = (
        f"{ctx.agent_name} was moved to the human queue: {ctx.failure_mode.replace('_', ' ')}"
        f"{rule}. {ctx.reason}".strip()
    )
    return text[:1000]  # always >= 20 chars: the fixed wording alone is longer


def _trigger(ctx: PacketContext) -> dict[str, Any]:
    out: dict[str, Any] = {"kind": ctx.trigger_kind}
    if ctx.rule_code and RULE_ID_RE.match(ctx.rule_code):
        out["rule_id"] = ctx.rule_code
    if ctx.alert_id is not None:
        out["alert_id"] = str(ctx.alert_id)
    if ctx.health_snapshot_id is not None and UUIDV7_RE.match(str(ctx.health_snapshot_id)):
        out["health_snapshot_id"] = str(ctx.health_snapshot_id)
    return out


def _accountability(ctx: PacketContext) -> dict[str, Any]:
    out: dict[str, Any] = {"owner": ctx.owner}
    if ctx.on_call:
        out["on_call"] = ctx.on_call
    if ctx.business_process:
        out["business_process"] = ctx.business_process
    line = f"{ctx.owner} owns {ctx.agent_name}"
    if ctx.on_call:
        line += f"; on call: {ctx.on_call}"
    out["line"] = line[:300]
    return out


def _original_input(tenant: UUID, row: Mapping[str, Any] | None) -> dict[str, Any]:
    if not row:
        return {}
    uri = str(row.get("uri") or "")
    prefix = f"tenant/{tenant}/"
    if not uri.startswith(prefix):
        return {}
    return {
        "ref": {
            "ref": f"blob://{tenant}/{uri[len(prefix) :]}",
            "sha256": bytes(row["sha256"]).hex(),
            "bytes": int(row["size_bytes"]),
            "content_type": str(row.get("content_type") or "application/json"),
        },
        "content_type": str(row.get("content_type") or "application/json"),
    }


def _base(ctx: PacketContext, task: TaskInput, packet_id: UUID, now: datetime) -> dict[str, Any]:
    deadline = now + timedelta(seconds=ctx.rto_s)
    provenance: dict[str, Any] = {
        "assembled_by": "control_plane",
        "policy_version": max(0, int(ctx.policy_version)),
        "trace_ids": [t for t in task.trace_ids if re.fullmatch(r"[0-9a-f]{32}", t)],
    }
    if ctx.transition_id is not None:
        provenance["transition_id"] = str(ctx.transition_id)
    return {
        "schema": SCHEMA,
        "packet_id": str(packet_id),
        "tenant_id": str(ctx.tenant_id),
        "agent_id": str(ctx.agent_id),
        "agent_name": ctx.agent_name[:128],
        "task_id": str(task.task_id),
        "created_at": iso(now),
        "fidelity": "request_only",
        "goal": f"Complete task {task.task_id} for {ctx.agent_name}"[:2000],
        "original_input": _original_input(ctx.tenant_id, task.first_input),
        "completed_steps": [],
        "pending_steps": [],
        "side_effects": [],
        "reason": {
            "plain_language": _plain_language(ctx),
            "failure_mode": ctx.failure_mode,
            "trigger": _trigger(ctx),
        },
        "next_action": DEFAULT_NEXT_ACTION,
        "deadline": {
            "at": iso(deadline),
            "derived_from": "tier_rto",
            "tier": ctx.tier,
            "rto_s": ctx.rto_s,
        },
        "accountability": _accountability(ctx),
        "redaction": {"capture_mode": task.capture_mode or "metadata", "profile": DEFAULT_PROFILE},
        "provenance": provenance,
    }


def _with_checkpoint(packet: dict[str, Any], task: TaskInput, now: datetime) -> dict[str, Any]:
    doc = task.checkpoint_doc or {}
    out = dict(packet)
    out["fidelity"] = "checkpoint"
    if doc.get("goal"):
        out["goal"] = str(doc["goal"])[:2000]
    out["completed_steps"] = list(doc.get("completed_steps") or [])
    out["pending_steps"] = list(doc.get("pending_steps") or [])
    out["side_effects"] = [
        {k: v for k, v in e.items() if k in SIDE_EFFECT_KEYS} if isinstance(e, Mapping) else e
        for e in (doc.get("side_effects") or [])
    ]
    redaction = doc.get("redaction")
    if isinstance(redaction, Mapping) and redaction.get("profile"):
        out["redaction"] = dict(redaction)
    pending = out["pending_steps"]
    if pending and isinstance(pending[0], Mapping):
        first = pending[0]
        text = str(first.get("description") or f"Continue with step '{first.get('step')}'.")
        out["next_action"] = (text if len(text) >= 5 else DEFAULT_NEXT_ACTION)[:300]
    provenance = dict(out["provenance"])
    provenance["checkpoint_id"] = str(task.checkpoint_id)
    provenance["checkpoint_seq"] = int(task.checkpoint_seq or 0)
    if task.checkpoint_at is not None:
        provenance["checkpoint_age_s"] = max(0, int((now - task.checkpoint_at).total_seconds()))
    trace = (doc.get("provenance") or {}).get("trace_id")
    if isinstance(trace, str) and trace not in provenance["trace_ids"]:
        provenance["trace_ids"] = [*provenance["trace_ids"], trace]
    out["provenance"] = provenance
    return out


def build(
    ctx: PacketContext,
    task: TaskInput,
    *,
    packet_id: UUID,
    now: datetime,
    side_effect_hold: bool = False,
) -> BuiltPacket:
    """``side_effect_hold``: the task was held for a human because of recorded side effects that
    are not idempotent (A-4); the next action says so."""
    packet = _base(ctx, task, packet_id, now)
    if task.checkpoint_id is not None and task.checkpoint_doc is not None:
        candidate = _with_checkpoint(packet, task, now)
        if not iter_errors(SCHEMA, candidate):
            packet = candidate
    if side_effect_hold:
        packet["next_action"] = HOLD_NEXT_ACTION
    errors = iter_errors(SCHEMA, packet)
    if errors:  # pragma: no cover - the request-only shape is built to validate
        raise ValueError(f"handoff packet does not validate: {errors[0]}")
    summary = (
        f"{ctx.agent_name}: {ctx.failure_mode.replace('_', ' ')}; "
        f"{len(packet['completed_steps'])} steps done, {len(packet['pending_steps'])} pending"
    )[:500]
    packet["summary"] = summary
    deadline = now + timedelta(seconds=ctx.rto_s)
    return BuiltPacket(
        packet=packet,
        sha256=packet_digest(packet),
        fidelity=packet["fidelity"],
        next_action=packet["next_action"],
        summary=summary,
        deadline_at=deadline,
    )


def checkpoint_age_p95(tasks: Sequence[TaskInput], now: datetime) -> int | None:
    """RPO evidence: p95 checkpoint age (s) over tasks that had a checkpoint at the cut."""
    ages = sorted(
        int((now - t.checkpoint_at).total_seconds()) for t in tasks if t.checkpoint_at is not None
    )
    if not ages:
        return None
    return ages[min(len(ages) - 1, round(0.95 * (len(ages) - 1)))]
