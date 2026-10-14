"""Per-item normalisation, steps 5-11 of §4.5, for one already-identified candidate.

``finalize`` scrubs, applies the capture policy, seals bodies (blob before row), derives,
stamps the envelope, validates against ``sibyl-event/1`` and routes the result into the
batch's ``BatchWrite``. A failure at any step becomes ``cand.fail(reason)``; nothing raises
past this module except infrastructure errors (blob store, DEKs), which fail the request.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from .config import IngestConfig
from .normalise import derive
from .normalise.candidate import PAYLOAD_SLOTS, Candidate, Content
from .normalise.envelope import (
    RowContext,
    event_row,
    fit_attrs,
    ingest_block,
    stamp,
    validate_canonical,
)
from .normalise.fields import dumps, parse_ts
from .normalise.jsonb_size import jsonb_size
from .normalise.scrubbing import (
    ENVELOPE_FIELD,
    Scrubber,
    ScrubRefused,
    ScrubTally,
    rule_ids,
    strictest,
)
from .payloads import PayloadSealer, SealedPayload
from .store import AgentRow, CheckpointRow, Policy, TenantInfo

GAP = "observation.gap"


@dataclass
class BatchContext:
    tenant_id: UUID
    key_id: UUID
    key_env: str
    tenant: TenantInfo
    policies: list[Policy]
    baseline_hash: bytes
    prices: dict[tuple[str, str], derive.Price]
    partitions: list[tuple[datetime, datetime]]
    now: datetime
    raw_id: UUID
    capture_owner: str | None
    cfg: IngestConfig

    def policy_for(self, agent: AgentRow | None) -> Policy:
        tenant_policy = next(p for p in self.policies if p.scope_kind == "tenant")
        if agent is not None:
            for p in self.policies:
                if p.scope_kind == "agent" and p.agent_id == agent.id:
                    return p
        return tenant_policy

    def covered(self, ts: datetime) -> bool:
        return any(lo <= ts < hi for lo, hi in self.partitions)


@dataclass
class BatchWrite:
    payloads: list[SealedPayload] = field(default_factory=list)
    events: list[tuple[Any, ...]] = field(default_factory=list)
    calls: dict[UUID, dict[str, str]] = field(default_factory=dict)
    call_items: dict[UUID, list[Candidate]] = field(default_factory=dict)
    checkpoints: list[CheckpointRow] = field(default_factory=list)
    model_pairs: set[tuple[str, str]] = field(default_factory=set)


def _output_chars(value: Any) -> int:
    if isinstance(value, str):
        return len(value)
    if isinstance(value, dict):
        return sum(_output_chars(v) for v in value.values())
    if isinstance(value, list):
        return sum(_output_chars(v) for v in value)
    return 0


def _metadata_view(attrs: dict[str, Any], doc: Any) -> None:
    """``metadata`` mode keeps hashes and ``output_chars`` only (step 6)."""
    if not isinstance(doc, dict):
        return
    hashes = {}
    for part, key in (
        ("input_messages", "input"),
        ("output_messages", "output"),
        ("system_instructions", "system"),
    ):
        if part in doc:
            hashes[key] = hashlib.sha256(dumps(doc[part])).hexdigest()
    if hashes:
        attrs["content_hashes"] = hashes
    if "output_messages" in doc:
        attrs["output_chars"] = _output_chars(doc["output_messages"])


class Finalizer:
    def __init__(
        self, bc: BatchContext, sealer: PayloadSealer, scrubber: Scrubber, write: BatchWrite
    ) -> None:
        self.bc = bc
        self.sealer = sealer
        self.scrubber = scrubber
        self.write = write

    async def _seal(
        self,
        data: bytes,
        *,
        kind: str,
        source_kind: str,
        content_type: str,
        parts: tuple[str, ...],
        mode: str,
        profile_hash: bytes,
        retention_days: int,
        agent: AgentRow | None,
        source_id: UUID | None,
    ) -> SealedPayload:
        sealed = await self.sealer.seal(
            self.bc.tenant_id,
            data,
            kind=kind,
            source_kind=source_kind,
            content_type=content_type,
            parts=parts,
            capture_mode=mode,
            redaction_profile_hash=profile_hash,
            now=self.bc.now,
            retention=timedelta(days=retention_days),
            agent_id=agent.id if agent else None,
            api_key_id=self.bc.key_id,
            source_id=source_id,
        )
        self.write.payloads.append(sealed)
        return sealed

    async def _content(
        self,
        cand: Candidate,
        event: dict[str, Any],
        content: Content,
        mode: str,
        policy: Policy,
        profile_hash: bytes,
        agent: AgentRow | None,
        tally: ScrubTally,
        pii: Any,
    ) -> tuple[UUID, bytes, int] | None:
        etype = event["type"]
        attrs = event["attrs"]
        if (
            self.bc.capture_owner == "sdk"
            and event["source"] == "gateway"
            and etype == "gen_ai.request"
        ):
            cand.warnings.append("gateway body dropped: X-Sibyl-Capture-Owner is sdk")
            return None
        scrubbed, doc = self.scrubber.scrub_content(content, etype, tally, pii)
        if etype == "checkpoint":
            await self._checkpoint(cand, event, doc, mode, profile_hash, agent)
            return None
        if mode == "metadata":
            if etype == "gen_ai.request":
                _metadata_view(attrs, doc)
            return None
        slot, kind, source_kind = PAYLOAD_SLOTS[etype]
        cap = self.bc.cfg.max_content_bytes
        if etype in ("gen_ai.request", "tool.call"):
            cap = min(cap, policy.max_payload_bytes)
        data = scrubbed.data
        extra: dict[str, Any] = {}
        if len(data) > cap:
            extra = {"truncated": True, "bytes_original": len(data)}
            data = data[:cap]
            cand.warnings.append("payload truncated tail-first at the capture cap")
        sealed = await self._seal(
            data,
            kind=kind,
            source_kind=source_kind,
            content_type=content.content_type,
            parts=scrubbed.parts,
            mode=mode,
            profile_hash=profile_hash,
            retention_days=policy.retention_days,
            agent=agent,
            source_id=UUID(event["event_id"]),
        )
        attrs[slot] = sealed.ref(self.bc.tenant_id, extra=extra)
        return sealed.id, sealed.sha256, sealed.size_bytes

    async def _checkpoint(
        self,
        cand: Candidate,
        event: dict[str, Any],
        doc: Any,
        mode: str,
        profile_hash: bytes,
        agent: AgentRow | None,
    ) -> None:
        attrs = event["attrs"]
        if mode == "metadata":
            cand.warnings.append("checkpoint row not stored in metadata capture mode")
            return None
        if not isinstance(doc, dict) or agent is None or not event.get("task_id"):
            cand.warnings.append(
                "checkpoint row skipped: body is not a checkpoint document with a task"
            )
            return None
        state_json = dumps(doc.get("state"))
        body = {k: v for k, v in doc.items() if k != "state"}
        if len(dumps(body)) > 60_000:
            cand.warnings.append("checkpoint row skipped: document over 64 KB without state")
            return None
        state_ref_id = None
        inline = len(state_json) <= self.bc.cfg.inline_state_max_bytes
        if not inline:
            sealed = await self._seal(
                state_json,
                kind="checkpoint_state",
                source_kind="checkpoint",
                content_type="application/json",
                parts=("state",),
                mode=mode,
                profile_hash=profile_hash,
                retention_days=self.bc.policy_for(agent).retention_days,
                agent=agent,
                source_id=UUID(attrs["checkpoint_id"]),
            )
            state_ref_id = sealed.id
            attrs["state_ref"] = sealed.ref(self.bc.tenant_id)
        self.write.checkpoints.append(
            CheckpointRow(
                id=UUID(attrs["checkpoint_id"]),
                created_at=parse_ts(event["ts"]),
                agent_id=agent.id,
                task_id=UUID(event["task_id"]),
                seq=attrs["seq"],
                step_index=attrs["step_index"],
                step_name=attrs.get("step_name"),
                state_bytes=len(state_json),
                state=state_json.decode() if inline else None,
                state_ref_id=state_ref_id,
                state_sha256=hashlib.sha256(state_json).digest(),
                state_schema=str(attrs.get("state_schema") or doc.get("state_schema") or "unknown")[
                    :200
                ],
                doc=dumps(body).decode(),
                capture_mode=mode,
                redaction_profile_hash=profile_hash,
                api_key_id=self.bc.key_id,
            )
        )
        return None

    def _redaction(
        self,
        emitter: dict[str, Any],
        tally: ScrubTally,
        name: str,
        version: int,
        profile_hash: bytes,
    ) -> dict[str, Any]:
        # The emitter's ids are untrusted text: only DB-conforming ids survive (0007 CHECK).
        emitted = emitter.get("rules_fired")
        rules = rule_ids([*(emitted if isinstance(emitted, list) else ()), *tally.rules])
        record: dict[str, Any] = {
            "id": name,
            "version": version,
            "rules_fired": rules,
            "secrets_scrubbed": int(emitter.get("secrets_scrubbed") or 0) + tally.secrets,
            "profile_hash": profile_hash.hex(),
        }
        claimed = emitter.get("emitter_profile_hash") or emitter.get("profile_hash")
        if claimed and claimed != profile_hash.hex():
            record["emitter_profile_hash"] = claimed
        if tally.secrets:
            record["late_hits"] = tally.secrets
        return record

    def _time_check(self, cand: Candidate, ts: datetime) -> bool:
        if self.bc.covered(ts):
            return True
        oldest = self.bc.now - timedelta(days=self.bc.tenant.raw_retention_days)
        cand.fail(
            "outside_retention" if ts < oldest else "no_partition",
            "event ts outside the stored window",
        )
        return False

    async def finalize(self, cand: Candidate, agent: AgentRow | None) -> None:
        assert cand.event is not None
        bc = self.bc
        if cand.env and cand.env != bc.key_env:
            cand.fail("env_mismatch", f"sibyl.env {cand.env!r} does not match the key")
            return
        if not self._time_check(cand, parse_ts(cand.event["ts"])):
            return
        policy = bc.policy_for(agent)
        mode = strictest(cand.event.get("capture_mode"), policy.capture_mode)
        redacted = mode == "redacted" and policy.profile_name != "secrets_only"
        profile_hash = policy.profile_hash if redacted else bc.baseline_hash
        profile_name, profile_version = (
            (policy.profile_name, 1) if redacted else ("secrets_only", 1)
        )
        pii = self.scrubber.pii(policy.detector_ids) if redacted else None
        emitter_profile = dict(cand.event.get("redaction_profile") or {})
        tally = ScrubTally()
        try:
            event = self.scrubber.scrub_event(cand.event, tally)
            event["emitter_id"] = event["emitter_id"][:128]  # truncate only after scrubbing
            event["agent_id"] = str(agent.id) if agent else None
            if pii is not None:
                event["attrs"], fired = pii.redact_json(event["attrs"])
                tally.rules.update(fired)
            payload = None
            if cand.content is not None and event["type"] in PAYLOAD_SLOTS:
                payload = await self._content(
                    cand, event, cand.content, mode, policy, profile_hash, agent, tally, pii
                )
            elif cand.content is not None:
                cand.warnings.append(f"payload_inline ignored on {event['type']}")
        except ScrubRefused as exc:
            cand.fail("schema_invalid", f"cannot scrub: {exc}")
            return
        event["capture_mode"] = mode
        event["redaction_profile"] = self._redaction(
            emitter_profile, tally, profile_name, profile_version, profile_hash
        )
        if pii is not None and pii.unimplemented:
            cand.warnings.append("pii detectors not implemented: " + ", ".join(pii.unimplemented))
        attrs = event["attrs"]
        model = attrs.get("response_model") or attrs.get("request_model")
        provider = attrs.get("provider")
        price = bc.prices.get((provider, model)) or bc.prices.get(
            (provider, attrs.get("request_model"))
        )
        klass, cost = derive.apply(event, price)
        if event["type"] == "gen_ai.request" and provider and attrs.get("request_model"):
            self.write.model_pairs.add((provider, attrs["request_model"]))
        try:
            event["attrs"], notes = fit_attrs(event["type"], attrs, bc.cfg.attrs_budget_bytes)
        except ValueError as exc:
            cand.fail("schema_invalid", str(exc))
            return
        cand.warnings.extend(notes)
        try:
            instrumentor = (
                self.scrubber.scrub_text(cand.instrumentor, ENVELOPE_FIELD, tally)
                if cand.instrumentor
                else None
            )
            sdk_version = (
                self.scrubber.scrub_text(cand.sdk_version, ENVELOPE_FIELD, tally)
                if cand.sdk_version
                else None
            )
        except ScrubRefused:
            instrumentor = sdk_version = None
        block = ingest_block(
            instrumentor, sdk_version, cand.warnings, bc.cfg.ingest_block_budget_bytes
        )
        event = stamp(event, bc.now, block)
        problem = validate_canonical(event)
        if problem is not None:
            cand.fail(*problem)
            return
        ctx = RowContext(bc.tenant_id, bc.key_id, bc.now, bc.raw_id, profile_hash, bc.cfg)
        row = event_row(
            event,
            ctx,
            agent_version_id=agent.current_version_id if agent else None,
            error_class=klass,
            cost=cost,
            payload=payload,
        )
        cand.event = event
        if event["type"] == "gen_ai.request":
            if not self._stage(cand, event, row):
                cand.fail("schema_invalid", "gen_ai.request contribution exceeds 16 KB")
        else:
            self.write.events.append(row)

    def _stage(self, cand: Candidate, event: dict[str, Any], row: tuple[Any, ...]) -> bool:
        call_id = UUID(event["call_id"])
        side = "gateway" if event["source"] == "gateway" else "sdk"
        doc = {"event": event, "row": _row_json(row)}
        if jsonb_size(doc) > self.bc.cfg.contribution_budget_bytes:
            return False
        self.write.calls.setdefault(call_id, {})[side] = dumps(doc).decode()
        self.write.call_items.setdefault(call_id, []).append(cand)
        return True


def _row_json(row: tuple[Any, ...]) -> dict[str, Any]:
    """The derived columns the flusher cannot recompute from the event alone."""
    from .normalise.envelope import EVENT_COLUMNS

    named = dict(zip((c for c, _ in EVENT_COLUMNS), row, strict=True))
    keep = (
        "agent_version_id",
        "error_class",
        "cost_usd",
        "api_key_id",
        "payload_ref_id",
        "payload_sha256",
        "payload_bytes",
        "raw_ref_id",
        "redaction_profile_hash",
        "observed_at",
    )
    out: dict[str, Any] = {}
    for key in keep:
        value = named[key]
        if isinstance(value, bytes):
            value = value.hex()
        elif value is not None and not isinstance(value, int | float | str):
            value = str(value)
        out[key] = value
    return out
