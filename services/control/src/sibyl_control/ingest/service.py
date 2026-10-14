"""One ingest request end to end (DATAMODEL §6.1 as amended: R61/T5b auto-register first).

    prelude tx (read-only): tenant gate, batch replay, capture policies, agents, prices
    backpressure: tenant event bucket
    auto-register: one short tx per unknown identity (audit lock → agent → routing_apply)
    normalise: scrub, capture, seal blobs, derive, validate (pipeline.Finalizer)
    batch tx: payload_refs → checkpoint → events → call_merge → events_rejected →
              model discovery → ingest_batch_seen → api_key.last_used_at; commit; respond

Nothing is acknowledged before commit. A request that cannot commit within the timeout is
503 with ``Retry-After`` and nothing is stored (blobs already written are unreferenced and
swept).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import socket
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from ..core.crypto.deks import KeyShredded, PgDekProvider
from ..core.db import Database
from ..core.problems import ProblemError
from . import store
from .backpressure import Backpressure, backpressure
from .config import RESPONSE_SCHEMA, IngestConfig
from .ids import deterministic_uuid7, uuid7
from .normalise.candidate import Candidate
from .normalise.fields import dumps, rfc3339
from .normalise.identity import (
    Claim,
    Directory,
    Resolution,
    candidate_hash,
    handoff_refs,
    resolve,
    split_refs,
    unclaimed_slug,
)
from .normalise.jsonb_size import jsonb_size
from .normalise.scrubbing import Scrubber, ScrubRefused, ScrubTally
from .payloads import PayloadSealer
from .pipeline import BatchContext, BatchWrite, Finalizer

log = logging.getLogger("sibyl.ingest")
MAX_NEW_AGENTS_PER_BATCH = 50
FINALIZE_CONCURRENCY = 16
_TRACE_HEX = frozenset("0123456789abcdef")


def first_trace(cand: Candidate) -> str | None:
    """The candidate's trace id as 32 lowercase hex (never the all-zero id), or None."""
    event = cand.event or {}
    value = event.get("trace_id") or cand.trace_hex
    if not isinstance(value, str) or len(value) != 32 or not set(value) <= _TRACE_HEX:
        return None
    return None if value == "0" * 32 else value


_EMITTER = f"ingest:{socket.gethostname()[:60]}:{os.getpid()}"
_REGISTRATION_ERRORS = (ProblemError,)


@dataclass(frozen=True)
class IngestPrincipal:
    tenant_id: UUID
    key_id: UUID
    env: str
    scopes: frozenset[str]
    bound_agent_id: UUID | None


@dataclass
class BatchRequest:
    route: str  # traces | logs | events
    principal: IngestPrincipal
    candidates: list[Candidate]
    batch_id: str | None = None
    agent_header: str | None = None
    capture_owner: str | None = None
    request_id: UUID | None = None
    decode_warnings: tuple[str, ...] = ()


@dataclass
class Rejection:
    index: int
    reason: str
    detail: str | None = None
    event_id: str | None = None
    trace_id: str | None = None
    span_id: str | None = None


@dataclass
class Outcome:
    batch_id: str
    accepted: int
    rejected: list[Rejection] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    replayed: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "accepted": self.accepted,
            "rejected": [
                {k: v for k, v in vars(r).items() if v is not None} for r in self.rejected
            ],
            "warnings": self.warnings,
        }

    @classmethod
    def from_json(cls, doc: dict[str, Any]) -> Outcome:
        return cls(
            doc["batch_id"],
            doc["accepted"],
            [Rejection(**r) for r in doc.get("rejected", [])],
            list(doc.get("warnings", [])),
            replayed=True,
        )


def _compact_for_cache(doc: dict[str, Any], limit: int = 16_000) -> dict[str, Any]:
    """``ingest_batch_seen.response_body`` is ≤ 16 KB (jsonb): drop details, then ids, then
    tail items. A replay of a heavily rejected batch therefore reports fewer details."""
    if jsonb_size(doc) <= limit:
        return doc
    rejected = [{k: v for k, v in r.items() if k != "detail"} for r in doc["rejected"]]
    doc = {**doc, "rejected": rejected, "warnings": doc["warnings"][:10]}
    if jsonb_size(doc) <= limit:
        return doc
    rejected = [{k: r[k] for k in ("index", "reason") if k in r} for r in rejected]
    while rejected and jsonb_size({**doc, "rejected": rejected}) > limit:
        rejected = rejected[: len(rejected) // 2]
    return {**doc, "rejected": rejected}


def _aggregate(warnings: list[str], limit: int) -> list[str]:
    counts = Counter(warnings)
    out = [w if n == 1 else f"{w} (x{n})" for w, n in counts.most_common()]
    return [w[:500] for w in out[:limit]]


class PartitionCache:
    def __init__(self, ttl_s: float = 60.0) -> None:
        self._ttl = ttl_s
        self._value: list[tuple[datetime, datetime]] = []
        self._at = -1e9

    async def get(self, conn: Any) -> list[tuple[datetime, datetime]]:
        now = time.monotonic()
        if now - self._at > self._ttl:
            self._value = await store.partition_ranges(conn, "events")
            self._at = now
        return self._value

    def clear(self) -> None:
        self._at = -1e9


class IngestService:
    def __init__(
        self,
        db: Database,
        sealer: PayloadSealer,
        deks: PgDekProvider,
        scrubber: Scrubber,
        backpressure_: Backpressure,
        cfg: IngestConfig,
        *,
        clock: Any = None,
    ) -> None:
        self.db = db
        self.sealer = sealer
        self.deks = deks
        self.scrubber = scrubber
        self.bp = backpressure_
        self.cfg = cfg
        self.clock = clock or (lambda: datetime.now(UTC))
        self.partitions = PartitionCache()
        self._seq = 0

    # -- prelude ----------------------------------------------------------------------------

    async def _prelude(self, req: BatchRequest, refs: list[str]) -> tuple[Any, ...]:
        tenant_id = req.principal.tenant_id
        async with self.db.tenant_tx(tenant_id, readonly=True) as conn:
            tenant = await store.load_tenant(conn, tenant_id)
            if tenant is None:
                raise ProblemError("unauthenticated")
            if tenant.status == "erasing":
                self.deks.invalidate(tenant_id)
                raise backpressure(
                    "tenant_erasing", self.cfg.erasing_retry_after_s, "tenant is being erased"
                )
            if tenant.status != "active":
                raise ProblemError("forbidden", "tenant is not active")
            if req.batch_id is not None:
                cached = await store.find_replay(conn, req.batch_id, self.cfg.batch_replay_window_h)
                if cached is not None:
                    return tenant, None, None, None, None, None, Outcome.from_json(cached)
            policies = await store.load_policies(conn)
            if not any(p.scope_kind == "tenant" for p in policies):
                raise ProblemError(
                    "capture_policy_missing", "the tenant has no capture policy", status=403
                )
            baseline = await store.baseline_profile_hash(conn)
            ids, slugs = split_refs(refs)
            if req.principal.bound_agent_id is not None:
                ids.append(req.principal.bound_agent_id)
            agents = await store.find_agents(conn, ids, slugs)
            models = {
                m
                for c in req.candidates
                if c.event is not None and c.event.get("type") == "gen_ai.request"
                for m in (
                    c.event["attrs"].get("request_model"),
                    c.event["attrs"].get("response_model"),
                )
                if isinstance(m, str)
            }
            prices = await store.load_prices(conn, models)
            partitions = await self.partitions.get(conn)
        return tenant, policies, baseline, agents, prices, partitions, None

    # -- identity -----------------------------------------------------------------------------

    async def _register(
        self,
        req: BatchRequest,
        claim: Claim,
        directory: Directory,
        discovered: list[Candidate],
        trace: str | None = None,
    ) -> Any:
        tenant_id = req.principal.tenant_id
        tally = ScrubTally()
        try:
            shown = self.scrubber.scrub_text(claim.candidate, self.scrubber_field(), tally)[:256]
        except ScrubRefused:
            shown = "[unscrubbable candidate]"
        async with self.db.tenant_tx(tenant_id, statement_timeout_ms=5_000) as conn:
            name = (
                shown[:200] or f"Discovered agent {claim.slug[-8:]}"
                if claim.via == "run_tree"
                else f"Unclaimed agent {claim.slug[-8:]}"
            )
            agent, inserted = await store.register_agent(
                conn,
                tenant_id,
                claim.slug,
                name,
                req.principal.key_id,
                req.request_id,
                claim.agent_id,
                discovered_via=claim.via,
                first_trace_id=UUID(hex=trace) if trace else None,
            )
        directory.add(agent)
        if inserted:
            discovered.append(self._discovered_event(req, claim, shown, agent, trace))
        return agent

    @staticmethod
    def scrubber_field() -> Any:
        from sibyl_schemas.scrub import ScrubField

        return ScrubField.STATE

    def _discovered_event(
        self, req: BatchRequest, claim: Claim, shown: str, agent: Any, trace: str | None
    ) -> Candidate:
        now = self.clock()
        self._seq += 1
        tenant_id = req.principal.tenant_id
        event = {
            "schema": "sibyl-event/1",
            "event_id": str(
                deterministic_uuid7(
                    int(now.timestamp() * 1000), tenant_id, agent.id, "agent.discovered"
                )
            ),
            "type": "agent.discovered",
            "tenant_id": str(tenant_id),
            "agent_id": str(agent.id),
            "task_id": None,
            "call_id": None,
            "ts": rfc3339(now),
            "source": "ingest",
            "emitter_id": _EMITTER,
            "seq": self._seq,
            "capture_mode": "metadata",
            "redaction_profile": {
                "id": "secrets_only",
                "version": 1,
                "rules_fired": [],
                "secrets_scrubbed": 0,
            },
            "policy_state": {"state": "not_applicable"},
            "attrs": {
                "discovered_via": claim.via,
                "candidate": shown,
                "candidate_hash": candidate_hash(claim.candidate),
                "resolved_agent_id": str(agent.id),
                "fail_mode_applied": agent.fail_mode,
                **({"first_trace_id": trace} if trace else {}),
            },
        }
        return Candidate(index=-1, event=event, agent_ref=str(agent.id))

    async def _scope(
        self, req: BatchRequest, directory: Directory, discovered: list[Candidate]
    ) -> Any:
        principal = req.principal
        bound = directory.by_id.get(principal.bound_agent_id) if principal.bound_agent_id else None
        header = req.agent_header
        if bound is not None:
            named = directory.lookup(header) if header else None
            if header and (named is None or named.id != bound.id):
                raise ProblemError(
                    "agent_not_permitted",
                    "X-Sibyl-Agent may only narrow the key's agent",
                    audit_denied=True,
                )
            return bound
        if not header:
            return None
        found = directory.lookup(header)
        if found is not None:
            return found
        trace = next((t for c in req.candidates if c.ok and (t := first_trace(c))), None)
        return await self._register(
            req, Claim(header, "gateway_header"), directory, discovered, trace
        )

    async def _identify(
        self, req: BatchRequest, scope: Any, directory: Directory, discovered: list[Candidate]
    ) -> dict[int, Any]:
        resolved: dict[int, Any] = {}
        claims: dict[str, Claim] = {}
        traces: dict[str, str] = {}
        pending: list[tuple[Candidate, Resolution]] = []
        for cand in req.candidates:
            if not cand.ok:
                continue
            res = resolve(
                cand.agent_ref,
                cand.agent_via,
                cand.event["type"],  # type: ignore[index]
                scope=scope,
                directory=directory,
                key_id=req.principal.key_id,
            )
            if res.refused:
                cand.fail("agent_not_permitted", "agent is outside what the key may act as")
            elif res.claim is not None:
                claims.setdefault(res.claim.slug, res.claim)
                trace = first_trace(cand)
                if trace is not None:
                    traces.setdefault(res.claim.slug, trace)
                pending.append((cand, res))
            else:
                resolved[cand.index] = res.agent
        registered: dict[str, Any] = {}
        for n, (slug, claim) in enumerate(claims.items()):
            if n >= MAX_NEW_AGENTS_PER_BATCH:
                break
            registered[slug] = await self._register(
                req, claim, directory, discovered, traces.get(slug)
            )
        for cand, res in pending:
            agent = registered.get(res.claim.slug) if res.claim else None
            if agent is None:
                cand.fail("agent_not_permitted", "auto-registration limit reached for this batch")
            else:
                resolved[cand.index] = agent
        return resolved

    async def _discover_handoffs(
        self, req: BatchRequest, directory: Directory, discovered: list[Candidate]
    ) -> None:
        """D50: an agent first seen as a handoff target in the run tree is registered
        ``discovered`` (never routed or gated until an admin confirms it). The events keep
        their own identity; this is a side registration bounded per batch."""
        seen: set[str] = set()
        for cand in req.candidates:
            ref = handoff_refs(cand.event) if cand.ok else None
            if ref is None or ref in seen or directory.lookup(ref) is not None:
                continue
            seen.add(ref)
            if directory.by_slug.get(unclaimed_slug(ref)) is not None:
                continue
            if len(seen) > MAX_NEW_AGENTS_PER_BATCH:
                break
            await self._register(
                req, Claim(ref, "run_tree"), directory, discovered, first_trace(cand)
            )

    # -- main entry ---------------------------------------------------------------------------

    async def ingest(self, req: BatchRequest) -> Outcome:
        async with self.bp.slot():
            try:
                async with asyncio.timeout(self.cfg.request_timeout_s):
                    return await self._ingest(req)
            except TimeoutError:
                raise ProblemError(
                    "database_timeout",
                    "ingest could not commit in time; nothing was stored",
                    extensions={"retry_after_s": self.cfg.db_retry_after_s},
                    headers={"Retry-After": str(self.cfg.db_retry_after_s)},
                ) from None
            except KeyShredded:
                self.deks.invalidate(req.principal.tenant_id)
                raise backpressure(
                    "tenant_erasing",
                    self.cfg.erasing_retry_after_s,
                    "the tenant's payload key is shredded",
                ) from None
            except (OSError, ConnectionError) as exc:
                log.warning("database unavailable: %s", type(exc).__name__)
                raise ProblemError(
                    "database_unavailable",
                    extensions={"retry_after_s": self.cfg.db_retry_after_s},
                    headers={"Retry-After": str(self.cfg.db_retry_after_s)},
                ) from None

    async def _ingest(self, req: BatchRequest) -> Outcome:
        principal = req.principal
        refs = [c.agent_ref for c in req.candidates if c.ok and c.agent_ref]
        handoffs = {r for c in req.candidates if c.ok and (r := handoff_refs(c.event))}
        refs += [*handoffs, *(unclaimed_slug(r) for r in handoffs)]
        if req.agent_header:
            refs.append(req.agent_header)
        tenant, policies, baseline, agents, prices, partitions, replay = await self._prelude(
            req, refs
        )
        if isinstance(replay, Outcome):
            return replay
        await self.bp.tenant(
            principal.tenant_id,
            tenant.events_per_s,
            tenant.burst,
            sum(1 for c in req.candidates if c.ok),
        )
        directory = Directory()
        for agent in agents:
            directory.add(agent)
        discovered: list[Candidate] = []
        scope = await self._scope(req, directory, discovered)
        resolved = await self._identify(req, scope, directory, discovered)
        await self._discover_handoffs(req, directory, discovered)
        announced = {
            resolved[c.index].id
            for c in req.candidates
            if c.ok
            and c.event is not None
            and c.event["type"] == "agent.discovered"
            and c.index in resolved
        }
        discovered = [d for d in discovered if UUID(d.event["agent_id"]) not in announced]  # type: ignore[index]
        now = self.clock()
        bc = BatchContext(
            principal.tenant_id,
            principal.key_id,
            principal.env,
            tenant,
            policies,
            baseline or b"\x00" * 32,
            prices,
            partitions,
            now,
            uuid7(now),
            req.capture_owner,
            self.cfg,
        )
        write = BatchWrite()
        finalizer = Finalizer(bc, self.sealer, self.scrubber, write)
        if req.candidates:
            await self.deks.active(principal.tenant_id, "payload")  # warm the cache once
        gate = asyncio.Semaphore(FINALIZE_CONCURRENCY)

        async def finalize(cand: Candidate, agent: Any) -> None:
            async with gate:  # blob writes overlap; rows are appended in completion order
                await finalizer.finalize(cand, agent)

        await asyncio.gather(*(finalize(c, resolved.get(c.index)) for c in req.candidates if c.ok))
        for cand in discovered:
            await finalizer.finalize(cand, directory.by_id.get(UUID(cand.event["agent_id"])))  # type: ignore[index]
        return await self._commit(req, bc, write)

    async def _raw_batch(self, req: BatchRequest, bc: BatchContext) -> Any:
        items = []
        for cand in req.candidates:
            entry: dict[str, Any] = {
                "index": cand.index,
                "trace_id": cand.trace_hex,
                "span_id": cand.span_hex,
            }
            if cand.dead_letter:
                entry["dead_letter"] = cand.dead_letter
            if cand.reject:
                entry["rejected"] = cand.reject.reason
            if cand.event is not None:
                try:
                    entry["event"] = self.scrubber.scrub_event(cand.event, ScrubTally())
                except ScrubRefused:
                    entry["event"] = None
            items.append(entry)
        doc = {"route": req.route, "received_at": rfc3339(bc.now), "items": items}
        policy = bc.policy_for(None)
        return await self.sealer.seal(
            bc.tenant_id,
            dumps(doc),
            kind="raw_batch",
            source_kind="event",
            content_type="application/vnd.sibyl.raw-batch+json",
            parts=("raw_span",),
            capture_mode=policy.capture_mode,
            redaction_profile_hash=bc.baseline_hash,
            now=bc.now,
            retention=timedelta(days=bc.tenant.raw_retention_days),
            api_key_id=bc.key_id,
            object_id=bc.raw_id,
        )

    def _rejection(self, cand: Candidate) -> Rejection:
        assert cand.reject is not None
        event_id = cand.event_id_hint
        if event_id is None and cand.event is not None:
            event_id = cand.event.get("event_id")
        return Rejection(
            cand.index,
            cand.reject.reason,
            cand.reject.detail,
            event_id,
            cand.trace_hex,
            cand.span_hex,
        )

    async def _commit(self, req: BatchRequest, bc: BatchContext, write: BatchWrite) -> Outcome:
        has_items = bool(req.candidates)
        raw = await self._raw_batch(req, bc) if has_items else None
        if raw is not None:
            write.payloads.insert(0, raw)
        batch_id = req.batch_id or str(bc.raw_id)
        tenant_id = bc.tenant_id
        async with self.db.tenant_tx(
            tenant_id, statement_timeout_ms=self.cfg.statement_timeout_ms
        ) as conn:
            await store.insert_payload_refs(conn, tenant_id, write.payloads)
            await store.insert_checkpoints(conn, tenant_id, write.checkpoints)
            await store.insert_events(conn, write.events)
            accepted_calls = await store.stage_calls(
                conn, write.calls, self.cfg.call_merge_flush_after_s
            )
            for call_id, items in write.call_items.items():
                if call_id not in accepted_calls:
                    for cand in items:
                        cand.fail("late_contribution", "the call was already flushed")
            rejected = [c for c in req.candidates if c.reject is not None]
            heads = [
                (
                    c.reject.reason,  # type: ignore[union-attr]
                    {
                        k: v
                        for k, v in {
                            "index": c.index,
                            "event_id": c.event_id_hint,
                            "trace_id": c.trace_hex,
                            "span_id": c.span_hex,
                            "route": req.route,
                            "detail": c.reject.detail,  # type: ignore[union-attr]
                        }.items()
                        if v is not None
                    },
                )
                for c in rejected
            ]
            await store.insert_rejections(conn, raw.id if raw else None, heads)
            await store.discover_models(conn, write.model_pairs)
            warnings = [*req.decode_warnings, *(w for c in req.candidates for w in c.warnings)]
            dead = Counter(c.dead_letter for c in req.candidates if c.dead_letter)
            warnings.extend(f"{n} items raw-only: {why}" for why, n in dead.items())
            outcome = Outcome(
                batch_id,
                sum(1 for c in req.candidates if c.reject is None and c.dead_letter is None),
                [self._rejection(c) for c in rejected],
                _aggregate(warnings, self.cfg.max_warnings),
            )
            if req.batch_id is not None:
                cached = _compact_for_cache(outcome.to_json())
                await store.remember_batch(
                    conn,
                    req.batch_id,
                    req.principal.key_id,
                    cached,
                    hashlib.sha256(dumps(cached)).digest(),
                )
            await store.touch_key(conn, req.principal.key_id)
        return outcome


def events_response(outcome: Outcome) -> dict[str, Any]:
    return {
        "schema": RESPONSE_SCHEMA,
        "batch_id": outcome.batch_id,
        "accepted": outcome.accepted,
        "rejected": [
            {
                k: v
                for k, v in (
                    ("index", r.index),
                    ("event_id", r.event_id),
                    ("reason", r.reason),
                    ("detail", r.detail),
                )
                if v is not None
            }
            for r in outcome.rejected
        ],
        "warnings": outcome.warnings,
        "replayed": outcome.replayed,
    }


def otlp_partial(outcome: Outcome, limit: int = 100) -> tuple[int, str]:
    if not outcome.rejected:
        return 0, ""
    entries = [
        {
            k: v
            for k, v in (("trace_id", r.trace_id), ("span_id", r.span_id), ("reason", r.reason))
            if v
        }
        for r in outcome.rejected[:limit]
    ]
    more = len(outcome.rejected) - limit
    message = json.dumps(entries, separators=(",", ":")) + (f" +{more} more" if more > 0 else "")
    return len(outcome.rejected), message
