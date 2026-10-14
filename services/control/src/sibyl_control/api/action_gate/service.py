"""Action Gate control-plane logic shared by the routes, the snapshot and the worker (D48).

The policy document model and the pure evaluator are ``sibyl_schemas.action_gate`` (lane
AG-ENFORCE). This module resolves which approved policies apply to an agent (agent-specific,
then its agent group's, then the tenant's; ``evaluate_all`` takes the most restrictive),
fills ``tool_allowlist`` from the agent identity where enforcement is on, runs the authoritative
cumulative check-and-increment and builds the snapshot references (chair ruling B22).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from sibyl_schemas import action_gate as ag
from sibyl_schemas.canonical import canonical_sha256

from ...core.problems import ProblemError

POLICY_BUDGET_BYTES = 1024 * 1024
"""B4: approved action policy documents of one tenant stay within 1 MiB of JSON, so the signed
snapshot (3 MiB raw / 2 MiB gzip) always has room for them; approval past it is refused."""
MAX_AGENT_POLICIES = 16
ARGS_MAX_BYTES = 256 * 1024
REASON_MAX = 500
DOCUMENT_DEFAULTS: Mapping[str, Any] = {
    "schema": ag.POLICY_SCHEMA_ID,
    "default_effect": "escalate",
    "tool_allowlist_enforced": False,
    "tool_allowlist": None,
    "sensitive_tools": [],
    "external_tools": [],
    "hold_timeout_s": 900,
    "rules": [],
}
"""Members a create request may leave out (``policy_id`` and ``version`` are always assigned)."""

_APPLICABLE_SQL = """
SELECT p.* FROM sibyl.action_policy p
 WHERE p.tenant_id = $1 AND p.state = 'approved'
   AND (p.scope_kind = 'tenant'
        OR (p.scope_kind = 'agent' AND p.agent_id = $2)
        OR (p.scope_kind = 'agent_group' AND p.agent_group_id = $3::uuid))
 ORDER BY CASE p.scope_kind WHEN 'agent' THEN 0 WHEN 'agent_group' THEN 1 ELSE 2 END
"""
_IDENTITY_SQL = (
    "SELECT allowed_tools FROM sibyl.agent_identity WHERE tenant_id = $1 AND agent_id = $2"
)


def json_value(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


def parse_document(document: Mapping[str, Any]) -> ag.ActionPolicy:
    """``parse_policy`` with its refusal as a 422 (the message names the offending member)."""
    try:
        return ag.parse_policy(dict(document))
    except ValueError as exc:
        detail = " ".join(str(exc).strip().splitlines())
        raise ProblemError(
            "validation_failed", "invalid action policy document: " + detail[:900]
        ) from None


def normalised(policy: ag.ActionPolicy) -> dict[str, Any]:
    document: dict[str, Any] = policy.model_dump(mode="json", by_alias=True)
    return document


def document_digest(document: Mapping[str, Any]) -> bytes:
    return bytes.fromhex(canonical_sha256(dict(document)))


def stored_policy(row: Mapping[str, Any]) -> ag.ActionPolicy:
    return ag.parse_policy(dict(json_value(row["document"])))


async def allowed_tools(conn: Any, tenant: UUID, agent_id: UUID) -> list[str] | None:
    value = await conn.fetchval(_IDENTITY_SQL, tenant, agent_id)
    return sorted(value) if value else None


def with_allowlist(document: Mapping[str, Any], tools: Sequence[str] | None) -> dict[str, Any]:
    """Allowlist enforcement on and no list of its own: the agent identity's declared tools."""
    out = dict(document)
    if out.get("tool_allowlist_enforced") and out.get("tool_allowlist") is None and tools:
        out["tool_allowlist"] = list(tools)
    return out


@dataclass(frozen=True)
class Applicable:
    rows: tuple[Mapping[str, Any], ...]
    policies: tuple[ag.ActionPolicy, ...]


async def applicable(conn: Any, tenant: UUID, agent: Mapping[str, Any]) -> Applicable:
    """Approved policies for the agent, agent-specific first (at most one per scope)."""
    rows = [
        dict(r)
        for r in await conn.fetch(_APPLICABLE_SQL, tenant, agent["id"], agent.get("agent_group_id"))
    ]
    policies = []
    for row in rows:
        document = json_value(row["document"])
        if document.get("tool_allowlist_enforced"):
            document = with_allowlist(document, await allowed_tools(conn, tenant, agent["id"]))
        policies.append(ag.parse_policy(document))
    return Applicable(tuple(rows), tuple(policies))


def effect_of(decision: ag.Decision) -> str:
    return str(getattr(decision.effect, "value", decision.effect))


def clip_reason(text: str | None, fallback: str) -> str:
    value = (text or "").strip() or fallback
    return value[:REASON_MAX]


def args_size(args: Any) -> int:
    size = len(json.dumps(args, separators=(",", ":"), ensure_ascii=False).encode())
    if size > ARGS_MAX_BYTES:
        raise ProblemError("payload_too_large", "tool arguments exceed 256 KiB")
    return size


def find_rule(policy: ag.ActionPolicy, rule_id: str) -> ag.ActionRule | None:
    return next((r for r in policy.rules if r.rule_id == rule_id), None)


# --- tier-1 four-eyes -------------------------------------------------------------------------


async def tier1_in_scope(
    conn: Any, tenant: UUID, scope_kind: str, agent_id: UUID | None, group_id: UUID | None
) -> bool:
    """A tier-1 agent is governed by this scope (four-eyes on approving the policy)."""
    if scope_kind == "agent":
        sql = "SELECT tier = 1 FROM sibyl.agent WHERE tenant_id = $1 AND id = $2"
        return bool(await conn.fetchval(sql, tenant, agent_id))
    if scope_kind == "agent_group":
        sql = (
            "SELECT EXISTS (SELECT 1 FROM sibyl.agent WHERE tenant_id = $1 AND agent_group_id = $2"
            " AND tier = 1 AND lifecycle <> 'retired')"
        )
        return bool(await conn.fetchval(sql, tenant, group_id))
    sql = (
        "SELECT EXISTS (SELECT 1 FROM sibyl.agent WHERE tenant_id = $1 AND tier = 1"
        " AND lifecycle <> 'retired')"
    )
    return bool(await conn.fetchval(sql, tenant))


async def approved_budget_ok(conn: Any, tenant: UUID, policy_row: Mapping[str, Any]) -> bool:
    """B4: the approved documents (without the version this one supersedes) plus this one."""
    used = await conn.fetchval(
        "SELECT coalesce(sum(octet_length(document::text)), 0) FROM sibyl.action_policy"
        " WHERE tenant_id = $1 AND state = 'approved' AND NOT (scope_kind = $2"
        " AND agent_id IS NOT DISTINCT FROM $3::uuid"
        " AND agent_group_id IS NOT DISTINCT FROM $4::uuid)",
        tenant,
        policy_row["scope_kind"],
        policy_row["agent_id"],
        policy_row["agent_group_id"],
    )
    mine = await conn.fetchval(
        "SELECT octet_length(document::text) FROM sibyl.action_policy"
        " WHERE tenant_id = $1 AND id = $2",
        tenant,
        policy_row["id"],
    )
    return int(used) + int(mine or 0) <= POLICY_BUDGET_BYTES


# --- cumulative counters ------------------------------------------------------------------------

_INCREMENT_SQL = """
INSERT INTO sibyl.action_counter AS c
       (tenant_id, agent_id, counter_key, window_s, window_start, value, max_value, calls)
SELECT $1, $2, $3, $4::int,
       to_timestamp(floor(extract(epoch FROM $7::timestamptz) / $4::int) * $4::int),
       $5::numeric, $6::numeric, 1
 WHERE $5::numeric <= $6::numeric
ON CONFLICT (tenant_id, agent_id, counter_key, window_s, window_start) DO UPDATE
   SET value = c.value + EXCLUDED.value, calls = c.calls + 1, max_value = EXCLUDED.max_value
 WHERE c.value + EXCLUDED.value <= EXCLUDED.max_value
RETURNING value, window_start
"""
_CURRENT_SQL = """
SELECT value, window_start FROM sibyl.action_counter
 WHERE tenant_id = $1 AND agent_id = $2 AND counter_key = $3 AND window_s = $4::int
   AND window_start = to_timestamp(floor(extract(epoch FROM $5::timestamptz) / $4::int) * $4::int)
"""


@dataclass(frozen=True)
class Cap:
    counter_key: str
    increment: Decimal
    max: Decimal
    window_s: int


@dataclass(frozen=True)
class CounterResult:
    accepted: bool
    cap: Cap
    value: Decimal
    window_start: datetime | None


async def check_and_increment(
    conn: Any, tenant: UUID, agent_id: UUID, cap: Cap, now: datetime
) -> CounterResult:
    """The authoritative cap: one conditional upsert, so concurrent decisions on the same window
    serialise on the row and the total never passes ``max`` (refused calls change nothing)."""
    row = await conn.fetchrow(
        _INCREMENT_SQL,
        tenant,
        agent_id,
        cap.counter_key,
        cap.window_s,
        cap.increment,
        cap.max,
        now,
    )
    if row is not None:
        return CounterResult(True, cap, Decimal(row["value"]), row["window_start"])
    current = await conn.fetchrow(
        _CURRENT_SQL, tenant, agent_id, cap.counter_key, cap.window_s, now
    )
    value = Decimal(current["value"]) if current is not None else Decimal(0)
    start = current["window_start"] if current is not None else None
    return CounterResult(False, cap, value, start)


_ADD_APPROVED_SQL = """
INSERT INTO sibyl.action_counter AS c
       (tenant_id, agent_id, counter_key, window_s, window_start, value, max_value, calls)
VALUES ($1, $2, $3, $4::int,
        to_timestamp(floor(extract(epoch FROM $7::timestamptz) / $4::int) * $4::int),
        $5::numeric, $6::numeric, 1)
ON CONFLICT (tenant_id, agent_id, counter_key, window_s, window_start) DO UPDATE
   SET value = c.value + EXCLUDED.value, calls = c.calls + 1, max_value = EXCLUDED.max_value
RETURNING value, window_start
"""


async def add_approved(
    conn: Any, tenant: UUID, agent_id: UUID, cap: Cap, now: datetime
) -> CounterResult:
    """An approved escalation counts toward its cap: a human said yes, so the amount is added
    even past ``max`` (the window then refuses every automatic increment until it ends). One
    upsert, so concurrent approvals serialise on the row and none is lost."""
    row = await conn.fetchrow(
        _ADD_APPROVED_SQL,
        tenant,
        agent_id,
        cap.counter_key,
        cap.window_s,
        cap.increment,
        cap.max,
        now,
    )
    return CounterResult(True, cap, Decimal(row["value"]), row["window_start"])


def lineage_key(counter_key: str, version_id: str, lineage_id: str) -> str:
    """Counters are kept per policy (``policy_id``), not per version: the key an enforcement
    point computes from the version's document (``<version id>/<rule_id>[/<hash>]``) is stored
    under the policy's stable id, so approving a new version never resets a window."""
    prefix = f"{version_id}/"
    if counter_key.startswith(prefix):
        return f"{lineage_id}/{counter_key[len(prefix) :]}"
    return counter_key


async def lineage_of(conn: Any, tenant: UUID, version_id: UUID) -> UUID | None:
    value: UUID | None = await conn.fetchval(
        "SELECT policy_id FROM sibyl.action_policy WHERE tenant_id = $1 AND id = $2",
        tenant,
        version_id,
    )
    return value


def decimal_text(value: Decimal) -> str:
    text = format(value.normalize(), "f")
    return "0" if text in ("-0", "") else text


def sample_allowed(call_id: str, *, sensitive: bool) -> bool:
    """``action.allowed`` is sampled 1 in 16 by a stable hash of the call id; sensitive tools are
    always recorded (ACTION-GATE.md §3)."""
    if sensitive:
        return True
    return hashlib.sha256(call_id.encode()).digest()[0] < 16


# --- approved escalations ----------------------------------------------------------------------

NO_COUNTER: tuple[None, ...] = (None, None, None, None, None)


async def counter_of(
    conn: Any, tenant: UUID, agent_id: UUID, call_id: str, decision: ag.Decision | None
) -> tuple[Any, ...]:
    """``(key, amount, max, window_s, policy version id)`` of the cap a held call is under: the
    enforcement point's authoritative decision for this call when it made one, else the control
    plane's own evaluation; all None when no cumulative rule applies."""
    stored = await conn.fetchrow(
        "SELECT policy_id, counter_key, amount, counter_max, window_s FROM sibyl.action_decision"
        " WHERE tenant_id = $1 AND agent_id = $2 AND call_id = $3 AND counter_key IS NOT NULL"
        " AND policy_id IS NOT NULL",
        tenant,
        agent_id,
        call_id,
    )
    if stored is not None:
        return (
            stored["counter_key"],
            Decimal(stored["amount"]),
            Decimal(stored["counter_max"]),
            int(stored["window_s"]),
            stored["policy_id"],
        )
    need = decision.needs_counter if decision is not None else None
    if decision is None or need is None or decision.policy_id is None:
        return NO_COUNTER
    return (
        need.counter_key,
        Decimal(need.increment),
        Decimal(need.max),
        int(need.window_s),
        UUID(decision.policy_id),
    )


async def count_approved(conn: Any, tenant: UUID, held: Mapping[str, Any], now: datetime) -> bool:
    """The final approval of a call under a cumulative cap adds it to the window, unless the
    authoritative decision already counted it (``within_cap``). → whether it was added."""
    if held["counter_key"] is None:
        return False
    counted = await conn.fetchval(
        "SELECT within_cap FROM sibyl.action_decision WHERE tenant_id = $1 AND agent_id = $2"
        " AND call_id = $3",
        tenant,
        held["agent_id"],
        held["call_id"],
    )
    if counted:
        return False
    version = held["counter_policy_id"]
    lineage = await lineage_of(conn, tenant, version) or version
    cap = Cap(
        counter_key=lineage_key(held["counter_key"], str(version), str(lineage)),
        increment=Decimal(held["counter_amount"]),
        max=Decimal(held["counter_max"]),
        window_s=int(held["counter_window_s"]),
    )
    await add_approved(conn, tenant, held["agent_id"], cap, now)
    return True
