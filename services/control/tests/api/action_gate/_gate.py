"""Lane AG-CORE test kit (loaded as ``sibyl_ag_gate``): Action Gate helpers on lane R's harness.

``gate`` wires an in-memory BlobStore into the app (held-action arguments are sealed payloads),
adds the gate keys (a tenant-level enforcement key and one bound to an agent) and builds agents
and approved policies by api or SQL.
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any
from uuid import UUID, uuid4

from sibyl_control.api.auth.common import LANE_STATE
from sibyl_schemas.action_gate import args_digest

_TESTS = Path(__file__).resolve().parents[2]
REASON = "action gate test: a reason long enough"


def _load(name: str, path: Path) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class MemoryBlob:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    async def put(self, key: str, data: bytes, *, content_type: str = "", **_: Any) -> None:
        self.objects[key] = data

    async def get(self, key: str) -> bytes:
        return self.objects[key]

    async def delete(self, key: str) -> None:
        self.objects.pop(key, None)

    async def exists(self, key: str) -> bool:
        return key in self.objects


@dataclass
class Gate:
    w: Any
    blob: MemoryBlob
    keys: dict[str, UUID] = field(default_factory=dict)

    @property
    def client(self) -> Any:
        return self.w.client

    @property
    def tenant(self) -> UUID:
        return UUID(str(self.w.a.id))

    def idem(self, who: str = "owner") -> dict[str, str]:
        return dict(self.w.idem(who))

    def hdr(self, who: str) -> dict[str, str]:
        return dict(self.w.headers(who))

    def agent(self, *, tier: int = 3, group: UUID | None = None) -> UUID:
        agent_id = uuid4()
        self.w.admin.execute(
            "INSERT INTO sibyl.agent (tenant_id, id, slug, name, kind, tier, fail_mode, lifecycle,"
            " agent_group_id) VALUES ($1, $2, $3, $3, 'autonomous_agent', $4, 'closed',"
            " 'deployed', $5)",
            self.tenant,
            agent_id,
            f"ag-{agent_id.hex[:10]}",
            tier,
            group,
        )
        return agent_id

    def bound_key(self, agent_id: UUID) -> str:
        token = f"bound-{agent_id.hex[:8]}"
        if token not in self.keys:
            self.keys[token] = self.w.add_key(token, self.w.a, agent_id=agent_id)
        return token

    def post(self, path: str, body: Any, who: str = "owner") -> Any:
        return self.client.post("/api/v1" + path, json=body, headers=self.idem(who))

    def get(self, path: str, who: str = "owner", **params: Any) -> Any:
        return self.client.get("/api/v1" + path, headers=self.hdr(who), params=params)

    def create_policy(
        self,
        document: dict[str, Any],
        *,
        scope_kind: str = "agent",
        scope_id: UUID | None = None,
        who: str = "owner",
        four_eyes: bool = False,
    ) -> Any:
        body = {
            "name": "payments guard",
            "scope_kind": scope_kind,
            "scope_id": None if scope_id is None else str(scope_id),
            "document": document,
            "four_eyes": four_eyes,
            "reason": REASON,
        }
        return self.post("/action-policies", body, who)

    def approve(self, policy_id: str, who: str = "owner") -> Any:
        return self.post(f"/action-policies/{policy_id}/approve", {"reason": REASON}, who)

    def approved_policy(self, agent_id: UUID | None, document: dict[str, Any], **kw: Any) -> str:
        scope = kw.pop("scope_kind", "agent" if agent_id is not None else "tenant")
        created = self.create_policy(document, scope_kind=scope, scope_id=agent_id, **kw)
        assert created.status_code == 201, created.text
        policy_id = str(created.json()["id"])
        approved = self.approve(policy_id)
        assert approved.status_code == 200, approved.text
        return policy_id

    def audit_since(self, seq: int) -> list[str]:
        rows = self.w.admin.fetch(
            "SELECT action FROM sibyl.audit_events WHERE tenant_id = $1 AND seq > $2 ORDER BY seq",
            self.tenant,
            seq,
        )
        return [r["action"] for r in rows]

    def hold_body(
        self, agent: UUID, call_id: str, args: dict[str, Any], *, tool: str = "payments.transfer"
    ) -> dict[str, Any]:
        """``sibyl_schemas.action_gate.HeldActionRequest`` as an enforcement point sends it."""
        return {
            "call_id": call_id,
            "agent_id": str(agent),
            "source": "sdk",
            "tool": tool,
            "args": args,
            "args_sha256": args_digest(args),
            "policy_id": None,
            "policy_version": None,
            "rule_id": None,
            "reason": "escalated by the SDK",
            "hold_timeout_s": 600,
        }

    def head(self) -> int:
        value = self.w.admin.fetchval(
            "SELECT coalesce(max(seq), -1) FROM sibyl.audit_events WHERE tenant_id = $1",
            self.tenant,
        )
        return int(value)


TRANSFER_POLICY: dict[str, Any] = {
    "schema": "sibyl-action-policy/1",
    "default_effect": "allow",
    "hold_timeout_s": 600,
    "sensitive_tools": ["payments.*"],
    "rules": [
        {
            "rule_id": "over_limit",
            "tool": "payments.transfer",
            "when": {"gt": ["/amount", 10000]},
            "effect": "block",
            "reason": "transfers above 10,000 are blocked",
        },
        {
            "rule_id": "needs_review",
            "tool": "payments.transfer",
            "when": {"gt": ["/amount", 5000]},
            "effect": "escalate",
            "reason": "transfers above 5,000 need a human",
        },
        {
            "rule_id": "small",
            "tool": "payments.transfer",
            "effect": "allow",
            "reason": "small transfers are fine",
        },
    ],
}


def make_gate(world: Any) -> Gate:
    blob = MemoryBlob()
    state = getattr(world.client.app.state, LANE_STATE, None)
    if state is None:
        state = {}
        setattr(world.client.app.state, LANE_STATE, state)
    state["blob"] = blob
    g = Gate(world, blob)
    g.keys["keys"] = world.add_key("keys", world.a)
    g.keys["keys-b"] = world.add_key("keys-b", world.b)
    return g
