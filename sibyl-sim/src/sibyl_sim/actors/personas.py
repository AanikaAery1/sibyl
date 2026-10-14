"""Scripted personas (D29; qa-expert §6): the Admin, the Operator and the Auditor.

Each verb is one real API call (or a lookup plus a call) made with the persona's token; the
response status is logged so predicates and the report can show "expected 409, got 409".
Verbs that need a step-up use the persona's stepped-up token (the in-process stand-in for
`POST /api/v1/auth/step-up` after an OIDC re-auth). Verbs belong to lanes (`PERSONA_VERBS`);
the runner never schedules a verb whose lane is missing.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping
from typing import Any
from uuid import uuid4

import httpx

from ..harness.clock import RunClock
from ..harness.world import World
from ..oracle.predicates import SHORT_CODES
from ..scenarios.model import AgentRef, PersonaStep
from . import sentinel_personas

log = logging.getLogger("sibyl_sim.personas")
API = "/api/v1"
STEP_UP_SUFFIX = ".stepup"
DEFAULT_REASON = "sibyl-sim persona action for the scenario script"


class PersonaRunner:
    def __init__(self, client: httpx.AsyncClient, api: str, world: World, clock: RunClock) -> None:
        self.client, self.api, self.world, self.clock = client, api, world, clock
        self.log: list[dict[str, Any]] = []
        self._lost: str | None = None  # a transport failure seen during the current step
        self._policies: dict[tuple[str, str | None], str] = {}  # (tenant, agent) -> policy id
        self._verbs: Mapping[str, Callable[[PersonaStep], Awaitable[tuple[int, Any]]]] = {
            "close_alert": self._close_alert,
            "close_without_verdict": self._close_without_verdict,
            "drain_unverdicted": self._drain,
            "approve": self._incident("approve"),
            "deny": self._incident("deny"),
            "self_approve": self._incident("approve"),
            "undo": self._incident("undo"),
            "clear_hold": self._incident("clear_hold"),
            "fail_back": self._incident("fail_back"),
            "pull_kill": self._pull_kill,
            "release_kill": self._release_kill,
            "claim_task": self._task("claim"),
            "complete_task": self._task("complete"),
            "edit_rule": self._edit_rule,
            "revoke_credential": self._revoke_credential,
            "draft_chain": self._draft_chain,
            "open_incident": self._open_incident,
            "approve_chain": self._approve_chain,
            "audit_check": self._audit_check,
            "label_write_attempt": self._label_write,
            "install_action_policy": self._install_policy,
            "approve_action_policy": self._approve_policy,
            "decide_held": self._decide_held,
            "configure_sentinel": sentinel_personas.configure_sentinel(self),
            "set_capture_mode": sentinel_personas.set_capture_mode(self),
        }

    # ------------------------------------------------------------------ plumbing

    def _token(self, step: PersonaStep, *, stepped_up: bool = False) -> str:
        persona = self.world.tenant(step.tenant).personas[step.persona]
        if stepped_up and persona.stepup_token:
            return persona.stepup_token
        return persona.token + STEP_UP_SUFFIX if stepped_up else persona.token

    async def _call(
        self, step: PersonaStep, method: str, path: str, body: Any = None, **kw: Any
    ) -> tuple[int, Any]:
        headers = {
            "Authorization": f"Bearer {self._token(step, stepped_up=kw.pop('stepped_up', False))}",
            "Idempotency-Key": str(uuid4()),
            **kw.pop("headers", {}),
        }
        try:
            resp = await self.client.request(
                method, f"{self.api}{API}{path}", json=body, headers=headers, params=kw or None
            )
        except httpx.HTTPError as exc:
            # a person's click whose answer was lost: status 0 fails the persona verdict
            # visibly, and the schedule goes on (the server may still have applied it)
            self._lost = f"transport:{type(exc).__name__}"
            return 0, {"type": self._lost}
        try:
            data = resp.json()
        except ValueError:
            data = None
        return resp.status_code, data

    async def _list(self, step: PersonaStep, path: str, **params: Any) -> list[dict[str, Any]]:
        status, body = await self._call(step, "GET", path, **params)
        return list(body.get("data") or []) if status == 200 and isinstance(body, dict) else []

    def _agent_id(self, step: PersonaStep) -> str | None:
        raw = step.args.get("agent")
        if not raw:
            return None
        ref = AgentRef.parse(raw)
        return str(self.world.tenant(ref.tenant).agent(ref.slug).id)

    async def run(self, step: PersonaStep) -> dict[str, Any]:
        t = self.clock.now()
        self._lost = None
        status, body = await self._verbs[step.verb](step)
        if self._lost and not 200 <= status < 300:
            body = {**body, "type": self._lost} if isinstance(body, dict) else {"type": self._lost}
            status = 0
        row = {
            "t": t,
            "persona": step.persona,
            "tenant": step.tenant,
            "verb": step.verb,
            "status": status,
            "expect_status": step.args.get("expect_status"),
            "code": (body or {}).get("type", "").rsplit("/", 1)[-1]
            if isinstance(body, dict)
            else None,
            "agent": step.args.get("agent"),
        }
        if isinstance(body, dict) and body.get("id"):
            row["id"] = body["id"]
        if isinstance(body, dict) and "decided" in body:
            row["decided"] = list(body["decided"])
            row["decision"] = step.args.get("action", "approve")
            if body.get("ambiguous"):
                row["ambiguous"] = list(body["ambiguous"])
        self.log.append(row)
        return row

    # ------------------------------------------------------------------ verbs

    async def _alert_for(self, step: PersonaStep) -> dict[str, Any] | None:
        match = step.args.get("match") or {}
        agent_ref = match.get("agent") or step.args.get("agent")
        params: dict[str, Any] = {}
        if agent_ref:
            ref = AgentRef.parse(agent_ref)
            params["agent_id"] = str(self.world.tenant(ref.tenant).agent(ref.slug).id)
        alerts = await self._list(step, "/alerts", include_suppressed="true", **params)
        rule = match.get("rule")
        wanted = {rule, SHORT_CODES.get(str(rule), rule)}
        for alert in alerts:
            if rule is None or alert.get("rule_code") in wanted:
                return alert
        return None

    async def _close_alert(self, step: PersonaStep) -> tuple[int, Any]:
        alert = await self._alert_for(step)
        if alert is None:
            return 404, {"detail": "no matching alert"}
        body = {"action": "close", "verdict": step.args.get("verdict", "tp")}
        return await self._call(step, "POST", f"/alerts/{alert['id']}/actions", body)

    async def _close_without_verdict(self, step: PersonaStep) -> tuple[int, Any]:
        alert = await self._alert_for(step)
        if alert is None:
            return 404, {"detail": "no matching alert"}
        return await self._call(step, "POST", f"/alerts/{alert['id']}/actions", {"action": "close"})

    async def _drain(self, step: PersonaStep) -> tuple[int, Any]:
        last: tuple[int, Any] = (200, None)
        for alert in await self._list(step, "/alerts", state="resolved"):
            if alert.get("verdict") is None:
                last = await self._call(
                    step,
                    "POST",
                    f"/alerts/{alert['id']}/actions",
                    {"action": "close", "verdict": step.args.get("verdict", "tp")},
                )
        return last

    def _incident(self, action: str) -> Callable[[PersonaStep], Awaitable[tuple[int, Any]]]:
        async def act(step: PersonaStep) -> tuple[int, Any]:
            agent_id = self._agent_id(step)
            incidents = await self._list(step, "/incidents", agent_id=agent_id, open="true")
            if not incidents:
                incidents = await self._list(step, "/incidents", agent_id=agent_id)
            if not incidents:
                return 404, {"detail": f"no incident for {step.args.get('agent')}"}
            body = {"action": action, "reason": step.args.get("reason", DEFAULT_REASON)}
            return await self._call(step, "POST", f"/incidents/{incidents[0]['id']}/actions", body)

        return act

    async def _pull_kill(self, step: PersonaStep) -> tuple[int, Any]:
        body = {
            "scope_kind": step.args.get("scope", "agent"),
            "scope_id": self._agent_id(step),
            "reason": step.args.get("reason", "sibyl-sim: kill pulled by the scenario script"),
        }
        return await self._call(step, "POST", "/kill-switches", body, stepped_up=True)

    async def _release_kill(self, step: PersonaStep) -> tuple[int, Any]:
        switches = await self._list(step, "/kill-switches")
        live = [k for k in switches if k.get("state", "pulled") == "pulled"]
        if not live:
            return 404, {"detail": "no live kill switch"}
        stepped = bool(step.args.get("stepped_up", True))
        body = {"reason": step.args.get("reason", DEFAULT_REASON)}
        return await self._call(
            step, "POST", f"/kill-switches/{live[0]['id']}/release", body, stepped_up=stepped
        )

    def _task(self, action: str) -> Callable[[PersonaStep], Awaitable[tuple[int, Any]]]:
        async def act(step: PersonaStep) -> tuple[int, Any]:
            tasks = await self._list(step, "/queue", agent_id=self._agent_id(step))
            if not tasks:
                return 404, {"detail": "no handoff task"}
            body: dict[str, Any] = {"action": action}
            if action == "complete":
                body |= {"outcome": "resolved", "outcome_note": "handled from checkpoint"}
            return await self._call(step, "POST", f"/handoff-tasks/{tasks[0]['id']}/actions", body)

        return act

    async def _edit_rule(self, step: PersonaStep) -> tuple[int, Any]:
        rules = await self._list(step, "/alert-rules")
        code = step.args.get("rule")
        rule = next((r for r in rules if code in (r.get("code"), r.get("short_code"))), None)
        if rule is None:
            return 404, {"detail": f"no rule {code}"}
        resp = await self.client.get(
            f"{self.api}{API}/alert-rules/{rule['id']}",
            headers={"Authorization": f"Bearer {self._token(step)}"},
        )
        etag = resp.headers.get("etag", "*")
        return await self._call(
            step,
            "PATCH",
            f"/alert-rules/{rule['id']}",
            dict(step.args.get("patch") or {}),
            headers={"If-Match": etag},
        )

    async def _draft_chain(self, step: PersonaStep) -> tuple[int, Any]:
        """A new fallback chain for an agent; backup steps name agents by slug."""
        tenant = self.world.tenant(step.tenant)
        steps = []
        for raw in step.args.get("steps") or ():
            item = dict(raw)
            if "backup_agent" in item:
                item["backup_agent_id"] = str(tenant.agent(item.pop("backup_agent")).id)
            if "provider" in item:
                pid = str(tenant.providers[item.pop("provider")])
                item["provider_id"] = pid
                if "model" in item:
                    name = item.pop("model")
                    models = await self._list(step, "/models", provider_id=pid)
                    item["model_id"] = next(m["id"] for m in models if m.get("model_name") == name)
                if item.pop("credential", None) == "active":
                    creds = await self._list(step, "/provider-credentials")
                    item["credential_id"] = next(
                        c["id"]
                        for c in creds
                        if str(c.get("provider_id")) == pid and c.get("status") == "active"
                    )
            steps.append(item)
        body = {"steps": steps, "note": step.args.get("note", DEFAULT_REASON)}
        return await self._call(
            step, "POST", f"/agents/{self._agent_id(step)}/fallback-chains", body
        )

    async def _open_incident(self, step: PersonaStep) -> tuple[int, Any]:
        """An operator-requested action (`openIncident`): its approval names this persona as
        the requester, which is what makes a later self-approval a four-eyes violation."""
        body = {
            "agent_id": self._agent_id(step),
            "action": step.args.get("action", "failover"),
            "reason": step.args.get("reason", DEFAULT_REASON),
        }
        return await self._call(step, "POST", "/incidents", body)

    async def _approve_chain(self, step: PersonaStep) -> tuple[int, Any]:
        chains = await self._list(step, f"/agents/{self._agent_id(step)}/fallback-chains")
        drafts = [c for c in chains if c.get("status") == "draft"]
        if not drafts:
            return 404, {"detail": "no draft chain"}
        draft = max(drafts, key=lambda c: int(c.get("version_no") or 0))
        body = {"action": "approve", "reason": step.args.get("reason", DEFAULT_REASON)}
        return await self._call(step, "POST", f"/fallback-chains/{draft['id']}/actions", body)

    async def _revoke_credential(self, step: PersonaStep) -> tuple[int, Any]:
        """S-15: revoke the vaulted credential of a fallback provider (step-up route)."""
        provider = self.world.tenant(step.tenant).providers.get(str(step.args.get("provider")))
        creds = await self._list(step, "/provider-credentials")
        live = [
            c
            for c in creds
            if str(c.get("provider_id")) == str(provider) and c.get("status") == "active"
        ]
        if not live:
            return 404, {"detail": f"no active credential for {step.args.get('provider')}"}
        body = {"reason": step.args.get("reason", DEFAULT_REASON)}
        path = f"/provider-credentials/{live[0]['id']}/revoke"
        return await self._call(step, "POST", path, body, stepped_up=True)

    async def _audit_check(self, step: PersonaStep) -> tuple[int, Any]:
        status, body = await self._call(step, "GET", "/audit/events")
        return status, body

    async def _label_write(self, step: PersonaStep) -> tuple[int, Any]:
        alert = await self._alert_for(step)
        target = alert["id"] if alert else uuid4()
        return await self._call(
            step, "POST", f"/alerts/{target}/actions", {"action": "close", "verdict": "fp"}
        )

    # ------------------------------------------------------------------ Action Gate (A-5)

    async def _install_policy(self, step: PersonaStep) -> tuple[int, Any]:
        """The Admin drafts an agent's action policy (the document is the scenario's)."""
        agent = self._agent_id(step)
        body: dict[str, Any] = {
            "name": step.args.get("name", f"sim policy for {step.args.get('agent')}"),
            "scope_kind": "agent",
            "scope_id": agent,
            "document": dict(step.args.get("document") or {}),
            "four_eyes": bool(step.args.get("four_eyes", False)),
            "reason": step.args.get("reason", DEFAULT_REASON),
        }
        status, data = await self._call(step, "POST", "/action-policies", body)
        if status == 201 and isinstance(data, dict) and data.get("id"):
            self._policies[(step.tenant, agent)] = str(data["id"])
        return status, data

    async def _approve_policy(self, step: PersonaStep) -> tuple[int, Any]:
        """A second person approves the draft (four-eyes on tier-1 agents)."""
        policy = self._policies.get((step.tenant, self._agent_id(step)))
        if policy is None:
            return 404, {"detail": "no drafted policy for this agent"}
        body = {"reason": step.args.get("reason", DEFAULT_REASON)}
        return await self._call(step, "POST", f"/action-policies/{policy}/approve", body)

    async def _decide_held(self, step: PersonaStep) -> tuple[int, Any]:
        """Approve or deny every pending held action of the agent (stepped up: sensitive tools
        need it); the decided ids go to the log so the oracle can tie executions to them."""
        action = str(step.args.get("action", "approve"))
        pending = await self._list(
            step, "/held-actions", state="pending", agent_id=self._agent_id(step)
        )
        decided: list[str] = []
        ambiguous: list[str] = []  # sent, answer lost: the person did decide; outcome unknown
        failure: Any = None
        status = 200 if pending else 404
        for held in pending:
            body = {"action": action, "reason": step.args.get("reason", DEFAULT_REASON)}
            got, answer = await self._call(
                step, "POST", f"/held-actions/{held['id']}/actions", body, stepped_up=True
            )
            if 200 <= got < 300 or got == 0:
                decided.append(str(held["id"]))
            if got == 0:
                ambiguous.append(str(held["id"]))
            if not 200 <= got < 300:
                status, failure = got, answer
        if not pending and step.args.get("allow_none"):
            status = 200
        out: dict[str, Any] = {"decided": decided}
        if ambiguous:
            out["ambiguous"] = ambiguous
        if not 200 <= status < 300 and status != 404:
            out["type"] = (failure or {}).get("type", "") if isinstance(failure, dict) else ""
        return status, out
