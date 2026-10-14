"""Lane SENTINEL test kit (loaded as ``sibyl_sentinel_kit``): configure Sentinel for a tenant,
build its subjects (incidents, held actions, tool-call trajectories) by SQL, and a fake LLM that
answers each task with a canned structured output."""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx

_TESTS = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path) -> Any:
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


fk = _load("sibyl_fake_llm", _TESTS / "core" / "llm" / "fake_llm.py")
R = _load("sibyl_lane_r_harness", _TESTS / "api" / "registry" / "_harness.py")

API_KEY = "sk-ant-test-0123456789abcdef"
OUTPUTS: dict[str, dict[str, Any]] = {
    "incident_explanation": {
        "severity": "warning",
        "summary": "Primary provider returned 5xx; Sibyl failed over.",
        "what_failed": "error_rate breached on the primary model",
        "likely_cause": "provider outage",
        "what_sibyl_did": "validated, checked viability, switched routing",
        "what_to_check": ["provider status page", "fallback latency"],
        "confidence": "medium",
    },
    "held_action_review": {
        "severity": "warning",
        "summary": "Transfer above the review threshold to a known payee.",
        "advice": "approve",
        "reasoning": "Consistent with declared purpose.",
        "risks": ["amount above usual"],
        "confidence": "medium",
    },
    "semantic_drift": {
        "severity": "info",
        "summary": "Tool use is consistent with the declared purpose.",
        "purpose_drift": False,
        "injection_like": False,
        "evidence": [],
        "recommendation": "No action.",
        "confidence": "high",
    },
    "fleet_summary": {
        "severity": "info",
        "summary": "Fleet healthy; one incident handled automatically.",
        "highlights": ["one failover completed"],
        "concerns": [],
        "recommendation": "Review the failover drill schedule.",
    },
}
FLAGGED_DRIFT = {
    **OUTPUTS["semantic_drift"],
    "severity": "critical",
    "summary": "Agent read an email then called an undeclared export tool.",
    "purpose_drift": True,
    "injection_like": True,
    "evidence": ["step 1 read_email", "step 2 export_all"],
    "recommendation": "Review the export calls; consider a stricter action policy.",
}


TASK_MARKERS = (
    ("Explain this incident", "incident_explanation"),
    ("held agent action", "held_action_review"),
    ("tool-call trajectories", "semantic_drift"),
    ("health of this agent fleet", "fleet_summary"),
)


def task_of(request: httpx.Request) -> str:
    """Which task a fake-LLM request is for (from the task instruction the prompt carries)."""
    text = request.content.decode()
    for marker, task in TASK_MARKERS:
        if marker in text:
            return task
    return "plain"


def responder(overrides: dict[str, Any] | None = None) -> Callable[[httpx.Request], str]:
    outputs = {**OUTPUTS, **(overrides or {})}

    def answer(request: httpx.Request) -> str:
        task = task_of(request)
        return "OK" if task == "plain" else json.dumps(outputs[task])

    return answer


def fake(provider: str = "anthropic", **overrides: Any) -> Any:
    llm = fk.FakeLlm(provider)
    llm.responder = responder(overrides)
    return llm


async def _no_sleep(_: float) -> None:
    return None


def configure(
    w: Any,
    tenant: Any,
    *,
    provider: str = "anthropic",
    model: str = "claude-fable-5-1",
    enabled: bool = True,
    tasks: tuple[str, ...] = tuple(OUTPUTS),
    budget: str = "5",
    sampling: str = "1",
    api_key: str | None = API_KEY,
    base_url: str | None = None,
) -> UUID:
    """Upsert the tenant's config by SQL with a key sealed exactly as the api seals it."""
    from sibyl_control.worker.sentinel.config import seal_key

    credential_id = uuid4()
    w.admin.execute("DELETE FROM sibyl.sentinel_config WHERE tenant_id = $1", tenant.id)
    cipher = nonce = key_id = version = None
    if api_key is not None:
        blob, key_id = w.loop.run_until_complete(
            seal_key(w.admin.raw, R.kek(), tenant.id, credential_id, api_key)
        )
        cipher, nonce, version = blob.ciphertext, blob.nonce, blob.key_version
    w.admin.execute(
        "INSERT INTO sibyl.sentinel_config (tenant_id, enabled, provider, model, base_url,"
        " credential_id, ciphertext, nonce, tenant_key_id, key_version, key_hint, key_updated_at,"
        " daily_budget_usd, sampling_rate, tasks, updated_by_user_id) VALUES ($1, $2, $3, $4, $5,"
        " $6, $7, $8, $9, $10, $11, CASE WHEN $7::bytea IS NULL THEN NULL ELSE now() END,"
        " $12::numeric, $13::numeric, $14, $15)",
        tenant.id,
        enabled,
        provider,
        model,
        base_url,
        credential_id,
        cipher,
        nonce,
        key_id,
        version,
        "cdef" if api_key else None,
        budget,
        sampling,
        list(tasks),
        tenant.users["owner"],
    )
    from sibyl_control.worker.sentinel.findings import _ENSURE_RULE_SQL, ALERT_WHAT_TO_DO

    w.admin.execute(_ENSURE_RULE_SQL, tenant.id, ALERT_WHAT_TO_DO)
    return credential_id


def reset(w: Any, tenant: Any) -> None:
    for table in ("sentinel_finding", "sentinel_usage"):
        w.admin.execute(f"DELETE FROM sibyl.{table} WHERE tenant_id = $1", tenant.id)  # noqa: S608
    w.admin.execute(
        "DELETE FROM sibyl.held_action WHERE tenant_id = $1 AND state = 'pending'", tenant.id
    )
    w.admin.execute(
        "DELETE FROM sibyl.events WHERE tenant_id = $1 AND event_type = 'tool.call'", tenant.id
    )
    w.admin.execute(
        "UPDATE sibyl.failover SET created_at = now() - interval '3 days' WHERE tenant_id = $1",
        tenant.id,
    )
    w.admin.execute(
        "UPDATE sibyl.alert SET state = 'resolved', resolved_at = now() WHERE tenant_id = $1"
        " AND dedupe_key LIKE 'sentinel_finding:%' AND state <> 'resolved'",
        tenant.id,
    )


def incident(sw: Any, agent: UUID, tenant: Any | None = None) -> UUID:
    tenant = tenant or sw.a
    alert = sw.alert(agent, tenant)
    fid = uuid4()
    sw.admin.execute(
        "INSERT INTO sibyl.failover (tenant_id, id, agent_id, kind, state, step, idempotency_key,"
        " trigger_alert_id, rule_codes, actor_kind, from_state, to_state, error, finished_at)"
        " VALUES ($1, $2, $3, 'failover', 'failed', 'check_viability', $4, $5, '{error_rate}',"
        " 'rule', 'active', 'failover', 'no viable target', now())",
        tenant.id,
        fid,
        agent,
        f"sentinel-test:{fid}",
        alert,
    )
    return fid


def payload_ref(sw: Any, agent: UUID, tenant: Any | None = None) -> UUID:
    tenant = tenant or sw.a
    key = sw.val(
        "SELECT id FROM sibyl.tenant_key WHERE tenant_id = $1 AND purpose = 'payload'", tenant.id
    )
    ref = uuid4()
    sw.admin.execute(
        "INSERT INTO sibyl.payload_refs (tenant_id, id, kind, uri, sha256, size_bytes,"
        " stored_bytes, tenant_key_id, key_version, nonce, capture_mode, redaction_profile_hash,"
        " agent_id, source_kind, expires_at) VALUES ($1, $2, 'span_content', $3, $4, 10, 12, $5,"
        " 1, $6, 'full', $7, $8, 'event', now() + interval '30 days')",
        tenant.id,
        ref,
        f"tenant/{tenant.id}/{ref}.bin",
        b"\x01" * 32,
        key,
        b"\x02" * 12,
        b"\x03" * 32,
        agent,
    )
    return ref


def hold(sw: Any, agent: UUID, tenant: Any | None = None, *, args_ref: UUID | None = None) -> UUID:
    tenant = tenant or sw.a
    hid = uuid4()
    sw.admin.execute(
        "INSERT INTO sibyl.held_action (tenant_id, id, agent_id, call_id, tool, source,"
        " args_sha256, args_payload_ref, args_bytes, server_effect, reason,"
        " requested_by_key_id, hold_timeout_s,"
        " expires_at) VALUES ($1, $2, $3, $4, 'payments.transfer', 'sdk', $5, $6, 20,"
        " 'escalate', 'transfers above 5,000 need a human', $7, 900,"
        " now() + interval '15 minutes')",
        tenant.id,
        hid,
        agent,
        f"call-{hid.hex[:12]}",
        b"\x05" * 32,
        args_ref,
        uuid4(),
    )
    return hid


def tool_events(
    sw: Any,
    agent: UUID,
    tools: list[str],
    tenant: Any | None = None,
    *,
    capture_mode: str = "metadata",
    payload: UUID | None = None,
) -> UUID:
    tenant = tenant or sw.a
    trace = uuid4()
    for seq, tool in enumerate(tools, start=1):
        sw.admin.execute(
            "INSERT INTO sibyl.events (tenant_id, event_id, ts, event_type, source, agent_id,"
            " trace_id, emitter_id, seq, policy_state, capture_mode, redaction_profile_hash,"
            " normaliser_version, status, latency_ms, attrs, payload_ref_id) VALUES ($1, $2,"
            " now() - make_interval(secs => $3), 'tool.call', 'sdk', $4, $5, 'sdk-1', $6, 'fresh',"
            " $7, $8, 'normaliser/1.0', 'ok', 40, $9::jsonb, $10)",
            tenant.id,
            uuid4(),
            60 - seq,
            agent,
            trace,
            seq,
            capture_mode,
            b"\x03" * 32,
            json.dumps({"tool_name": tool, "tool_type": "function"}),
            payload,
        )
    return trace


def capture_policy(
    sw: Any, mode: str, *, agent: UUID | None = None, tenant: Any | None = None
) -> None:
    """Supersede the active tenant (or agent) capture policy with ``mode`` (rows are immutable)."""
    tenant = tenant or sw.a
    profile = sw.val(
        "SELECT id FROM sibyl.redaction_profile WHERE tenant_id = $1 AND name = 'secrets_only'",
        tenant.id,
    )
    scope = "agent" if agent is not None else "tenant"
    new = uuid4()
    raw = sw.admin.raw

    async def swap() -> None:
        async with raw.transaction():
            await raw.execute("SET CONSTRAINTS ALL DEFERRED")
            old = await raw.fetchrow(
                "SELECT id, version_no FROM sibyl.capture_policy WHERE tenant_id = $1"
                " AND scope_kind = $2 AND agent_id IS NOT DISTINCT FROM $3"
                " AND superseded_by IS NULL",
                tenant.id,
                scope,
                agent,
            )
            if old is not None:
                await raw.execute(
                    "UPDATE sibyl.capture_policy SET superseded_by = $2 WHERE tenant_id = $1"
                    " AND id = $3",
                    tenant.id,
                    new,
                    old["id"],
                )
            await raw.execute(
                "INSERT INTO sibyl.capture_policy (tenant_id, id, scope_kind, agent_id,"
                " capture_mode, redaction_profile_id, consequences_version, chosen_by, version_no)"
                " VALUES ($1, $2, $3, $4, $5, $6, 'c1', $7, $8)",
                tenant.id,
                new,
                scope,
                agent,
                mode,
                profile,
                tenant.users["owner"],
                (old["version_no"] if old else 0) + 1,
            )

    sw.run(swap())


def deps(sw: Any, llm: Any, **kw: Any) -> Any:
    from sibyl_control.worker.sentinel.runner import Deps

    return Deps(
        settings=sw.w.settings,
        kek=R.kek(),
        transport_factory=lambda policy: llm.transport(),
        client_kw={"sleep": _no_sleep, "max_retries": 0},
        rng=kw.pop("rng", lambda: 0.0),
        **kw,
    )


def fk_usage() -> Any:
    from sibyl_control.core.llm import Usage

    return Usage(100, 10)


def findings(sw: Any, tenant: Any | None = None) -> list[Any]:
    tenant = tenant or sw.a
    return sw.rows(
        "SELECT * FROM sibyl.sentinel_finding WHERE tenant_id = $1 ORDER BY created_at, id",
        tenant.id,
    )


def usage(sw: Any, tenant: Any | None = None) -> Any:
    tenant = tenant or sw.a
    return sw.one(
        "SELECT * FROM sibyl.sentinel_usage WHERE tenant_id = $1 AND day = (now() AT TIME ZONE"
        " 'UTC')::date",
        tenant.id,
    )
