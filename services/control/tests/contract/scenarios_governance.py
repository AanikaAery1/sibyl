"""Lane P (alerts, provider incidents) and lane U (audit log, anchors, exports, erasure, legal
holds) scenarios on real tenant-A objects."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from ._world_kit import REASON, Req, Scenario, _api, _with_agent, agent, provider
from .pg_world import ContractWorld

# --- alerts and provider incidents (lane P) -----------------------------------------------------
# Alerts are written by the worker's rules loop; here they are seeded like lane P's own suite
# (``tests/api/alerts/test_alerts.py``): an open alert on a fresh, ungrouped agent with its
# fire-time health snapshot, so ``close`` writes a real ``alert_verdict`` label row.

ALERT_RULE = "error_rate"
ALERT_CLOSE = {
    "action": "close",
    "verdict": "tp",
    "verdict_note": "contract scenario verdict",
    "reason": REASON,
}


def _health(w: ContractWorld, agent_id: UUID, at: datetime) -> UUID:
    rows = w.admin.in_tenant(
        w.a.id,
        "INSERT INTO sibyl.health_snapshot (tenant_id, evaluated_at, agent_id, score, band,"
        " provisional, events_seen, observation_coverage, factors, horizons, scoring_config_id,"
        " policy_version, routing_state_at, window_start, window_end, grain_s)"
        " SELECT $1, $2::timestamptz, $3, 42, 'failed', false, 300, 1, '[]'::jsonb, '{}'::jsonb,"
        " c.id, 1, 'active', $2::timestamptz - interval '5 minutes', $2::timestamptz, 300"
        " FROM sibyl.scoring_config c WHERE c.tenant_id = $1 LIMIT 1 RETURNING id",
        w.a.id,
        at,
        agent_id,
    )
    return UUID(str(rows[0]["id"]))


def alert_row(
    w: ContractWorld,
    *,
    agent_id: UUID | str | None = None,
    provider_id: UUID | None = None,
    incident_id: UUID | None = None,
    snapshot: bool = False,
) -> UUID:
    """An open alert: agent scope when ``agent_id`` is given, else provider scope."""
    fired = datetime.now(UTC) - timedelta(minutes=10)
    agent = None if agent_id is None else UUID(str(agent_id))
    scope = "agent" if agent is not None else "provider"
    snap = _health(w, agent, fired) if snapshot and agent is not None else None
    rows = w.admin.in_tenant(
        w.a.id,
        "INSERT INTO sibyl.alert (tenant_id, rule_id, scope, agent_id, provider_id, severity,"
        " state, dedupe_key, first_fired_at, last_evaluated_at, what_to_do, evidence,"
        " health_snapshot_id, provider_incident_id, summary)"
        " VALUES ($1, (SELECT r.id FROM sibyl.alert_rule r WHERE r.tenant_id = $1"
        " AND r.code = $2 ORDER BY r.id LIMIT 1), $3, $4, $5, 'warning', 'open', $6, $7, $7,"
        " 'Check the provider.', '{\"rule\": \"error_rate\"}', $8, $9, 'Error rate 60%')"
        " RETURNING id",
        w.a.id,
        ALERT_RULE,
        scope,
        agent,
        provider_id,
        f"{ALERT_RULE}:{scope}:{agent or provider_id}:{uuid4()}",
        fired,
        snap,
        incident_id,
    )
    return UUID(str(rows[0]["id"]))


def provider_incident(w: ContractWorld) -> UUID:
    """An open provider incident over two agents, with its provider alert and a member alert."""
    pid = provider(w)
    members = [UUID(agent(w)["id"]), UUID(agent(w)["id"])]
    rows = w.admin.in_tenant(
        w.a.id,
        "INSERT INTO sibyl.provider_incident (tenant_id, provider_id, severity, rule_codes,"
        " affected_agent_ids, summary) VALUES ($1, $2, 'critical', $3, $4,"
        " 'contract scenario: provider degraded for 2 agents') RETURNING id",
        w.a.id,
        pid,
        [ALERT_RULE],
        members,
    )
    incident = UUID(str(rows[0]["id"]))
    alert_row(w, provider_id=pid, incident_id=incident)
    alert_row(w, agent_id=members[0], incident_id=incident)
    return incident


ALERTS: dict[str, Scenario] = {
    "listAlerts": _with_agent(lambda w, a: (alert_row(w, agent_id=a["id"]), Req("/alerts"))[1]),
    "getAlert": _with_agent(
        lambda w, a: Req(f"/alerts/{alert_row(w, agent_id=a['id'], snapshot=True)}")
    ),
    "actOnAlert": _with_agent(
        lambda w, a: Req(
            f"/alerts/{alert_row(w, agent_id=a['id'], snapshot=True)}/actions", ALERT_CLOSE
        )
    ),
    "listProviderIncidents": lambda w: (provider_incident(w), Req("/provider-incidents"))[1],
    "getProviderIncident": lambda w: Req(f"/provider-incidents/{provider_incident(w)}"),
}


# --- governance: audit log, anchors, exports, erasure, legal holds (lane U) ---------------------
# Lifted from lane U's ``tests/api/governance/test_contract_pg.py``. Anchors are written with the
# worker's own ``write_anchor`` and the world's published ``audit_anchor`` key. The worker's
# erasure execution is not running here, so a completed request is walked through the state
# machine by the fixture loader (four-eyes approval through the api first) and carries a
# certificate built by the worker's ``certificate.build`` over a real ``erasure`` anchor.


def anchor(w: ContractWorld, kind: str = "hourly") -> dict[str, Any]:
    from sibyl_control.worker.housekeeping.anchoring import write_anchor

    conn = w.admin.conn
    with w.admin.tx(w.a.id):
        result = conn.run(write_anchor(conn.raw, w.a.id, w.anchor_signer, kind=kind))
    return dict(result.row)


def agent_audit_seq(w: ContractWorld, agent_id: str) -> int:
    """The latest audit row about ``agent_id`` (its registration at least)."""
    with w.admin.tx(w.a.id):
        seq = w.admin.fetchval(
            "SELECT max(seq) FROM sibyl.audit_events WHERE tenant_id = $1"
            " AND resource_type = 'agent' AND resource_id = $2",
            w.a.id,
            UUID(agent_id),
        )
    assert seq is not None, f"no audit row about agent {agent_id}"
    return int(seq)


def _agent_audit_row(w: ContractWorld) -> Req:
    created = agent(w)
    seq = agent_audit_seq(w, created["id"])
    # audit seqs are per tenant: the foreign-tenant case must not land on B's own row
    assert seq > w.audit_head(w.b.id), (seq, w.audit_head(w.b.id))
    return Req(f"/audit/events/{seq}", agent_id=created["id"])


def _export_body(w: ContractWorld) -> dict[str, Any]:
    head = w.audit_head(w.a.id)
    return {"from_seq": max(0, head - 20), "to_seq": head, "format": "jsonl"}


def _hold_body(agent_id: str) -> dict[str, Any]:
    now = datetime.now(UTC)
    return {
        "scope_kind": "agent",
        "scope_ref": agent_id,
        "window_from": (now - timedelta(days=1)).isoformat(),
        "expires_at": (now + timedelta(days=5)).isoformat(),
        "reason": REASON,
    }


def _hold(w: ContractWorld) -> str:
    resp = _api(w, "POST", "/legal-holds", _hold_body(agent(w)["id"]))
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


def erasure_request(w: ContractWorld, agent_id: str | None = None) -> str:
    """An agent-scope erasure request filed by the owner (state ``requested``)."""
    body = {
        "scope_kind": "agent",
        "scope_ref": agent_id or agent(w)["id"],
        "legal_basis": "gdpr_art17",
        "reason": REASON,
    }
    resp = _api(w, "POST", "/erasure-requests", body)
    assert resp.status_code == 201 and resp.json()["state"] == "requested", resp.text
    return str(resp.json()["id"])


def _approved_erasure(w: ContractWorld) -> str:
    request_id = erasure_request(w)
    resp = w.client.post(
        f"/api/v1/erasure-requests/{request_id}/actions",
        json={"action": "approve", "reason": REASON},
        headers=w.idem("approver"),
    )
    assert resp.status_code == 200 and resp.json()["state"] == "approved", resp.text
    return request_id


def completed_erasure(w: ContractWorld) -> str:
    from sibyl_control.worker.housekeeping import certificate

    request_id = UUID(_approved_erasure(w))
    signed = anchor(w, kind="erasure")
    with w.admin.tx(w.a.id):
        for state in ("executing", "objects_deleted", "verified"):
            w.admin.execute(
                "UPDATE sibyl.erasure_request SET state = $3 WHERE tenant_id = $1 AND id = $2",
                w.a.id,
                request_id,
                state,
            )
        row = w.admin.fetchrow(
            "SELECT * FROM sibyl.erasure_request WHERE tenant_id = $1 AND id = $2",
            w.a.id,
            request_id,
        )
        completed = datetime.now(UTC)
        expires = completed + timedelta(days=7)
        cert = certificate.build(
            request=row,
            tenant_id=w.a.id,
            counts={"objects_deleted": {"payload_refs": 0}},
            shredded_keys=[],
            anchor=signed,
            ledger_entry={"seq": 1},
            ledger_entry_hash="0" * 64,
            completed_at=completed.isoformat(),
            backups_expire_at=expires.isoformat(),
            backup_retention_days=7,
            retained_tables=["audit_events", "erasure_request", "tenant"],
            requested_at=None,
            approved_at=row["approved_at"].isoformat(),
        )
        w.admin.execute(
            "UPDATE sibyl.erasure_request SET state = 'completed', completed_at = $3,"
            " backups_expire_at = $4, completion_anchor_id = $5, certificate_sha256 = $6,"
            " execution_log = execution_log || jsonb_build_array(jsonb_build_object("
            "'step', 'completed', 'at', $7::text, 'certificate', $8::jsonb))"
            " WHERE tenant_id = $1 AND id = $2",
            w.a.id,
            request_id,
            completed,
            expires,
            signed["id"],
            certificate.digest(cert),
            completed.isoformat(),
            cert,
        )
    return str(request_id)


GOVERNANCE: dict[str, Scenario] = {
    "listAuditEvents": lambda w: Req("/audit/events"),
    "getAuditEvent": _agent_audit_row,
    "listAuditAnchors": lambda w: (anchor(w), Req("/audit/anchors"))[1],
    "listAuditSigningKeys": lambda w: Req("/audit/signing-keys"),
    "verifyAuditChain": lambda w: (anchor(w), Req("/audit/verifications", {}))[1],
    "createAuditExport": lambda w: Req("/audit/exports", _export_body(w)),
    "getAuditExport": lambda w: Req(
        f"/audit/exports/{_api(w, 'POST', '/audit/exports', _export_body(w)).json()['id']}"
    ),
    "listErasureRequests": lambda w: (erasure_request(w), Req("/erasure-requests"))[1],
    "requestErasure": lambda w: Req(
        "/erasure-requests",
        {
            "scope_kind": "agent",
            "scope_ref": agent(w)["id"],
            "legal_basis": "gdpr_art17",
            "reason": REASON,
        },
    ),
    "getErasureRequest": lambda w: Req(f"/erasure-requests/{erasure_request(w)}"),
    "actOnErasureRequest": lambda w: Req(
        f"/erasure-requests/{erasure_request(w)}/actions",
        {"action": "approve", "reason": REASON},
        who="approver",  # four-eyes: the owner filed it
    ),
    "getErasureCertificate": lambda w: Req(f"/erasure-requests/{completed_erasure(w)}/certificate"),
    "listLegalHolds": lambda w: (_hold(w), Req("/legal-holds"))[1],
    "placeLegalHold": lambda w: Req("/legal-holds", _hold_body(agent(w)["id"])),
    "releaseLegalHold": lambda w: Req(f"/legal-holds/{_hold(w)}/release", {"reason": REASON}),
}
