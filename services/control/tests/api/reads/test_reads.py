"""Read routes on PG17: routing, fleet, health, history, risk, metrics, checkpoints, events,
traces and payloads (decrypt, reveal + audit, packet kinds, swept/shredded), with group and
bound-key object rules."""

from __future__ import annotations

import hashlib
import os
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
import sibyl_lane_a_kit as kit  # loaded by conftest
from sibyl_control.core.blob.base import BlobNotFound
from sibyl_control.core.crypto.envelope import EncryptedBlob, build_aad, seal
from sibyl_control.core.crypto.sealed import pack, payload_context

API = "/api/v1"
RH = hashlib.sha256(b"profile").digest()


class MemoryBlob:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    async def get(self, key: str) -> bytes:
        if key not in self.objects:
            raise BlobNotFound(key)
        return self.objects[key]


@pytest.fixture
def blob() -> MemoryBlob:
    return MemoryBlob()


@pytest.fixture
def lane(lane_db: Any, blob: MemoryBlob) -> Any:
    with kit.lane_app(lane_db, extra_state={"blob": blob}) as app:
        yield app


def tok(lane: Any, w: Any, role: str) -> str:
    return kit.add_session(lane.db, w.tenant, w.users[role])


def get(lane: Any, token: str, path: str, **kw: Any) -> Any:
    headers = kw.pop("headers", {})
    return lane.client.get(f"{API}{path}", headers=lane.bearer(token, **headers), **kw)


# ---- seeds ---------------------------------------------------------------------------------------


ERROR_FACTOR = {
    "rule": "error_rate_high",
    "weight": 0.5,
    "value": 0.2,
    "threshold": 0.05,
    "direction": "above",
    "explanation": "errors",
}


def add_snapshot(
    db: Any,
    w: Any,
    agent: UUID,
    *,
    score: int,
    band: str,
    ago_min: int = 1,
    factors: list[dict[str, Any]] | None = None,
) -> UUID:
    with db.admin.tx(w.tenant):
        config = db.admin.fetchval(
            "SELECT id FROM sibyl.scoring_config WHERE tenant_id = $1 LIMIT 1", w.tenant
        )
        return db.admin.fetchval(
            "INSERT INTO sibyl.health_snapshot (tenant_id, evaluated_at, agent_id, score, band,"
            " provisional,"
            " events_seen, observation_coverage, factors, horizons, predicted_failure_mode,"
            " scoring_config_id, policy_version, routing_state_at, window_start, window_end,"
            " grain_s)"
            " VALUES ($1, now() - make_interval(mins => $6), $2, $3, $4, false, 120, 0.950,"
            " $5::jsonb,"
            " $7::jsonb, NULL, $8, 3, 'active', now() - interval '10 minutes', now(), 60)"
            " RETURNING id",
            w.tenant,
            agent,
            score,
            band,
            [ERROR_FACTOR] if factors is None else factors,
            ago_min,
            {
                "1h": {
                    "horizon_s": 3600,
                    "probability_band": "0.25",
                    "confidence": "medium",
                    "contributing_rules": ["error_rate_trend"],
                    "source": "rules/v1",
                }
            },
            config,
        )


def add_event(
    db: Any,
    w: Any,
    agent: UUID | None,
    *,
    trace: UUID | None = None,
    ago_s: int = 5,
    event_type: str = "gen_ai.request",
    payload: UUID | None = None,
) -> UUID:
    eid = uuid4()
    with db.admin.tx(w.tenant):
        db.admin.execute(
            "INSERT INTO sibyl.events (tenant_id, event_id, ts, event_type, source, agent_id,"
            " call_id,"
            " trace_id, emitter_id, seq, policy_state, capture_mode, redaction_profile_hash,"
            " normaliser_version, status, payload_ref_id, attrs)"
            " VALUES ($1, $2, now() - make_interval(secs => $3), $4, 'gateway', $5, $6, $7, 'gw',"
            " 1,"
            " 'fresh', 'full', $8, 'normaliser/1.0', 'ok', $9, '{\"gen_ai.system\": \"openai\"}')",
            w.tenant,
            eid,
            ago_s,
            event_type,
            agent,
            uuid4() if event_type == "gen_ai.request" else None,
            trace,
            RH,
            payload,
        )
    return eid


def add_payload(
    db: Any,
    w: Any,
    blob: MemoryBlob,
    agent: UUID,
    body: bytes,
    *,
    kind: str = "span_content",
    state: str = "stored",
) -> UUID:
    ref = uuid4()
    with db.admin.tx(w.tenant):
        key = db.admin.fetchrow(
            "SELECT id, wrapped_dek FROM sibyl.tenant_key WHERE tenant_id = $1 AND purpose ="
            " 'payload'"
            " AND version = 1",
            w.tenant,
        )
        dek = kit.TEST_KEK.unwrap(bytes(key["wrapped_dek"]), kit.wrap_aad(w.tenant, "payload", 1))
        sealed = seal(dek, body, build_aad(w.tenant, "payload", 1) + payload_context(ref))
        uri = f"tenant/{w.tenant}/2026-10-11/{kind}/{ref}.bin"
        packed = pack(EncryptedBlob(1, sealed.nonce, sealed.ciphertext))
        blob.objects[uri] = packed
        db.admin.execute(
            "INSERT INTO sibyl.payload_refs (tenant_id, id, kind, uri, content_type, sha256,"
            " size_bytes,"
            " stored_bytes, tenant_key_id, key_version, nonce, capture_mode,"
            " redaction_profile_hash,"
            " agent_id, source_kind, expires_at, state, swept_at)"
            " VALUES ($1, $2, $3, $4, 'application/json', $5, $6, $7, $8, 1, $9, 'full', $10, $11,"
            " 'event',"
            " now() + interval '30 days', $12, CASE WHEN $12 = 'swept' THEN now() END)",
            w.tenant,
            ref,
            kind,
            uri,
            hashlib.sha256(body).digest(),
            len(body),
            len(packed),
            key["id"],
            sealed.nonce,
            RH,
            agent,
            state,
        )
    return ref


# ---- routing -------------------------------------------------------------------------------------


def test_routing_state_and_transitions(lane: Any, world: Any) -> None:
    token = tok(lane, world, "viewer")
    agent = world.agents["in_g1"]
    resp = get(lane, token, f"/agents/{agent}/routing")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["state"] == "active" and body["target_kind"] == "primary"
    assert body["last_transition"]["trigger"] == "register"
    assert (
        get(
            lane, token, f"/agents/{agent}/routing", headers={"If-None-Match": resp.headers["etag"]}
        ).status_code
        == 304
    )
    page = get(lane, token, f"/agents/{agent}/routing/transitions").json()
    assert [t["to_state"] for t in page["data"]] == ["active"] and page["has_more"] is False
    assert get(lane, token, f"/agents/{uuid4()}/routing").status_code == 404


def test_group_engineer_sees_only_in_group_agents(lane: Any, world: Any) -> None:
    eng = tok(lane, world, "engineer")
    add_snapshot(lane.db, world, world.agents["other"], score=40, band="degraded")
    add_snapshot(lane.db, world, world.agents["in_g2"], score=90, band="healthy")
    assert (
        get(lane, eng, f"/agents/{world.agents['in_g2']}/health").status_code == 200
    )  # child group
    # agents:read is tenant-wide for engineers (✓), so health is visible; payloads:read is G.
    assert get(lane, eng, f"/agents/{world.agents['other']}/health").status_code == 200
    assert get(lane, eng, f"/agents/{world.agents['other']}/checkpoints").status_code == 404
    assert get(lane, eng, f"/agents/{world.agents['in_g1']}/checkpoints").status_code == 200
    assert "access.denied" in kit.audit_actions(lane.db, world.tenant)


def test_bound_key_reads_only_its_agent(lane: Any, world: Any) -> None:
    kit.add_capture_policy(lane.db, world.tenant, world.users["owner"])
    admin = tok(lane, world, "admin")
    made = lane.client.post(
        f"{API}/api-keys",
        json={
            "name": "sdk",
            "env": "test",
            "scopes": ["routing:read", "agents:read"],
            "agent_id": str(world.agents["in_g1"]),
        },
        headers=lane.bearer(admin, **kit.idem()),
    ).json()
    key = made["secret"]
    own = get(lane, key, f"/agents/{world.agents['in_g1']}/routing")
    assert own.status_code == 200 and own.json()["last_transition"] is None
    assert get(lane, key, f"/agents/{world.agents['other']}/routing").status_code == 404
    add_snapshot(lane.db, world, world.agents["in_g1"], score=80, band="healthy")
    assert get(lane, key, f"/agents/{world.agents['in_g1']}/health").status_code == 200
    assert get(lane, key, f"/agents/{world.agents['other']}/health").status_code == 404
    assert get(lane, key, "/fleet/health").status_code == 403  # session-only route


# ---- health, history, risk, fleet -------------------------------------------------------------


def test_health_document_history_and_risk(lane: Any, world: Any) -> None:
    token = tok(lane, world, "viewer")
    agent = world.agents["in_g1"]
    assert get(lane, token, f"/agents/{agent}/health").json()["type"].endswith("/no_snapshot_yet")
    for i, (score, band) in enumerate([(90, "healthy"), (70, "watch"), (40, "degraded")]):
        add_snapshot(lane.db, world, agent, score=score, band=band, ago_min=30 - i * 10)
    doc = get(lane, token, f"/agents/{agent}/health").json()
    assert doc["schema"] == "sibyl-health/1" and doc["score"] == 40 and doc["status"] == "degraded"
    assert doc["provisional"]["events_needed"] == 50 and doc["window"]["grain_s"] == 60
    from sibyl_schemas.models.health import HealthDocument

    document = doc | {
        "feature_snapshot_ref": f"fs_{uuid4()}",
        "horizons": {
            h: {"probability_band": "0.05", "source": "rules/v1", "confidence": "low"}
            for h in ("15m", "1h", "24h")
        },
    }
    HealthDocument.model_validate(document)  # the wire model accepts the shape
    hist = get(lane, token, f"/agents/{agent}/health/history", params={"limit": 2}).json()
    assert [p["score"] for p in hist["data"]] == [90, 70] and hist["has_more"]
    stepped = get(lane, token, f"/agents/{agent}/health/history", params={"step": "1h"}).json()
    assert len(stepped["data"]) <= 2
    wide = get(
        lane,
        token,
        f"/agents/{agent}/health/history",
        params={"from": "2026-01-01T00:00:00Z", "to": "2026-02-01T00:00:00Z"},
    )
    assert wide.status_code == 422 and wide.json()["type"].endswith("/range_too_wide")
    risk = get(lane, token, f"/agents/{agent}/risk").json()
    assert set(risk["horizons"]) == {"15m", "1h", "24h"}
    assert (
        risk["horizons"]["1h"]["probability_band"] == "0.25"
        and risk["horizons"]["15m"]["abstained"]
    )
    assert risk["leading_rules_firing"] == ["error_rate_trend"]


def test_risk_horizons_follow_the_frozen_risk_document(lane: Any, world: Any) -> None:
    """Lane P CR: the stored sibyl-health/1 horizons carry ``source`` (and may carry
    ``predicted_failure_mode``); the risk read projects them onto ``RiskHorizon`` exactly."""
    from sibyl_control.core.risk import RiskDocument

    token = tok(lane, world, "viewer")
    agent = world.agents["in_g2"]
    add_snapshot(lane.db, world, agent, score=70, band="watch")
    risk = get(lane, token, f"/agents/{agent}/risk").json()
    keys = {"horizon_s", "probability_band", "probability", "confidence"}
    keys |= {"contributing_rules", "abstained"}
    assert all(set(h) == keys for h in risk["horizons"].values())
    assert risk["horizons"]["1h"]["horizon_s"] == 3600
    assert "source" not in risk["horizons"]["1h"]
    RiskDocument.model_validate(risk)


def test_verbose_health_lists_zero_penalty_factors(lane: Any, world: Any) -> None:
    """ML.md §3.6: ``?verbose=1`` adds every other rule of the scoring config that applies to
    the agent's tier with penalty 0; the plain document is unchanged and has its own ETag."""
    token = tok(lane, world, "viewer")
    agent = world.agents["in_g2"]
    add_snapshot(lane.db, world, agent, score=60, band="watch")
    plain = get(lane, token, f"/agents/{agent}/health")
    verbose = get(lane, token, f"/agents/{agent}/health", params={"verbose": 1})
    assert plain.status_code == verbose.status_code == 200
    assert plain.headers["etag"] != verbose.headers["etag"]
    base = plain.json()["factors"]
    extra = verbose.json()["factors"][len(base) :]
    assert verbose.json()["factors"][: len(base)] == base
    assert extra, "zero-penalty factors listed"
    assert all(f["penalty"] == 0 and f["weight"] > 0 and f["evidence"] for f in extra)
    rules = [f["rule"] for f in extra]
    assert rules == sorted(rules) and "error_rate" in rules
    assert {f["rule"] for f in base}.isdisjoint(rules)


def test_health_document_strips_engine_bookkeeping(lane: Any, world: Any) -> None:
    """B-04 / ML.md §3.6: the engine's ``_hysteresis`` and ``_clamp`` rows ride in
    ``health_snapshot.factors`` for restart resume and are stripped from the API, so every
    returned factor is a ``sibyl-health/1`` Factor (plain and verbose)."""
    from sibyl_schemas.models.health import Factor

    token = tok(lane, world, "viewer")
    agent = world.agents["in_g1"]
    bookkeeping = [
        {"rule": "_hysteresis", "band": "failed", "pending": [0, None], "rules": {}},
        {"rule": "_clamp", "penalty": 10},
    ]
    add_snapshot(
        lane.db, world, agent, score=0, band="failed", factors=[ERROR_FACTOR, *bookkeeping]
    )
    for params in ({}, {"verbose": 1}):
        factors = get(lane, token, f"/agents/{agent}/health", params=params).json()["factors"]
        assert factors and not [f for f in factors if str(f["rule"]).startswith("_")]
        for f in factors:
            Factor.model_validate(f)
        assert factors[0]["rule"] == "error_rate_high"


def test_fleet_health_counts_and_group_scope(lane: Any, world: Any) -> None:
    add_snapshot(lane.db, world, world.agents["in_g1"], score=90, band="healthy")
    add_snapshot(lane.db, world, world.agents["other"], score=30, band="failed")
    with lane.db.admin.tx(world.tenant):
        rule = lane.db.admin.fetchval(
            "SELECT id FROM sibyl.alert_rule WHERE tenant_id = $1 LIMIT 1", world.tenant
        )
        lane.db.admin.execute(
            "INSERT INTO sibyl.alert (tenant_id, rule_id, scope, agent_id, severity, state,"
            " dedupe_key, summary, what_to_do)"
            " VALUES ($1, $2, 'agent', $3, 'warning', 'open', 'k1', 'slow', 'look')",
            world.tenant,
            rule,
            world.agents["other"],
        )
    viewer = get(lane, tok(lane, world, "viewer"), "/fleet/health").json()
    assert viewer["counts_by_band"]["healthy"] == 1 and viewer["counts_by_band"]["failed"] == 1
    assert viewer["counts_by_band"]["unscored"] == 1 and viewer["counts_by_routing_state"] == {
        "active": 3
    }
    assert viewer["open_alerts"] == 1
    filtered = get(
        lane, tok(lane, world, "viewer"), "/fleet/health", params={"band": "failed"}
    ).json()
    assert filtered["counts_by_routing_state"] == {"active": 1}


# ---- metrics and checkpoints ---------------------------------------------------------------------


def test_metrics_grains_and_ranges(lane: Any, world: Any) -> None:
    agent = world.agents["in_g1"]
    with lane.db.admin.tx(world.tenant):
        for minutes in (0, 5, 10):
            lane.db.admin.execute(
                "INSERT INTO sibyl.agent_metrics_5m (tenant_id, agent_id, provider, model,"
                " bucket_start,"
                " request_count, error_count, tokens_in, cost_usd, latency_hist)"
                " VALUES ($1, $2, 'openai', 'gpt', date_bin('5 minutes', now() -"
                " make_interval(mins => $3),"
                " '2000-01-01'::timestamptz), 10, 1, 100, 0.12345, sibyl.zero_hist())",
                world.tenant,
                agent,
                minutes,
            )
    token = tok(lane, world, "viewer")
    five = get(lane, token, f"/agents/{agent}/metrics", params={"grain": "5m"}).json()["data"]
    assert len(five) == 3 and five[0]["requests"] == 10 and five[0]["cost_usd"] == "0.1235"
    fifteen = get(lane, token, f"/agents/{agent}/metrics", params={"grain": "15m"}).json()["data"]
    assert sum(b["requests"] for b in fifteen) == 30 and len(fifteen) <= 2
    too_wide = get(
        lane,
        token,
        f"/agents/{agent}/metrics",
        params={"grain": "1m", "from": "2026-01-01T00:00:00Z", "to": "2026-01-05T00:00:00Z"},
    )
    assert too_wide.status_code == 422 and too_wide.json()["type"].endswith("/grain_range")
    assert get(lane, token, f"/agents/{agent}/metrics", params={"grain": "2m"}).status_code == 422


def test_checkpoint_state_only_for_unaudited_packet_readers(lane: Any, world: Any) -> None:
    agent = world.agents["in_g1"]
    with lane.db.admin.tx(world.tenant):
        lane.db.admin.execute(
            "INSERT INTO sibyl.checkpoint (tenant_id, id, agent_id, task_id, seq, step_index,"
            " state_bytes,"
            " state, state_schema, doc, capture_mode, redaction_profile_hash)"
            " VALUES ($1, $2, $3, $4, 1, 0, 12, '{\"step\": 1}', 'state/1', '{}', 'full', $5)",
            world.tenant,
            uuid4(),
            agent,
            uuid4(),
            RH,
        )
    owner = get(lane, tok(lane, world, "owner"), f"/agents/{agent}/checkpoints").json()["data"]
    assert owner[0]["state"] == {"step": 1}
    auditor = get(lane, tok(lane, world, "auditor"), f"/agents/{agent}/checkpoints").json()["data"]
    assert auditor[0]["state"] is None and auditor[0]["seq"] == 1
    assert get(lane, tok(lane, world, "viewer"), f"/agents/{agent}/checkpoints").status_code == 403


# ---- events and traces ---------------------------------------------------------------------------


def test_events_list_filter_page_and_scope(lane: Any, world: Any) -> None:
    trace = uuid4()
    ids = [
        add_event(lane.db, world, world.agents["in_g1"], trace=trace, ago_s=s) for s in (30, 20, 10)
    ]
    add_event(lane.db, world, world.agents["other"], trace=trace)
    add_event(lane.db, world, None, event_type="provider.status")
    owner = tok(lane, world, "owner")
    page = get(
        lane, owner, "/events", params={"limit": 2, "agent_id": str(world.agents["in_g1"])}
    ).json()
    assert [e["event_id"] for e in page["data"]] == [str(ids[2]), str(ids[1])]
    nxt = get(
        lane,
        owner,
        "/events",
        params={"limit": 2, "agent_id": str(world.agents["in_g1"]), "cursor": page["next_cursor"]},
    ).json()
    assert [e["event_id"] for e in nxt["data"]] == [str(ids[0])]
    assert all("body" not in e and "content" not in e for e in page["data"])
    eng = tok(lane, world, "engineer")
    scoped = get(lane, eng, "/events").json()["data"]
    assert {e["agent_id"] for e in scoped} == {str(world.agents["in_g1"])}
    one = get(lane, owner, f"/events/{ids[0]}").json()
    assert one["trace_id"] == trace.hex and one["attrs"] == {"gen_ai.system": "openai"}
    other_event = add_event(lane.db, world, world.agents["other"])
    assert get(lane, eng, f"/events/{other_event}").status_code == 404
    spans = get(lane, owner, f"/traces/{trace.hex}").json()["spans"]
    assert len(spans) == 4
    assert len(get(lane, eng, f"/traces/{trace.hex}").json()["spans"]) == 3
    assert get(lane, owner, f"/traces/{uuid4().hex}").status_code == 404
    assert get(lane, owner, "/events", params={"trace_id": "nothex"}).status_code == 422


# ---- payloads ------------------------------------------------------------------------------------


def test_payload_read_decrypts_and_checks_integrity(
    lane: Any, world: Any, blob: MemoryBlob
) -> None:
    body = b'{"messages": "redacted prompt"}'
    ref = add_payload(lane.db, world, blob, world.agents["in_g1"], body)
    resp = get(lane, tok(lane, world, "owner"), f"/payloads/{ref}")
    assert resp.status_code == 200, resp.text
    assert resp.content == body and resp.headers["x-sibyl-capture-mode"] == "full"
    assert resp.headers["etag"] == f'"{hashlib.sha256(body).hexdigest()}"'
    assert "x-sibyl-audit-receipt" not in resp.headers
    eng = tok(lane, world, "engineer")
    assert get(lane, eng, f"/payloads/{ref}").status_code == 200  # in group, unaudited
    blob.objects[next(iter(blob.objects))] = os.urandom(len(body) + 16)
    assert get(lane, tok(lane, world, "owner"), f"/payloads/{ref}").status_code == 500


def test_payload_reveal_needs_a_reason_and_is_audited(
    lane: Any, world: Any, blob: MemoryBlob
) -> None:
    ref = add_payload(lane.db, world, blob, world.agents["other"], b"secret-free body")
    eng = tok(lane, world, "engineer")
    assert get(lane, eng, f"/payloads/{ref}").status_code == 404  # out of group, no reveal scope
    auditor = tok(lane, world, "auditor")
    missing = get(lane, auditor, f"/payloads/{ref}")
    assert missing.status_code == 428 and missing.json()["type"].endswith("/reveal_reason_required")
    ok = get(
        lane,
        auditor,
        f"/payloads/{ref}",
        headers={"X-Sibyl-Reveal-Reason": "quarterly access review"},
    )
    assert ok.status_code == 200 and ok.headers["x-sibyl-audit-receipt"].startswith(
        f"{world.tenant}:"
    )
    row = kit.audit_rows(lane.db, world.tenant, "data.revealed")[-1]
    assert (
        row["detail"]["payload_ref"] == str(ref)
        and row["detail"]["reveal_reason"] == "quarterly access review"
    )
    sec = tok(lane, world, "security_admin")
    assert get(lane, sec, f"/payloads/{ref}").status_code == 200  # security_admin: payloads:read ✓


def test_audit_exports_need_audit_export_or_an_audited_reveal(
    lane: Any, world: Any, blob: MemoryBlob
) -> None:
    """Lane U CR: an ``anchor_export`` payload is never served on a plain ``payloads:read``."""
    export = add_payload(lane.db, world, blob, None, b'{"type":"header"}', kind="anchor_export")
    owner = tok(lane, world, "owner")  # holds audit:export
    assert get(lane, owner, f"/payloads/{export}").status_code == 200
    reader = kit.add_user(
        lane.db, world.tenant, world.issuer_id, roles=("engineer",), subject="eng-tw"
    )
    plain = kit.add_session(lane.db, world.tenant, reader)  # tenant-wide payloads:read only
    assert get(lane, plain, f"/payloads/{export}").status_code == 404
    auditor = tok(lane, world, "auditor")  # audited read: reason + data.revealed
    assert get(lane, auditor, f"/payloads/{export}").status_code == 200  # holds audit:export too


def test_packet_kinds_swept_and_shredded(lane: Any, world: Any, blob: MemoryBlob) -> None:
    owner = tok(lane, world, "owner")
    packet = add_payload(lane.db, world, blob, world.agents["in_g1"], b"{}", kind="handoff_packet")
    assert get(lane, owner, f"/payloads/{packet}").status_code == 200
    viewer = tok(lane, world, "viewer")
    assert get(lane, viewer, f"/payloads/{packet}").status_code == 403  # no payloads:read at all
    swept = add_payload(lane.db, world, blob, world.agents["in_g1"], b"{}", state="swept")
    assert get(lane, owner, f"/payloads/{swept}").json()["type"].endswith("/payload_swept")
    gone = add_payload(lane.db, world, blob, world.agents["in_g1"], b"{}")
    blob.objects.clear()
    assert get(lane, owner, f"/payloads/{gone}").json()["type"].endswith("/payload_swept")
    assert get(lane, owner, f"/payloads/{uuid4()}").status_code == 404
    _ = timedelta
