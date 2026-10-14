"""G-policy decisions through ``SnapshotPolicyView``: fail-mode matrix, kill switch, routing."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from sibyl_gateway.policy.service import SnapshotPolicyView
from sibyl_gateway.policy.store import SnapshotStore
from sibyl_gateway.policy.verify import PinnedKeySet
from sibyl_gateway.policy.view import (
    CredentialRef,
    DecisionRequest,
    KeyPrincipal,
    KeyRejected,
    ModelList,
    PolicyState,
    PolicyView,
    Refuse,
    Serve,
)

from ..support import (
    ANTHROPIC,
    BILLING,
    BOUND_KEY,
    CRED,
    GATEWAY_KEY,
    GATEWAY_PREFIX,
    OPENAI,
    QUOTE,
    READONLY_KEY,
    TENANT,
    UNCLAIMED,
    Clock,
    TestSigner,
    body,
    make_key,
    set_agent,
    tenant_block,
)
from ..support import PEPPER as _PEPPER

T0 = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
AGE = {"fresh": 5, "stale": 120, "expired": 400}


def build(block: dict[str, Any] | None = None, *, age: float = 5, env: str = "live"):
    signer = TestSigner()
    clock = Clock(T0)
    store = SnapshotStore(PinnedKeySet.from_document(signer.key_set()), clock=clock)
    view = SnapshotPolicyView(store, pepper=_PEPPER, env=env, clock=clock)
    if block is not None:
        raw, kid, sig = signer.deliver(body(1, issued_at=T0, tenants={str(TENANT): block}))
        store.offer("gw", raw, kid=kid, signature=sig)
    clock.advance(age)
    return view, clock


def principal(view: SnapshotPolicyView, key: str = GATEWAY_KEY) -> KeyPrincipal:
    out = view.authenticate(key)
    assert isinstance(out, KeyPrincipal), out
    return out


def ask(view: SnapshotPolicyView, key: str = GATEWAY_KEY, **kw: Any) -> Serve | Refuse:
    kw.setdefault("agent_header", "quote-assistant")
    kw.setdefault("has_provider_credential", True)
    return view.decide(
        DecisionRequest(
            principal=principal(view, key),
            operation=kw.pop("operation", "chat.completions"),
            request_id="req-1",
            **kw,
        )
    )


def refused(decision: Serve | Refuse, code: str) -> Refuse:
    assert isinstance(decision, Refuse), decision
    assert decision.error_code == code
    return decision


def test_view_satisfies_the_frozen_protocol() -> None:
    view, _ = build(tenant_block())
    assert isinstance(view, PolicyView)


# -- fail-mode matrix (API.md §3.5) -------------------------------------------------------


@pytest.mark.parametrize(
    ("state", "mode", "expected"),
    [
        ("fresh", "open", None),
        ("fresh", "closed", None),
        ("stale", "open", None),
        ("stale", "closed", None),
        ("expired", "open", None),
        ("expired", "closed", "sibyl_policy_expired"),
    ],
)
def test_fail_mode_matrix(state: str, mode: str, expected: str | None) -> None:
    view, _ = build(set_agent(tenant_block(), QUOTE, fail_mode=mode), age=AGE[state])
    decision = ask(view)
    if expected is None:
        assert isinstance(decision, Serve)
        assert decision.policy.state is PolicyState(state)
        assert decision.response_headers()["X-Sibyl-Policy-State"] == state
        if state == "expired":
            assert decision.audit_events == ("policy.stale_bypass",)
            assert decision.targets[0].route == "stale_primary"
    else:
        assert refused(decision, expected).audit_event == "policy.fail_closed_block"


def test_no_snapshot_ever_refuses_everything() -> None:
    view, _ = build(None)
    assert view.status().state is PolicyState.UNAVAILABLE
    fake = KeyPrincipal(TENANT, TENANT, GATEWAY_PREFIX, "live", frozenset({"gateway:proxy"}))
    decision = view.decide(DecisionRequest(fake, "chat.completions", "r", True))
    assert refused(decision, "sibyl_no_snapshot").http_status == 503
    assert isinstance(view.authenticate(GATEWAY_KEY), KeyRejected)


@pytest.mark.parametrize("state", list(AGE))
@pytest.mark.parametrize("kill", ["route", "agent_switch", "tenant_switch"])
def test_kill_beats_every_state_and_fail_open(state: str, kill: str) -> None:
    block = set_agent(tenant_block(), QUOTE, fail_mode="open")
    if kill == "route":
        set_agent(block, QUOTE, route={"state": "killed"})
    else:
        block["kill_switches"] = [
            {
                "kill_switch_id": "0192f0d1-0000-7000-8000-000000000009",
                "scope_kind": "agent" if kill == "agent_switch" else "tenant",
                "scope_id": str(QUOTE) if kill == "agent_switch" else None,
                "pulled_at": "2026-10-10T11:00:00.000Z",
            }
        ]
    view, _ = build(block, age=AGE[state])
    assert refused(ask(view), "sibyl_agent_killed").http_status == 403


def test_provider_kill_removes_targets_and_refuses_when_none_left() -> None:
    block = tenant_block()
    block["kill_switches"] = [
        {
            "kill_switch_id": "0192f0d1-0000-7000-8000-000000000008",
            "scope_kind": "provider",
            "scope_id": str(OPENAI),
            "pulled_at": "2026-10-10T11:00:00.000Z",
        }
    ]
    view, _ = build(block)
    refused(ask(view), "sibyl_agent_killed")


def test_fixture_killed_agent_is_refused_by_slug() -> None:
    view, _ = build(tenant_block())
    decision = refused(ask(view, agent_header="unclaimed/3f9a1c0e"), "sibyl_agent_killed")
    assert decision.agent_id == UNCLAIMED


# -- agent resolution and scopes -----------------------------------------------------------


def test_bound_key_narrows_never_widens() -> None:
    view, _ = build(tenant_block())
    assert isinstance(ask(view, BOUND_KEY, agent_header=None), Serve)
    assert isinstance(ask(view, BOUND_KEY, agent_header=str(QUOTE)), Serve)
    denied = refused(ask(view, BOUND_KEY, agent_header="billing-agent"), "sibyl_agent_mismatch")
    assert denied.audit_event == "access.denied"
    refused(ask(view, BOUND_KEY, agent_header="no-such-agent"), "sibyl_agent_mismatch")


def test_key_without_gateway_proxy_is_refused() -> None:
    view, _ = build(tenant_block())
    refused(ask(view, READONLY_KEY), "sibyl_scope_missing")
    assert refused(view.models(principal(view, READONLY_KEY), None), "sibyl_scope_missing")


def test_unknown_agent_on_tenant_key_is_provisional_metadata_only() -> None:
    view, _ = build(tenant_block())
    decision = ask(view, agent_header="invoice-bot", requested_model="gpt-5.4")
    assert isinstance(decision, Serve)
    assert str(decision.agent_id).startswith("unclaimed/")
    assert decision.capture_mode == "metadata"
    assert decision.fail_mode == "open"
    assert "agent.discovered" in decision.audit_events
    assert decision.targets[0].credential == "passthrough"
    refused(ask(view, agent_header="invoice-bot"), "sibyl_agent_unknown")  # no model to route


# -- routing states --------------------------------------------------------------------------


def test_quarantined_and_handed_off() -> None:
    view, _ = build(set_agent(tenant_block(), QUOTE, route={"state": "quarantined"}))
    refused(ask(view), "sibyl_agent_quarantined")
    route = {"state": "failed_over", "target_kind": "human_queue", "step_position": 4}
    view, _ = build(set_agent(tenant_block(), QUOTE, route=route))
    assert refused(ask(view), "sibyl_agent_handed_off").retry_after_s == 300


def test_failed_over_same_provider_uses_passthrough() -> None:
    view, _ = build(tenant_block())
    decision = ask(view, agent_header="billing-agent", requested_model="gpt-5.4")
    assert isinstance(decision, Serve)
    target = decision.targets[0]
    assert (target.route, target.model, target.provider_id) == ("failover", "gpt-5-mini", OPENAI)
    assert target.credential == "passthrough"


def test_failover_to_other_provider_uses_vaulted_credential_only() -> None:
    route = {"state": "failed_over", "target_kind": "model", "step_position": 3}
    view, _ = build(set_agent(tenant_block(), BILLING, route=route))
    decision = ask(view, agent_header="billing-agent", dialect="anthropic")
    assert isinstance(decision, Serve)
    target = decision.targets[0]
    assert target.provider_id == ANTHROPIC and target.dialect == "anthropic"
    assert target.credential == CredentialRef(CRED, 0)
    # an OpenAI-speaking caller cannot follow a failover onto an Anthropic-protocol target
    refused(ask(view, agent_header="billing-agent"), "sibyl_bad_request")


def test_cross_provider_step_without_credential_is_skipped() -> None:
    block = tenant_block()
    steps = block["agents"][str(BILLING)]["fallback_chain"]["steps"]
    del steps[2]["credential_id"]
    route = {"state": "failed_over", "target_kind": "model", "step_position": 3}
    view, _ = build(set_agent(block, BILLING, route=route))
    refused(ask(view, agent_header="billing-agent"), "upstream_error")


def test_inline_fallback_order_retry_and_header_none() -> None:
    view, _ = build(set_agent(tenant_block(), QUOTE, inline_fallback=True))
    decision = ask(view)
    assert isinstance(decision, Serve)
    # same-protocol only: the Anthropic step (claude-sonnet-5) is not a target for OpenAI calls
    assert [(t.route, t.model, t.max_attempts) for t in decision.targets] == [
        ("primary", "gpt-5.4", 2),
        ("inline_fallback", "gpt-5-mini", 1),
    ]
    only = ask(view, fallback_header="none")
    assert isinstance(only, Serve) and len(only.targets) == 1
    embed = ask(view, operation="embeddings")
    assert isinstance(embed, Serve) and [t.route for t in embed.targets] == ["primary"]


def test_sibyl_only_call_needs_a_vaulted_route() -> None:
    view, _ = build(tenant_block())
    refused(ask(view, has_provider_credential=False), "sibyl_bad_request")
    view, _ = build(set_agent(tenant_block(), QUOTE, inline_fallback=True))
    refused(ask(view, has_provider_credential=False), "sibyl_bad_request")
    decision = ask(view, has_provider_credential=False, dialect="anthropic")
    assert isinstance(decision, Serve)
    assert [t.provider_id for t in decision.targets] == [ANTHROPIC]
    assert isinstance(decision.targets[0].credential, CredentialRef)


# -- native protocols (D50): targets and fallback stay inside the caller's protocol ----------

GEMINI = UUID("0192f0a1-7b2c-7e3d-9a4b-5c6d7e8f9a14")


def native_block() -> dict[str, Any]:
    """QUOTE speaks Anthropic: primary claude, inline fallback to another Claude model, then
    to OpenAI and Gemini steps (other protocols: never targets for an Anthropic caller)."""
    block = tenant_block()
    block["providers"][str(GEMINI)] = {
        "slug": "gemini",
        "provider_kind": "custom",
        "dialect": "gemini",
        "base_url": "https://generativelanguage.googleapis.com",
        "is_enabled": True,
    }
    steps = [
        {
            "position": 1,
            "kind": "alt_provider",
            "provider_id": str(OPENAI),
            "model": "gpt-5.4",
            "credential_id": str(CRED),
            "viable": True,
        },
        {
            "position": 2,
            "kind": "alt_model_same_provider",
            "provider_id": str(ANTHROPIC),
            "model": "claude-haiku-5",
            "viable": True,
        },
        {
            "position": 3,
            "kind": "alt_provider",
            "provider_id": str(GEMINI),
            "model": "gemini-2.5-pro",
            "credential_id": str(CRED),
            "viable": True,
        },
    ]
    chain = {"chain_id": "0192f0b2-0000-7000-8000-0000000000c9", "version": 1, "steps": steps}
    return set_agent(
        block,
        QUOTE,
        primary={"provider_id": str(ANTHROPIC), "model": "claude-sonnet-5"},
        inline_fallback=True,
        fallback_chain=chain,
        identity={"allowed_models": None},
    )


def test_native_inline_fallback_stays_inside_the_protocol() -> None:
    view, _ = build(native_block())
    decision = ask(view, dialect="anthropic", requested_model="claude-sonnet-5")
    assert isinstance(decision, Serve)
    assert [(t.route, t.model, t.dialect) for t in decision.targets] == [
        ("primary", "claude-sonnet-5", "anthropic"),
        ("inline_fallback", "claude-haiku-5", "anthropic"),
    ]
    assert decision.targets[1].credential == "passthrough"  # same provider as the primary


def test_native_caller_on_a_foreign_primary_is_refused_not_translated() -> None:
    view, _ = build(native_block())
    # OpenAI caller, Anthropic primary: only the OpenAI step (vaulted) is eligible
    decision = ask(view, requested_model="claude-sonnet-5")
    assert isinstance(decision, Serve)
    assert [(t.route, t.model, t.dialect) for t in decision.targets] == [
        ("inline_fallback", "gpt-5.4", "openai_compatible")
    ]
    gemini = ask(view, dialect="gemini", requested_model="claude-sonnet-5")
    assert isinstance(gemini, Serve)
    assert [t.dialect for t in gemini.targets] == ["gemini"]
    refused(ask(view, dialect="gemini", fallback_header="none"), "sibyl_bad_request")


def test_provisional_agents_route_to_a_provider_of_the_callers_protocol() -> None:
    block = native_block()
    view, _ = build(block)
    decision = ask(view, agent_header="new-bot", requested_model="claude-x", dialect="anthropic")
    assert isinstance(decision, Serve) and decision.targets[0].provider_id == ANTHROPIC
    decision = ask(view, agent_header="new-bot", requested_model="gemini-x", dialect="gemini")
    assert isinstance(decision, Serve) and decision.targets[0].provider_id == GEMINI
    del block["providers"][str(GEMINI)]
    view, _ = build(block)
    refused(
        ask(view, agent_header="new-bot", requested_model="g", dialect="gemini"),
        "sibyl_agent_unknown",
    )


@pytest.mark.parametrize(("pct", "route"), [(100, "canary"), (0, "failover")])
def test_failing_back_canary_split(pct: int, route: str) -> None:
    state = {"state": "failing_back", "canary_pct": pct}
    view, _ = build(set_agent(tenant_block(), BILLING, route=state))
    decision = ask(view, agent_header="billing-agent", task_id="t-1")
    assert isinstance(decision, Serve) and decision.targets[0].route == route


def test_degraded_modes() -> None:
    queued = set_agent(
        tenant_block(), QUOTE, route={"state": "degraded"}, degraded_mode="queue_only"
    )
    view, _ = build(queued)
    refused(ask(view), "sibyl_agent_queued")
    view, _ = build(set_agent(tenant_block(), QUOTE, route={"state": "degraded"}))
    decision = ask(view, has_tools=True)
    assert isinstance(decision, Serve) and decision.strip_tools
    assert decision.response_headers()["X-Sibyl-Degraded-Mode"] == "safe_no_tools"


def test_identity_block_and_observe() -> None:
    block = set_agent(tenant_block(), QUOTE, identity={"enforcement": "block"})
    view, _ = build(block)
    denied = refused(ask(view, requested_model="gpt-4o"), "sibyl_model_not_allowed")
    assert denied.audit_event == "policy.blocked"
    view, _ = build(tenant_block())
    observed = ask(view, requested_model="gpt-4o")
    assert isinstance(observed, Serve) and observed.policy_violation
    assert "policy.violated" in observed.audit_events
    no_tools = set_agent(
        tenant_block(), QUOTE, identity={"enforcement": "block", "allowed_tools": []}
    )
    view, _ = build(no_tools)
    refused(ask(view, has_tools=True), "sibyl_policy_blocked")


def test_capture_header_only_tightens_and_limits_come_from_the_plan() -> None:
    view, _ = build(tenant_block())
    tight = ask(view, capture_header="metadata")
    assert isinstance(tight, Serve) and tight.capture_mode == "metadata"
    assert tight.limits.rps_limit == 20 and tight.limits.burst == 40
    assert tight.limits.max_inflight == 50 and not tight.limits.budget_exhausted
    assert len(tight.redaction_profile_hash) == 64
    spent = set_agent(tenant_block(), QUOTE, limits={"spent_usd_month": "1500.0000"})
    view, _ = build(spent)
    over = ask(view)
    assert isinstance(over, Serve) and over.limits.budget_exhausted


def test_models_come_from_the_snapshot_never_upstream() -> None:
    view, _ = build(tenant_block())
    listing = view.models(principal(view), "quote-assistant")
    assert isinstance(listing, ModelList)
    assert listing.models == ("claude-sonnet-5", "gpt-5-mini", "gpt-5.4")
    open_identity = set_agent(tenant_block(), QUOTE, identity={"allowed_models": None})
    view, _ = build(open_identity)
    listing = view.models(principal(view), "quote-assistant")
    assert isinstance(listing, ModelList) and "gpt-5.4" in listing.models


# -- authentication --------------------------------------------------------------------------


def test_authenticate_accepts_only_exact_live_keys() -> None:
    view, _ = build(tenant_block())
    good = principal(view)
    assert (good.tenant_id, good.prefix) == (TENANT, GATEWAY_PREFIX)
    assert principal(view, BOUND_KEY).bound_agent_id == QUOTE
    bad_secret = GATEWAY_KEY[:-1] + ("A" if GATEWAY_KEY[-1] != "A" else "B")
    unknown, _ = make_key("Unknown00001")
    for key in (bad_secret, unknown, "sbl_live_short", "", GATEWAY_KEY.replace("live", "test")):
        assert view.authenticate(key) == KeyRejected("sibyl_key_invalid")
    test_env, _ = build(tenant_block(), env="test")
    assert test_env.authenticate(GATEWAY_KEY) == KeyRejected("sibyl_key_invalid")


def test_expired_and_rotation_grace() -> None:
    block = tenant_block()
    entry = block["api_keys"][GATEWAY_PREFIX]
    entry["expires_at"] = "2026-10-10T12:00:01.000Z"
    view, clock = build(block, age=0)
    assert isinstance(view.authenticate(GATEWAY_KEY), KeyPrincipal)
    clock.advance(2)
    assert view.authenticate(GATEWAY_KEY) == KeyRejected("sibyl_key_expired")
    block = tenant_block()
    block["api_keys"][GATEWAY_PREFIX].update(
        status="rotating", rotation_grace_until="2026-10-10T12:00:30.000Z"
    )
    view, clock = build(block, age=0)
    assert isinstance(view.authenticate(GATEWAY_KEY), KeyPrincipal)
    clock.advance(31)
    assert view.authenticate(GATEWAY_KEY) == KeyRejected("sibyl_key_expired")


def test_tenant_isolation_keys_resolve_to_their_own_block() -> None:
    signer = TestSigner()
    clock = Clock(T0)
    store = SnapshotStore(PinnedKeySet.from_document(signer.key_set()), clock=clock)
    other = UUID("0192767f-0000-7000-8000-00000000b001")
    other_block = tenant_block()
    other_key, digest = make_key("OtherTenant1")
    other_block["api_keys"] = {
        "OtherTenant1": {**other_block["api_keys"][GATEWAY_PREFIX], "secret_hash": digest}
    }
    for stream, tid, blk in (("a", TENANT, tenant_block()), ("b", other, other_block)):
        raw, kid, sig = signer.deliver(body(1, issued_at=T0, tenants={str(tid): blk}))
        store.offer(stream, raw, kid=kid, signature=sig)
    view = SnapshotPolicyView(store, pepper=_PEPPER, env="live", clock=clock)
    assert principal(view, other_key).tenant_id == other
    assert principal(view).tenant_id == TENANT
    clock.advance(timedelta(minutes=10).total_seconds())
    assert view.status().state is PolicyState.EXPIRED
