/**
 * The scripted live scenario (meridian only), timed so the console feels alive within the
 * first minute: provider degradation → hard outage → one provider incident → tiered automatic
 * failover with handoff packets → a tier-1 predicted move waiting for four-eyes approval →
 * recovery and a canaried failback, with the Action Gate's blocks and holds woven in
 * (action-gate-script.ts). `advance` applies beats and periodic checks in 5 s steps.
 */
import "server-only";
import { SECOND, iso } from "./core";
import { agentId, providerId, type AgentSpec, type ProviderSlug } from "./fixtures";
import { newRuntime } from "./build";
import { scoreAt } from "./health";
import { chooseTarget, completeFailover, emitIncident, fireAlert, openIncident, requestApproval, resolveAlert, addStep } from "./ops";
import { PACKETS } from "./packets";
import { expireHeld } from "./action-gate";
import { ACTION_GATE_BEATS } from "./action-gate-script";
import { MONITOR_BEATS } from "./monitor";
import { EXTERNAL_MONITOR_BEATS } from "./external-monitors-state";
import { recordDiscovery } from "./runs";
import { applyRouting, PRIMARY } from "./routing";
import { appendAudit, emit, makeAnchor, nextId, type AgentRt, type World } from "./world";

export interface Beat {
  at: number;
  id: string;
  label: string;
  run: (w: World, at: number) => void;
}

const ANTHROPIC = ["claims-triage", "invoice-reconciler", "dispatch-planner", "customer-chat", "contract-reviewer", "kb-search", "email-summarizer"];

const rtOf = (w: World, slug: string): AgentRt | undefined => w.agents.get(agentId(w.slug, slug));

function setStatus(w: World, provider: ProviderSlug, status: World["providerStatus"][ProviderSlug][number]["status"], at: number): void {
  w.providerStatus[provider] = [...w.providerStatus[provider], { at, status }];
}

function autoFailover(w: World, slug: string, at: number, packetKey?: string): void {
  const rt = rtOf(w, slug);
  if (!rt || rt.routing.state !== "active") return;
  if (rt.routing.operator_hold_until && rt.routing.operator_hold_until > at) return;
  const alert = [...w.alerts.values()].find((a) => a.agent_id === rt.id && a.state === "open" && a.rule_code === "error_rate");
  const inc = openIncident(w, rt, {
    kind: "failover",
    actor_kind: "rule",
    alertId: alert?.id ?? null,
    rule_codes: ["error_rate", "consecutive_failures", "provider_status"],
    reason: "Detected failure: Anthropic returning 503 on every call; band failed after hysteresis",
    at,
  });
  const target = chooseTarget(w, rt, at);
  completeFailover(w, inc, rt, { target, trigger: "rule", actor_kind: "rule", at, packet: packetKey ? (PACKETS[packetKey] ?? null) : null });
}

const OUTAGE_SCRIPT: readonly Beat[] = [
  { at: 15, id: "degrade", label: "Anthropic latency climbs (degraded performance)", run: (w, at) => setStatus(w, "anthropic", "degraded_performance", at) },
  { at: 30, id: "outage", label: "Anthropic hard outage: 503 on every call", run: (w, at) => setStatus(w, "anthropic", "major_outage", at) },
  {
    at: 33,
    id: "alerts",
    label: "Error-rate alerts fire on the 7 Anthropic agents",
    run: (w, at) => ANTHROPIC.forEach((slug, i) => fireAlert(w, rtOf(w, slug) ?? null, { rule: "error_rate", severity: "critical", at: at + i * 350 })),
  },
  {
    at: 36,
    id: "collapse",
    label: "Collapsed into one provider incident",
    run: (w, at) => {
      const id = nextId(w, "provider-incident");
      const members = ANTHROPIC.map((s) => rtOf(w, s)?.id).filter((x): x is string => Boolean(x));
      const memberAlerts = [...w.alerts.values()].filter((a) => a.state === "open" && a.rule_code === "error_rate" && a.agent_id && members.includes(a.agent_id));
      for (const a of memberAlerts) w.alerts.set(a.id, { ...a, provider_incident_id: id });
      w.providerIncidents.set(id, { id, provider_id: providerId(w.slug, "anthropic"), state: "open", opened_at: iso(at), resolved_at: null, affected_agent_ids: members, legal_hold_id: null });
      appendAudit(w, { action: "alert.fired", actor_type: "rule", resource_type: "provider_incident", resource_id: id, resource_ref: "anthropic", detail: { collapsed_alerts: memberAlerts.length, affected_agents: members.length, rule_code: "error_rate" }, severity: "warning" }, at);
      emit(w, "provider_incident.opened", { provider_incident_id: id, provider_id: providerId(w.slug, "anthropic"), affected_agent_ids: members }, at);
    },
  },
  { at: 42, id: "t1", label: "Tier 1 fails over to OpenAI (≤ 60 s budget)", run: (w, at) => autoFailover(w, "claims-triage", at, "claims-triage-outage") },
  {
    at: 52,
    id: "t2",
    label: "Tier 2 fails over (≤ 90 s budget)",
    run: (w, at) => {
      autoFailover(w, "invoice-reconciler", at);
      autoFailover(w, "dispatch-planner", at + 1200);
      autoFailover(w, "customer-chat", at + 2400, "customer-chat-outage");
    },
  },
  {
    at: 64,
    id: "t3",
    label: "Tier 3 fails over (≤ 120 s budget)",
    run: (w, at) => ["contract-reviewer", "kb-search", "email-summarizer"].forEach((s, i) => autoFailover(w, s, at + i * 1100)),
  },
  {
    at: 80,
    id: "ramp",
    label: "Quote assistant: OpenAI rate-limit headroom starts falling",
    run: (w, at) => {
      const rt = rtOf(w, "quote-assistant");
      if (rt) rt.anomalies = [...rt.anomalies, { kind: "ratelimit_ramp", from: at, to: null }];
    },
  },
  {
    at: 200,
    id: "approval",
    label: "Leading rule L3 predicts a rate limit: tier-1 move awaits approval",
    run: (w, at) => {
      const rt = rtOf(w, "quote-assistant");
      if (!rt || rt.routing.state !== "active") return;
      const alert = fireAlert(w, rt, { rule: "ratelimit_proximity", severity: "warning", at });
      const inc = openIncident(w, rt, { kind: "preemptive", actor_kind: "rule", alertId: alert.id, rule_codes: ["ratelimit_proximity", "fallback_pressure"], reason: "Predicted rate limit in ~15 min (rules/v1, medium); tier-1 pre-emptive move needs a human (D13)", at: at + 300 });
      requestApproval(w, inc, rt, { action: "preemptive_failover", byKind: "rule", evidence: { predicted: "rate limit in ~15 m", source: "rules/v1", confidence: "medium", contributing_rules: ["ratelimit_proximity"], headroom: "4.6%", target: "ollama/llama-3.3-70b" }, at: at + 400 });
    },
  },
  { at: 600, id: "recover", label: "Anthropic recovers", run: (w, at) => setStatus(w, "anthropic", "operational", at) },
  {
    at: 660,
    id: "resolve",
    label: "Alerts resolve by hysteresis (verdict wanted)",
    run: (w, at) => {
      for (const a of w.alerts.values()) if (a.state !== "resolved" && a.rule_code === "error_rate" && a.provider_incident_id) resolveAlert(w, a.id, at, true);
      for (const pi of w.providerIncidents.values()) {
        if (pi.state === "resolved") continue;
        w.providerIncidents.set(pi.id, { ...pi, state: "resolved", resolved_at: iso(at) });
        emit(w, "provider_incident.resolved", { provider_incident_id: pi.id, provider_id: pi.provider_id, affected_agent_ids: pi.affected_agent_ids }, at);
      }
    },
  },
  { at: 900, id: "canary", label: "Failback canary starts at 10%", run: (w, at) => canaryStep(w, at, 10) },
  { at: 960, id: "canary50", label: "Canary at 50%, all windows green", run: (w, at) => canaryStep(w, at, 50) },
  { at: 1020, id: "failback", label: "Failback complete: primary at 100%", run: (w, at) => canaryStep(w, at, 100) },
];

/** The outage story plus the Action Gate and wave 3 monitoring beats (monitor.ts), in time order (runBeats walks it in sequence). */
export const MERIDIAN_SCRIPT: readonly Beat[] = [...OUTAGE_SCRIPT, ...ACTION_GATE_BEATS, ...MONITOR_BEATS, ...EXTERNAL_MONITOR_BEATS].sort((a, b) => a.at - b.at);

function canaryStep(w: World, at: number, pct: number): void {
  for (const slug of ANTHROPIC) {
    const rt = rtOf(w, slug);
    if (!rt) continue;
    const ok = pct === 10 ? rt.routing.state === "failed_over" && rt.routing.target_kind === "model" : rt.routing.state === "failing_back";
    if (!ok) continue;
    if (pct === 10) {
      applyRouting(w, rt, { to: "failing_back", trigger: "failback_probe", actor_kind: "system", target: PRIMARY, canary_pct: 10, reason: "Primary healthy for 5 minutes and probe passed", at });
      appendAudit(w, { action: "failback.started", actor_type: "system", resource_type: "agent", resource_id: rt.id, resource_ref: slug, detail: { canary_pct: 10 } }, at);
    } else if (pct < 100) {
      rt.routing = { ...rt.routing, canary_pct: pct };
      emit(w, "policy_changed", { tenant_id: w.tenantId, routing_version: w.routingVersion, agent_id: rt.id }, at);
    } else {
      applyRouting(w, rt, { to: "active", trigger: "canary", actor_kind: "system", target: PRIMARY, canary_pct: 100, reason: "Canary at 100% with all windows green", at });
      appendAudit(w, { action: "failback.completed", actor_type: "system", resource_type: "agent", resource_id: rt.id, resource_ref: slug, detail: { canary_pct: 100 } }, at);
    }
  }
}

export function scriptFor(w: World): readonly Beat[] {
  return w.slug === "meridian" ? MERIDIAN_SCRIPT : [];
}

// ── Periodic checks ───────────────────────────────────────────────────────

function expireApprovals(w: World, t: number): void {
  for (const ap of w.approvals.values()) {
    if (ap.state !== "pending" || Date.parse(ap.expires_at) > t) continue;
    const inc = w.incidents.get(ap.incident_id);
    const rt = w.agents.get(ap.agent_id);
    w.approvals.set(ap.id, { ...ap, state: "expired", decided_at: iso(t) });
    appendAudit(w, { action: "approval.expired", actor_type: "system", resource_type: "approval", resource_id: ap.id, resource_ref: rt?.spec.slug ?? null, detail: { timeout_policy: ap.timeout_policy } }, t);
    emit(w, "approval.expired", { approval_id: ap.id, incident_id: ap.incident_id, agent_id: ap.agent_id, tier: ap.tier, requested_action: ap.requested_action, expires_at: ap.expires_at, state: "expired" }, t);
    if (!inc || !rt || rt.routing.state !== "awaiting_approval") continue;
    if (ap.timeout_policy === "fail_safe") {
      completeFailover(w, inc, rt, { target: chooseTarget(w, rt, t, true), trigger: "approval_timeout", actor_kind: "system", approvalId: ap.id, at: t });
    } else {
      const tr = applyRouting(w, rt, { to: "degraded", trigger: "approval_timeout", actor_kind: "system", approval_id: ap.id, failover_id: inc.id, reason: "Approval expired; timeout policy hold", at: t });
      inc.transition_ids = [...inc.transition_ids, tr.id];
      addStep(inc, "done", t, "Approval expired; held in degraded");
      inc.state = "cancelled";
      inc.finished_at = t;
      emitIncident(w, inc, rt);
    }
  }
}

function holdSuppression(w: World, t: number): void {
  for (const rt of w.agents.values()) {
    if (!rt.routing.operator_hold_until || rt.routing.operator_hold_until <= t) continue;
    if (scoreAt(w, rt, t).band !== "failed") continue;
    rt.holdSuppressed += 1;
    const alert = [...w.alerts.values()].find((a) => a.agent_id === rt.id && a.state !== "resolved");
    if (alert) w.alerts.set(alert.id, { ...alert, hold_suppressed_count: (alert.hold_suppressed_count ?? 0) + 1 });
  }
}

function bandTransitions(w: World, t: number): void {
  for (const rt of w.agents.values()) {
    const r = scoreAt(w, rt, t);
    const band = r.band;
    if (rt.lastBand !== null && rt.lastBand !== band) {
      emit(w, "health.transition", { agent_id: rt.id, from_band: rt.lastBand, to_band: band, score: r.score }, t);
    }
    rt.lastBand = band;
  }
}

/** Sandbox onboarding: the first gateway call with X-Sibyl-Agent registers the agent (~5 s). */
function discover(w: World, t: number): void {
  const due = w.pending.filter((x) => x.at <= t);
  if (due.length === 0) return;
  w.pending = w.pending.filter((x) => x.at > t);
  for (const d of due) {
    const spec: AgentSpec = { slug: d.slug, name: "Quote worker", kind: "autonomous_agent", tier: 3, risk_class: "unclassified", provider: "openai", model: "gpt-5-mini", modelClass: "small", framework: null, process: "Quote-to-cash", owner: "admin", pii: false, sdk: false, fail_mode: "open", rpm: 4, baseErr: 0.004, baseP95: 2100, costPerCall: 0.0012, description: "Auto-registered on its first gateway call (X-Sibyl-Agent: quote-worker)." };
    const rt = newRuntime(w, spec, d.at, true);
    w.agents.set(rt.id, rt);
    recordDiscovery(w, rt.id, "gateway_header", null, d.at);
    appendAudit(w, { action: "asset.discovered", actor_type: "api_key", resource_type: "agent", resource_id: rt.id, resource_ref: spec.slug, detail: { source: "gateway", header: "X-Sibyl-Agent", tier: 3, lifecycle: "discovered", fidelity: "request_only" } }, d.at);
    emit(w, "graph.changed", { tenant_id: w.tenantId, graph_version: w.counter }, d.at);
  }
}

/** Operator-started failbacks ramp 10 → 50 → 100 % over a minute (the scripted ones follow the script). */
function progressOperatorFailback(w: World, t: number): void {
  for (const rt of w.agents.values()) {
    if (rt.routing.state !== "failing_back") continue;
    const last = w.transitions.find((x) => x.id === rt.routing.last_transition_id);
    if (last?.trigger !== "operator") continue;
    const age = t - rt.routing.state_since;
    if (age >= 60 * SECOND) {
      applyRouting(w, rt, { to: "active", trigger: "canary", actor_kind: "system", target: PRIMARY, canary_pct: 100, reason: "Canary at 100% with all windows green", at: t });
      appendAudit(w, { action: "failback.completed", actor_type: "system", resource_type: "agent", resource_id: rt.id, resource_ref: rt.spec.slug, detail: { canary_pct: 100 } }, t);
    } else if (age >= 30 * SECOND && rt.routing.canary_pct < 50) {
      rt.routing = { ...rt.routing, canary_pct: 50 };
    }
  }
}

const STEP_MS = 5 * SECOND;
const ANCHOR_EVERY_MS = 10 * 60 * SECOND;

/** Apply every beat and periodic check up to `toMs` (absolute virtual time). */
function runBeats(w: World, script: readonly Beat[], upTo: number): void {
  while (w.scriptIndex < script.length) {
    const beat = script[w.scriptIndex];
    if (!beat || w.anchorAt + beat.at * SECOND > upTo) break;
    beat.run(w, w.anchorAt + beat.at * SECOND);
    w.scriptIndex += 1;
  }
}

export function advance(w: World, toMs: number): void {
  const script = scriptFor(w);
  let t = w.lastStepAt;
  while (t + STEP_MS <= toMs) {
    t += STEP_MS;
    runBeats(w, script, t);
    discover(w, t);
    expireApprovals(w, t);
    expireHeld(w, t);
    progressOperatorFailback(w, t);
    if ((t - w.anchorAt) % (10 * SECOND) === 0) holdSuppression(w, t);
    bandTransitions(w, t);
    if ((t - w.anchorAt) % ANCHOR_EVERY_MS === 0) makeAnchor(w, "hourly", t);
  }
  w.lastStepAt = t;
  // Beats land on their own second, not the next 5 s tick.
  runBeats(w, script, toMs);
  discover(w, toMs);
}
