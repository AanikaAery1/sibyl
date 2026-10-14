/**
 * Builds a tenant's world as it stands at scenario time 0, including the pre-rolled history
 * the demo script expects (shipper §1.1): three days of registry and config audit rows with
 * hourly anchors, the S-27 tier-1 PII agent parked in a forced hold (D22), the S-11 tool-loop
 * packet waiting in the On-call Operator's queue, and a few resolved alerts awaiting a verdict (D33).
 */
import "server-only";
import type { ApiKey, ContinuityPlan, FallbackChain, FallbackStep } from "@/lib/api/types";
import { PERSONAS, type TenantSlug } from "@/lib/auth/personas";
import { MINUTE, hexFor, idFor, iso, tokenFor } from "./core";
import {
  ALT_MODEL,
  ALT_PROVIDER,
  RTO_BY_TIER,
  TENANT_AGENTS,
  TENANT_META,
  agentId,
  modelId,
  providerId,
  tenantId,
  type AgentSpec,
} from "./fixtures";
import { appendAudit, makeAnchor, type AgentRt, type World } from "./world";
import { PACKETS } from "./packets";
import { seedActionPolicies } from "./action-gate";
import { completeFailover, createHandoffTask, fireAlert, openIncident, requestApproval, addStep } from "./ops";
import { applyRouting } from "./routing";

const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

function chainFor(w: World, spec: AgentSpec, id: string): FallbackChain {
  const chainId = idFor(`chain:${w.slug}:${spec.slug}`);
  const alt = ALT_PROVIDER[spec.provider];
  const steps: FallbackStep[] = [
    { id: idFor(`step:${chainId}:0`), position: 0, kind: "retry", risk: "low", max_attempts: 2, viable: true },
    { id: idFor(`step:${chainId}:1`), position: 1, kind: "alt_model_same_provider", provider_id: providerId(w.slug, spec.provider), model_id: modelId(w.slug, spec.provider, ALT_MODEL[spec.model] ?? spec.model), risk: "low", viable: true },
    { id: idFor(`step:${chainId}:2`), position: 2, kind: "alt_provider", provider_id: providerId(w.slug, alt.provider), model_id: modelId(w.slug, alt.provider, alt.model), credential_id: idFor(`cred:${w.slug}:${alt.provider}`), risk: "medium", viable: true },
  ];
  if (spec.tier === 1) {
    steps.push({ id: idFor(`step:${chainId}:3`), position: 3, kind: "backup_agent", backup_agent_id: agentId(w.slug, `${spec.slug}-standby`), risk: "high", viable: true });
  }
  steps.push({ id: idFor(`step:${chainId}:9`), position: steps.length, kind: "human_queue", risk: "low", params: { queue: "default" }, viable: true });
  return {
    id: chainId,
    agent_id: id,
    status: "approved",
    steps,
    note: spec.tier === 1 ? "Four-eyes approved: Platform Admin requested, On-call Operator approved" : null,
    requested_by_user_id: PERSONAS[0]?.userId ?? null,
    approved_by_user_id: spec.tier === 1 ? (PERSONAS[1]?.userId ?? null) : (PERSONAS[0]?.userId ?? null),
    approved_at: iso(w.anchorAt - 3 * DAY + 6 * HOUR),
    created_at: iso(w.anchorAt - 3 * DAY + 5 * HOUR),
  };
}

function planFor(spec: AgentSpec, id: string, chainId: string, at: number): ContinuityPlan {
  return {
    agent_id: id,
    rto_s: RTO_BY_TIER[spec.tier],
    rpo_s: spec.sdk ? 300 : 0,
    credential_mode: "vaulted",
    degraded_mode: spec.tier === 1 ? "queue_only" : spec.kind === "chatbot" ? "safe_no_tools" : "continue",
    inline_fallback: spec.tier !== 1,
    preemptive_mode: spec.tier === 1 ? "approval" : spec.tier === 2 ? "degrade_then_auto" : "auto",
    approval_timeout_s: 600,
    approval_timeout_policy: spec.pii && spec.tier === 1 ? "hold" : spec.tier === 1 ? "hold" : "fail_safe",
    fallback_chain_id: chainId,
    on_call_user_id: PERSONAS[1]?.userId ?? null,
    on_call_ref: "operator",
    budget_usd_month: (spec.costPerCall * spec.rpm * 60 * 24 * 31 * 1.4).toFixed(2),
    max_inflight: Math.max(4, Math.round(spec.rpm / 3)),
    rps_limit: Math.max(2, Math.round(spec.rpm / 10)),
    drill_schedule: spec.tier === 1 ? "monthly" : spec.tier === 2 ? "quarterly" : null,
    row_version: 3,
    updated_at: iso(at),
  };
}

export function newRuntime(w: World, spec: AgentSpec, createdAt: number, discovered = false): AgentRt {
  return {
    id: agentId(w.slug, spec.slug),
    tenant: w.slug,
    spec,
    lifecycle: discovered ? "discovered" : "monitored",
    createdAt,
    routing: {
      state: "active",
      target_kind: "primary",
      target_provider: null,
      target_model: null,
      current_step_id: null,
      canary_pct: 0,
      operator_hold_until: null,
      state_since: createdAt,
      pending_approval_id: null,
      last_transition_id: null,
    },
    served: [],
    anomalies: [],
    holdSuppressed: 0,
    lastBand: null,
    discovered,
  };
}

function emptyWorld(slug: TenantSlug, anchorAt: number): World {
  return {
    slug,
    anchorAt,
    tenantId: tenantId(slug),
    name: TENANT_META[slug].name,
    region: TENANT_META[slug].region,
    routingVersion: 40,
    seq: 0,
    providerStatus: { openai: [], anthropic: [], ollama: [] },
    agents: new Map(),
    plans: new Map(),
    chains: new Map(),
    transitions: [],
    incidents: new Map(),
    approvals: new Map(),
    alerts: new Map(),
    providerIncidents: new Map(),
    tasks: new Map(),
    packets: new Map(),
    killSwitches: new Map(),
    audit: [],
    anchors: [],
    exports: new Map(),
    apiKeys: [],
    tenantKeys: [],
    capturePolicies: [],
    users: [],
    memberships: [],
    outbox: [],
    idempotency: new Map(),
    completedDespiteFailure: 0,
    counter: 0,
    scriptIndex: 0,
    lastStepAt: anchorAt,
    pending: [],
    actionPolicies: new Map(),
    heldActions: new Map(),
    actionCounters: new Map(),
  };
}

function seedPeople(w: World, at: number): void {
  for (const p of PERSONAS) {
    const roles = p.bindings[w.slug];
    if (!roles) continue;
    w.users.push({ id: p.userId, email: p.email, display_name: p.fullName, status: "active", oidc_issuer_id: idFor(`issuer:${w.slug}`), last_login_at: iso(w.anchorAt - 40 * MINUTE), created_at: iso(at) });
    for (const role of roles) {
      const mid = idFor(`membership:${w.slug}:${p.id}:${role}`);
      w.memberships.push({ id: mid, user_id: p.userId, role_name: role, scope_kind: "tenant", scope_id: null, expires_at: null, created_at: iso(at) });
      appendAudit(w, { action: "membership.granted", actor_type: "system", resource_type: "membership", resource_id: mid, resource_ref: `${p.name}:${role}`, detail: { role_name: role, scope_kind: "tenant" } }, at + 1000);
    }
  }
}

function seedKeys(w: World, at: number): void {
  for (const purpose of ["payload", "credential", "config"] as const) {
    w.tenantKeys.push({ id: idFor(`tkey:${w.slug}:${purpose}:1`), purpose, version: 1, algorithm: "AES-256-GCM", kek_id: `kek/${w.region}/sibyl-dev`, state: "retired", activated_at: iso(at - 90 * DAY), retired_at: iso(at), shredded_at: null });
    w.tenantKeys.push({ id: idFor(`tkey:${w.slug}:${purpose}:2`), purpose, version: 2, algorithm: "AES-256-GCM", kek_id: `kek/${w.region}/sibyl-dev`, state: "active", activated_at: iso(at), retired_at: null, shredded_at: null });
  }
  if (w.slug === "sandbox") return;
  const policyId = idFor(`capture:${w.slug}:1`);
  w.capturePolicies.push({ id: policyId, scope_kind: "tenant", agent_id: null, capture_mode: "full", redaction_profile_id: idFor("redaction:secrets_only"), payload_retention_days: 30, max_payload_bytes: 262144, header_allowlist: [], consequences_version: "2026-10", version_no: 1, superseded_by: null, created_at: iso(at) });
  appendAudit(w, { action: "capture.policy_set", actor_type: "human", actor_id: PERSONAS[0]?.userId, resource_type: "capture_policy", resource_id: policyId, detail: { capture_mode: "full", payload_retention_days: 30, scrub: "secrets_only (always on)" } }, at + 2000);
  const keys: [string, ApiKey["scopes"], string | null][] = [
    ["gateway-prod", ["gateway:proxy", "routing:read"], null],
    ["claims-triage-sdk", ["ingest:write", "routing:read", "handoff:write"], agentId(w.slug, "claims-triage")],
    ["break-glass-1", ["killswitch:pull"], null],
  ];
  for (const [name, scopes, bound] of keys) {
    if (bound && !w.slug.startsWith("meridian")) continue;
    const id = idFor(`apikey:${w.slug}:${name}`);
    w.apiKeys.push({ id, name, env: "live", prefix: tokenFor(`prefix:${id}`, 12), scopes, agent_id: bound, status: "active", expires_at: iso(at + 365 * DAY), last_used_at: name === "break-glass-1" ? null : iso(w.anchorAt - 2 * MINUTE), last_used_ip_hash: name === "break-glass-1" ? null : hexFor(`ip:${id}`, 16), rotated_from_id: null, rotation_grace_until: null, created_by: PERSONAS[0]?.userId ?? null, created_at: iso(at + 3000) });
    appendAudit(w, { action: "api_key.created", actor_type: "human", actor_id: PERSONAS[0]?.userId, resource_type: "api_key", resource_id: id, resource_ref: name, detail: { scopes, agent_id: bound }, severity: scopes.includes("killswitch:pull") ? "warning" : "info" }, at + 3000);
  }
}

function seedAgents(w: World, at: number): void {
  TENANT_AGENTS[w.slug].forEach((spec, i) => {
    const created = at + 10 * MINUTE + i * 7 * MINUTE;
    const rt = newRuntime(w, spec, created);
    w.agents.set(rt.id, rt);
    const chain = chainFor(w, spec, rt.id);
    w.chains.set(rt.id, chain);
    w.plans.set(rt.id, planFor(spec, rt.id, chain.id, created + 2 * HOUR));
    appendAudit(w, { action: "asset.created", actor_type: "human", actor_id: PERSONAS[0]?.userId, resource_type: "agent", resource_id: rt.id, resource_ref: spec.slug, detail: { tier: spec.tier, risk_class: spec.risk_class, provider: spec.provider, model: spec.model, fail_mode: spec.fail_mode } }, created);
    appendAudit(w, { action: "config.changed", actor_type: "human", actor_id: PERSONAS[0]?.userId, resource_type: "continuity_plan", resource_id: rt.id, resource_ref: spec.slug, detail: { fallback_chain_id: chain.id, rto_s: RTO_BY_TIER[spec.tier], steps: chain.steps.map((s) => s.kind) } }, created + 2 * HOUR);
    appendAudit(w, { action: "asset.approved", actor_type: "human", actor_id: (spec.tier === 1 ? PERSONAS[1] : PERSONAS[0])?.userId, resource_type: "agent", resource_id: rt.id, resource_ref: spec.slug, detail: { to_stage: "monitored", four_eyes: spec.tier === 1 } }, created + 3 * HOUR);
  });
}

/** Resolved history so the alert screens are not empty and the D33 queue has entries. */
function seedAlertHistory(w: World): void {
  const pick = (slug: string): AgentRt | undefined => w.agents.get(agentId(w.slug, slug));
  const history: [string, string, "warning" | "info", number, "tp" | "fp" | "unsure" | null][] = [
    ["freight-pricer", "p95_latency", "warning", 26, "fp"],
    ["dispatch-planner", "error_rate", "warning", 21, "tp"],
    ["ticket-router", "latency_trend", "info", 19, null],
    ["report-writer", "p95_latency", "info", 15, null],
    ["kb-search", "quality_proxy", "warning", 11, "unsure"],
    ["route-optimizer", "fallback_pressure", "info", 7, null],
    ["returns-agent", "error_rate", "warning", 5, "tp"],
  ];
  for (const [slug, rule, sev, hoursAgo, verdict] of history) {
    const rt = pick(slug);
    if (!rt) continue;
    const at = w.anchorAt - hoursAgo * HOUR;
    const alert = fireAlert(w, rt, { rule, severity: sev, at });
    const resolvedAt = at + 18 * MINUTE;
    w.alerts.set(alert.id, { ...alert, state: "resolved", resolved_at: iso(resolvedAt), verdict, verdict_note: verdict === "fp" ? "Batch job at month-end; expected" : null, verdict_wanted: verdict === null, health_snapshot: { score: 71, band: "watch" } });
    if (verdict) {
      appendAudit(w, { action: "alert.labelled", actor_type: "human", actor_id: PERSONAS[1]?.userId, resource_type: "alert", resource_id: alert.id, resource_ref: slug, detail: { verdict } }, resolvedAt + 30 * MINUTE);
    }
  }
}

/** Two tasks completed yesterday: the "completed despite failure" counter starts at 2. */
function seedCompletedTasks(w: World): void {
  const done: [string, string][] = [["claims-triage", "claims-triage-outage"], ["customer-chat", "customer-chat-outage"]];
  for (const [i, [slug, key]] of done.entries()) {
    const rt = w.agents.get(agentId(w.slug, slug));
    const tpl = PACKETS[key];
    if (!rt || !tpl) continue;
    const at = w.anchorAt - (20 - i * 3) * HOUR;
    const task = createHandoffTask(w, rt, null, tpl, at);
    w.tasks.set(task.id, { ...task, state: "completed", outcome: "resolved", outcome_note: "Completed manually by operator", claimed_by: PERSONAS[1]?.userId ?? null, claimed_at: iso(at + 4 * MINUTE), completed_at: iso(at + 19 * MINUTE) });
    appendAudit(w, { action: "handoff.completed", actor_type: "human", actor_id: PERSONAS[1]?.userId, resource_type: "handoff_task", resource_id: task.id, detail: { outcome: "resolved" } }, at + 19 * MINUTE);
    w.completedDespiteFailure += 1;
  }
}

/** S-27: tier-1 PII agent, approval timed out → worker forced hold (D22). */
function preRollForcedHold(w: World): void {
  const rt = w.agents.get(agentId(w.slug, "kyc-verifier"));
  if (!rt) return;
  const start = w.anchorAt - 22 * MINUTE;
  rt.anomalies = [{ kind: "latency", from: start - 6 * MINUTE, to: null }];
  const alert = fireAlert(w, rt, { rule: "latency_trend", severity: "warning", at: start });
  const inc = openIncident(w, rt, { kind: "preemptive", actor_kind: "rule", alertId: alert.id, rule_codes: ["latency_trend", "p95_latency"], reason: "Leading rules predict latency degradation inside 15 minutes; tier-1 pre-emptive move needs approval (D13)", at: start + 500 });
  requestApproval(w, inc, rt, { action: "preemptive_failover", byKind: "rule", evidence: { predicted: "latency_degradation in ~15 m", source: "rules/v1", confidence: "medium", contributing_rules: ["latency_trend"] }, at: start + 600 });
  const expiresAt = start + 600 + 600_000;
  const approvalId = inc.approval_id;
  const approval = approvalId ? w.approvals.get(approvalId) : undefined;
  if (approval && approvalId) w.approvals.set(approvalId, { ...approval, state: "expired", decided_at: iso(expiresAt) });
  appendAudit(w, { action: "approval.expired", actor_type: "system", resource_type: "approval", resource_id: approvalId, resource_ref: rt.spec.slug, detail: { timeout_policy: "fail_safe", timeout_policy_applied: "hold_forced_d22", reason: "Tier-1 agent with PII exposure: hold is forced regardless of the stored policy" }, severity: "warning" }, expiresAt);
  const tr = applyRouting(w, rt, { to: "degraded", trigger: "approval_timeout", actor_kind: "system", approval_id: approvalId, failover_id: inc.id, reason: "Approval expired; hold forced for a tier-1 PII agent (D22)", at: expiresAt + 100 });
  inc.transition_ids = [...inc.transition_ids, tr.id];
  addStep(inc, "done", expiresAt + 200, "Approval expired; held in degraded (hold_forced_d22)");
  inc.state = "cancelled";
  inc.finished_at = expiresAt + 200;
  inc.error = "approval_expired";
}

/** S-11: tool loop on order-intake → handoff to the human queue with a checkpoint packet. */
function preRollToolLoop(w: World): void {
  const rt = w.agents.get(agentId(w.slug, "order-intake"));
  const tpl = PACKETS["order-intake-loop"];
  if (!rt || !tpl) return;
  const start = w.anchorAt - 7 * MINUTE;
  rt.anomalies = [{ kind: "tool_loop", from: start - 5 * MINUTE, to: start + 2000 }];
  const alert = fireAlert(w, rt, { rule: "tool_loop", severity: "warning", at: start });
  const inc = openIncident(w, rt, { kind: "failover", actor_kind: "rule", alertId: alert.id, rule_codes: ["tool_loop"], reason: "Tool-call loop detected (37 identical slot searches in 5 minutes); work handed to a person", at: start + 400 });
  completeFailover(w, inc, rt, { target: { kind: "human_queue", provider: null, model: null, label: "human queue" }, trigger: "rule", actor_kind: "rule", at: start + 500, packet: tpl });
}

export function buildWorld(slug: TenantSlug, anchorAt: number): World {
  const w = emptyWorld(slug, anchorAt);
  const genesis = anchorAt - 3 * DAY;
  appendAudit(w, { action: "audit.genesis", actor_type: "system", resource_type: "tenant", resource_id: w.tenantId, resource_ref: slug, detail: { chain: "sha256", canonicaliser: "rfc8785" } }, genesis);
  appendAudit(w, { action: "tenant.created", actor_type: "system", resource_type: "tenant", resource_id: w.tenantId, resource_ref: slug, detail: { region_declared: w.region } }, genesis + 1000);
  seedPeople(w, genesis + 5000);
  seedKeys(w, genesis + HOUR);
  makeAnchor(w, "hourly", genesis + 2 * HOUR);
  if (slug !== "sandbox") {
    seedAgents(w, genesis + 3 * HOUR);
    makeAnchor(w, "hourly", genesis + DAY);
    seedCompletedTasks(w);
    seedAlertHistory(w);
    seedActionPolicies(w, genesis + 4 * HOUR);
    makeAnchor(w, "hourly", anchorAt - 2 * HOUR);
  }
  if (slug === "meridian") {
    preRollForcedHold(w);
    preRollToolLoop(w);
    makeAnchor(w, "hourly", anchorAt - 60_000);
  }
  return w;
}

