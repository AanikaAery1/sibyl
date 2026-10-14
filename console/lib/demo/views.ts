/**
 * Projections from the demo world to the exact OpenAPI response shapes.
 */
import "server-only";
import { groupIdFor } from "./action-gate-seed";
import type {
  Agent,
  AgentSummary,
  FleetHealth,
  Incident,
  IncidentActionName,
  Provider,
  RoutingState,
  RoutingTransition,
} from "@/lib/api/types";
import type { BffPrincipal } from "@/lib/bff/principal-types";
import { iso } from "./core";
import { PROVIDERS, modelId, providerId } from "./fixtures";
import { healthDocAt, providerStatusAt } from "./health";
import { discoveryOf, isProvisional } from "./runs";
import type { AgentRt, IncidentRec, TransitionRec, World } from "./world";

/** The contract's RoutingTransition (drops the console-side agent_id and snapshot). */
export function stripTransition(t: TransitionRec): RoutingTransition {
  const copy: Partial<TransitionRec> = { ...t };
  delete copy.agent_id;
  delete copy.health_snapshot;
  return copy as RoutingTransition;
}

export function routingState(w: World, rt: AgentRt): RoutingState {
  const r = rt.routing;
  const last = r.last_transition_id ? w.transitions.find((t) => t.id === r.last_transition_id) : undefined;
  const pending = r.pending_approval_id ? w.approvals.get(r.pending_approval_id) : undefined;
  return {
    agent_id: rt.id,
    state: r.state,
    target_kind: r.target_kind,
    target_provider_id: r.target_provider ? providerId(w.slug, r.target_provider) : null,
    target_model_id: r.target_provider && r.target_model ? modelId(w.slug, r.target_provider, r.target_model) : null,
    target_agent_id: null,
    current_step_id: r.current_step_id,
    canary_pct: r.canary_pct,
    routing_version: w.routingVersion,
    operator_hold_until: r.operator_hold_until ? iso(r.operator_hold_until) : null,
    state_since: iso(r.state_since),
    last_transition: last ? stripTransition(last) : null,
    pending_approval: pending && pending.state === "pending" ? pending : null,
  };
}

/** Console extension fields ride alongside the contract under `x_console` (never sent live). */
export interface ConsoleAgentExtras {
  provider: string;
  model: string;
  served_provider: string | null;
  served_model: string | null;
  process: string;
  /** Demo agent group (the business process); live agents carry `agent_group_id` instead. */
  group_id: string;
  description: string;
  fidelity: "checkpoint" | "request_only";
  pii: boolean;
  hold_suppressed_count: number;
}

export function agentSummary(w: World, rt: AgentRt, t: number): AgentSummary & { x_console: ConsoleAgentExtras } {
  const h = healthDocAt(w, rt, t);
  const plan = w.plans.get(rt.id);
  return {
    id: rt.id,
    slug: rt.spec.slug,
    name: rt.spec.name,
    kind: rt.spec.kind,
    tier: rt.spec.tier,
    risk_class: rt.spec.risk_class,
    lifecycle: rt.lifecycle,
    fail_mode: rt.spec.fail_mode,
    // Live: a discovered agent stays provisional until an admin confirms it (claim); demo keeps the health flag otherwise.
    is_provisional: rt.discovered ? isProvisional(w, rt) : h.provisional.flag,
    ...discoveryOf(w, rt),
    agent_group_id: null,
    routing: { state: rt.routing.state, target_kind: rt.routing.target_kind, operator_hold_until: rt.routing.operator_hold_until ? iso(rt.routing.operator_hold_until) : null },
    health: { band: h.status, score: h.score, provisional: h.provisional.flag, evaluated_at: h.computed_at },
    continuity: { rto_s: plan?.rto_s ?? 0, has_plan: Boolean(plan) },
    x_console: extras(rt),
  };
}

function extras(rt: AgentRt): ConsoleAgentExtras {
  const served = rt.served.at(-1);
  const servedProvider = served ? served.provider : rt.spec.provider;
  return {
    provider: rt.spec.provider,
    model: rt.spec.model,
    served_provider: rt.routing.state === "killed" || rt.routing.state === "quarantined" ? null : servedProvider,
    served_model: served ? served.model : rt.spec.model,
    process: rt.spec.process,
    group_id: groupIdFor(rt.tenant, rt.spec.process),
    description: rt.spec.description,
    fidelity: rt.spec.sdk ? "checkpoint" : "request_only",
    pii: rt.spec.pii,
    hold_suppressed_count: rt.holdSuppressed,
  };
}

export function agentDetail(w: World, rt: AgentRt, t: number): Agent & { x_console: ConsoleAgentExtras } {
  const summary = agentSummary(w, rt, t);
  return {
    ...summary,
    description: rt.spec.description,
    framework: rt.spec.framework,
    owner_user_id: null,
    business_process_id: null,
    cost_center: `CC-${rt.spec.process.slice(0, 3).toUpperCase()}-01`,
    tags: [rt.spec.provider, ...(rt.spec.pii ? ["pii"] : []), rt.spec.sdk ? "sdk" : "gateway-only"],
    current_version: null,
    identity: null,
    continuity_plan_etag: `"${w.plans.get(rt.id)?.row_version ?? 0}"`,
    created_at: iso(rt.createdAt),
    updated_at: iso(rt.routing.state_since),
  };
}

export function availableActions(w: World, inc: IncidentRec, rt: AgentRt, p: BffPrincipal, t: number): IncidentActionName[] {
  const has = (s: string): boolean => p.scopes.includes(s as BffPrincipal["scopes"][number]);
  const out: IncidentActionName[] = [];
  const approval = inc.approval_id ? w.approvals.get(inc.approval_id) : undefined;
  if (approval?.state === "pending" && has("approvals:decide")) out.push("approve", "deny");
  const lastAutomated = [...w.transitions].reverse().find((tr) => tr.agent_id === rt.id && (tr.actor_kind === "rule" || tr.actor_kind === "policy") && !tr.undone_by && tr.to_state !== "awaiting_approval");
  if (lastAutomated && inc.transition_ids.includes(lastAutomated.id) && rt.routing.state !== "killed" && has("routing:override")) out.push("undo");
  if (rt.routing.operator_hold_until && rt.routing.operator_hold_until > t && has("routing:override") && (p.roles.includes("owner") || p.roles.includes("security_admin"))) out.push("clear_hold");
  if (rt.routing.state === "failed_over" && inc.state === "done" && has("routing:override")) out.push("fail_back");
  if ((rt.routing.state === "quarantined" && has("quarantine:act")) || (rt.routing.state === "killed" && has("killswitch:release"))) out.push("release");
  if ((inc.state === "pending" || inc.state === "waiting_approval") && has("routing:override")) out.push("cancel");
  return out;
}

export function incidentView(w: World, inc: IncidentRec, p: BffPrincipal, t: number): Incident & { x_console: Record<string, unknown> } {
  const rt = w.agents.get(inc.agent_id);
  if (!rt) throw new Error(`incident ${inc.id} references unknown agent`);
  const transitions = w.transitions.filter((tr) => inc.transition_ids.includes(tr.id));
  const last = transitions.at(-1);
  const alert = inc.trigger_alert_id ? w.alerts.get(inc.trigger_alert_id) : undefined;
  const plan = w.plans.get(rt.id);
  return {
    id: inc.id,
    agent_id: inc.agent_id,
    kind: inc.kind,
    state: inc.state,
    step: inc.step,
    priority: rt.spec.tier === 1 ? "immediate" : "normal",
    actor_kind: inc.actor_kind,
    requested_by_user_id: inc.requested_by_user_id,
    trigger_alert_id: inc.trigger_alert_id,
    rule_codes: inc.rule_codes,
    from_state: inc.from_state,
    to_state: inc.to_state,
    chosen_step: inc.chosen_step,
    approval: inc.approval_id ? (w.approvals.get(inc.approval_id) ?? null) : null,
    transition: last ? stripTransition(last) : null,
    routing: routingState(w, rt),
    alert: alert ? { ...alert } : null,
    health_evidence: inc.health_snapshot ? { ...inc.health_snapshot } : null,
    handoff_tasks: inc.handoff_task_ids.map((id) => w.tasks.get(id)).filter((x) => x !== undefined).map((task) => ({ id: task.id, agent_id: task.agent_id, incident_id: task.incident_id, state: task.state, priority: task.priority, summary: task.summary, failure_mode: task.failure_mode, fidelity: task.fidelity, deadline_at: task.deadline_at, claimed_by: task.claimed_by, created_at: task.created_at })),
    undo_plan: last && last.actor_kind !== "human" ? { inverse_to_state: last.from_state, hold_minutes: 30 } : null,
    step_results: Object.fromEntries(inc.steps.map((s, i) => [`${i}:${s.step}`, { at: iso(s.at), note: s.note }])),
    operator_hold_until: rt.routing.operator_hold_until ? iso(rt.routing.operator_hold_until) : null,
    error: inc.error,
    available_actions: availableActions(w, inc, rt, p, t),
    created_at: iso(inc.created_at),
    finished_at: inc.finished_at ? iso(inc.finished_at) : null,
    x_console: {
      agent_slug: rt.spec.slug,
      agent_name: rt.spec.name,
      tier: rt.spec.tier,
      reason: inc.reason,
      rto_s: plan?.rto_s ?? 0,
      rpo_s: plan?.rpo_s ?? 0,
      checkpoint_age_s: rt.spec.sdk ? 95 : null,
      steps: inc.steps.map((s) => ({ step: s.step, at: iso(s.at), note: s.note })),
      transitions: transitions.map(stripTransition),
      hold_suppressed_count: rt.holdSuppressed,
    },
  };
}

export function fleetHealth(w: World, t: number): FleetHealth {
  const byBand: Record<string, number> = { healthy: 0, watch: 0, degraded: 0, failed: 0 };
  const byState: Record<string, number> = {};
  for (const rt of w.agents.values()) {
    const h = healthDocAt(w, rt, t);
    byBand[h.status] = (byBand[h.status] ?? 0) + 1;
    byState[rt.routing.state] = (byState[rt.routing.state] ?? 0) + 1;
  }
  return {
    counts_by_band: byBand,
    counts_by_routing_state: byState,
    open_alerts: [...w.alerts.values()].filter((a) => a.state !== "resolved").length,
    open_incidents: [...w.incidents.values()].filter((i) => i.state !== "done" && i.state !== "cancelled" && i.state !== "failed").length + [...w.agents.values()].filter((a) => a.routing.state === "failed_over" || a.routing.state === "failing_back").length,
    pending_approvals: [...w.approvals.values()].filter((a) => a.state === "pending").length,
    queue_depth: [...w.tasks.values()].filter((x) => x.state === "queued" || x.state === "claimed").length,
    provider_incidents: [...w.providerIncidents.values()].filter((p) => p.state !== "resolved"),
  };
}

export function providersView(w: World, t: number): Provider[] {
  return PROVIDERS.map((p) => {
    const status = providerStatusAt(w, p.slug, t);
    return {
      id: providerId(w.slug, p.slug),
      slug: p.slug,
      name: p.name,
      provider_kind: p.provider_kind,
      dialect: p.dialect,
      base_url: p.base_url,
      status_feed_url: p.slug === "ollama" ? null : `https://status.${p.slug}.com/api/v2/summary.json`,
      allowlist_basis: "dns:public",
      is_enabled: true,
      latest_status: { provider_id: providerId(w.slug, p.slug), status, observed_at: iso(t), source: p.slug === "ollama" ? "probe" : "status_feed" },
    };
  });
}
