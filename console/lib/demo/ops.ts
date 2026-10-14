/**
 * Shared operations used by the scripted scenario and by user actions: alerts, the failover
 * saga (validate → check_viability → write_routing → create_handoff_tasks →
 * mark_alert_actioned → done), approvals and handoff tasks. Each writes its audit row(s) and
 * outbox event(s) at the same instant, like the real worker's single transaction.
 */
import "server-only";
import type { Alert, AlertSeverity, ApprovalAction, Fidelity, FailureMode } from "@/lib/api/types";
import { MINUTE, iso } from "./core";
import { ALT_MODEL, ALT_PROVIDER, RTO_BY_TIER, providerId, type ProviderSlug } from "./fixtures";
import { healthDocAt, providerStatusAt } from "./health";
import { buildPacket, type PacketTemplate } from "./packets";
import { applyRouting, type RouteTarget } from "./routing";
import { appendAudit, emit, nextId, type AgentRt, type IncidentRec, type World } from "./world";

export function fireAlert(
  w: World,
  rt: AgentRt | null,
  o: { rule: string; severity: AlertSeverity; provider?: ProviderSlug; at: number; providerIncidentId?: string | null },
): Alert {
  const id = nextId(w, "alert");
  const hs = rt ? healthDocAt(w, rt, o.at) : null;
  const alert: Alert = {
    id,
    agent_id: rt?.id ?? null,
    provider_id: o.provider ? providerId(w.slug, o.provider) : rt ? providerId(w.slug, rt.spec.provider) : null,
    rule_code: o.rule,
    severity: o.severity,
    state: "open",
    fired_at: iso(o.at),
    acked_at: null,
    resolved_at: null,
    silenced_until: null,
    verdict: null,
    verdict_note: null,
    hold_suppressed_count: 0,
    health_snapshot_id: hs?.health_snapshot_id ?? null,
    provider_incident_id: o.providerIncidentId ?? null,
    incident_id: null,
    health_snapshot: hs ? { score: hs.score, band: hs.status, factors: hs.factors } : null,
  };
  w.alerts.set(id, alert);
  appendAudit(
    w,
    {
      action: "alert.fired",
      actor_type: "rule",
      resource_type: "alert",
      resource_id: id,
      resource_ref: rt?.spec.slug ?? o.provider ?? null,
      detail: { rule_code: o.rule, severity: o.severity, agent_id: rt?.id ?? null, score: hs?.score ?? null },
      severity: o.severity === "critical" ? "warning" : "info",
    },
    o.at,
  );
  emit(
    w,
    "alert.fired",
    { alert_id: id, agent_id: rt?.id ?? null, provider_id: alert.provider_id, rule_code: o.rule, severity: o.severity, state: "open", provider_incident_id: alert.provider_incident_id },
    o.at,
  );
  return alert;
}

export function resolveAlert(w: World, alertId: string, at: number, verdictWanted: boolean): void {
  const alert = w.alerts.get(alertId);
  if (!alert || alert.state === "resolved") return;
  w.alerts.set(alertId, { ...alert, state: "resolved", resolved_at: iso(at), verdict_wanted: verdictWanted });
  emit(w, "alert.resolved", { alert_id: alertId, agent_id: alert.agent_id, rule_code: alert.rule_code, severity: alert.severity, state: "resolved" }, at);
}

interface OpenIncident {
  kind: IncidentRec["kind"];
  actor_kind: IncidentRec["actor_kind"];
  user?: string | null;
  alertId?: string | null;
  rule_codes?: string[];
  reason: string;
  at: number;
}

export function openIncident(w: World, rt: AgentRt, o: OpenIncident): IncidentRec {
  const id = nextId(w, "incident");
  const inc: IncidentRec = {
    id,
    agent_id: rt.id,
    kind: o.kind,
    state: "running",
    step: "validate",
    actor_kind: o.actor_kind,
    requested_by_user_id: o.user ?? null,
    trigger_alert_id: o.alertId ?? null,
    rule_codes: o.rule_codes ?? [],
    from_state: rt.routing.state,
    to_state: null,
    chosen_step: null,
    approval_id: null,
    transition_ids: [],
    steps: [{ step: "validate", at: o.at, note: "Preconditions hold; no other saga in flight" }],
    handoff_task_ids: [],
    created_at: o.at,
    finished_at: null,
    reason: o.reason,
    error: null,
    health_snapshot: healthDocAt(w, rt, o.at),
  };
  w.incidents.set(id, inc);
  if (o.alertId) {
    const alert = w.alerts.get(o.alertId);
    if (alert) w.alerts.set(o.alertId, { ...alert, incident_id: id });
  }
  appendAudit(
    w,
    {
      action: o.kind === "kill" ? "killswitch.pulled" : o.actor_kind === "human" ? "override.by_human" : "failover.proposed",
      actor_type: o.actor_kind,
      actor_id: o.user ?? null,
      resource_type: "incident",
      resource_id: id,
      resource_ref: rt.spec.slug,
      reason: o.reason,
      detail: { kind: o.kind, agent_id: rt.id, rule_codes: o.rule_codes ?? [], alert_id: o.alertId ?? null },
      severity: "warning",
    },
    o.at,
  );
  emitIncident(w, inc, rt);
  return inc;
}

export function emitIncident(w: World, inc: IncidentRec, rt: AgentRt): void {
  emit(
    w,
    "incident.updated",
    { incident_id: inc.id, agent_id: inc.agent_id, kind: inc.kind, state: inc.state, step: inc.step, routing_state: rt.routing.state, transition_id: inc.transition_ids.at(-1) ?? null },
    inc.steps.at(-1)?.at ?? inc.created_at,
  );
}

/** Pick the first viable chain step for a failover, skipping steps on a provider that is down. */
export function chooseTarget(w: World, rt: AgentRt, at: number, preferProvider = false): RouteTarget & { label: string } {
  const chain = w.chains.get(rt.id);
  const primaryDown = providerStatusAt(w, rt.spec.provider, at) !== "operational";
  for (const step of chain?.steps ?? []) {
    if (step.kind === "alt_model_same_provider" && !primaryDown && !preferProvider) {
      const model = ALT_MODEL[rt.spec.model] ?? rt.spec.model;
      return { kind: "model", provider: rt.spec.provider, model, step_id: step.id, label: `${rt.spec.provider}/${model}` };
    }
    if (step.kind === "alt_provider") {
      const alt = ALT_PROVIDER[rt.spec.provider];
      if (providerStatusAt(w, alt.provider, at) === "operational") {
        return { kind: "model", provider: alt.provider, model: alt.model, step_id: step.id, label: `${alt.provider}/${alt.model}` };
      }
    }
    if (step.kind === "human_queue") return { kind: "human_queue", provider: null, model: null, step_id: step.id, label: "human queue" };
  }
  return { kind: "human_queue", provider: null, model: null, label: "human queue" };
}

export function addStep(inc: IncidentRec, step: IncidentRec["steps"][number]["step"], at: number, note: string): void {
  inc.steps = [...inc.steps, { step, at, note }];
  if (step !== "waiting_approval") inc.step = step;
}

interface CompleteFailover {
  target: RouteTarget & { label: string };
  trigger: "rule" | "approval" | "operator" | "approval_timeout";
  actor_kind: IncidentRec["actor_kind"];
  user?: string | null;
  approvalId?: string | null;
  at: number;
  packet?: PacketTemplate | null;
}

/** write_routing → create_handoff_tasks → mark_alert_actioned → done, spaced a few hundred ms apart. */
export function completeFailover(w: World, inc: IncidentRec, rt: AgentRt, o: CompleteFailover): void {
  addStep(inc, "check_viability", o.at + 150, `Chosen step: ${o.target.label}`);
  inc.chosen_step = { kind: o.target.kind, provider: o.target.provider, model: o.target.model, step_id: o.target.step_id ?? null };
  const tr = applyRouting(w, rt, {
    to: "failed_over",
    trigger: o.trigger,
    actor_kind: o.actor_kind === "human" ? "human" : o.actor_kind,
    actor_user_id: o.user ?? null,
    target: o.target,
    rule_codes: inc.rule_codes,
    alert_ids: inc.trigger_alert_id ? [inc.trigger_alert_id] : [],
    approval_id: o.approvalId ?? null,
    failover_id: inc.id,
    reason: inc.reason,
    at: o.at + 400,
  });
  inc.transition_ids = [...inc.transition_ids, tr.id];
  inc.to_state = "failed_over";
  addStep(inc, "write_routing", o.at + 400, `routing_apply → failed_over (${o.target.label}), version ${tr.routing_version}`);
  appendAudit(
    w,
    { action: "failover.started", actor_type: o.actor_kind, actor_id: o.user ?? null, resource_type: "incident", resource_id: inc.id, resource_ref: rt.spec.slug, detail: { target: o.target.label, transition_id: tr.id } },
    o.at + 410,
  );
  if (o.packet) {
    const task = createHandoffTask(w, rt, inc, o.packet, o.at + 700);
    addStep(inc, "create_handoff_tasks", o.at + 700, `1 in-flight task handed off (${task.fidelity})`);
  } else {
    addStep(inc, "create_handoff_tasks", o.at + 700, "No in-flight tasks to hand off");
  }
  addStep(inc, "mark_alert_actioned", o.at + 800, inc.trigger_alert_id ? "Trigger alert linked to this incident" : "No trigger alert");
  addStep(inc, "done", o.at + 900, "Saga complete");
  inc.state = "done";
  inc.finished_at = o.at + 900;
  appendAudit(
    w,
    { action: "failover.completed", actor_type: o.actor_kind, actor_id: o.user ?? null, resource_type: "incident", resource_id: inc.id, resource_ref: rt.spec.slug, detail: { target: o.target.label, rto_s: w.plans.get(rt.id)?.rto_s ?? RTO_BY_TIER[rt.spec.tier], elapsed_s: Math.round((o.at + 900 - inc.created_at) / 1000) } },
    o.at + 900,
  );
  emitIncident(w, inc, rt);
}

export function requestApproval(
  w: World,
  inc: IncidentRec,
  rt: AgentRt,
  o: { action: ApprovalAction; byKind: "rule" | "human"; user?: string | null; evidence: Record<string, unknown>; at: number },
): void {
  const plan = w.plans.get(rt.id);
  const id = nextId(w, "approval");
  const timeout = plan?.approval_timeout_s ?? 600;
  w.approvals.set(id, {
    id,
    incident_id: inc.id,
    agent_id: rt.id,
    requested_action: o.action,
    tier: rt.spec.tier,
    requested_by_kind: o.byKind,
    requested_by_user_id: o.user ?? null,
    alert_id: inc.trigger_alert_id,
    evidence: o.evidence,
    risk: rt.spec.pii ? "pii" : null,
    expires_at: iso(o.at + timeout * 1000),
    timeout_policy: rt.spec.pii && rt.spec.tier === 1 ? "hold" : (plan?.approval_timeout_policy ?? "hold"),
    state: "pending",
    decided_by_user_id: null,
    decided_at: null,
    decision_reason: null,
  });
  inc.approval_id = id;
  inc.state = "waiting_approval";
  addStep(inc, "waiting_approval", o.at + 200, `Approval required: ${o.action.replaceAll("_", " ")} on a tier-${rt.spec.tier} agent`);
  const tr = applyRouting(w, rt, {
    to: "awaiting_approval",
    trigger: o.byKind === "rule" ? "rule" : "operator",
    actor_kind: o.byKind === "rule" ? "rule" : "human",
    actor_user_id: o.user ?? null,
    rule_codes: inc.rule_codes,
    approval_id: id,
    failover_id: inc.id,
    reason: inc.reason,
    at: o.at + 250,
  });
  inc.transition_ids = [...inc.transition_ids, tr.id];
  appendAudit(
    w,
    { action: "approval.requested", actor_type: o.byKind, actor_id: o.user ?? null, resource_type: "approval", resource_id: id, resource_ref: rt.spec.slug, detail: { requested_action: o.action, tier: rt.spec.tier, incident_id: inc.id, expires_in_s: timeout }, severity: "warning" },
    o.at + 260,
  );
  emit(w, "approval.requested", { approval_id: id, incident_id: inc.id, agent_id: rt.id, tier: rt.spec.tier, requested_action: o.action, expires_at: iso(o.at + timeout * 1000), state: "pending" }, o.at + 260);
  emitIncident(w, inc, rt);
}

export function createHandoffTask(w: World, rt: AgentRt, inc: IncidentRec | null, tpl: PacketTemplate, at: number) {
  const id = nextId(w, "task");
  const plan = w.plans.get(rt.id);
  const rto = plan?.rto_s ?? RTO_BY_TIER[rt.spec.tier];
  const packet = buildPacket(w, rt, tpl, { taskId: id, at, rtoS: rto, transitionId: inc?.transition_ids.at(-1) ?? null });
  const task = {
    id,
    agent_id: rt.id,
    incident_id: inc?.id ?? null,
    state: "queued" as const,
    priority: rt.spec.tier,
    summary: packet.summary ?? packet.goal,
    failure_mode: packet.reason.failure_mode as FailureMode,
    fidelity: packet.fidelity as Fidelity,
    deadline_at: packet.deadline.at,
    claimed_by: null,
    created_at: iso(at),
    accountable_user_id: null,
    lock_expires_at: null,
    outcome: null,
    outcome_note: null,
    next_action: packet.next_action,
    rating: null,
    packet_sha256: null,
    claimed_at: null,
    completed_at: null,
  };
  w.tasks.set(id, task);
  w.packets.set(id, packet);
  if (inc) inc.handoff_task_ids = [...inc.handoff_task_ids, id];
  appendAudit(
    w,
    { action: "handoff.created", actor_type: inc?.actor_kind === "human" ? "human" : "rule", resource_type: "handoff_task", resource_id: id, resource_ref: rt.spec.slug, detail: { fidelity: task.fidelity, failure_mode: task.failure_mode, incident_id: inc?.id ?? null, priority: task.priority } },
    at,
  );
  emit(w, "handoff.queued", { task_id: id, agent_id: rt.id, priority: task.priority, deadline_at: task.deadline_at, state: "queued" }, at);
  return task;
}

export const holdFor = (at: number): number => at + 30 * MINUTE;
