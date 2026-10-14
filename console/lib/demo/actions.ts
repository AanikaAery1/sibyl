/**
 * Human actions in demo mode, enforcing the same rules the API does: scopes, step-up,
 * four-eyes (409 self_approval), mandatory verdicts (422 verdict_required), the D21 undo hold,
 * capture policy before keys (409 capture_policy_missing), and the 409 vocabulary of §6.4.
 */
import "server-only";
import { ProblemError, forbidden, notFound } from "@/lib/api/problem";
import type {
  AlertAction,
  HandoffTaskAction,
  IncidentActionBody,
  IncidentCreate,
  KillSwitch,
  KillSwitchCreate,
  Scope,
} from "@/lib/api/types";
import type { BffPrincipal } from "@/lib/bff/principal-types";
import { MINUTE, iso } from "./core";
import { providerId } from "./fixtures";
import { chooseTarget, completeFailover, emitIncident, holdFor, openIncident, requestApproval, addStep } from "./ops";
import { PACKETS } from "./packets";
import { applyRouting, PRIMARY } from "./routing";
import { appendAudit, emit, nextId, type AgentRt, type IncidentRec, type World } from "./world";

export function requireScope(p: BffPrincipal, scope: Scope): void {
  if (!p.scopes.includes(scope)) throw forbidden(scope);
}

export function requireStepUp(p: BffPrincipal, t: number): void {
  if (!p.stepUpUntil || p.stepUpUntil < t) {
    throw new ProblemError(403, "step_up_required", "Re-authentication required", "This action needs a fresh sign-in (step-up) within the last 5 minutes.", { step_up_url: "/api/bff/session?step_up=1" });
  }
}

function requireReason(reason: string | undefined, min: number): string {
  const r = (reason ?? "").trim();
  if (r.length < min) {
    throw new ProblemError(422, "validation_failed", "Reason too short", `Give a reason of at least ${min} characters; it is written to the audit log.`, { errors: [{ pointer: "/reason", code: "min_length", message: `At least ${min} characters` }] });
  }
  return r;
}

const agentOf = (w: World, id: string): AgentRt => {
  const rt = w.agents.get(id);
  if (!rt) throw notFound("Agent");
  return rt;
};

// ── Incident actions (POST /incidents/{id}/actions) ───────────────────────

export function incidentAction(w: World, p: BffPrincipal, incidentId: string, body: IncidentActionBody, t: number): IncidentRec {
  const inc = w.incidents.get(incidentId);
  if (!inc) throw notFound("Incident");
  const rt = agentOf(w, inc.agent_id);
  requireScope(p, "incidents:act");
  const reason = requireReason(body.reason, 10);

  switch (body.action) {
    case "approve":
    case "deny":
      return decide(w, p, inc, rt, body.action, reason, t);
    case "undo":
      return undo(w, p, inc, rt, reason, t);
    case "clear_hold": {
      requireScope(p, "routing:override");
      if (!rt.routing.operator_hold_until || rt.routing.operator_hold_until <= t) throw new ProblemError(409, "invalid_transition", "No hold to clear", "Automation is not paused on this agent.");
      applyRouting(w, rt, { to: rt.routing.state, trigger: "operator", actor_kind: "human", actor_user_id: p.userId, hold_until: null, reason, at: t });
      return inc;
    }
    case "fail_back": {
      requireScope(p, "routing:override");
      if (rt.routing.state !== "failed_over") throw new ProblemError(409, "invalid_transition", "Not failed over", `Agent is '${rt.routing.state}'; fail back needs 'failed_over'.`, { from_state: rt.routing.state, action: "fail_back" });
      applyRouting(w, rt, { to: "failing_back", trigger: "operator", actor_kind: "human", actor_user_id: p.userId, target: PRIMARY, canary_pct: 10, reason, at: t });
      appendAudit(w, { action: "failback.started", actor_type: "human", actor_id: p.userId, resource_type: "agent", resource_id: rt.id, resource_ref: rt.spec.slug, reason, detail: { canary_pct: 10 } }, t);
      return inc;
    }
    case "release":
      return release(w, p, inc, rt, reason, t);
    case "cancel": {
      requireScope(p, "routing:override");
      if (inc.state !== "waiting_approval" && inc.state !== "pending") throw new ProblemError(409, "invalid_transition", "Nothing to cancel", "The saga has already written routing.");
      const ap = inc.approval_id ? w.approvals.get(inc.approval_id) : undefined;
      if (ap) w.approvals.set(ap.id, { ...ap, state: "cancelled", decided_at: iso(t), decided_by_user_id: p.userId, decision_reason: reason });
      const tr = applyRouting(w, rt, { to: "degraded", trigger: "operator", actor_kind: "human", actor_user_id: p.userId, failover_id: inc.id, reason, at: t });
      inc.transition_ids = [...inc.transition_ids, tr.id];
      addStep(inc, "done", t, "Cancelled by operator");
      inc.state = "cancelled";
      inc.finished_at = t;
      appendAudit(w, { action: "failover.rolled_back", actor_type: "human", actor_id: p.userId, resource_type: "incident", resource_id: inc.id, resource_ref: rt.spec.slug, reason, detail: { cause: "operator_cancel" } }, t);
      emitIncident(w, inc, rt);
      return inc;
    }
    default:
      throw new ProblemError(422, "validation_failed", "Unknown action", `Unsupported action '${String(body.action)}'.`);
  }
}

function decide(w: World, p: BffPrincipal, inc: IncidentRec, rt: AgentRt, action: "approve" | "deny", reason: string, t: number): IncidentRec {
  requireScope(p, "approvals:decide");
  const ap = inc.approval_id ? w.approvals.get(inc.approval_id) : undefined;
  if (!ap || ap.state !== "pending" || Date.parse(ap.expires_at) <= t) {
    throw new ProblemError(409, "approval_not_pending", "Approval is not pending", `This approval is ${ap?.state ?? "missing"}; nothing to decide.`);
  }
  if (ap.requested_by_user_id && ap.requested_by_user_id === p.userId) {
    appendAudit(w, { action: "access.denied", actor_type: "human", actor_id: p.userId, resource_type: "approval", resource_id: ap.id, resource_ref: rt.spec.slug, reason: "self_approval", detail: { rule: "requester ≠ approver (four-eyes)" }, severity: "warning" }, t);
    throw new ProblemError(409, "self_approval", "You requested this action", "Four-eyes rule: a second person with approvals:decide must approve a change you requested.");
  }
  w.approvals.set(ap.id, { ...ap, state: action === "approve" ? "approved" : "denied", decided_by_user_id: p.userId, decided_at: iso(t), decision_reason: reason });
  appendAudit(w, { action: action === "approve" ? "approval.granted" : "approval.denied", actor_type: "human", actor_id: p.userId, resource_type: "approval", resource_id: ap.id, resource_ref: rt.spec.slug, reason, detail: { requested_action: ap.requested_action, tier: ap.tier, incident_id: inc.id }, severity: "warning" }, t);
  emit(w, "approval.decided", { approval_id: ap.id, incident_id: inc.id, agent_id: rt.id, tier: ap.tier, requested_action: ap.requested_action, expires_at: ap.expires_at, state: action === "approve" ? "approved" : "denied" }, t);
  if (action === "approve") {
    rt.anomalies = rt.anomalies.map((a) => (a.to === null ? { ...a, to: t + 1000 } : a));
    const preferProvider = ap.requested_action !== "backup_agent_failover";
    const target = ap.requested_action === "backup_agent_failover" ? { kind: "agent" as const, provider: null, model: null, label: `backup agent ${rt.spec.slug}-standby` } : chooseTarget(w, rt, t, preferProvider);
    addStep(inc, "check_viability", t + 50, `Approved by ${p.name}`);
    inc.state = "running";
    completeFailover(w, inc, rt, { target, trigger: "approval", actor_kind: inc.actor_kind, user: inc.requested_by_user_id, approvalId: ap.id, at: t + 100 });
  } else {
    const tr = applyRouting(w, rt, { to: "degraded", trigger: "approval", actor_kind: "human", actor_user_id: p.userId, approval_id: ap.id, failover_id: inc.id, reason, at: t });
    inc.transition_ids = [...inc.transition_ids, tr.id];
    addStep(inc, "done", t, `Denied by ${p.name}`);
    inc.state = "cancelled";
    inc.finished_at = t;
    emitIncident(w, inc, rt);
  }
  return inc;
}

function undo(w: World, p: BffPrincipal, inc: IncidentRec, rt: AgentRt, reason: string, t: number): IncidentRec {
  requireScope(p, "routing:override");
  if (rt.routing.state === "killed") throw new ProblemError(409, "invalid_transition", "Agent is killed", "Release the kill switch first.", { from_state: "killed", action: "undo" });
  const target = [...w.transitions].reverse().find((tr) => tr.agent_id === rt.id && (tr.actor_kind === "rule" || tr.actor_kind === "policy") && tr.to_state !== "awaiting_approval");
  if (!target || !inc.transition_ids.includes(target.id)) throw new ProblemError(409, "nothing_to_undo", "Nothing to undo", "No automated transition from this incident is still in effect.");
  if (target.undone_by) throw new ProblemError(409, "already_undone", "Already undone", "That transition has already been inverted.");
  const holdUntil = Math.max(holdFor(t), rt.routing.operator_hold_until ?? 0);
  const to = target.from_state ?? "active";
  const tr = applyRouting(w, rt, { to, trigger: "undo", actor_kind: "human", actor_user_id: p.userId, target: PRIMARY, inverse_of: target.id, hold_until: holdUntil, failover_id: inc.id, reason, at: t });
  w.transitions = w.transitions.map((x) => (x.id === target.id ? { ...x, undone_by: tr.id } : x));
  inc.transition_ids = [...inc.transition_ids, tr.id];
  for (const id of inc.handoff_task_ids) {
    const task = w.tasks.get(id);
    if (task?.state === "queued") w.tasks.set(id, { ...task, state: "returned", outcome: "returned_to_agent" });
  }
  appendAudit(w, { action: "failover.undone", actor_type: "human", actor_id: p.userId, resource_type: "incident", resource_id: inc.id, resource_ref: rt.spec.slug, reason, detail: { inverse_of: target.id, operator_hold_until: iso(holdUntil), hold: "D21: rule and policy actors blocked for 30 minutes" }, severity: "warning" }, t);
  emitIncident(w, inc, rt);
  return inc;
}

function release(w: World, p: BffPrincipal, inc: IncidentRec, rt: AgentRt, reason: string, t: number): IncidentRec {
  if (rt.routing.state === "killed") {
    requireScope(p, "killswitch:release");
    requireStepUp(p, t);
    for (const ks of w.killSwitches.values()) {
      if (ks.state === "pulled" && ks.affected_agent_ids.includes(rt.id) && ks.scope_kind === "agent") {
        w.killSwitches.set(ks.id, { ...ks, state: "released", released_by: p.userId, released_at: iso(t) });
      }
    }
    applyRouting(w, rt, { to: "active", trigger: "operator", actor_kind: "human", actor_user_id: p.userId, target: PRIMARY, reason, at: t });
    appendAudit(w, { action: "killswitch.released", actor_type: "human", actor_id: p.userId, resource_type: "agent", resource_id: rt.id, resource_ref: rt.spec.slug, reason, detail: { pulled_via: "console" }, severity: "critical" }, t);
    return inc;
  }
  if (rt.routing.state !== "quarantined") throw new ProblemError(409, "invalid_transition", "Nothing to release", `Agent is '${rt.routing.state}'.`, { from_state: rt.routing.state, action: "release" });
  requireScope(p, "quarantine:act");
  applyRouting(w, rt, { to: "active", trigger: "operator", actor_kind: "human", actor_user_id: p.userId, target: PRIMARY, reason, at: t });
  appendAudit(w, { action: "quarantine.released", actor_type: "human", actor_id: p.userId, resource_type: "agent", resource_id: rt.id, resource_ref: rt.spec.slug, reason }, t);
  return inc;
}

// ── POST /incidents (human-opened) ────────────────────────────────────────

const liveSaga = (w: World, agent: string): IncidentRec | undefined =>
  [...w.incidents.values()].find((i) => i.agent_id === agent && (i.state === "pending" || i.state === "running" || i.state === "waiting_approval"));

export function createIncident(w: World, p: BffPrincipal, body: IncidentCreate, t: number): { inc: IncidentRec; status: 201 | 202 } {
  requireScope(p, "incidents:act");
  const rt = agentOf(w, body.agent_id);
  const reason = requireReason(body.reason, 10);
  const existing = liveSaga(w, rt.id);
  if (existing) throw new ProblemError(409, "saga_in_flight", "Another action is in flight", "This agent already has a pending or waiting saga.", { incident_id: existing.id });

  if (body.action === "kill") {
    const ks = pullKill(w, p, { scope_kind: "agent", scope_id: rt.id, reason }, t);
    const inc = [...w.incidents.values()].reverse().find((i) => i.agent_id === rt.id && i.kind === "kill");
    if (!inc || !ks) throw new Error("kill did not open an incident");
    return { inc, status: 201 };
  }
  if (body.action === "quarantine") {
    requireScope(p, "quarantine:act");
    if (!["active", "degraded", "failed_over"].includes(rt.routing.state)) throw new ProblemError(409, "invalid_transition", "Cannot quarantine", `Agent is '${rt.routing.state}'.`, { from_state: rt.routing.state, action: "quarantine" });
    const inc = openIncident(w, rt, { kind: "quarantine", actor_kind: "human", user: p.userId, reason, at: t });
    const tr = applyRouting(w, rt, { to: "quarantined", trigger: "operator", actor_kind: "human", actor_user_id: p.userId, failover_id: inc.id, reason, at: t + 200 });
    inc.transition_ids = [tr.id];
    addStep(inc, "write_routing", t + 200, "routing_apply → quarantined; gateway refuses with 403 sibyl_agent_quarantined");
    addStep(inc, "done", t + 300, "Saga complete");
    inc.state = "done";
    inc.finished_at = t + 300;
    appendAudit(w, { action: "quarantine.applied", actor_type: "human", actor_id: p.userId, resource_type: "agent", resource_id: rt.id, resource_ref: rt.spec.slug, reason }, t + 200);
    emitIncident(w, inc, rt);
    return { inc, status: 201 };
  }
  requireScope(p, "routing:override");
  if (body.action === "failover" || body.action === "handoff") {
    if (!["active", "degraded"].includes(rt.routing.state) && body.action === "failover") {
      throw new ProblemError(409, "invalid_transition", "Cannot fail over", `Agent is '${rt.routing.state}'.`, { from_state: rt.routing.state, action: "failover" });
    }
    const wantsBackup = body.target?.kind === "agent";
    const inc = openIncident(w, rt, { kind: "failover", actor_kind: "human", user: p.userId, reason, at: t });
    if (wantsBackup && rt.spec.tier === 1) {
      requestApproval(w, inc, rt, { action: "backup_agent_failover", byKind: "human", user: p.userId, evidence: { requested_target: `${rt.spec.slug}-standby`, note: "Backup-agent hops on tier 1 are approval-gated even on detected failure (D13)" }, at: t });
      return { inc, status: 202 };
    }
    const target =
      body.action === "handoff"
        ? { kind: "human_queue" as const, provider: null, model: null, label: "human queue" }
        : wantsBackup
          ? { kind: "agent" as const, provider: null, model: null, label: `backup agent ${rt.spec.slug}-standby` }
          : chooseTarget(w, rt, t, body.target?.kind === "model" && Boolean(body.target.provider_id));
    const tpl = body.action === "handoff" ? (rt.spec.sdk ? PACKETS["claims-triage-outage"] : PACKETS["customer-chat-outage"]) : null;
    completeFailover(w, inc, rt, { target, trigger: "operator", actor_kind: "human", user: p.userId, at: t, packet: tpl ?? null });
    return { inc, status: 201 };
  }
  // degrade / recover
  const to = body.action === "degrade" ? "degraded" : "active";
  const inc = openIncident(w, rt, { kind: body.action, actor_kind: "human", user: p.userId, reason, at: t });
  const tr = applyRouting(w, rt, { to, trigger: "operator", actor_kind: "human", actor_user_id: p.userId, failover_id: inc.id, reason, at: t + 200, ...(to === "active" ? { target: PRIMARY } : {}) });
  inc.transition_ids = [tr.id];
  addStep(inc, "done", t + 300, `routing_apply → ${to}`);
  inc.state = "done";
  inc.finished_at = t + 300;
  emitIncident(w, inc, rt);
  return { inc, status: 201 };
}

// ── Kill switch ───────────────────────────────────────────────────────────

export function pullKill(w: World, p: BffPrincipal, body: KillSwitchCreate, t: number): KillSwitch {
  requireScope(p, "killswitch:pull");
  requireStepUp(p, t);
  const reason = requireReason(body.reason, 20);
  let affected: AgentRt[];
  if (body.scope_kind === "tenant") affected = [...w.agents.values()];
  else if (body.scope_kind === "agent") affected = [agentOf(w, body.scope_id ?? "")];
  else affected = [...w.agents.values()].filter((a) => providerId(w.slug, a.spec.provider) === body.scope_id);
  affected = affected.filter((a) => a.routing.state !== "killed");
  if (affected.length === 0) throw new ProblemError(409, "already_pulled", "Already killed", "Every agent in that scope is already killed.");
  const id = nextId(w, "kill");
  for (const rt of affected) {
    const inc = openIncident(w, rt, { kind: "kill", actor_kind: "human", user: p.userId, reason, at: t });
    const tr = applyRouting(w, rt, { to: "killed", trigger: "operator", actor_kind: "human", actor_user_id: p.userId, failover_id: inc.id, reason, at: t + 100 });
    inc.transition_ids = [tr.id];
    addStep(inc, "write_routing", t + 100, "routing_apply → killed (beats fail-open and stale snapshots)");
    addStep(inc, "done", t + 200, "Kill applied");
    inc.state = "done";
    inc.finished_at = t + 200;
  }
  const ks: KillSwitch = {
    id,
    scope_kind: body.scope_kind,
    scope_id: body.scope_id ?? null,
    state: "pulled",
    reason,
    pulled_by: p.userId,
    pulled_via_break_glass: false,
    pulled_at: iso(t),
    routing_version_at_pull: w.routingVersion,
    affected_agent_ids: affected.map((a) => a.id),
    acks: [{ kill_switch_id: id, gateway_id: "gw-local-1", snapshot_version: w.routingVersion, applied_at: iso(t + 850) }],
    released_by: null,
    released_at: null,
  };
  w.killSwitches.set(id, ks);
  appendAudit(w, { action: "killswitch.pulled", actor_type: "human", actor_id: p.userId, resource_type: "kill_switch", resource_id: id, resource_ref: body.scope_kind === "agent" ? (affected[0]?.spec.slug ?? null) : body.scope_kind, reason, detail: { scope_kind: body.scope_kind, affected_agents: affected.length, step_up: true }, severity: "critical" }, t);
  appendAudit(w, { action: "killswitch.applied", actor_type: "system", resource_type: "kill_switch", resource_id: id, detail: { gateway_id: "gw-local-1", snapshot_version: w.routingVersion, applied_in_ms: 850 }, severity: "critical" }, t + 850);
  emit(w, "killswitch.pulled", { kill_switch_id: id, scope_kind: body.scope_kind, scope_id: body.scope_id ?? null }, t);
  emit(w, "killswitch.applied", { kill_switch_id: id, scope_kind: body.scope_kind, scope_id: body.scope_id ?? null, snapshot_version: w.routingVersion, gateway_id: "gw-local-1" }, t + 850);
  return ks;
}

export function releaseKill(w: World, p: BffPrincipal, id: string, reasonIn: string | undefined, t: number): KillSwitch {
  requireScope(p, "killswitch:release");
  requireStepUp(p, t);
  const reason = requireReason(reasonIn, 10);
  const ks = w.killSwitches.get(id);
  if (!ks) throw notFound("Kill switch");
  if (ks.state !== "pulled") throw new ProblemError(409, "not_pulled", "Not pulled", "This kill switch is already released.");
  for (const aid of ks.affected_agent_ids) {
    const rt = w.agents.get(aid);
    if (rt?.routing.state === "killed") applyRouting(w, rt, { to: "active", trigger: "operator", actor_kind: "human", actor_user_id: p.userId, target: PRIMARY, reason, at: t });
  }
  const next = { ...ks, state: "released" as const, released_by: p.userId, released_at: iso(t) };
  w.killSwitches.set(id, next);
  appendAudit(w, { action: "killswitch.released", actor_type: "human", actor_id: p.userId, resource_type: "kill_switch", resource_id: id, reason, detail: { affected_agents: ks.affected_agent_ids.length }, severity: "critical" }, t);
  emit(w, "killswitch.released", { kill_switch_id: id, scope_kind: ks.scope_kind, scope_id: ks.scope_id }, t);
  return next;
}

// ── Operator queue ────────────────────────────────────────────────────────

export function handoffAction(w: World, p: BffPrincipal, taskId: string, body: HandoffTaskAction, t: number) {
  const task = w.tasks.get(taskId);
  if (!task) throw notFound("Handoff task");
  if (body.action === "reassign") requireScope(p, "users:manage");
  else requireScope(p, "queue:act");
  const mine = task.claimed_by === p.userId;
  const lockLive = task.lock_expires_at ? Date.parse(task.lock_expires_at) > t : false;
  let next = task;
  let audit = "";
  switch (body.action) {
    case "claim":
      if (task.state === "claimed" && !mine && lockLive) throw new ProblemError(409, "claimed_by_other", "Claimed by someone else", "Another operator holds the lock on this task.");
      if (task.state !== "queued" && task.state !== "expired" && !(task.state === "claimed" && !lockLive)) throw new ProblemError(409, "invalid_transition", "Cannot claim", `Task is '${task.state}'.`);
      next = { ...task, state: "claimed", claimed_by: p.userId, claimed_at: iso(t), lock_expires_at: iso(t + 30 * MINUTE), accountable_user_id: p.userId };
      audit = "handoff.claimed";
      break;
    case "extend_lock":
    case "release_claim":
      if (task.state !== "claimed" || !mine) throw new ProblemError(409, "claimed_by_other", "Not your claim", "Only the operator holding the claim can do this.");
      next = body.action === "extend_lock" ? { ...task, lock_expires_at: iso(t + 30 * MINUTE) } : { ...task, state: "queued", claimed_by: null, claimed_at: null, lock_expires_at: null };
      audit = body.action === "extend_lock" ? "handoff.lock_extended" : "handoff.claim_released";
      break;
    case "complete": {
      if (task.state !== "claimed") throw new ProblemError(409, "invalid_transition", "Claim it first", "A task must be claimed before it can be completed.");
      if (!mine) throw new ProblemError(409, "claimed_by_other", "Claimed by someone else", "Another operator holds the lock on this task.");
      if (!lockLive) throw new ProblemError(409, "lock_lapsed", "Your lock lapsed", "Claim the task again before completing it.");
      if (!body.outcome) throw new ProblemError(422, "validation_failed", "Outcome required", "Choose resolved, escalated or abandoned.", { errors: [{ pointer: "/outcome", code: "required", message: "Required" }] });
      next = { ...task, state: "completed", outcome: body.outcome, outcome_note: body.outcome_note ?? null, next_action: body.next_action ?? task.next_action ?? null, rating: body.rating ?? null, completed_at: iso(t) };
      if (body.outcome === "resolved") w.completedDespiteFailure += 1;
      audit = "handoff.completed";
      break;
    }
    case "return":
      if (task.state !== "queued") throw new ProblemError(409, "invalid_transition", "Cannot return", "Only a queued task can be returned to the agent.");
      next = { ...task, state: "returned", outcome: "returned_to_agent" };
      audit = "handoff.returned";
      break;
    default:
      throw new ProblemError(422, "validation_failed", "Unsupported action", `'${body.action}' is not available in the console.`);
  }
  w.tasks.set(task.id, next);
  const rt = w.agents.get(task.agent_id);
  appendAudit(w, { action: audit, actor_type: "human", actor_id: p.userId, resource_type: "handoff_task", resource_id: task.id, resource_ref: rt?.spec.slug ?? null, reason: body.reason ?? body.outcome_note ?? null, detail: { outcome: next.outcome ?? null, state: next.state } }, t);
  emit(w, `handoff.${next.state === "completed" ? "completed" : next.state === "claimed" ? "claimed" : next.state === "returned" ? "returned" : "queued"}`, { task_id: task.id, agent_id: task.agent_id, priority: task.priority, deadline_at: task.deadline_at, state: next.state, claimed_by_user_id: next.claimed_by ?? null }, t);
  return next;
}

// ── Alerts ────────────────────────────────────────────────────────────────

export function alertAction(w: World, p: BffPrincipal, alertId: string, body: AlertAction, t: number) {
  requireScope(p, "alerts:act");
  const alert = w.alerts.get(alertId);
  if (!alert) throw notFound("Alert");
  let next = alert;
  if (body.action === "ack") {
    if (alert.state !== "open") throw new ProblemError(409, "invalid_transition", "Cannot acknowledge", `Alert is '${alert.state}'.`);
    next = { ...alert, state: "acked", acked_at: iso(t) };
    appendAudit(w, { action: "alert.acked", actor_type: "human", actor_id: p.userId, resource_type: "alert", resource_id: alert.id, detail: { rule_code: alert.rule_code } }, t);
  } else if (body.action === "silence") {
    const until = body.until ? Date.parse(body.until) : t + 60 * MINUTE;
    next = { ...alert, silenced_until: iso(until) };
    appendAudit(w, { action: "alert.silenced", actor_type: "human", actor_id: p.userId, resource_type: "alert", resource_id: alert.id, reason: body.reason ?? null, detail: { until: iso(until) } }, t);
  } else {
    if (!body.verdict) {
      throw new ProblemError(422, "verdict_required", "A verdict is required", "Every alert is closed with a verdict (true positive, false positive or unsure). It becomes a label for rule tuning (D24).", { errors: [{ pointer: "/verdict", code: "required", message: "Choose a verdict" }] });
    }
    if (alert.state === "resolved" && alert.verdict) throw new ProblemError(409, "already_resolved", "Already closed", "This alert already has a verdict.");
    next = { ...alert, state: "resolved", resolved_at: alert.resolved_at ?? iso(t), verdict: body.verdict, verdict_note: body.verdict_note ?? null, verdict_wanted: false };
    appendAudit(w, { action: "alert.labelled", actor_type: "human", actor_id: p.userId, resource_type: "alert", resource_id: alert.id, reason: body.verdict_note ?? null, detail: { verdict: body.verdict, rule_code: alert.rule_code, label_kind: "alert_verdict" } }, t);
    emit(w, "alert.resolved", { alert_id: alert.id, agent_id: alert.agent_id, rule_code: alert.rule_code, severity: alert.severity, state: "resolved" }, t);
  }
  w.alerts.set(alert.id, next);
  emit(w, "alert.updated", { alert_id: alert.id, agent_id: alert.agent_id, rule_code: alert.rule_code, severity: alert.severity, state: next.state }, t);
  return next;
}
