/**
 * The demo's single write path for routing (mirrors `routing_apply()`): every transition
 * bumps routing_version, records a RoutingTransition with its health snapshot (the decision
 * record), appends `route.changed` to the audit chain and emits `policy_changed`.
 */
import "server-only";
import type { ActorKind, RoutingStateName, TargetKind, TransitionTrigger } from "@/lib/api/types";
import { healthDocAt } from "./health";
import type { ProviderSlug } from "./fixtures";
import { appendAudit, emit, nextId, routingVersionBump, type AgentRt, type TransitionRec, type World } from "./world";

export interface RouteTarget {
  kind: TargetKind;
  provider: ProviderSlug | null;
  model: string | null;
  agent_id?: string | null;
  step_id?: string | null;
}

export interface ApplyRouting {
  to: RoutingStateName;
  trigger: TransitionTrigger;
  actor_kind: ActorKind;
  actor_user_id?: string | null;
  target?: RouteTarget;
  rule_codes?: string[];
  alert_ids?: string[];
  approval_id?: string | null;
  failover_id?: string | null;
  inverse_of?: string | null;
  hold_until?: number | null;
  reason?: string | null;
  canary_pct?: number;
  at: number;
}

const targetObj = (t: { kind: TargetKind; provider: string | null; model: string | null }): Record<string, unknown> => ({
  kind: t.kind,
  ...(t.provider ? { provider: t.provider } : {}),
  ...(t.model ? { model: t.model } : {}),
});

/** Which provider/model actually serves traffic for a routing state + target. */
function servedFor(rt: AgentRt, to: RoutingStateName, target: RouteTarget): { provider: ProviderSlug | null; model: string | null } {
  if (to === "killed" || to === "quarantined") return { provider: null, model: null };
  if (target.kind === "human_queue" || target.kind === "agent") return { provider: null, model: null };
  if (target.kind === "primary") return { provider: rt.spec.provider, model: rt.spec.model };
  return { provider: target.provider, model: target.model };
}

export function applyRouting(w: World, rt: AgentRt, o: ApplyRouting): TransitionRec {
  const from = rt.routing.state;
  const fromTarget = { kind: rt.routing.target_kind, provider: rt.routing.target_provider, model: rt.routing.target_model };
  const target: RouteTarget = o.target ?? {
    kind: rt.routing.target_kind,
    provider: rt.routing.target_provider,
    model: rt.routing.target_model,
  };
  const version = routingVersionBump(w);
  const id = nextId(w, "transition");
  const snapshot = healthDocAt(w, rt, o.at);
  const holdUntil = o.hold_until === undefined ? rt.routing.operator_hold_until : o.hold_until;

  const rec: TransitionRec = {
    id,
    agent_id: rt.id,
    failover_id: o.failover_id ?? null,
    from_state: from,
    to_state: o.to,
    from_target: targetObj(fromTarget),
    to_target: targetObj(target),
    trigger: o.trigger,
    actor_kind: o.actor_kind,
    actor_user_id: o.actor_user_id ?? null,
    rule_codes: o.rule_codes ?? [],
    alert_ids: o.alert_ids ?? [],
    health_snapshot_id: snapshot.health_snapshot_id,
    approval_id: o.approval_id ?? null,
    inverse_of: o.inverse_of ?? null,
    undone_by: null,
    operator_hold_until: holdUntil ? new Date(holdUntil).toISOString() : null,
    routing_version: version,
    reason: o.reason ?? null,
    created_at: new Date(o.at).toISOString(),
    health_snapshot: snapshot,
  };

  const audit = appendAudit(
    w,
    {
      action: "route.changed",
      actor_type: o.actor_kind === "api_key" ? "api_key" : o.actor_kind,
      actor_id: o.actor_user_id ?? null,
      resource_type: "agent",
      resource_id: rt.id,
      resource_ref: rt.spec.slug,
      reason: o.reason ?? null,
      detail: {
        transition_id: id,
        from_state: from,
        to_state: o.to,
        trigger: o.trigger,
        to_target: targetObj(target),
        rule_codes: o.rule_codes ?? [],
        health_snapshot_id: snapshot.health_snapshot_id,
        score: snapshot.score,
        band: snapshot.status,
        failover_id: o.failover_id ?? null,
        inverse_of: o.inverse_of ?? null,
        routing_version: version,
      },
      severity: o.to === "killed" ? "critical" : o.to === "failed_over" || o.to === "awaiting_approval" ? "warning" : "info",
    },
    o.at,
  );
  rec.audit_seq = audit.seq;
  w.transitions.push(rec);

  const served = servedFor(rt, o.to, target);
  const changedServing =
    served.provider !== (rt.served.at(-1)?.provider ?? rt.spec.provider) || served.model !== (rt.served.at(-1)?.model ?? rt.spec.model);
  rt.served = changedServing ? [...rt.served, { at: o.at, ...served }] : rt.served;
  rt.routing = {
    state: o.to,
    target_kind: target.kind,
    target_provider: target.provider,
    target_model: target.model,
    current_step_id: target.step_id ?? null,
    canary_pct: o.canary_pct ?? (o.to === "failing_back" ? rt.routing.canary_pct : 0),
    operator_hold_until: holdUntil ?? null,
    state_since: o.at,
    pending_approval_id: o.to === "awaiting_approval" ? (o.approval_id ?? null) : null,
    last_transition_id: id,
  };
  emit(w, "policy_changed", { tenant_id: w.tenantId, routing_version: version, agent_id: rt.id }, o.at);
  return rec;
}

export const PRIMARY: RouteTarget = { kind: "primary", provider: null, model: null };
