"use client";
/** Routing state + the approved fallback chain, with the step currently serving highlighted. */
import Link from "next/link";
import type { ContinuityPlan, FallbackChain, Provider, RoutingState } from "@/lib/api/types";
import { PROVIDER_LABEL, label } from "@/lib/labels";
import { formatDuration } from "@/lib/format";
import { RoutingPill } from "@/components/ui/StatePill";
import { Clock, Ago } from "@/components/ui/Time";
import { Icon } from "@/components/ui/Icon";

const STEP_NAME: Record<string, string> = {
  retry: "Retry",
  alt_model_same_provider: "Alternate model",
  alt_provider: "Alternate provider",
  backup_agent: "Backup agent",
  degraded_safe_mode: "Safe mode",
  human_queue: "Human queue",
};

interface RoutingPanelProps {
  routing: RoutingState;
  chain: FallbackChain | null;
  providers: Provider[];
  primary: { provider: string; model: string };
  served: { provider: string | null; model: string | null };
  incidentHref?: string | null;
}

export function RoutingPanel({ routing, chain, providers, primary, served, incidentHref }: RoutingPanelProps) {
  const pName = (id?: string | null): string => {
    const p = providers.find((x) => x.id === id);
    return p ? label(PROVIDER_LABEL, p.slug) : "—";
  };
  const primaryDown = providers.find((p) => p.slug === primary.provider)?.latest_status?.status;
  const onPrimary = routing.target_kind === "primary";
  return (
    <section className="panel" aria-labelledby="routing-title">
      <div className="panel-head">
        <h3 id="routing-title">Routing</h3>
        <RoutingPill state={routing.state} holdUntil={routing.operator_hold_until} />
      </div>
      <div className="panel-pad" style={{ display: "flex", flexDirection: "column", gap: 6, paddingBottom: 6 }}>
        <div className="title-sm">
          {routing.state === "killed"
            ? "Stopped by the kill switch"
            : routing.target_kind === "human_queue"
              ? "Work is going to the operator queue"
              : served.provider
                ? `Serving from ${label(PROVIDER_LABEL, served.provider)}${served.model ? ` · ${served.model}` : ""}`
                : "No traffic"}
        </div>
        <div className="caption">
          Since <Clock at={routing.state_since} /> (<Ago at={routing.state_since} />) · routing version <span className="num">{routing.routing_version}</span>
          {routing.state === "failing_back" ? ` · canary at ${routing.canary_pct ?? 0}%` : ""}
        </div>
        {incidentHref ? (
          <Link href={incidentHref} className="caption" style={{ display: "inline-flex", alignItems: "center", gap: 4, marginTop: 4 }}>
            Open the incident <Icon name="chevronRight" size={12} />
          </Link>
        ) : null}
      </div>
      <div className="chain" aria-label="Fallback chain">
        <span className="chain-step" data-state={onPrimary && routing.state !== "killed" ? "primary" : primaryDown && primaryDown !== "operational" ? "down" : undefined}>
          Primary · {primary.provider ? label(PROVIDER_LABEL, primary.provider) : (primary.model || "—")}
        </span>
        {(chain?.steps ?? [])
          .filter((s) => s.kind !== "retry")
          .map((s) => {
            const current = routing.current_step_id === s.id && !onPrimary;
            const target = s.kind === "alt_model_same_provider" || s.kind === "alt_provider" ? pName(s.provider_id) : s.kind === "backup_agent" ? "standby" : "";
            return (
              <span key={s.id} style={{ display: "contents" }}>
                <Icon name="chevronRight" size={14} className="chain-arrow" />
                <span className="chain-step" data-state={current ? (s.kind === "human_queue" ? "human" : "current") : s.kind === "alt_model_same_provider" && primaryDown && primaryDown !== "operational" ? "down" : undefined} title={s.risk ? `risk: ${s.risk}` : undefined}>
                  {STEP_NAME[s.kind] ?? s.kind}
                  {target ? <span className="caption">· {target}</span> : null}
                  {s.kind === "backup_agent" ? <Icon name="lock" size={12} aria-label="needs approval on tier 1" /> : null}
                </span>
              </span>
            );
          })}
      </div>
      {chain?.note ? <p className="caption" style={{ padding: "0 var(--row-x) 14px" }}>{chain.note}</p> : null}
    </section>
  );
}

export function PlanPanel({ plan }: { plan: ContinuityPlan | null }) {
  if (!plan) {
    return (
      <section className="panel panel-pad">
        <h3 className="title-sm">No continuity plan</h3>
        <p className="muted" style={{ marginTop: 6 }}>Failover cannot run until the agent has a plan with an approved fallback chain.</p>
      </section>
    );
  }
  const rows: [string, string][] = [
    ["RTO", plan.rto_s ? formatDuration(plan.rto_s) : "Not set"],
    ["RPO", plan.rpo_s ? formatDuration(plan.rpo_s) : "Request only"],
    ["Degraded mode", (plan.degraded_mode ?? "continue").replaceAll("_", " ")],
    ["Predicted failure", plan.preemptive_mode === "approval" ? "Needs approval" : plan.preemptive_mode === "degrade_then_auto" ? "Degrade, then automatic after 20 s" : "Automatic"],
    ["Approval timeout", `${formatDuration(plan.approval_timeout_s)} → ${plan.approval_timeout_policy === "hold" ? "hold" : "fail safe"}`],
    ["Inline fallback", plan.inline_fallback ? "On" : "Off"],
    ["On call", plan.on_call_ref ?? "—"],
    ["Drills", plan.drill_schedule ?? "Not scheduled"],
  ];
  return (
    <section className="panel" aria-labelledby="plan-title">
      <div className="panel-head">
        <h3 id="plan-title">Continuity plan</h3>
        <span className="caption mono">v{plan.row_version}</span>
      </div>
      <dl className="kv">
        {rows.map(([k, v]) => (
          <div key={k}>
            <dt>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
