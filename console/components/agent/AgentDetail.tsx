"use client";
/**
 * Agent detail (B2, B8): explainable health, routing with its chain, continuity plan,
 * last-hour metrics and recent events, all refreshed by live events.
 *
 * Live data is thinner than the demo's: an agent the worker has not scored yet has no health
 * document, one that never routed has no routing row, and the primary/served model come from
 * the model registry rather than the demo-only `x_console` extras. Each case renders a designed
 * state instead of "not found".
 */
import Link from "next/link";
import { useState } from "react";
import type { Agent, Alert, ContinuityPlan, FallbackChain, HealthPoint, Incident, MetricBucket, Page, Provider, RoutingState, RoutingTransition } from "@/lib/api/types";
import type { components } from "@/lib/api/schema.gen";
import type { HealthDocument } from "@/lib/api/documents";
import { agentPaths, chainInForce, foldBuckets } from "@/lib/agent-data";
import { useBff } from "@/hooks/useBff";
import { useNow } from "@/hooks/useNow";
import { HealthRing } from "@/components/ui/HealthRing";
import { FidelityBadge, Pill, TierBadge } from "@/components/ui/StatePill";
import { Icon } from "@/components/ui/Icon";
import { Clock } from "@/components/ui/Time";
import { Timeline, type TimelineEntry } from "@/components/ui/Bits";
import { PROVIDER_LABEL, ROUTING_LABEL, label } from "@/lib/labels";
import { ruleLabel } from "@/lib/health/scoring";
import { useSession } from "@/components/shell/Session";
import type { AgentExtras } from "@/components/fleet/types";
import { HealthPanel, PredictionPanel } from "./HealthPanel";
import { PlanPanel, RoutingPanel } from "./RoutingPanel";
import { MetricsStrip } from "./MetricsStrip";
import { ActionsPanel } from "./ActionsPanel";
import { AgentDriftPanel } from "@/components/drift/AgentDriftPanel";
import { awaitingConfirmation } from "@/lib/agents/discovery";
import { RecentRuns } from "@/components/runs/RecentRuns";

type Model = components["schemas"]["Model"];
type AgentView = Agent & { x_console?: AgentExtras };

export interface AgentInitial {
  agent: AgentView | null;
  health: HealthDocument | null;
  routing: RoutingState | null;
  plan: ContinuityPlan | null;
  chains: Page<FallbackChain> | null;
  metrics: Page<MetricBucket> | null;
  history: Page<HealthPoint> | null;
  transitions: Page<RoutingTransition> | null;
  alerts: Page<Alert> | null;
  incidents: Page<Incident> | null;
  providers: Page<Provider> | null;
}

interface ModelRef {
  provider: string;
  model: string;
}

/** Primary and currently served model: demo extras when present, else the live model registry. */
function useModels(agent: AgentView | undefined, routing: RoutingState | undefined, providers: readonly Provider[]): { primary: ModelRef; served: { provider: string | null; model: string | null } } {
  const x = agent?.x_console;
  const { data: models } = useBff<Page<Model>>(agent && !x ? "/models?limit=200" : null);
  if (x) return { primary: { provider: x.provider, model: x.model }, served: { provider: x.served_provider, model: x.served_model } };
  const byId = new Map((models?.data ?? []).map((m) => [m.id, m]));
  const slugOf = (providerId: string | null | undefined): string => providers.find((p) => p.id === providerId)?.slug ?? "";
  const primaryModel = byId.get(agent?.current_version?.primary_model_id ?? "");
  const primary = { provider: slugOf(primaryModel?.provider_id), model: primaryModel?.model_name ?? "" };
  if (!routing || routing.state === "killed" || routing.state === "quarantined" || routing.target_kind === "human_queue") return { primary, served: { provider: null, model: null } };
  if (routing.target_kind === "primary") return { primary, served: { provider: primary.provider || null, model: primary.model || null } };
  const target = byId.get(routing.target_model_id ?? "");
  return { primary, served: { provider: slugOf(routing.target_provider_id ?? target?.provider_id) || null, model: target?.model_name ?? null } };
}

export function AgentDetail({ id, initial }: { id: string; initial: AgentInitial }) {
  const s = useSession();
  const [mountedAt] = useState(() => Date.now());
  const p = agentPaths(id, s.mode, mountedAt);
  const now = useNow(5000);
  const { data: agent, error: agentError } = useBff<AgentView>(p.base, initial.agent);
  const { data: health } = useBff<HealthDocument>(p.health, initial.health);
  const { data: routing } = useBff<RoutingState>(p.routing, initial.routing);
  const { data: chains } = useBff<Page<FallbackChain>>(p.chains, initial.chains);
  const { data: metrics } = useBff<Page<MetricBucket>>(p.metrics, initial.metrics);
  const { data: history } = useBff<Page<HealthPoint>>(p.history, initial.history);
  const { data: transitions } = useBff<Page<RoutingTransition>>(p.transitions, initial.transitions);
  const { data: alerts } = useBff<Page<Alert>>(p.alerts, initial.alerts);
  const { data: incidents } = useBff<Page<Incident>>(p.incidents, initial.incidents);
  const { data: providers } = useBff<Page<Provider>>("/providers?limit=200", initial.providers);
  const { primary, served } = useModels(agent, routing, providers?.data ?? []);

  if (!agent) {
    return (
      <div className="page">
        <Link href="/fleet" className="btn btn-plain btn-sm" style={{ alignSelf: "flex-start" }}>
          <Icon name="arrowLeft" size={14} /> Fleet
        </Link>
        <div className="panel panel-pad">{agentError ? "This agent does not exist in this tenant." : "Loading agent…"}</div>
      </div>
    );
  }

  const x = agent.x_console;
  const tags = agent.tags ?? [];
  const pii = x?.pii ?? tags.includes("pii");
  const holdSuppressed = x?.hold_suppressed_count ?? (alerts?.data ?? []).reduce((n, a) => n + ((a as Alert & { hold_suppressed_count?: number }).hold_suppressed_count ?? 0), 0);
  const chain = chainInForce(chains?.data);
  const liveIncident = incidents?.data.find((i) => i.state === "waiting_approval" || i.routing.last_transition?.failover_id === i.id) ?? null;
  const held = routing?.operator_hold_until && Date.parse(routing.operator_hold_until) > now;

  const events: TimelineEntry[] = [
    ...(transitions?.data ?? []).map((t) => ({
      key: `t-${t.id}`,
      at: t.created_at,
      title: `${t.from_state ? ROUTING_LABEL[t.from_state] : "Registered"} → ${ROUTING_LABEL[t.to_state]}`,
      note: `${t.trigger.replaceAll("_", " ")} · ${t.actor_kind}${t.reason ? ` · ${t.reason}` : ""}`,
      state: (t.to_state === "failed_over" ? "moved" : t.to_state === "killed" || t.to_state === "awaiting_approval" ? "warn" : "done") as TimelineEntry["state"],
    })),
    ...(alerts?.data ?? []).map((a) => ({
      key: `a-${a.id}`,
      at: a.fired_at,
      title: `Alert · ${ruleLabel(a.rule_code)} (${a.severity})`,
      note: a.state === "resolved" ? `Resolved${a.verdict ? ` · verdict ${a.verdict}` : " · awaiting verdict"}` : a.state === "acked" ? "Acknowledged" : "Open",
      state: (a.state === "resolved" ? "done" : "warn") as TimelineEntry["state"],
    })),
  ]
    .sort((m, n) => Date.parse(n.at) - Date.parse(m.at))
    .slice(0, 10)
    .map((e) => ({ ...e, time: <Clock at={e.at} /> }));

  return (
    <div className="page">
      <Link href="/fleet" className="btn btn-plain btn-sm" style={{ alignSelf: "flex-start", marginBottom: -12 }}>
        <Icon name="arrowLeft" size={14} /> Fleet
      </Link>

      <header style={{ display: "flex", gap: 20, alignItems: "center", flexWrap: "wrap" }}>
        <HealthRing score={health?.score ?? agent.health?.score ?? null} band={health?.status ?? agent.health?.band ?? null} size={84} provisional={health?.provisional?.flag} caption="score" />
        <div className="grow">
          <div className="eyebrow">{x?.process ?? "Agent"} · {agent.kind.replaceAll("_", " ")}</div>
          <h1 className="large-title" data-testid="agent-name">
            {agent.name}
          </h1>
          <p className="subtle" style={{ marginTop: 4, maxWidth: "70ch" }}>
            {agent.description}
          </p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 10, alignItems: "center" }}>
            <TierBadge tier={agent.tier} />
            <span className="tag mono">{agent.slug}</span>
            <span className="tag">{agent.lifecycle}</span>
            <span className="tag">risk {agent.risk_class ?? "unclassified"}</span>
            <span className="tag">fail {agent.fail_mode}</span>
            {primary.model ? <span className="tag">{primary.provider ? `${label(PROVIDER_LABEL, primary.provider)} · ` : ""}{primary.model}</span> : null}
            {x ? <FidelityBadge fidelity={x.fidelity} /> : null}
            {pii ? <Pill tone="quiet">PII</Pill> : null}
            {awaitingConfirmation(agent) ? (
              <Link href="/discovered" style={{ textDecoration: "none" }} data-testid="agent-awaiting-confirmation">
                <Pill tone="watch" dot>
                  Discovered · not routed until confirmed
                </Pill>
              </Link>
            ) : null}
          </div>
        </div>
      </header>

      {held && routing ? (
        <div className="banner" data-tone="human" role="status" data-testid="hold-banner">
          <Icon name="pause" size={16} />
          <span>
            <strong>Automation paused until <Clock at={routing.operator_hold_until} seconds={false} /></strong> after a human undo (D21). Rules keep scoring{holdSuppressed ? `; ${holdSuppressed} automatic moves suppressed so far` : ""}. People and the kill switch are not blocked.
          </span>
        </div>
      ) : null}
      {routing?.pending_approval ? (
        <Link href={`/incidents/${routing.pending_approval.incident_id}`} className="banner" data-tone="human" style={{ textDecoration: "none" }}>
          <Icon name="hand" size={16} />
          <span className="grow">
            <strong>Waiting for approval:</strong> {routing.pending_approval.requested_action.replaceAll("_", " ")} · expires <Clock at={routing.pending_approval.expires_at} seconds={false} />
          </span>
          <Icon name="chevronRight" size={14} />
        </Link>
      ) : null}

      <div className="grid-split">
        <div className="stack">
          {health ? (
            <>
              <HealthPanel health={health} />
              <PredictionPanel health={health} />
            </>
          ) : (
            <section className="panel" aria-labelledby="health-title" data-testid="not-scored">
              <div className="panel-head">
                <h3 id="health-title">Health score</h3>
                <span className="caption">Not scored yet</span>
              </div>
              <p className="row muted">The first score appears after the agent&apos;s first full evaluation window with traffic. Until then no rule can move it.</p>
            </section>
          )}
        </div>
        <div className="stack">
          {routing ? (
            <RoutingPanel routing={routing} chain={chain} providers={providers?.data ?? []} primary={primary} served={served} incidentHref={liveIncident ? `/incidents/${liveIncident.id}` : null} />
          ) : (
            <section className="panel panel-pad">
              <h3 className="title-sm">No routing state yet</h3>
              <p className="muted" style={{ marginTop: 6 }}>Routing starts with the agent&apos;s first policy snapshot. Until then the gateway serves it on its primary model.</p>
            </section>
          )}
          <ActionsPanel agentId={agent.id} agentName={agent.name} tier={agent.tier} state={routing?.state ?? "active"} chain={chain} />
          <PlanPanel plan={initial.plan} />
        </div>
      </div>

      <section className="section" aria-labelledby="metrics-title">
        <div className="section-title">
          <h2 id="metrics-title">Last hour</h2>
          <span className="meta">1-minute buckets</span>
        </div>
        <MetricsStrip metrics={foldBuckets(metrics?.data ?? [])} history={history?.data ?? []} />
      </section>

      <AgentDriftPanel agentId={agent.id} agentName={agent.name} />

      <RecentRuns agentId={agent.id} />

      <section className="section" aria-labelledby="events-title">
        <div className="section-title">
          <h2 id="events-title">Recent events</h2>
          <Link className="meta" href={`/audit?resource_id=${agent.id}`}>
            Audit trail
          </Link>
        </div>
        <div className="panel">{events.length ? <Timeline items={events} label="Recent routing changes and alerts" /> : <p className="row muted">Nothing has happened to this agent yet.</p>}</div>
      </section>
    </div>
  );
}
