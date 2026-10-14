"use client";
/**
 * Fleet overview (demo beats B1–B4): every agent's health, tier, routing state and provider,
 * live. Default view is the fleet map grouped by provider; list view is a sortable table.
 */
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useMemo } from "react";
import type { Band, FleetHealth, Page, Provider, ProviderIncident } from "@/lib/api/types";
import { useBff } from "@/hooks/useBff";
import { useActionCounts } from "@/hooks/useActionCounts";
import { BAND_LABEL, PROVIDER_LABEL, label } from "@/lib/labels";
import { formatDuration } from "@/lib/format";
import { HealthRing } from "@/components/ui/HealthRing";
import { BandPill, Pill, RoutingPill, TierBadge } from "@/components/ui/StatePill";
import { EmptyState } from "@/components/ui/Bits";
import { Icon } from "@/components/ui/Icon";
import { useSession } from "@/components/shell/Session";
import type { FleetAgent } from "./types";
import { ProviderIncidentCard } from "./ProviderIncidentCard";
import type { DriftPage } from "@/lib/api/monitor";
import { DRIFT_FLEET_PATH, VERDICT_LABEL, hintsByAgent, type AgentDriftHint } from "@/lib/drift/view";
import { awaitingConfirmation } from "@/lib/agents/discovery";

interface FleetViewProps {
  initialAgents: Page<FleetAgent> | null;
  initialFleet: FleetHealth | null;
  initialProviders: Page<Provider> | null;
}

const BANDS: Band[] = ["healthy", "watch", "degraded", "failed"];

export function FleetView({ initialAgents, initialFleet, initialProviders }: FleetViewProps) {
  const s = useSession();
  const router = useRouter();
  const params = useSearchParams();
  const view = params.get("view") === "list" ? "list" : "map";
  const bandFilter = params.get("band") as Band | null;
  const q = params.get("q") ?? "";

  const { data: agents } = useBff<Page<FleetAgent>>("/agents?limit=200", initialAgents);
  const { data: fleet } = useBff<FleetHealth>("/fleet/health", initialFleet);
  const { data: providers } = useBff<Page<Provider>>("/providers", initialProviders);
  const actions = useActionCounts();
  const { data: drift } = useBff<DriftPage>(s.can("drift:read") ? DRIFT_FLEET_PATH : null);
  const driftHints = useMemo(() => hintsByAgent(drift?.data ?? []), [drift]);

  const setParam = (k: string, v: string | null): void => {
    const next = new URLSearchParams(params.toString());
    if (v === null || v === "") next.delete(k);
    else next.set(k, v);
    router.replace(`/fleet${next.toString() ? `?${next}` : ""}`, { scroll: false });
  };

  const all = agents?.data ?? [];
  // The live agent list carries no provider (only the demo adds x_console); group by tier there.
  const hasProvider = all.some((a) => Boolean(a.x_console?.provider));
  const group = params.get("group") === "tier" || !hasProvider ? "tier" : "provider";
  const shown = all.filter((a) => (!bandFilter || a.health.band === bandFilter) && (!q || `${a.name} ${a.slug}`.toLowerCase().includes(q.toLowerCase())));
  const counts = (fleet?.counts_by_band ?? {}) as Record<string, number>;
  const states = (fleet?.counts_by_routing_state ?? {}) as Record<string, number>;
  const providerById = new Map((providers?.data ?? []).map((p) => [p.id, p]));

  const groups = useMemo(() => {
    const keyOf = (a: FleetAgent): string => (group === "tier" ? `T${a.tier}` : (a.x_console?.provider ?? "unknown"));
    const map = new Map<string, FleetAgent[]>();
    for (const a of shown) map.set(keyOf(a), [...(map.get(keyOf(a)) ?? []), a]);
    return [...map.entries()].sort(([x], [y]) => x.localeCompare(y));
  }, [shown, group]);

  if (all.length === 0) {
    return (
      <div className="page">
        <Header tenantName={s.tenantName} total={0} counts={counts} states={states} />
        <div className="panel">
          <EmptyState icon="sparkle" title="No agents yet" action={<Link className="btn btn-primary" href="/onboarding">Connect your first agent</Link>}>
            {s.tenant === "sandbox" ? "Set a capture policy, mint a gateway key and point an OpenAI client at the gateway. The agent appears here within seconds." : "Agents appear here as soon as they register or call the gateway."}
          </EmptyState>
        </div>
      </div>
    );
  }

  const awaiting = all.filter(awaitingConfirmation);
  return (
    <div className="page">
      <Header tenantName={s.tenantName} total={all.length} counts={counts} states={states} />

      {(fleet?.provider_incidents ?? []).map((pi: ProviderIncident) => (
        <ProviderIncidentCard key={pi.id} incident={pi} agents={all} provider={providerById.get(pi.provider_id)} />
      ))}

      {awaiting.length ? (
        <Link href="/discovered" className="banner" data-tone="watch" style={{ textDecoration: "none" }} data-testid="discovered-banner">
          <Icon name="search" size={16} />
          <span className="grow">
            <strong>{awaiting.length} discovered agents</strong> seen in telemetry and not yet confirmed. They are watched and policy-checked, but never routed or failed over until you confirm them.
          </span>
          <Icon name="chevronRight" size={14} />
        </Link>
      ) : null}

      <section className="panel" aria-label="Fleet summary">
        <div className="stats">
          <Stat k="Agents" v={all.length} />
          <Stat k="Healthy" v={counts.healthy ?? 0} small={`of ${all.length}`} />
          <Stat k="Failed over" v={(states.failed_over ?? 0) + (states.failing_back ?? 0)} tone={(states.failed_over ?? 0) > 0 ? "moved" : undefined} />
          <Stat k="Awaiting a human" v={fleet?.pending_approvals ?? 0} tone={(fleet?.pending_approvals ?? 0) > 0 ? "human" : undefined} href="/incidents" />
          <Stat k="In operator queue" v={fleet?.queue_depth ?? 0} href="/queue" />
          <Stat k="Open alerts" v={fleet?.open_alerts ?? 0} tone={(fleet?.open_alerts ?? 0) > 0 ? "failed" : undefined} href="/alerts" />
          {actions ? <Stat k="Actions stopped · 24 h" v={actions.total.blocked + actions.total.escalated} small={`${actions.total.blocked} blocked`} tone={actions.total.blocked ? "failed" : undefined} href="/audit?action=action" /> : null}
        </div>
        <div className="hairline-top" style={{ padding: "14px var(--row-x) 16px", display: "flex", flexDirection: "column", gap: 10 }}>
          <div className="bandbar" role="img" aria-label={BANDS.map((b) => `${counts[b] ?? 0} ${b}`).join(", ")}>
            {BANDS.map((b) => (counts[b] ?? 0) > 0 ? <span key={b} data-band={b} style={{ flexGrow: counts[b] ?? 0 }} /> : null)}
          </div>
          <div className="legend">
            {BANDS.map((b) => (
              <span key={b} data-band={b}>
                <i />
                {BAND_LABEL[b]} <b>{counts[b] ?? 0}</b>
              </span>
            ))}
          </div>
        </div>
      </section>

      <section className="section" aria-labelledby="agents-title">
        <div className="section-title" style={{ flexWrap: "wrap", gap: 10, alignItems: "center" }}>
          <h2 id="agents-title">Agents</h2>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center", minWidth: 0, maxWidth: "100%" }}>
            <label className="sr-only" htmlFor="fleet-search">
              Filter agents
            </label>
            <input id="fleet-search" className="input" style={{ width: 200, minHeight: 34, height: 34, borderRadius: 999 }} placeholder="Filter by name" defaultValue={q} onChange={(e) => setParam("q", e.target.value)} />
            <div className="seg" role="group" aria-label="Band filter">
              <button type="button" aria-pressed={!bandFilter} onClick={() => setParam("band", null)}>
                All
              </button>
              {BANDS.filter((b) => b !== "healthy").map((b) => (
                <button key={b} type="button" aria-pressed={bandFilter === b} onClick={() => setParam("band", bandFilter === b ? null : b)}>
                  {BAND_LABEL[b]} <span className="count">{counts[b] ?? 0}</span>
                </button>
              ))}
            </div>
            <div className="seg" role="group" aria-label="View">
              <button type="button" aria-pressed={view === "map"} onClick={() => setParam("view", null)} data-testid="view-map">
                <Icon name="fleet" size={14} /> Map
              </button>
              <button type="button" aria-pressed={view === "list"} onClick={() => setParam("view", "list")} data-testid="view-list">
                <Icon name="list" size={14} /> List
              </button>
            </div>
            {view === "map" && hasProvider ? (
              <div className="seg hide-sm" role="group" aria-label="Group by">
                <button type="button" aria-pressed={group === "provider"} onClick={() => setParam("group", null)}>
                  Provider
                </button>
                <button type="button" aria-pressed={group === "tier"} onClick={() => setParam("group", "tier")}>
                  Tier
                </button>
              </div>
            ) : null}
          </div>
        </div>

        {shown.length === 0 ? (
          <div className="panel">
            <EmptyState icon="search" title="No agents match">
              Clear the filter to see all {all.length} agents.
            </EmptyState>
          </div>
        ) : view === "map" ? (
          <div className="stack">
            {groups.map(([key, items]) => {
              const prov = (providers?.data ?? []).find((p) => p.slug === key);
              const status = prov?.latest_status?.status;
              return (
                <div className="panel" key={key} data-testid={`group-${key}`}>
                  <div className="panel-head">
                    <h3>
                      {group === "tier" ? `Tier ${key.slice(1)}` : label(PROVIDER_LABEL, key)} <span className="muted" style={{ fontWeight: 500 }}>· {items.length}</span>
                    </h3>
                    {status && status !== "operational" ? (
                      <Pill tone={status === "major_outage" ? "failed" : "degraded"} dot live>
                        {label({ major_outage: "Major outage", degraded_performance: "Degraded performance", partial_outage: "Partial outage" }, status)}
                      </Pill>
                    ) : group === "provider" ? (
                      <span className="caption">Operational</span>
                    ) : null}
                  </div>
                  <div className="tiles">
                    {items.map((a) => (
                      <AgentTile key={a.id} a={a} drift={driftHints.get(a.id)} />
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <AgentTable agents={shown} />
        )}
      </section>
    </div>
  );
}

function Header({ tenantName, total, counts, states }: { tenantName: string; total: number; counts: Record<string, number>; states: Record<string, number> }) {
  const moved = (states.failed_over ?? 0) + (states.failing_back ?? 0);
  return (
    <header className="page-head">
      <div>
        <div className="eyebrow">
          <span className="pill" data-tone="healthy" data-live="true" style={{ height: "auto", padding: 0, background: "none" }}>
            <span className="dot" />
          </span>
          {tenantName} · {total} agents · live
        </div>
        <h1 className="large-title">Fleet</h1>
        <p className="lede num">
          {counts.healthy ?? 0} healthy, {counts.watch ?? 0} on watch, {(counts.degraded ?? 0) + (counts.failed ?? 0)} degraded or failed.
          {moved ? ` ${moved} running on a fallback.` : " Every agent is on its primary."}
        </p>
      </div>
    </header>
  );
}

function Stat({ k, v, small, tone, href }: { k: string; v: number; small?: string; tone?: "failed" | "human" | "moved"; href?: string }) {
  const body = (
    <>
      <span className="k">{k}</span>
      <span className="v">
        {v}
        {small ? <small> {small}</small> : null}
      </span>
    </>
  );
  return href ? (
    <Link href={href} className="stat" data-tone={tone} style={{ color: "inherit", textDecoration: "none" }}>
      {body}
    </Link>
  ) : (
    <div className="stat" data-tone={tone}>
      {body}
    </div>
  );
}

function AgentTile({ a, drift }: { a: FleetAgent; drift?: AgentDriftHint }) {
  const band = a.health.band ?? null;
  const state = a.routing.state ?? "active";
  const served = a.x_console?.served_provider;
  const moved = served && a.x_console && served !== a.x_console.provider;
  return (
    <Link href={`/agents/${a.id}`} className="tile" data-band={band ?? "none"} data-testid={`tile-${a.slug}`}>
      <div className="tile-top">
        <HealthRing score={a.health.score} band={band} size={34} provisional={a.health.provisional} />
        <div className="grow">
          <div className="tile-name truncate">{a.name}</div>
          <div className="caption truncate mono">{a.slug}</div>
        </div>
      </div>
      <div className="tile-meta">
        <TierBadge tier={a.tier} />
        {state !== "active" ? <RoutingPill state={state} holdUntil={a.routing.operator_hold_until} /> : <BandPill band={band} provisional={a.health.provisional} />}
      </div>
      {moved ? (
        <div className="caption" style={{ position: "relative", display: "flex", alignItems: "center", gap: 6 }}>
          <Icon name="route" size={13} /> Serving from {label(PROVIDER_LABEL, served)}
        </div>
      ) : state === "failed_over" && a.x_console && !served ? (
        <div className="caption" style={{ position: "relative", display: "flex", alignItems: "center", gap: 6 }}>
          <Icon name="hand" size={13} /> Work handed to people
        </div>
      ) : null}
      {drift && (drift.identity || drift.verdict !== "none") ? (
        <div className="caption tile-hint" data-testid="drift-hint" style={{ color: drift.verdict === "drift" ? "var(--degraded)" : drift.verdict === "watch" ? "var(--watch)" : "var(--moved)" }}>
          <Icon name={drift.identity ? "cpu" : "activity"} size={13} />
          {drift.identity ? "Model changed" : `${VERDICT_LABEL[drift.verdict]} · behaviour`}
          {drift.identity && drift.verdict !== "none" ? ` · ${VERDICT_LABEL[drift.verdict].toLowerCase()}` : ""}
        </div>
      ) : null}
    </Link>
  );
}

function AgentTable({ agents }: { agents: FleetAgent[] }) {
  const router = useRouter();
  return (
    <div className="panel table-wrap">
      <table className="table stack">
        <thead>
          <tr>
            <th scope="col">Agent</th>
            <th scope="col">Tier</th>
            <th scope="col">Health</th>
            <th scope="col">Routing</th>
            <th scope="col" className="hide-sm">Provider</th>
            <th scope="col" className="r hide-sm">RTO</th>
          </tr>
        </thead>
        <tbody>
          {agents.map((a) => (
            <tr key={a.id} data-href={`/agents/${a.id}`} style={{ cursor: "pointer" }} onClick={() => router.push(`/agents/${a.id}`)}>
              <td>
                <Link href={`/agents/${a.id}`} style={{ color: "var(--text)", fontWeight: 600 }}>
                  {a.name}
                </Link>
                <div className="caption mono">{a.slug}</div>
              </td>
              <td>
                <TierBadge tier={a.tier} />
              </td>
              <td>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                  <HealthRing score={a.health.score} band={a.health.band ?? null} size={26} provisional={a.health.provisional} />
                  <BandPill band={a.health.band ?? null} provisional={a.health.provisional} />
                </span>
              </td>
              <td>
                <RoutingPill state={a.routing.state ?? "active"} holdUntil={a.routing.operator_hold_until} />
              </td>
              <td className="hide-sm">
                {a.x_console ? label(PROVIDER_LABEL, a.x_console.served_provider ?? a.x_console.provider) : <span className="muted">Not reported</span>}
                <div className="caption mono">{a.x_console?.served_model ?? a.x_console?.model}</div>
              </td>
              <td className="r num hide-sm">{a.continuity?.rto_s ? formatDuration(a.continuity.rto_s) : "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
