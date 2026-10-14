"use client";
/** One provider incident instead of N alerts (B3): blast radius and tiered failover progress. */
import Link from "next/link";
import type { Provider, ProviderIncident } from "@/lib/api/types";
import { Ago } from "@/components/ui/Time";
import { Pill, TierBadge } from "@/components/ui/StatePill";
import { Icon } from "@/components/ui/Icon";
import type { FleetAgent } from "./types";

export function ProviderIncidentCard({ incident, agents, provider }: { incident: ProviderIncident; agents: FleetAgent[]; provider?: Provider }) {
  const members = agents.filter((a) => incident.affected_agent_ids.includes(a.id));
  const moved = members.filter((a) => a.routing.state === "failed_over" || a.routing.state === "failing_back");
  const processes = [...new Set(members.map((a) => a.x_console?.process).filter(Boolean))];
  const pct = members.length ? moved.length / members.length : 0;
  return (
    <section className="panel" aria-labelledby={`pi-${incident.id}`} data-testid="provider-incident">
      <div className="panel-pad" style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "flex-start", justifyContent: "space-between", gap: 12 }}>
          <div>
            <Pill tone="failed" dot live>
              Provider incident · opened <Ago at={incident.opened_at} />
            </Pill>
            <h2 id={`pi-${incident.id}`} style={{ marginTop: 10, fontSize: "var(--fs-title1)", fontWeight: 700, letterSpacing: "var(--track-title)" }}>
              {provider?.name ?? "Provider"} major outage
            </h2>
            <p className="subtle" style={{ marginTop: 4 }}>
              {members.length} agents on one incident.{processes.length ? ` ${processes.length} business processes in the blast radius: ${processes.join(", ")}.` : ""}
            </p>
          </div>
          <Link className="btn" href="/incidents">
            Open incidents <Icon name="chevronRight" size={14} />
          </Link>
        </div>
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 6 }}>
            <span className="subtle">Failover by tier (T1 ≤ 60 s, T2 ≤ 90 s, T3 ≤ 120 s)</span>
            <span className="num" style={{ fontWeight: 650 }}>
              {moved.length} of {members.length} moved
            </span>
          </div>
          <div className="meter" role="progressbar" aria-valuemin={0} aria-valuemax={members.length} aria-valuenow={moved.length} aria-label="Agents failed over">
            <span style={{ transform: `scaleX(${pct})`, ["--meter" as string]: "var(--moved-dot)" } as React.CSSProperties} />
          </div>
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          {members
            .slice()
            .sort((x, y) => x.tier - y.tier)
            .map((a) => (
              <Link key={a.id} href={`/agents/${a.id}`} className="tag" style={{ height: 28, padding: "0 10px", gap: 8, background: a.routing.state === "failed_over" ? "var(--moved-tint)" : "var(--failed-tint)", color: a.routing.state === "failed_over" ? "var(--moved)" : "var(--failed)", textDecoration: "none" }}>
                <TierBadge tier={a.tier} />
                {a.name}
                <Icon name={a.routing.state === "failed_over" ? "check" : "clock"} size={13} />
              </Link>
            ))}
        </div>
      </div>
    </section>
  );
}
