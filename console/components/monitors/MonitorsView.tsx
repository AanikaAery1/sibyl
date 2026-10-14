"use client";
/**
 * External monitors (D53): outside agents (an MCP assistant, a webhook receiver, a script on the
 * REST API) registered to watch the fleet and report advisory findings next to Sentinel's.
 * `monitors:admin` registers them; `sentinel:read` holders see the list read-only.
 */
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";
import type { AgentGroup, Monitor } from "@/lib/api/external-monitors";
import type { Page } from "@/lib/api/types";
import { useBff } from "@/hooks/useBff";
import { AGENT_GROUPS_PATH, MONITORS_PATH, MONITOR_ADVISORY_COPY, filterMonitors, monitorCounts, watchedLabel, webhookHealth, type StateFilter } from "@/lib/monitors/view";
import { EmptyState } from "@/components/ui/Bits";
import { Icon } from "@/components/ui/Icon";
import { Ago } from "@/components/ui/Time";
import { DemoMark } from "@/components/ui/DemoMark";
import { useSession } from "@/components/shell/Session";
import { AdvisoryMark } from "@/components/sentinel/Bits";
import { DeliveryPill, MonitorKindTag, MonitorStatePill } from "./Bits";
import { RegisterMonitor } from "./RegisterMonitor";

const FILTERS: readonly [StateFilter, string][] = [
  ["all", "All"],
  ["active", "Active"],
  ["paused", "Paused"],
  ["revoked", "Revoked"],
];

const linkStyle = { textDecoration: "underline", textUnderlineOffset: 2 } as const;

function Stat({ k, v, tone, small }: { k: string; v: number; tone?: "failed" | "watch"; small?: string }) {
  return (
    <div className="stat">
      <span className="k">{k}</span>
      <span className="v" style={tone && v ? { color: `var(--${tone})` } : undefined}>
        {v}
        {small ? <small> {small}</small> : null}
      </span>
    </div>
  );
}

function MonitorRow({ m, groups }: { m: Monitor; groups: ReadonlyMap<string, string> }) {
  const health = webhookHealth(m.webhooks);
  return (
    <Link href={`/monitors/${m.id}`} className="row" data-testid="monitor-row" data-state={m.state} style={{ alignItems: "flex-start"}}>
      <span className="rt-glyph" aria-hidden style={{ background: "var(--advisory-tint)", color: "var(--advisory)", marginTop: 2 }}>
        <Icon name="eye" size={13} />
      </span>
      <div className="grow" style={{ minWidth: 0, display: "flex", flexDirection: "column", gap: 5 }}>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <span className="title-sm" style={{ overflowWrap: "anywhere" }}>
            {m.name}
          </span>
          <MonitorKindTag kind={m.kind} />
          <MonitorStatePill state={m.state} />
        </div>
        <div className="caption" style={{ display: "flex", gap: "4px 12px", flexWrap: "wrap" }}>
          <span data-testid="monitor-watches">{watchedLabel(m, groups)}</span>
          <span className="num">
            {m.keys.length} {m.keys.length === 1 ? "key" : "keys"}
          </span>
          <span className="num">{m.rate_limit_per_min}/min</span>
        </div>
        {m.webhooks.length ? (
          <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }} data-testid="monitor-webhooks">
            <span className="caption">
              {m.webhooks.length} {m.webhooks.length === 1 ? "webhook" : "webhooks"}
            </span>
            <DeliveryPill status={health} />
          </div>
        ) : null}
      </div>
      <div style={{ flex: "none", display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 3, textAlign: "right" }}>
        <span className="title-sm num" data-testid="monitor-findings-24h">
          {m.findings_24h ?? 0}
          <span className="caption"> in 24 h</span>
        </span>
        <span className="caption">{m.last_finding_at ? <Ago at={m.last_finding_at} /> : "no findings yet"}</span>
      </div>
    </Link>
  );
}

export function MonitorsView({ initial, state }: { initial: Page<Monitor> | null; state: StateFilter }) {
  const s = useSession();
  const router = useRouter();
  const params = useSearchParams();
  const canRead = s.can("monitors:admin") || s.can("sentinel:read");
  const canAdmin = s.can("monitors:admin");
  const { data, error } = useBff<Page<Monitor>>(canRead ? MONITORS_PATH : null, initial);
  const { data: groups } = useBff<Page<AgentGroup>>(canRead ? AGENT_GROUPS_PATH : null);
  const [registering, setRegistering] = useState(false);
  const all = data?.data ?? [];
  const rows = filterMonitors(all, state);
  const counts = monitorCounts(all);
  const groupNames = new Map((groups?.data ?? []).map((g) => [g.id, g.name]));

  const setState = (v: StateFilter): void => {
    const next = new URLSearchParams(params.toString());
    if (v === "all") next.delete("state");
    else next.set("state", v);
    router.replace(`/monitors${next.toString() ? `?${next}` : ""}`, { scroll: false });
  };

  if (!canRead) {
    return (
      <div className="page">
        <h1 className="large-title">Monitors</h1>
        <div className="panel">
          <EmptyState icon="lock" title="Monitors are restricted">
            Your role ({s.roleLabels.join(" + ") || "none"}) cannot see external monitors.
          </EmptyState>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <div className="eyebrow">
            <AdvisoryMark text="Monitor · advisory agents" /> <DemoMark paths={[MONITORS_PATH]} />
          </div>
          <h1 className="large-title">Monitors</h1>
          <p className="lede">
            Outside agents that watch the fleet with a monitor key: an MCP assistant, a webhook receiver or a script on the REST API. Their findings appear on{" "}
            <Link href="/sentinel?source=external" style={linkStyle}>
              Sentinel
            </Link>{" "}
            and beside the decisions they concern.
          </p>
        </div>
        {canAdmin ? (
          <button type="button" className="btn btn-primary" onClick={() => setRegistering(true)} data-testid="monitor-register-open">
            <Icon name="plus" size={15} /> Register monitor
          </button>
        ) : null}
      </header>

      <div className="banner" data-tone="advisory" role="note" data-testid="monitor-advisory">
        <Icon name="eye" size={16} />
        <span>{MONITOR_ADVISORY_COPY}</span>
      </div>

      {!canAdmin ? (
        <p className="caption" data-testid="monitors-read-only">
          Read-only: registering, pausing and revoking monitors needs the monitors:admin permission.
        </p>
      ) : null}

      <section className="panel" aria-label="Monitor summary">
        <div className="stats">
          <Stat k="Active" v={counts.active} small={`of ${counts.total - counts.revoked}`} />
          <Stat k="Paused" v={counts.paused} tone="watch" />
          <Stat k="Findings, 24 h" v={counts.findings24h} />
          <Stat k="Failing webhooks" v={counts.failingWebhooks} tone="failed" />
        </div>
      </section>

      <section className="section" aria-labelledby="monitors-title">
        <div className="section-title" style={{ flexWrap: "wrap", gap: 10 }}>
          <h2 id="monitors-title">Registered monitors</h2>
          <div className="seg" role="group" aria-label="State">
            {FILTERS.map(([k, l]) => (
              <button key={k} type="button" aria-pressed={state === k} onClick={() => setState(k)} data-testid={`monitor-filter-${k}`}>
                {l}{" "}
                <span className="count">{k === "all" ? counts.total : counts[k]}</span>
              </button>
            ))}
          </div>
        </div>
        <div className="panel">
          {error ? (
            <EmptyState icon="lock" title="Not permitted" />
          ) : rows.length === 0 ? (
            <EmptyState icon="eye" title={all.length ? "No monitors in this state" : "No monitors yet"}>
              {all.length ? "Pick another filter." : "Register one to let your own Claude, OpenAI or Gemini agent, an MCP assistant or a script watch the fleet. Sentinel is the built-in monitor."}
            </EmptyState>
          ) : (
            rows.map((m) => <MonitorRow key={m.id} m={m} groups={groupNames} />)
          )}
        </div>
      </section>

      {canAdmin ? <RegisterMonitor open={registering} onClose={() => setRegistering(false)} /> : null}
    </div>
  );
}
