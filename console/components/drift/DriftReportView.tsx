"use client";
/** One immutable drift report: every feature's numbers, identity findings and the config used. */
import Link from "next/link";
import type { DriftReport } from "@/lib/api/monitor";
import type { AgentSummary } from "@/lib/api/types";
import { useBff } from "@/hooks/useBff";
import { IDENTITY_HELP, IDENTITY_LABEL, formatStat } from "@/lib/drift/view";
import { PROVIDER_LABEL, label } from "@/lib/labels";
import { EmptyState } from "@/components/ui/Bits";
import { Icon } from "@/components/ui/Icon";
import { DateTime } from "@/components/ui/Time";
import { DemoMark } from "@/components/ui/DemoMark";
import { useSession } from "@/components/shell/Session";
import { FeatureTable, IdentityFlag, VerdictPill, WatchOnlyNote } from "./Bits";

export function DriftReportView({ id, initial }: { id: string; initial: DriftReport | null }) {
  const s = useSession();
  const path = `/drift/reports/${id}`;
  const { data: r } = useBff<DriftReport>(s.can("drift:read") ? path : null, initial);
  const { data: agent } = useBff<AgentSummary>(r ? `/agents/${r.agent_id}` : null);
  if (!r) {
    return (
      <div className="page">
        <Link href="/drift" className="caption">
          ← Model drift
        </Link>
        <div className="panel">
          <EmptyState icon="search" title="Report not found">
            Drift reports are kept for 30 days.
          </EmptyState>
        </div>
      </div>
    );
  }
  return (
    <div className="page">
      <header>
        <Link href={agent ? `/agents/${agent.id}` : "/drift"} className="eyebrow" style={{ textDecoration: "none", color: "var(--text-2)" }}>
          <Icon name="arrowLeft" size={12} /> {agent?.name ?? "Model drift"} <DemoMark paths={[path]} />
        </Link>
        <h1 className="large-title">Drift report</h1>
        <p className="lede">
          {label(PROVIDER_LABEL, r.provider)} · <span className="mono">{r.model}</span> · evaluated <DateTime at={r.evaluated_at} /> over {r.sample_count.toLocaleString("en-IN")} calls · worst excess {formatStat(r.max_ratio)}× the drift line
        </p>
        <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 8 }}>
          <VerdictPill verdict={r.verdict} />
          {r.identity_changed ? <IdentityFlag /> : null}
        </div>
      </header>
      <WatchOnlyNote />
      {r.identity.map((i) => (
        <div key={`${i.kind}-${i.value}`} className="banner" data-tone="moved">
          <Icon name="cpu" size={16} />
          <span>
            <strong>{IDENTITY_LABEL[i.kind]}:</strong> <span className="mono">{i.value}</span> on {i.count} calls. {IDENTITY_HELP[i.kind]}
          </span>
        </div>
      ))}
      <section className="panel" aria-label="Features">
        <FeatureTable features={r.features} />
      </section>
      {r.config ? (
        <details className="panel">
          <summary className="row" style={{ cursor: "pointer" }}>
            <span className="title-sm">Windows, minimum samples and hysteresis used</span>
          </summary>
          <pre className="code" style={{ margin: "0 var(--row-x) 16px" }}>
            {JSON.stringify(r.config, null, 2)}
          </pre>
        </details>
      ) : null}
    </div>
  );
}
