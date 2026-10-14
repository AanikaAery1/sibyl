"use client";
/**
 * Model drift across the fleet (D51): one row per agent + provider + requested model with its
 * latest verdict, identity changes highlighted, drifting features named. Filters live in the URL.
 * Watch-only: this screen links to the evidence; it has no actions that move traffic.
 */
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import type { DriftPage } from "@/lib/api/monitor";
import { useBff } from "@/hooks/useBff";
import { DRIFT_FLEET_PATH, FEATURE_LABEL, filterAndSort, parseDriftQuery, summaryOf, type DriftFilter } from "@/lib/drift/view";
import { PROVIDER_LABEL, label } from "@/lib/labels";
import { EmptyState } from "@/components/ui/Bits";
import { Icon } from "@/components/ui/Icon";
import { Ago } from "@/components/ui/Time";
import { DemoMark } from "@/components/ui/DemoMark";
import { useSession } from "@/components/shell/Session";
import { IdentityFlag, VerdictPill, WatchOnlyNote } from "./Bits";

const FILTERS: [DriftFilter, string][] = [
  ["all", "All"],
  ["drift", "Drift"],
  ["watch", "Watch"],
  ["identity", "Model changed"],
  ["collecting", "Collecting"],
];

export function DriftFleetView({ initial }: { initial: DriftPage | null }) {
  const s = useSession();
  const router = useRouter();
  const params = useSearchParams();
  const query = parseDriftQuery(params);
  const can = s.can("drift:read");
  const { data, error } = useBff<DriftPage>(can ? DRIFT_FLEET_PATH : null, initial);
  const all = data?.data ?? [];
  const summary = summaryOf(all, data?.summary);
  const rows = filterAndSort(all, query);

  const setParam = (k: string, v: string | null): void => {
    const next = new URLSearchParams(params.toString());
    if (!v || v === "all") next.delete(k);
    else next.set(k, v);
    router.replace(`/drift${next.toString() ? `?${next}` : ""}`, { scroll: false });
  };

  if (!can) {
    return (
      <div className="page">
        <h1 className="large-title">Model drift</h1>
        <div className="panel">
          <EmptyState icon="lock" title="Drift is restricted">
            Your role ({s.roleLabels.join(" + ") || "none"}) cannot read drift reports.
          </EmptyState>
        </div>
      </div>
    );
  }

  const count = (f: DriftFilter): number => (f === "all" ? summary.baselines : f === "drift" ? summary.drift : f === "watch" ? summary.watch : f === "identity" ? summary.identity_changed : summary.collecting);

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <div className="eyebrow">
            Monitor · deterministic, no LLM in the path <DemoMark paths={[DRIFT_FLEET_PATH]} />
          </div>
          <h1 className="large-title">Model drift</h1>
          <p className="lede num">
            {summary.drift || summary.watch || summary.identity_changed
              ? `${summary.drift} drifting, ${summary.watch} on watch, ${summary.identity_changed} served a model the baseline never saw.`
              : "Every agent behaves like its baseline."}{" "}
            Each agent is compared with its own frozen baseline every 10 minutes.
          </p>
        </div>
      </header>

      <WatchOnlyNote />

      <section className="panel" aria-label="Drift summary">
        <div className="stats">
          <Stat k="Baselines" v={summary.baselines} small={`${summary.frozen} frozen`} />
          <Stat k="Drift" v={summary.drift} tone={summary.drift ? "degraded" : undefined} />
          <Stat k="Watch" v={summary.watch} tone={summary.watch ? "watch" : undefined} />
          <Stat k="Model changed" v={summary.identity_changed} tone={summary.identity_changed ? "moved" : undefined} />
          <Stat k="Collecting" v={summary.collecting} />
          {summary.open_alerts !== undefined ? <Stat k="Open drift alerts" v={summary.open_alerts} href="/alerts" /> : null}
        </div>
      </section>

      <section className="section" aria-labelledby="drift-keys">
        <div className="section-title" style={{ flexWrap: "wrap", gap: 10, alignItems: "center" }}>
          <h2 id="drift-keys">Agents and models</h2>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center", maxWidth: "100%" }}>
            <label className="sr-only" htmlFor="drift-search">
              Filter by agent or model
            </label>
            <input id="drift-search" className="input" style={{ width: 200, minHeight: 34, height: 34, borderRadius: 999 }} placeholder="Agent or model" defaultValue={query.q} onChange={(e) => setParam("q", e.target.value)} />
            <div className="seg" role="group" aria-label="Show">
              {FILTERS.map(([f, l]) => (
                <button key={f} type="button" aria-pressed={query.filter === f} onClick={() => setParam("filter", f)} data-testid={`drift-filter-${f}`}>
                  {l} <span className="count">{count(f)}</span>
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="panel">
          {error ? (
            <EmptyState icon="lock" title="Not permitted" />
          ) : rows.length === 0 ? (
            <EmptyState icon="activity" title={all.length ? "Nothing matches" : "No baselines yet"}>
              {all.length ? "Clear the filter to see every baseline." : "A baseline starts collecting when an agent's first model call arrives and freezes after 500 calls over at least 6 hours."}
            </EmptyState>
          ) : (
            rows.map((r) => (
              <Link key={r.baseline_id} href={`/agents/${r.agent_id}?tab=drift`} className="row" data-testid="drift-row" data-verdict={r.verdict ?? "none"}>
                <div className="grow" style={{ minWidth: 0, display: "flex", flexDirection: "column", gap: 4 }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
                    <span className="title-sm">{r.agent_name ?? "Agent"}</span>
                    <span className="caption mono">
                      {label(PROVIDER_LABEL, r.provider)} · {r.model}
                    </span>
                  </div>
                  <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                    {r.identity_changed ? <IdentityFlag /> : null}
                    {(r.drifting_features ?? []).map((f) => (
                      <span key={f} className="tag">
                        {FEATURE_LABEL[f]}
                      </span>
                    ))}
                    {r.state === "collecting" ? <span className="caption num">{r.sample_count ?? 0} of 500 calls collected</span> : null}
                    {r.state === "frozen" && !r.drifting_features?.length && !r.identity_changed ? <span className="caption">All features inside their thresholds</span> : null}
                  </div>
                </div>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 6, flex: "none" }}>
                  <VerdictPill verdict={r.verdict} collecting={r.state === "collecting"} />
                  <span className="caption">{r.evaluated_at ? <Ago at={r.evaluated_at} /> : "not evaluated yet"}</span>
                </div>
                <Icon name="chevronRight" size={14} />
              </Link>
            ))
          )}
        </div>
      </section>
    </div>
  );
}

function Stat({ k, v, small, tone, href }: { k: string; v: number; small?: string; tone?: "degraded" | "watch" | "moved"; href?: string }) {
  const style = tone ? { color: `var(--${tone})` } : undefined;
  const body = (
    <>
      <span className="k">{k}</span>
      <span className="v" style={style}>
        {v}
        {small ? <small> {small}</small> : null}
      </span>
    </>
  );
  return href ? (
    <Link href={href} className="stat" style={{ color: "inherit", textDecoration: "none" }}>
      {body}
    </Link>
  ) : (
    <div className="stat">{body}</div>
  );
}
