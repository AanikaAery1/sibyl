"use client";
/**
 * Findings (D52 + D53): every explanation, review and summary Sentinel wrote, next to the
 * findings external monitors reported, newest first, from the unified `GET /findings`. Each row
 * says who wrote it. Advisory only; the page says so before anything else. Monitor-written text
 * is untrusted and rendered as plain text.
 */
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import type { SentinelConfig } from "@/lib/api/monitor";
import type { Finding, FindingKind } from "@/lib/api/external-monitors";
import type { AgentSummary, Page } from "@/lib/api/types";
import { useBff } from "@/hooks/useBff";
import { ADVISORY_COPY, ALL_TASKS, SENTINEL_CONFIG_PATH, KIND_LABEL, PROVIDER_NAME, formatUsd } from "@/lib/sentinel/view";
import { FINDING_SUBJECT_LABEL, findingsFeedPath, plainText, type SourceFilter } from "@/lib/monitors/view";
import { EmptyState } from "@/components/ui/Bits";
import { Icon } from "@/components/ui/Icon";
import { Ago } from "@/components/ui/Time";
import { DemoMark } from "@/components/ui/DemoMark";
import { useSession } from "@/components/shell/Session";
import { AdvisoryMark, BudgetMeter, KindPill, SeverityTag, SourceTag } from "./Bits";

const SOURCES: readonly { key: SourceFilter; label: string; testId: string }[] = [
  { key: null, label: "All sources", testId: "source-all" },
  { key: "sentinel", label: "Sentinel", testId: "source-sentinel" },
  { key: "external", label: "Monitors", testId: "source-external" },
];

function rowMeta(f: Finding): string {
  if (f.source === "sentinel") return `${f.model ?? ""} · ${formatUsd(f.cost_usd)} · ${(f.tokens_in ?? 0) + (f.tokens_out ?? 0)} tokens`;
  const model = [f.provider, f.model].filter(Boolean).map((x) => plainText(x, 128)).join(" · ");
  return [model || "external monitor", f.confidence ? `${f.confidence} confidence` : null].filter(Boolean).join(" · ");
}

export function FindingsView({ initial, initialConfig, kind, source }: { initial: Page<Finding> | null; initialConfig: SentinelConfig | null; kind: FindingKind | null; source: SourceFilter }) {
  const s = useSession();
  const router = useRouter();
  const params = useSearchParams();
  const can = s.can("sentinel:read");
  const path = findingsFeedPath({ source, kind });
  const { data, error } = useBff<Page<Finding>>(can ? path : null, initial);
  const { data: config } = useBff<SentinelConfig>(can ? SENTINEL_CONFIG_PATH : null, initialConfig);
  const { data: agents } = useBff<Page<AgentSummary>>("/agents?limit=200");
  const names = new Map((agents?.data ?? []).map((a) => [a.id, a.name]));
  const rows = data?.data ?? [];

  const setParam = (k: "kind" | "source", v: string | null): void => {
    const next = new URLSearchParams(params.toString());
    if (v) next.set(k, v);
    else next.delete(k);
    router.replace(`/sentinel${next.toString() ? `?${next}` : ""}`, { scroll: false });
  };

  if (!can) {
    return (
      <div className="page">
        <h1 className="large-title">Sentinel</h1>
        <div className="panel">
          <EmptyState icon="lock" title="Sentinel is restricted">
            Your role ({s.roleLabels.join(" + ") || "none"}) cannot read Sentinel findings.
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
            <AdvisoryMark text="Monitor · advisory AI" /> <DemoMark paths={[path, SENTINEL_CONFIG_PATH]} />
          </div>
          <h1 className="large-title">Sentinel</h1>
          <p className="lede">
            {config?.configured
              ? `${config.enabled ? "On" : "Off"} · ${config.provider ? PROVIDER_NAME[config.provider] : ""} ${config.model ?? ""} on your own key. Explains incidents, reviews held actions for the approver, reads sampled runs for semantic drift and summarises the fleet.`
              : "Not set up. Sentinel runs on your own Anthropic, OpenAI or Gemini key, within a daily budget."}{" "}
            External monitors report here too.
          </p>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <Link className="btn" href="/monitors" data-testid="sentinel-monitors">
            <Icon name="eye" size={15} /> Monitors
          </Link>
          {s.can("sentinel:admin") ? (
            <Link className="btn" href="/settings/sentinel" data-testid="sentinel-setup">
              <Icon name="settings" size={15} /> Set up
            </Link>
          ) : null}
        </div>
      </header>

      <div className="banner" data-tone="advisory" role="note" data-testid="advisory-note">
        <Icon name="sparkle" size={16} />
        <span>{ADVISORY_COPY} External monitors are advisory in exactly the same way.</span>
      </div>

      {config?.configured ? (
        <section className="panel panel-pad" aria-label="Today's budget">
          <BudgetMeter config={config} />
        </section>
      ) : null}

      <section className="section" aria-labelledby="findings-title">
        <div className="section-title" style={{ flexWrap: "wrap", gap: 10 }}>
          <h2 id="findings-title">Findings</h2>
          <div className="seg" role="group" aria-label="Source">
            {SOURCES.map((o) => (
              <button key={o.testId} type="button" aria-pressed={source === o.key} onClick={() => setParam("source", o.key)} data-testid={o.testId}>
                {o.label}
              </button>
            ))}
          </div>
          <div className="seg" role="group" aria-label="Kind">
            <button type="button" aria-pressed={!kind} onClick={() => setParam("kind", null)}>
              All
            </button>
            {ALL_TASKS.map((k) => (
              <button key={k} type="button" aria-pressed={kind === k} onClick={() => setParam("kind", k)} data-testid={`kind-${k}`}>
                {KIND_LABEL[k]}
              </button>
            ))}
          </div>
        </div>
        <div className="panel">
          {error ? (
            <EmptyState icon="lock" title="Not permitted" />
          ) : rows.length === 0 ? (
            <EmptyState icon="sparkle" title="No findings yet">
              {source === "external" ? "Findings appear here when a registered monitor reports one." : config?.enabled ? "Findings appear as Sentinel explains incidents, reviews held actions and samples runs." : "Turn Sentinel on in its settings to get explanations and reviews."}
            </EmptyState>
          ) : (
            rows.map((f) => {
              const subject = f.agent_id ? names.get(f.agent_id) : null;
              const external = f.source === "external";
              return (
                <Link key={f.id} href={`/sentinel/${f.id}`} className="row" data-testid="finding-row" data-source={f.source} style={{ alignItems: "flex-start" }}>
                  <span className="rt-glyph" aria-hidden style={{ background: "var(--advisory-tint)", color: "var(--advisory)", marginTop: 2 }}>
                    <Icon name={external ? "eye" : "sparkle"} size={13} />
                  </span>
                  <div className="grow" style={{ minWidth: 0, display: "flex", flexDirection: "column", gap: 5 }}>
                    <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                      <SourceTag finding={f} />
                      <KindPill finding={f} />
                      <SeverityTag severity={f.severity} />
                      <span className="caption">
                        {FINDING_SUBJECT_LABEL[f.subject_kind]}
                        {subject ? ` · ${subject}` : ""}
                      </span>
                    </div>
                    <div className="title-sm" style={{ fontWeight: 550, overflowWrap: "anywhere" }}>
                      {external ? plainText(f.summary, 400) : f.summary}
                    </div>
                    <div className="caption mono">
                      {rowMeta(f)}
                      {f.feedback ? ` · rated ${f.feedback.replace("_", " ")}` : ""}
                    </div>
                  </div>
                  <span className="caption" style={{ flex: "none" }}>
                    <Ago at={f.created_at} />
                  </span>
                </Link>
              );
            })
          )}
        </div>
      </section>
    </div>
  );
}
