"use client";
/**
 * Finding building blocks (Sentinel and external monitors). Every finding surface wears the
 * advisory mark and the indigo dashed edge so its output never reads as a human decision or a
 * system state. Model and monitor text is untrusted content: plain text only, never HTML.
 */
import { useState } from "react";
import { useSWRConfig } from "swr";
import type { SentinelConfig, SentinelProvider } from "@/lib/api/monitor";
import type { Finding, FindingFeedback } from "@/lib/api/external-monitors";
import { ProblemError } from "@/lib/api/problem";
import { bffSend, route } from "@/lib/client/bff";
import { FEEDBACK_LABEL, PROVIDER_NAME, SEVERITY_TONE, bodyRows, budgetUsage, formatUsd } from "@/lib/sentinel/view";
import { FINDING_KIND_LABEL, externalBodyRows, plainText, sourceLabel } from "@/lib/monitors/view";
import { Icon } from "@/components/ui/Icon";
import { Pill } from "@/components/ui/StatePill";
import { useSession } from "@/components/shell/Session";

export function AdvisoryMark({ text = "Sentinel · advisory" }: { text?: string }) {
  return (
    <span className="advisory-mark" title="Advisory: never allows, blocks, approves or fails over anything">
      <Icon name="sparkle" size={12} /> {text}
    </span>
  );
}

export function KindPill({ finding }: { finding: Pick<Finding, "kind"> }) {
  return <Pill tone="advisory">{FINDING_KIND_LABEL[finding.kind]}</Pill>;
}

/** Who wrote a finding: Sentinel, or an external monitor by name. */
export function SourceTag({ finding }: { finding: Pick<Finding, "source" | "monitor_name"> }) {
  return (
    <span className="source-tag" data-source={finding.source} data-testid="finding-source">
      <Icon name={finding.source === "sentinel" ? "sparkle" : "eye"} size={12} />
      {sourceLabel(finding)}
    </span>
  );
}

export function SeverityTag({ severity }: { severity: Finding["severity"] }) {
  return (
    <Pill tone={SEVERITY_TONE[severity]} dot={severity !== "info"}>
      {severity[0]?.toUpperCase()}
      {severity.slice(1)}
    </Pill>
  );
}

/** Sentinel's own record carries the prompt hash; the unified feed does not. */
type ProvenanceInput = Finding & { prompt_sha256?: string | null; cost_estimated?: boolean | null };

export function Provenance({ f }: { f: ProvenanceInput }) {
  if (f.source === "external") {
    return (
      <div className="provenance" data-testid="provenance">
        <span>
          Reported by <b>{sourceLabel(f).replace(/^Monitor: /, "")}</b> with its monitor key
        </span>
        {f.provider || f.model ? (
          <span>
            {f.provider ? plainText(f.provider, 64) : ""}
            {f.provider && f.model ? " · " : ""}
            {f.model ? <span className="mono">{plainText(f.model, 128)}</span> : null}
          </span>
        ) : null}
        {f.confidence ? <span>{f.confidence} confidence</span> : null}
      </div>
    );
  }
  const provider = f.provider && f.provider in PROVIDER_NAME ? PROVIDER_NAME[f.provider as SentinelProvider] : (f.provider ?? "—");
  return (
    <div className="provenance" data-testid="provenance">
      <span>
        <b>{provider}</b> · <span className="mono">{f.model}</span>
      </span>
      {f.prompt_sha256 ? (
        <span>
          prompt <span className="mono">{f.prompt_sha256.slice(0, 12)}…</span>
        </span>
      ) : null}
      <span className="num">
        {f.tokens_in?.toLocaleString("en-IN") ?? "—"} in · {f.tokens_out?.toLocaleString("en-IN") ?? "—"} out
      </span>
      <span className="num">
        {formatUsd(f.cost_usd)}
        {f.cost_estimated ? " (estimated)" : ""}
      </span>
      <span>{f.trigger === "on_demand" ? "asked by a person" : "scheduled"}</span>
    </div>
  );
}

/** Sentinel's validated structured output as labelled rows. */
export function FindingBody({ f }: { f: Pick<Finding, "body"> }) {
  const rows = bodyRows(f.body);
  if (!rows.length) return null;
  return (
    <dl className="untrusted" data-label="Written by Sentinel's model · advisory" style={{ display: "flex", flexDirection: "column", gap: 12, margin: 0 }}>
      {rows.map((r) => (
        <div key={r.key}>
          <dt className="caption" style={{ fontWeight: 650, marginBottom: 3 }}>
            {r.label}
          </dt>
          <dd style={{ margin: 0 }}>
            {r.items ? (
              <ul style={{ margin: 0, paddingLeft: 18, display: "flex", flexDirection: "column", gap: 3 }}>
                {r.items.map((it, i) => (
                  <li key={i}>{it}</li>
                ))}
              </ul>
            ) : r.flag !== null ? (
              <span>{r.flag ? "Yes" : "No"}</span>
            ) : (
              <span style={{ whiteSpace: "pre-wrap" }}>{r.text}</span>
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}

/**
 * An external monitor's free-form body: untrusted text in the fenced frame, never HTML,
 * markdown or links (lib/monitors/view.ts `externalBodyRows` strips direction overrides).
 */
export function ExternalBody({ f }: { f: Pick<Finding, "body" | "source" | "monitor_name"> }) {
  const rows = externalBodyRows(f.body);
  if (!rows.length) return <p className="muted">The monitor sent no detail beyond the summary.</p>;
  return (
    <dl className="untrusted" data-label={`Written by ${sourceLabel(f)} · untrusted · advisory`} style={{ display: "flex", flexDirection: "column", gap: 12, margin: 0 }} data-testid="external-body">
      {rows.map((r) => (
        <div key={r.key}>
          <dt className="caption" style={{ fontWeight: 650, marginBottom: 3 }}>
            {r.label}
          </dt>
          <dd style={{ margin: 0 }}>
            {r.items ? (
              <ul style={{ margin: 0, paddingLeft: 18, display: "flex", flexDirection: "column", gap: 3 }}>
                {r.items.map((it, i) => (
                  <li key={i}>{it}</li>
                ))}
              </ul>
            ) : r.flag !== null ? (
              <span>{r.flag ? "Yes" : "No"}</span>
            ) : (
              <span style={{ whiteSpace: "pre-wrap" }}>{r.text}</span>
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}

export function FeedbackButtons({ f }: { f: Pick<Finding, "id" | "feedback"> }) {
  const s = useSession();
  const { mutate } = useSWRConfig();
  const [busy, setBusy] = useState<FindingFeedback | null>(null);
  const [error, setError] = useState<string | null>(null);
  if (!s.can("sentinel:read")) return null;
  const send = async (feedback: FindingFeedback): Promise<void> => {
    setBusy(feedback);
    setError(null);
    try {
      await bffSend(route("/findings/{finding_id}/feedback", { finding_id: f.id }), { feedback });
      await mutate((key) => typeof key === "string" && (key.startsWith("/sentinel") || key.startsWith("/findings")));
    } catch (err) {
      setError(err instanceof ProblemError ? (err.problem.detail ?? err.problem.title) : "Not recorded.");
    } finally {
      setBusy(null);
    }
  };
  return (
    <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }} data-testid="feedback">
      <span className="caption">Was this useful?</span>
      {(Object.keys(FEEDBACK_LABEL) as FindingFeedback[]).map((k) => (
        <button key={k} type="button" className="btn btn-sm" aria-pressed={f.feedback === k} disabled={busy !== null} onClick={() => void send(k)} data-testid={`feedback-${k}`} style={f.feedback === k ? { boxShadow: "inset 0 0 0 1.5px var(--advisory-dot)" } : undefined}>
          {busy === k ? <span className="spinner" aria-hidden /> : k === "useful" ? <Icon name="thumbsUp" size={13} /> : null}
          {FEEDBACK_LABEL[k]}
        </button>
      ))}
      {error ? (
        <span className="caption" role="alert" style={{ color: "var(--failed)" }}>
          {error}
        </span>
      ) : null}
    </div>
  );
}

export function BudgetMeter({ config }: { config: SentinelConfig | null | undefined }) {
  const u = budgetUsage(config);
  return (
    <div className="budget stack" style={{ gap: 6 }} data-exhausted={u.exhausted ? "true" : undefined} data-testid="budget">
      <div style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
        <span className="title-sm num">
          {formatUsd(u.spent)} <span className="caption">of {u.budget !== null ? formatUsd(u.budget) : "no budget"} today</span>
        </span>
        <span className="caption num">
          {u.findings} findings · {u.calls} calls · {u.skipped} skipped by sampling
        </span>
      </div>
      <div className="meter" role="meter" aria-label="Today's Sentinel spend" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round((u.share ?? 0) * 100)}>
        <span style={{ transform: `scaleX(${u.share ?? 0})` }} />
      </div>
      {u.exhausted ? <span className="caption" style={{ color: "var(--failed)" }}>Today&apos;s budget is spent: Sentinel pauses until midnight UTC. Nothing else is affected.</span> : null}
    </div>
  );
}
