"use client";
/**
 * An agent's drift (D51): the baseline per provider + model (state, window, samples), the latest
 * report's per-feature numbers, the served-model and fingerprint history with identity findings,
 * recent verdicts, open drift alerts, and "Reset baseline" (drift:write, reason required,
 * audited `drift.baseline_reset`). Watch-only throughout.
 */
import Link from "next/link";
import { useMemo, useState } from "react";
import { useSWRConfig } from "swr";
import type { AgentDrift, DriftBaseline, DriftBaselineResetResult, DriftReport } from "@/lib/api/monitor";
import { ProblemError } from "@/lib/api/problem";
import { bffSend } from "@/lib/client/bff";
import { useBff } from "@/hooks/useBff";
import { BASELINE_STATE_LABEL, DRIFT_HISTORY, DRIFT_RANGE_HOURS, IDENTITY_HELP, IDENTITY_LABEL, VERDICT_LABEL, agentDriftPath, driftHistoryHasMore, servedHistory, type DriftHistoryRange } from "@/lib/drift/view";
import { sinceHours } from "@/lib/audit-query";
import { serverNow } from "@/lib/client/sources";
import { PROVIDER_LABEL, label } from "@/lib/labels";
import { ruleLabel } from "@/lib/health/scoring";
import { Icon } from "@/components/ui/Icon";
import { Layer } from "@/components/ui/Layer";
import { Pill } from "@/components/ui/StatePill";
import { Ago, Clock, DateTime } from "@/components/ui/Time";
import { DemoMark } from "@/components/ui/DemoMark";
import { useToast } from "@/components/ui/Toast";
import { useSession } from "@/components/shell/Session";
import { FeatureTable, IdentityFlag, VerdictPill, WatchOnlyNote } from "./Bits";

const MIN_REASON = 10;

export function AgentDriftPanel({ agentId, agentName }: { agentId: string; agentName: string }) {
  const s = useSession();
  // History paging (`since`, `limit`): the window is fixed when chosen so the read key stays stable.
  const [range, setRange] = useState<{ key: DriftHistoryRange; since: string | null }>({ key: "recent", since: null });
  const [limit, setLimit] = useState<number>(DRIFT_HISTORY.default);
  const path = agentDriftPath(agentId, { since: range.since, limit });
  const { data, error } = useBff<AgentDrift>(s.can("drift:read") ? path : null);
  const [resetOpen, setResetOpen] = useState(false);
  const chooseRange = (key: DriftHistoryRange): void => {
    const hours = DRIFT_RANGE_HOURS[key];
    setRange({ key, since: hours === null ? null : sinceHours(serverNow(), hours) });
    setLimit(DRIFT_HISTORY.default);
  };

  if (!s.can("drift:read")) return null;

  const current = (data?.baselines ?? []).filter((b) => b.state !== "superseded");
  const superseded = (data?.baselines ?? []).filter((b) => b.state === "superseded");
  const served = data ? servedHistory(data) : [];

  return (
    <section className="section" aria-labelledby="drift-title" data-testid="agent-drift">
      <div className="section-title">
        <h2 id="drift-title">
          Model drift <DemoMark paths={[path]} />
        </h2>
        <div className="meta" style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <Link href="/drift">Fleet drift</Link>
          {s.can("drift:write") && current.length ? (
            <button type="button" className="btn btn-sm" onClick={() => setResetOpen(true)} data-testid="drift-reset-open">
              <Icon name="replay" size={14} /> Reset baseline
            </button>
          ) : null}
        </div>
      </div>

      {error ? (
        <div className="panel panel-pad muted">Drift is not available for this agent.</div>
      ) : !data ? (
        <div className="panel panel-pad muted">Loading drift…</div>
      ) : (
        <div className="stack">
          {data.open_alerts.length ? (
            <div className="banner" data-tone="watch" role="status" data-testid="drift-alerts">
              <Icon name="bell" size={16} />
              <span className="grow">
                {data.open_alerts.map((a) => (
                  <span key={a.id} style={{ display: "block" }}>
                    <strong>{ruleLabel(a.rule)}</strong> since <Clock at={a.first_fired_at} seconds={false} />
                    {a.summary ? ` · ${a.summary}` : ""}
                  </span>
                ))}
              </span>
              <Link href={`/alerts?agent_id=${agentId}`} className="caption" style={{ color: "inherit", textDecoration: "underline", fontWeight: 600 }}>
                Alerts
              </Link>
            </div>
          ) : null}
          <WatchOnlyNote compact />

          {current.length ? (
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }} data-testid="drift-history-controls">
              <div className="seg" role="group" aria-label="Verdict history">
                {(
                  [
                    ["recent", "Latest"],
                    ["24h", "Last 24 h"],
                    ["7d", "Last 7 days"],
                  ] as const
                ).map(([k, l]) => (
                  <button key={k} type="button" aria-pressed={range.key === k} onClick={() => chooseRange(k)} data-testid={`drift-range-${k}`}>
                    {l}
                  </button>
                ))}
              </div>
              <span className="caption num grow" data-testid="drift-history-count">
                {data.history.length} {data.history.length === 1 ? "evaluation" : "evaluations"}
              </span>
              {driftHistoryHasMore(data.history.length, limit) ? (
                <button type="button" className="btn btn-sm" onClick={() => setLimit((n) => Math.min(DRIFT_HISTORY.max, n + DRIFT_HISTORY.step))} data-testid="drift-history-more">
                  Show earlier
                </button>
              ) : null}
            </div>
          ) : null}
          {current.length === 0 ? <div className="panel panel-pad muted">No baseline yet: one starts collecting with this agent&apos;s first model call.</div> : null}
          {current.map((b) => (
            <KeyPanel key={b.id} baseline={b} report={data.latest.find((r) => r.baseline_id === b.id) ?? null} history={data.history.filter((h) => h.baseline_id === b.id)} />
          ))}

          <section className="panel" aria-labelledby="served-title">
            <div className="panel-head">
              <h3 id="served-title">Served model and fingerprint</h3>
              <span className="caption">What the provider said it served</span>
            </div>
            {served.length === 0 ? (
              <p className="row muted">No served-model data yet (the baseline is still collecting).</p>
            ) : (
              served.map((r, i) => (
                <div className="row" key={`${r.kind}-${r.value}-${i}`} data-testid={r.seen === "new" ? "served-new" : "served-baseline"}>
                  <Icon name={r.kind === "model" ? "cpu" : "key"} size={16} />
                  <div className="grow" style={{ minWidth: 0 }}>
                    <div className="mono" style={{ overflowWrap: "anywhere" }}>
                      {r.value}
                    </div>
                    <div className="caption">
                      {r.kind === "model" ? "Served model" : "System fingerprint"} · requested {r.requested} on {label(PROVIDER_LABEL, r.provider)}
                      {r.finding ? ` · ${IDENTITY_HELP[r.finding]}` : ""}
                    </div>
                  </div>
                  {r.seen === "new" && r.finding ? (
                    <span style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 2 }}>
                      <IdentityFlag label={IDENTITY_LABEL[r.finding]} />
                      <span className="caption num">{r.count} calls in window</span>
                    </span>
                  ) : (
                    <Pill tone="quiet">In baseline</Pill>
                  )}
                </div>
              ))
            )}
          </section>

          {superseded.length ? (
            <details className="panel">
              <summary className="row" style={{ cursor: "pointer" }}>
                <span className="title-sm grow">Earlier baselines</span>
                <span className="caption">{superseded.length} superseded</span>
              </summary>
              {superseded.map((b) => (
                <div className="row" key={b.id}>
                  <div className="grow">
                    <div className="title-sm">
                      {label(PROVIDER_LABEL, b.provider)} · {b.model}
                    </div>
                    <div className="caption">
                      Superseded <DateTime at={b.superseded_at} />
                    </div>
                  </div>
                </div>
              ))}
            </details>
          ) : null}
        </div>
      )}
      <ResetDialog open={resetOpen} onClose={() => setResetOpen(false)} agentId={agentId} agentName={agentName} baselines={current} />
    </section>
  );
}

function KeyPanel({ baseline: b, report, history }: { baseline: DriftBaseline; report: DriftReport | null; history: AgentDrift["history"] }) {
  // The page the history controls asked for (newest first from the API).
  const recent = history;
  return (
    <section className="panel" aria-label={`${b.provider} ${b.model} drift`} data-testid="drift-key">
      <div className="panel-head" style={{ flexWrap: "wrap", gap: 8 }}>
        <h3>
          {label(PROVIDER_LABEL, b.provider)} · <span className="mono">{b.model}</span>
        </h3>
        <span style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
          {report?.identity_changed ? <IdentityFlag /> : null}
          <VerdictPill verdict={report?.verdict} collecting={b.state === "collecting"} />
        </span>
      </div>
      <dl className="kv">
        <div>
          <dt>Baseline</dt>
          <dd data-testid="baseline-state">
            {BASELINE_STATE_LABEL[b.state]}
            {b.frozen_at ? (
              <>
                {" "}
                · frozen <DateTime at={b.frozen_at} />
              </>
            ) : null}
          </dd>
        </div>
        <div>
          <dt>Baseline window</dt>
          <dd>
            <DateTime at={b.window_start} /> → {b.window_end ? <DateTime at={b.window_end} /> : "now"}
          </dd>
        </div>
        <div>
          <dt>Baseline samples</dt>
          <dd className="num">
            {b.sample_count.toLocaleString("en-IN")} calls{b.tool_sample_count ? ` · ${b.tool_sample_count.toLocaleString("en-IN")} tool calls` : ""}
            {b.state === "collecting" ? " · freezes at 500 calls over 6 h" : ""}
          </dd>
        </div>
        {b.reset_reason ? (
          <div>
            <dt>Reset reason</dt>
            <dd>“{b.reset_reason}”</dd>
          </div>
        ) : null}
        {report ? (
          <div>
            <dt>Latest evaluation</dt>
            <dd>
              <Ago at={report.evaluated_at} /> · window {report.sample_count.toLocaleString("en-IN")} calls
            </dd>
          </div>
        ) : null}
      </dl>
      {report ? (
        <>
          {report.identity.length ? (
            <div className="hairline-top panel-pad stack" style={{ gap: 6 }}>
              {report.identity.map((i) => (
                <div key={`${i.kind}-${i.value}`} className="banner" data-tone="moved" data-testid="identity-finding">
                  <Icon name="cpu" size={16} />
                  <span>
                    <strong>{IDENTITY_LABEL[i.kind]}:</strong> <span className="mono">{i.value}</span> on {i.count} calls (requested {i.requested_model}). {IDENTITY_HELP[i.kind]}
                  </span>
                </div>
              ))}
            </div>
          ) : null}
          <div className="hairline-top">
            <FeatureTable features={report.features} />
          </div>
          <p className="caption panel-pad" style={{ paddingTop: 10 }}>
            Verdicts compare the excess over the sampling noise floor with the thresholds. PSI over the baseline&apos;s decile bins; Jensen–Shannon (base 2) for shares and mixes. A feature below 200 calls (50 tool calls) never decides a verdict.{" "}
            <Link href={`/drift/reports/${report.id}`} className="caption">
              Report
            </Link>
          </p>
        </>
      ) : (
        <p className="row muted hairline-top">{b.state === "collecting" ? "Collecting: no verdicts until the baseline freezes." : "Not evaluated yet."}</p>
      )}
      {recent.length ? (
        <div className="hairline-top" style={{ padding: "12px var(--row-x) 14px" }}>
          <div className="caption" style={{ marginBottom: 8 }}>
            Evaluations in the chosen window, oldest to newest
          </div>
          <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }} role="list" aria-label="Recent verdicts">
            {[...recent].reverse().map((h) => (
              <span key={h.id} role="listitem" title={`${VERDICT_LABEL[h.verdict]}${h.identity_changed ? " · model changed" : ""} · ${new Date(h.evaluated_at).toISOString()}`}>
                <Pill tone={h.verdict === "drift" ? "degraded" : h.verdict === "watch" ? "watch" : h.identity_changed ? "moved" : "quiet"}>
                  <span className="sr-only">{VERDICT_LABEL[h.verdict]}</span>
                  <span aria-hidden>{h.verdict === "none" ? (h.identity_changed ? "M" : "·") : h.verdict === "watch" ? "W" : "D"}</span>
                </Pill>
              </span>
            ))}
          </div>
        </div>
      ) : null}
    </section>
  );
}

function ResetDialog({ open, onClose, agentId, agentName, baselines }: { open: boolean; onClose: () => void; agentId: string; agentName: string; baselines: readonly DriftBaseline[] }) {
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const idem = useMemo(() => crypto.randomUUID(), [open]); // eslint-disable-line react-hooks/exhaustive-deps
  const short = reason.trim().length < MIN_REASON;

  const submit = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      let receipt: string | null = null;
      const res = await bffSend<DriftBaselineResetResult>(`/agents/${agentId}/drift/baseline`, { reason: reason.trim() }, { idempotencyKey: idem, onHeaders: (h) => (receipt = h.get("x-sibyl-audit-receipt")) });
      await mutate((key) => typeof key === "string" && (key.startsWith("/drift") || key.startsWith(`/agents/${agentId}`) || key.startsWith("/alerts")));
      toast.success("Baseline reset", `${res.superseded.length} baseline${res.superseded.length === 1 ? "" : "s"} superseded; collecting again.${receipt ? ` Receipt ${receipt}` : ""}`);
      setReason("");
      onClose();
    } catch (err) {
      setError(err instanceof ProblemError ? (err.problem.detail ?? err.problem.title) : "Not reset.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Layer
      open={open}
      onClose={onClose}
      title="Reset drift baseline"
      description={`${agentName} · ${baselines.map((b) => `${b.provider}/${b.model}`).join(", ")}`}
      testId="drift-reset"
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button type="button" className="btn btn-primary" disabled={short || busy} onClick={() => void submit()} data-testid="drift-reset-submit">
            {busy ? <span className="spinner" aria-hidden /> : null}Reset baseline
          </button>
        </>
      }
    >
      <div className="stack" style={{ gap: 12, padding: "4px 0" }}>
        <p className="muted">
          The current baseline is superseded and a new one collects from now. Use it after an intended change (a new prompt, a model upgrade you approved). Open drift alerts for this agent resolve. The reset is written to the audit log.
        </p>
        <div className="field">
          <label htmlFor="drift-reason">Reason</label>
          <textarea id="drift-reason" className="textarea" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Approved upgrade to the 2026-10-08 snapshot; new behaviour is expected." aria-describedby="drift-reason-hint" />
          <span id="drift-reason-hint" className="hint">
            Required, at least {MIN_REASON} characters.
          </span>
        </div>
        {error ? (
          <div className="banner" data-tone="failed" role="alert">
            <Icon name="incident" size={16} />
            {error}
          </div>
        ) : null}
      </div>
    </Layer>
  );
}
