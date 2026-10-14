/**
 * Drift building blocks: verdict pill, identity flag, and the per-feature table that shows every
 * number a verdict came from (statistic, raw value, noise floor, excess, thresholds, samples).
 */
import type { DriftFeatureResult, DriftVerdict } from "@/lib/api/monitor";
import { FEATURE_LABEL, STAT_LABEL, VERDICT_LABEL, VERDICT_TONE, excessFill, featureStatusText, formatStat, watchMark } from "@/lib/drift/view";
import { Pill } from "@/components/ui/StatePill";
import { Icon } from "@/components/ui/Icon";

export function VerdictPill({ verdict, collecting = false }: { verdict: DriftVerdict | null | undefined; collecting?: boolean }) {
  if (collecting) return <Pill tone="quiet">Collecting baseline</Pill>;
  if (!verdict) return <Pill tone="quiet">Not evaluated</Pill>;
  return (
    <Pill tone={VERDICT_TONE[verdict]} dot={verdict !== "none"}>
      {VERDICT_LABEL[verdict]}
    </Pill>
  );
}

export function IdentityFlag({ label = "Model identity changed" }: { label?: string }) {
  return (
    <span className="identity-flag" data-testid="identity-flag">
      <Icon name="cpu" size={13} /> {label}
    </span>
  );
}

function ExcessBar({ f }: { f: DriftFeatureResult }) {
  const fill = excessFill(f);
  if (fill === null) return <span className="caption">—</span>;
  return (
    <span className="excess" data-verdict={f.verdict} role="img" aria-label={`${Math.round(fill * 100)}% of the drift threshold`}>
      <span style={{ width: `${Math.max(2, fill * 100)}%` }} />
      <i style={{ left: `${watchMark(f) * 100}%` }} aria-hidden />
    </span>
  );
}

export function FeatureTable({ features }: { features: readonly DriftFeatureResult[] }) {
  return (
    <div className="table-wrap" tabIndex={0} role="region" aria-label="Per-feature drift statistics">
      <table className="table feature-table" data-testid="feature-table">
        <caption className="sr-only">Per-feature drift statistics</caption>
        <thead>
          <tr>
            <th scope="col">Feature</th>
            <th scope="col" className="num">Value</th>
            <th scope="col" className="num">Noise floor</th>
            <th scope="col" className="num">Excess</th>
            <th scope="col" className="hide-sm">vs drift line</th>
            <th scope="col">Verdict</th>
          </tr>
        </thead>
        <tbody>
          {features.map((f) => {
            const note = featureStatusText(f);
            return (
              <tr key={f.feature} data-verdict={f.verdict} data-status={f.status} data-testid={`feature-${f.feature}`}>
                <th scope="row" style={{ fontWeight: 600, textAlign: "left" }}>
                  {FEATURE_LABEL[f.feature]}
                  <div className="caption" style={{ fontWeight: 400 }}>
                    {STAT_LABEL[f.statistic]} · watch {formatStat(f.watch)} / drift {formatStat(f.drift)} · {f.n_baseline ?? "—"} → {f.n_window ?? "—"} samples
                  </div>
                  {f.contributors?.length ? (
                    <div className="caption" style={{ fontWeight: 400 }}>
                      {f.contributors.slice(0, 2).map((c) => `${c.label} ${formatStat(c.baseline)} → ${formatStat(c.window)}`).join(" · ")}
                    </div>
                  ) : null}
                  {note ? <div className="caption" style={{ fontWeight: 400 }}>{note}</div> : null}
                </th>
                <td className="num mono">{formatStat(f.value)}</td>
                <td className="num mono">{f.status === "ok" ? formatStat(f.noise_floor) : "—"}</td>
                <td className="num mono">{formatStat(f.excess)}</td>
                <td className="hide-sm">
                  <ExcessBar f={f} />
                </td>
                <td>{f.status === "ok" ? <VerdictPill verdict={f.verdict} /> : <Pill tone="quiet">Undecided</Pill>}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function WatchOnlyNote({ compact = false }: { compact?: boolean }) {
  return (
    <div className="banner" data-tone="quiet" role="note" data-testid="watch-only">
      <Icon name="eye" size={16} />
      <span>
        <strong>Watch-only.</strong> {compact ? "Drift raises alerts for a person; it never triggers a failover on its own." : "Drift raises silent_drift and model_change alerts for a person to look at. It never triggers a failover, a hold or a policy change on its own; the health score is unchanged by it."}
      </span>
    </div>
  );
}
