"use client";
/**
 * Explainable score (ML §3, §6.1): every factor names its rule, value, threshold and penalty,
 * and the penalties sum to 100 − score. This is the decision record the Compliance Auditor exports.
 */
import type { HealthDocument, HealthFactor } from "@/lib/api/documents";
import { ruleLabel, scoreArithmetic, scoreChecks, splitFactors } from "@/lib/health/scoring";
import { BandPill, Pill } from "@/components/ui/StatePill";
import { Clock } from "@/components/ui/Time";
import { Icon } from "@/components/ui/Icon";
import { label, FAILURE_MODE_LABEL } from "@/lib/labels";

function fmtValue(f: HealthFactor, v: number | string | boolean): string {
  if (typeof v !== "number") return String(v).replaceAll("_", " ");
  if (f.rule === "p95_latency") return `${(v / 1000).toFixed(1)} s`;
  if (f.rule === "consecutive_failures") return String(v);
  if (f.rule === "latency_trend") return `${v}×`;
  return `${(v * 100).toFixed(1)}%`;
}

export function FactorList({ factors, band }: { factors: readonly HealthFactor[]; band: string }) {
  if (factors.length === 0) {
    return (
      <div className="row" style={{ color: "var(--text-2)" }}>
        <Icon name="check" size={16} style={{ color: "var(--healthy-dot)" }} />
        Every rule is inside its threshold. No penalties.
      </div>
    );
  }
  return (
    <ul aria-label="Contributing factors" data-band={band}>
      {factors.map((f) => {
        const cap = Math.round(f.weight * 100);
        return (
          <li className="factor" key={f.rule} data-testid={`factor-${f.rule}`}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
              <span className="f-name">{ruleLabel(f.rule)}</span>
              <Pill tone="quiet">{f.kind === "leading" ? "leading · 15 min" : "detected"}</Pill>
            </div>
            <span className="f-pen" aria-label={`penalty ${f.penalty ?? 0} of ${cap}`}>
              −{f.penalty ?? 0}
            </span>
            <div className="f-bar" aria-hidden>
              <span style={{ transform: `scaleX(${cap ? (f.penalty ?? 0) / cap : 0})` }} />
            </div>
            <p className="f-exp">
              {f.explanation}
              <span className="caption" style={{ display: "block", marginTop: 2 }}>
                value {fmtValue(f, f.value)} · threshold {fmtValue(f, f.threshold)} · cap {cap} for this tier
              </span>
            </p>
          </li>
        );
      })}
    </ul>
  );
}

const GRAIN_LABEL: Readonly<Record<number, string>> = { 60: "1-min", 300: "5-min", 900: "15-min", 3600: "1-hour" };

export function HealthPanel({ health }: { health: HealthDocument }) {
  const { rules, clamp } = splitFactors(health.factors);
  const sum = rules.reduce((a, f) => a + (f.penalty ?? 0), 0);
  const arithmetic = scoreArithmetic(rules, health.score, health.status);
  const consistent = scoreChecks(rules, clamp, health.score);
  const grain = GRAIN_LABEL[health.window?.grain_s ?? 300] ?? "5-min";
  const ref = health.feature_snapshot_ref;
  return (
    <section className="panel" aria-labelledby="health-title" data-band={health.status}>
      <div className="panel-head">
        <h3 id="health-title">Health score</h3>
        <span className="caption">
          <Clock at={health.computed_at} /> · {grain} window · rules/v1
        </span>
      </div>
      <div className="panel-pad" style={{ display: "flex", flexDirection: "column", gap: 12, paddingBottom: 8 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <BandPill band={health.status} provisional={health.provisional?.flag} />
          {health.recommended_action && health.recommended_action !== "none" ? <Pill tone="accent">Recommended: {health.recommended_action.replaceAll("_", " ")}</Pill> : null}
        </div>
        <div className="arith" data-testid="score-arithmetic">
          {arithmetic}
        </div>
        {health.provisional?.flag ? (
          <div className="banner" data-tone="info">
            <Icon name="info" size={16} />
            Provisional: {health.provisional.events_seen} of {health.provisional.events_needed} events seen. The band is capped at watch and no rule can move this agent yet.
          </div>
        ) : null}
      </div>
      <FactorList factors={rules} band={health.status} />
      <div className="row hairline-top caption" style={{ minHeight: 44 }}>
        <Icon name={consistent ? "check" : "incident"} size={15} style={{ color: consistent ? "var(--healthy-dot)" : "var(--failed-dot)" }} />
        <span className="num">
          Σ penalties {sum} {sum > 100 || clamp > 0 ? `> 100, clamped to ${health.score}` : `= 100 − ${health.score}`}
          {consistent ? " · arithmetic checks" : " · mismatch"}
        </span>
        <span className="grow" />
        {ref ? <span className="mono">{ref.slice(0, 15)}…</span> : null}
      </div>
    </section>
  );
}

export function PredictionPanel({ health }: { health: HealthDocument }) {
  // The live worker omits horizons when the prediction extension is off; say so, don't guess.
  const hz = (health.horizons ?? {}) as Partial<HealthDocument["horizons"]>;
  const horizons = [
    ["15 min", hz["15m"]],
    ["1 hour", hz["1h"]],
    ["24 hours", hz["24h"]],
  ] as const;
  if (horizons.every(([, h]) => !h)) {
    return (
      <section className="panel" aria-labelledby="pred-title">
        <div className="panel-head">
          <h3 id="pred-title">Failure risk</h3>
          <span className="caption">Not evaluated</span>
        </div>
        <p className="row muted">No prediction was made for this score. Leading rules still count in the health score above.</p>
      </section>
    );
  }
  return (
    <section className="panel" aria-labelledby="pred-title">
      <div className="panel-head">
        <h3 id="pred-title">Failure risk</h3>
        <span className="caption">{health.predicted_failure_mode ? label(FAILURE_MODE_LABEL, health.predicted_failure_mode) : "No predicted failure"}</span>
      </div>
      <div className="stats" style={{ gridTemplateColumns: "repeat(3, 1fr)" }}>
        {horizons.map(([name, h]) => {
          if (!h || h.abstained) {
            return (
              <div className="stat" key={name}>
                <span className="k">{name}</span>
                <span className="v muted">—</span>
                <span className="caption">abstained</span>
              </div>
            );
          }
          const p = Number(h.probability_band);
          const tone = p >= 0.9 ? "failed" : p >= 0.6 ? "degraded" : p >= 0.25 ? "watch" : "healthy";
          return (
            <div className="stat" key={name}>
              <span className="k">{name}</span>
              <span className="v" style={{ color: tone === "healthy" ? undefined : `var(--${tone})` }}>
                {Math.round(p * 100)}
                <small>%</small>
              </span>
              <span className="caption">{h.confidence} confidence</span>
            </div>
          );
        })}
      </div>
      <p className="caption" style={{ padding: "0 var(--row-x) 14px" }}>
        Rule-derived probability bands (rules/v1), not calibrated frequencies. Phase 2 replaces them with a calibrated model once it beats the rules.
      </p>
    </section>
  );
}
