"use client";
/** Last hour at 1-minute grain: requests, error rate, p95 and score, as sparklines. */
import type { HealthPoint, MetricBucket } from "@/lib/api/types";
import { Sparkline } from "@/components/ui/Sparkline";
import { ms, pct } from "@/lib/format";

interface Props {
  metrics: readonly MetricBucket[];
  history: readonly HealthPoint[];
}

export function MetricsStrip({ metrics, history }: Props) {
  const req = metrics.map((m) => m.requests);
  const err = metrics.map((m) => (m.requests ? m.errors / m.requests : null));
  const p95 = metrics.map((m) => m.p95_ms ?? null);
  const score = history.map((h) => h.score);
  const last = <T,>(xs: readonly T[]): T | undefined => xs[xs.length - 1];
  const lastErr = [...err].reverse().find((x) => x !== null) ?? null;
  const cards = [
    { k: "Requests / min", v: String(last(req) ?? "—"), vals: req, color: "var(--text-3)" },
    { k: "Error rate", v: pct(lastErr), vals: err, color: (lastErr ?? 0) > 0.1 ? "var(--failed-dot)" : "var(--text-3)", min: 0 },
    { k: "p95 latency", v: ms(last(p95) ?? null), vals: p95, color: "var(--text-3)", min: 0 },
    { k: "Health score", v: String(last(score) ?? "—"), vals: score, color: (last(score) ?? 100) < 70 ? "var(--degraded-dot)" : "var(--healthy-dot)", min: 0, max: 100 },
  ];
  return (
    <section className="panel" aria-label="Last hour">
      <div className="stats">
        {cards.map((c) => (
          <div className="stat" key={c.k}>
            <span className="k">{c.k}</span>
            <span className="v" style={{ fontSize: 22 }}>
              {c.v}
            </span>
            <Sparkline values={c.vals} width={180} height={34} label={c.k} color={c.color} min={c.min} max={c.max} />
          </div>
        ))}
      </div>
    </section>
  );
}
