/** Score ring: arc length = score, color = band, dashed grey when provisional. */
import type { Band } from "@/lib/api/types";

interface HealthRingProps {
  score: number | null | undefined;
  band: Band | null | undefined;
  size?: number;
  stroke?: number;
  provisional?: boolean;
  caption?: string;
}

export function HealthRing({ score, band, size = 40, stroke, provisional = false, caption }: HealthRingProps) {
  const sw = stroke ?? Math.max(3, Math.round(size / 11));
  const r = (size - sw) / 2;
  const c = 2 * Math.PI * r;
  const value = Math.max(0, Math.min(100, score ?? 0));
  const offset = c * (1 - value / 100);
  const fontSize = Math.round(size * (caption ? 0.27 : 0.32));
  return (
    <span
      className="hring"
      data-band={band ?? "none"}
      data-provisional={provisional ? "true" : undefined}
      role="img"
      aria-label={score === null || score === undefined ? "No health score yet" : `Health ${value} of 100${band ? `, ${band}` : ""}${provisional ? ", provisional" : ""}`}
      style={{ width: size, height: size }}
    >
      <svg width={size} height={size} aria-hidden>
        <circle className="track" cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={sw} />
        <circle
          className="value"
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          strokeWidth={sw}
          strokeLinecap="round"
          strokeDasharray={provisional ? undefined : c}
          strokeDashoffset={provisional ? undefined : offset}
        />
      </svg>
      <span className="label" style={{ fontSize }} aria-hidden>
        <span>
          {score ?? "–"}
          {caption ? <small>{caption}</small> : null}
        </span>
      </span>
    </span>
  );
}
