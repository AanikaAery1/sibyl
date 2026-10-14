/** Minimal sparkline: area + line + last point, optional threshold. Values scale to the box. */
interface SparklineProps {
  values: readonly (number | null)[];
  width?: number;
  height?: number;
  label: string;
  color?: string;
  threshold?: number;
  min?: number;
  max?: number;
}

export function Sparkline({ values, width = 120, height = 32, label, color, threshold, min, max }: SparklineProps) {
  const pts = values.map((v, i) => ({ i, v })).filter((p): p is { i: number; v: number } => p.v !== null && Number.isFinite(p.v));
  if (pts.length < 2) {
    return <svg className="spark" width={width} height={height} role="img" aria-label={`${label}: not enough data`} />;
  }
  const lo = min ?? Math.min(...pts.map((p) => p.v), threshold ?? Infinity);
  const hi = max ?? Math.max(...pts.map((p) => p.v), threshold ?? -Infinity);
  const span = hi - lo || 1;
  const pad = 2;
  const x = (i: number): number => pad + (i / Math.max(1, values.length - 1)) * (width - pad * 2);
  const y = (v: number): number => pad + (1 - (v - lo) / span) * (height - pad * 2);
  const line = pts.map((p, k) => `${k === 0 ? "M" : "L"}${x(p.i).toFixed(1)},${y(p.v).toFixed(1)}`).join(" ");
  const first = pts[0];
  const last = pts[pts.length - 1];
  const area = first && last ? `${line} L${x(last.i).toFixed(1)},${height} L${x(first.i).toFixed(1)},${height} Z` : "";
  return (
    <svg
      className="spark"
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label={`${label}: latest ${last ? Math.round(last.v * 100) / 100 : "—"}`}
      style={color ? ({ ["--spark" as string]: color } as React.CSSProperties) : undefined}
    >
      <path className="area" d={area} />
      {threshold !== undefined ? <line className="threshold" x1={0} x2={width} y1={y(threshold)} y2={y(threshold)} /> : null}
      <path className="line" d={line} />
      {last ? <circle className="last" cx={x(last.i)} cy={y(last.v)} r={2.4} /> : null}
    </svg>
  );
}
