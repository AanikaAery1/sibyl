/** Formatting helpers shared by server and client (pure; timezone passed explicitly). */

export const DEFAULT_TZ = "Asia/Kolkata";

export function formatClock(isoOrMs: string | number | null | undefined, tz: string, withSeconds = true): string {
  if (isoOrMs === null || isoOrMs === undefined) return "—";
  const d = new Date(isoOrMs);
  if (Number.isNaN(d.getTime())) return "—";
  return new Intl.DateTimeFormat("en-GB", { timeZone: tz, hour: "2-digit", minute: "2-digit", ...(withSeconds ? { second: "2-digit" } : {}), hour12: false }).format(d);
}

export function formatDateTime(isoOrMs: string | number | null | undefined, tz: string): string {
  if (isoOrMs === null || isoOrMs === undefined) return "—";
  const d = new Date(isoOrMs);
  if (Number.isNaN(d.getTime())) return "—";
  return new Intl.DateTimeFormat("en-GB", { timeZone: tz, day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", hour12: false }).format(d);
}

export function formatDuration(totalSeconds: number): string {
  const s = Math.max(0, Math.round(totalSeconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  if (m < 60) return rem ? `${m}m ${rem}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const mm = m % 60;
  if (h < 48) return mm ? `${h}h ${mm}m` : `${h}h`;
  return `${Math.floor(h / 24)}d`;
}

/** "MM:SS" or "H:MM:SS" for live clocks. */
export function formatStopwatch(totalSeconds: number): string {
  const s = Math.max(0, Math.floor(totalSeconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const mm = String(m).padStart(h ? 2 : 1, "0");
  return h ? `${h}:${mm}:${String(sec).padStart(2, "0")}` : `${mm}:${String(sec).padStart(2, "0")}`;
}

export function relative(isoOrMs: string | number | null | undefined, nowMs: number): string {
  if (isoOrMs === null || isoOrMs === undefined) return "—";
  const t = new Date(isoOrMs).getTime();
  if (Number.isNaN(t)) return "—";
  const diff = Math.round((nowMs - t) / 1000);
  if (Math.abs(diff) < 5) return "just now";
  if (diff < 0) return `in ${formatDuration(-diff)}`;
  return `${formatDuration(diff)} ago`;
}

export function pct(x: number | null | undefined, digits = 1): string {
  if (x === null || x === undefined || Number.isNaN(x)) return "—";
  return `${(x * 100).toFixed(digits)}%`;
}

export function ms(x: number | null | undefined): string {
  if (x === null || x === undefined) return "—";
  return x >= 1000 ? `${(x / 1000).toFixed(1)} s` : `${Math.round(x)} ms`;
}

export function usd(x: string | number | null | undefined): string {
  if (x === null || x === undefined) return "—";
  const n = typeof x === "string" ? Number(x) : x;
  return n < 1 ? `$${n.toFixed(3)}` : `$${n.toFixed(2)}`;
}

export function shortHash(h: string | null | undefined, n = 10): string {
  return h ? `${h.slice(0, n)}…` : "—";
}

export function shortId(id: string | null | undefined): string {
  return id ? id.slice(-6) : "—";
}
