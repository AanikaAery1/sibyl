/**
 * Which paths the live BFF may forward (pure; unit-tested). Only contract templates, matched
 * segment by segment, and never the families the browser must not reach through the console:
 * `/auth/*` (served by the dedicated relays), `/policy/*` (gateway-only; Caddy hides it) and
 * `/.well-known/*`. Parameter slots never accept `.` or `..`, so nothing can climb out of
 * `/api/v1` once the URL is normalised.
 */
import { CONTRACT_PATHS } from "@/lib/api/paths.gen";

const BLOCKED_FIRST_SEGMENTS = new Set(["auth", "policy", ".well-known"]);
const SEGMENT_RE = /^(?!\.{1,2}$)[A-Za-z0-9._~-]+$/;

/**
 * Spec paths a lane may forward before the OpenAPI document has them (forwarded like contract
 * paths; an unmounted one answers 404 and falls back to demo data). Empty: the Action Gate paths
 * that used to sit here are in the contract now. A path drops out by itself once it is.
 */
const SPEC_PENDING_PATHS: readonly string[] = [];
export const PENDING_PATHS: readonly string[] = SPEC_PENDING_PATHS.filter((t) => !CONTRACT_PATHS.includes(t));

const TEMPLATES = [...CONTRACT_PATHS, ...PENDING_PATHS].map((t) => ({ template: t, parts: t.split("/").filter(Boolean) }));

export function safeSegment(segment: string): boolean {
  return SEGMENT_RE.test(segment);
}

/** True for a spec path the API may not have mounted yet (an unmounted route answers 404, not 501). */
export function isPendingTemplate(template: string | null): boolean {
  return template !== null && PENDING_PATHS.includes(template);
}

export function contractTemplate(path: string): string | null {
  const parts = path.split("/").filter(Boolean);
  if (parts.length === 0 || !parts.every(safeSegment) || BLOCKED_FIRST_SEGMENTS.has(parts[0] ?? "")) return null;
  for (const { template, parts: tp } of TEMPLATES) {
    if (tp.length !== parts.length) continue;
    if (tp.every((seg, i) => (seg.startsWith("{") ? true : seg === parts[i]))) return template;
  }
  return null;
}
