/**
 * Deterministic building blocks for demo-data mode: ids, noise and a virtual clock.
 * Everything the demo shows is a pure function of (fixtures, scenario elapsed time, user
 * actions in order), so screenshots and e2e runs are reproducible after a reset.
 */
import "server-only";

/** cyrb128: small, fast, well-distributed 128-bit string hash (public domain). */
function cyrb128(str: string): [number, number, number, number] {
  let h1 = 1779033703;
  let h2 = 3144134277;
  let h3 = 1013904242;
  let h4 = 2773480762;
  for (let i = 0; i < str.length; i++) {
    const k = str.charCodeAt(i);
    h1 = h2 ^ Math.imul(h1 ^ k, 597399067);
    h2 = h3 ^ Math.imul(h2 ^ k, 2869860233);
    h3 = h4 ^ Math.imul(h3 ^ k, 951274213);
    h4 = h1 ^ Math.imul(h4 ^ k, 2716044179);
  }
  h1 = Math.imul(h3 ^ (h1 >>> 18), 597399067);
  h2 = Math.imul(h4 ^ (h2 >>> 22), 2869860233);
  h3 = Math.imul(h1 ^ (h3 >>> 17), 951274213);
  h4 = Math.imul(h2 ^ (h4 >>> 19), 2716044179);
  h1 ^= h2 ^ h3 ^ h4;
  h2 ^= h1;
  h3 ^= h1;
  h4 ^= h1;
  return [h1 >>> 0, h2 >>> 0, h3 >>> 0, h4 >>> 0];
}

const hex8 = (n: number): string => n.toString(16).padStart(8, "0");

/** A UUIDv7-shaped id derived from a stable name (version nibble 7, RFC 4122 variant). */
export function idFor(name: string): string {
  const [a, b, c, d] = cyrb128(name);
  const h = hex8(a) + hex8(b) + hex8(c) + hex8(d);
  const variant = ((parseInt(h.slice(16, 17), 16) & 0x3) | 0x8).toString(16);
  return `0192${h.slice(4, 8)}-${h.slice(8, 12)}-7${h.slice(13, 16)}-${variant}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

/** Deterministic noise in [-1, 1] for (key, bucket). */
export function noise(key: string, bucket: number): number {
  const [a] = cyrb128(`${key}#${bucket}`);
  return (a / 0xffffffff) * 2 - 1;
}

/** Deterministic hex string of the given length. */
export function hexFor(name: string, length: number): string {
  let out = "";
  let i = 0;
  while (out.length < length) {
    const [a, b, c, d] = cyrb128(`${name}:${i++}`);
    out += hex8(a) + hex8(b) + hex8(c) + hex8(d);
  }
  return out.slice(0, length);
}

/** Deterministic base62-ish token (for demo API-key secrets). */
export function tokenFor(name: string, length: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const hex = hexFor(name, length * 2);
  let out = "";
  for (let i = 0; i < length; i++) out += alphabet[parseInt(hex.slice(i * 2, i * 2 + 2), 16) % alphabet.length];
  return out;
}

export const MINUTE = 60_000;
export const SECOND = 1_000;

export interface DemoClockState {
  anchorMs: number;
  startedRealMs: number;
  pausedElapsedMs: number | null;
  baseElapsedMs: number;
}

function initialAnchor(): number {
  const fixed = process.env.SIBYL_DEMO_ANCHOR;
  if (fixed) {
    const parsed = Date.parse(fixed);
    if (!Number.isNaN(parsed)) return parsed;
  }
  return Math.floor(Date.now() / MINUTE) * MINUTE;
}

export function newClock(): DemoClockState {
  return { anchorMs: initialAnchor(), startedRealMs: Date.now(), pausedElapsedMs: null, baseElapsedMs: 0 };
}

export function elapsedMs(c: DemoClockState): number {
  if (c.pausedElapsedMs !== null) return c.pausedElapsedMs;
  return c.baseElapsedMs + (Date.now() - c.startedRealMs);
}

export function clockNow(c: DemoClockState): number {
  return c.anchorMs + elapsedMs(c);
}

export const iso = (ms: number): string => new Date(ms).toISOString();
