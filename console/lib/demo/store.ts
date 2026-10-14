/**
 * Process-wide demo store: one virtual clock and one world per tenant. Reads advance the
 * scenario lazily to "now", so the demo works under `next dev`, `next start` and in tests
 * without a background timer. Control: reset, pause/resume, seek (rebuild + replay to t).
 */
import "server-only";
import type { TenantSlug } from "@/lib/auth/personas";
import { SECOND, clockNow, elapsedMs, newClock, type DemoClockState } from "./core";
import { buildWorld } from "./build";
import { advance, scriptFor } from "./scenario";
import type { World } from "./world";

interface DemoStore {
  version: number;
  clock: DemoClockState;
  worlds: Partial<Record<TenantSlug, World>>;
}

const STORE_VERSION = 9;
const g = globalThis as typeof globalThis & { __sibylDemo?: DemoStore };

function fresh(): DemoStore {
  return { version: STORE_VERSION, clock: newClock(), worlds: {} };
}

function store(): DemoStore {
  if (!g.__sibylDemo || g.__sibylDemo.version !== STORE_VERSION) g.__sibylDemo = fresh();
  return g.__sibylDemo;
}

export function demoNow(): number {
  return clockNow(store().clock);
}

/** The tenant world, advanced to the current virtual time. */
export function getWorld(slug: TenantSlug): World {
  const s = store();
  const existing = s.worlds[slug] ?? buildWorld(slug, s.clock.anchorMs);
  s.worlds[slug] = existing;
  advance(existing, clockNow(s.clock));
  return existing;
}

export interface ScenarioStatus {
  anchor: string;
  now: string;
  elapsed_s: number;
  paused: boolean;
  beats: { id: string; at_s: number; label: string; done: boolean }[];
}

export function scenarioStatus(): ScenarioStatus {
  const s = store();
  const w = getWorld("meridian");
  const elapsed = elapsedMs(s.clock);
  return {
    anchor: new Date(s.clock.anchorMs).toISOString(),
    now: new Date(clockNow(s.clock)).toISOString(),
    elapsed_s: Math.floor(elapsed / SECOND),
    paused: s.clock.pausedElapsedMs !== null,
    beats: scriptFor(w).map((b, i) => ({ id: b.id, at_s: b.at, label: b.label, done: i < w.scriptIndex })),
  };
}

export function resetDemo(): void {
  g.__sibylDemo = fresh();
}

export function pauseDemo(): void {
  const s = store();
  if (s.clock.pausedElapsedMs === null) s.clock = { ...s.clock, pausedElapsedMs: elapsedMs(s.clock) };
}

export function resumeDemo(): void {
  const s = store();
  if (s.clock.pausedElapsedMs === null) return;
  s.clock = { ...s.clock, baseElapsedMs: s.clock.pausedElapsedMs, startedRealMs: Date.now(), pausedElapsedMs: null };
}

/** Rebuild every world and replay to `seconds` after the anchor (user actions are dropped). */
export function seekDemo(seconds: number, pause: boolean): void {
  const prev = store();
  const elapsed = Math.max(0, seconds) * SECOND;
  g.__sibylDemo = {
    version: STORE_VERSION,
    clock: { anchorMs: prev.clock.anchorMs, startedRealMs: Date.now(), baseElapsedMs: elapsed, pausedElapsedMs: pause ? elapsed : null },
    worlds: {},
  };
}
