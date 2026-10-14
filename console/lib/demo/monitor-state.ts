/**
 * Demo state for drift, Sentinel, telemetry runs and discovery (wave 3), kept beside the world in
 * a WeakMap so the shared World shape and its id counter stay untouched: seeds use stable
 * `idFor` names (never `nextId`) and anchor-relative times only, so they are identical whenever
 * they are first touched. A rebuilt world (seek, reset) gets fresh state automatically.
 */
import "server-only";
import type { DiscoveredVia, SentinelConfig, SentinelFinding, TelemetryEvent } from "@/lib/api/monitor";
import type { World } from "./world";

export interface DriftReset {
  agentId: string;
  at: number;
  since: number;
  reason: string;
  userId: string;
  /** Baseline ids superseded by this reset. */
  superseded: string[];
}

export type SentinelConfigRec = Omit<SentinelConfig, "usage_today" | "advisory">;

export interface MonitorState {
  /** Scenario beats already applied, by id → virtual time (drift profiles read these). */
  marks: Map<string, number>;
  driftResets: DriftReset[];
  sentinel: SentinelConfigRec;
  findings: Map<string, SentinelFinding>;
  events: TelemetryEvent[];
  /** Discovered agents: how and where ingest first saw them. */
  discovery: Map<string, { via: DiscoveredVia; firstTraceId: string | null; at: number }>;
  /** Confirmed (claimed) agents → when an admin confirmed them. */
  claimed: Map<string, number>;
}

// Process-wide like the demo store (store.ts): route handlers and server components are separate
// module instances in the Next build, and both must see the same state for the same world.
const g = globalThis as typeof globalThis & { __sibylMonitorStates?: WeakMap<World, MonitorState> };
const STATES: WeakMap<World, MonitorState> = (g.__sibylMonitorStates ??= new WeakMap<World, MonitorState>());

export const UNCONFIGURED: SentinelConfigRec = {
  configured: false,
  enabled: false,
  provider: null,
  model: null,
  base_url: null,
  has_key: false,
  key_hint: null,
  key_updated_at: null,
  daily_budget_usd: null,
  sampling_rate: null,
  tasks: [],
  price_in_usd_per_mtok: null,
  price_out_usd_per_mtok: null,
  version: 0,
  updated_at: null,
};

type Seeder = (w: World, s: MonitorState) => void;
const seeders: Seeder[] = [];

/** Modules register their seeds here (sentinel config, seeded findings, past runs). */
export function onSeed(fn: Seeder): void {
  seeders.push(fn);
}

export function monitorState(w: World): MonitorState {
  const cur = STATES.get(w);
  if (cur) return cur;
  const s: MonitorState = { marks: new Map(), driftResets: [], sentinel: { ...UNCONFIGURED }, findings: new Map(), events: [], discovery: new Map(), claimed: new Map() };
  STATES.set(w, s);
  for (const seed of seeders) seed(w, s);
  return s;
}

export function markAt(w: World, id: string): number | null {
  return monitorState(w).marks.get(id) ?? null;
}
