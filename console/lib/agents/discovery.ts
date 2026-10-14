/**
 * Discovery state of an agent (D50, B37), from the API's dedicated fields rather than
 * `is_provisional` (which also flags young agents still collecting a health baseline):
 *
 * - `discovered_via` says how ingest first saw it (null for an agent registered through the API),
 * - `first_trace_id` is the trace of the first telemetry that named it (null when unknown),
 * - `confirmed_at` is when an admin confirmed it (`POST /agents/{id}/claim`).
 *
 * Discovered and not yet confirmed means "awaiting confirmation": never routed or failed over,
 * while the Action Gate, quarantine and kill switch still apply. Pure and unit-tested.
 */
import type { DiscoveredVia } from "@/lib/api/monitor";

export interface DiscoveryFields {
  discovered_via?: DiscoveredVia | null;
  first_trace_id?: string | null;
  confirmed_at?: string | null;
}

export type DiscoveryState = "awaiting" | "confirmed" | null;

export function discoveryState(a: DiscoveryFields): DiscoveryState {
  if (a.discovered_via == null) return null;
  return a.confirmed_at == null ? "awaiting" : "confirmed";
}

export const awaitingConfirmation = (a: DiscoveryFields): boolean => discoveryState(a) === "awaiting";

export const DISCOVERED_VIA_LABEL: Readonly<Record<DiscoveredVia, string>> = {
  gateway_header: "Gateway header",
  api_key_default: "API key default",
  span_attr: "Span attribute",
  a2a_card: "A2A agent card",
  mcp_list_tools: "MCP tool list",
  egress_log: "Egress log",
  run_tree: "Handoff in a run tree",
};

/** Where a trace link lands: the console resolves the trace to its top-level run. */
export const tracePagePath = (traceId: string): string => `/traces/${traceId}`;
