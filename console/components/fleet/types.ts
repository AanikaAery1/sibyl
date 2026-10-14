import type { AgentSummary } from "@/lib/api/types";

/** Console helper fields the demo BFF adds next to the contract (`x_console`). */
export interface AgentExtras {
  provider: string;
  model: string;
  served_provider: string | null;
  served_model: string | null;
  process: string;
  group_id?: string;
  description: string;
  fidelity: "checkpoint" | "request_only";
  pii: boolean;
  hold_suppressed_count: number;
}

export type FleetAgent = AgentSummary & { x_console?: AgentExtras };
