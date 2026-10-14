import type { Incident, RoutingTransition } from "@/lib/api/types";

/** Console helper fields the demo BFF adds to an Incident (`x_console`). */
export interface IncidentExtras {
  agent_slug: string;
  agent_name: string;
  tier: number;
  reason: string;
  rto_s: number;
  rpo_s: number;
  checkpoint_age_s: number | null;
  steps: { step: string; at: string; note: string }[];
  transitions: RoutingTransition[];
  hold_suppressed_count: number;
}

export type IncidentView = Incident & { x_console?: IncidentExtras };
