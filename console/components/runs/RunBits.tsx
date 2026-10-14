"use client";
/** Small pieces shared by the runs list and the agent's recent runs. */
import type { RunStatus } from "@/lib/api/monitor";
import { RUN_STATUS_LABEL } from "@/lib/runs/tree";
import { Pill } from "@/components/ui/StatePill";

export const runDuration = (v: number | null | undefined): string => (v == null ? "—" : v >= 1000 ? `${(v / 1000).toFixed(1)} s` : `${Math.round(v)} ms`);

export function RunStatusPill({ status }: { status: RunStatus }) {
  if (status === "ok") return <Pill tone="quiet">OK</Pill>;
  if (status === "running") return <Pill tone="moved" dot live>Running</Pill>;
  return <Pill tone={status === "error" ? "failed" : "neutral"}>{RUN_STATUS_LABEL[status]}</Pill>;
}
