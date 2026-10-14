"use client";
/**
 * Action Gate outcomes per agent over the last 24 hours, from `GET /action-summary` (distinct
 * calls counted from the audit chain on the control plane: blocked, escalated, approved, denied,
 * expired). Needs `actions:read`; without it the counts are null and the badges stay hidden.
 */
import type { ActionSummary } from "@/lib/api/action-gate";
import { ACTION_SUMMARY_PATH } from "@/lib/action-gate/paths";
import { summaryCounts, type ActionCounts } from "@/lib/action-gate/wire";
import { useBff } from "@/hooks/useBff";
import { useSession } from "@/components/shell/Session";

export type { ActionCounts };

export function useActionCounts(): { byAgent: Map<string, ActionCounts>; total: ActionCounts } | null {
  const s = useSession();
  const can = s.can("actions:read");
  const { data } = useBff<ActionSummary>(can ? ACTION_SUMMARY_PATH : null);
  if (!can || !data) return null;
  return summaryCounts(data);
}
