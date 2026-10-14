/** Action Gate vocabulary and tones (colour = meaning only: block red, escalate the human purple). */
import type { ActionEffect, HeldState, PolicyScopeKind, PolicyState } from "@/lib/api/action-gate";
import type { Tone } from "@/lib/labels";

export const EFFECT_LABEL: Readonly<Record<ActionEffect, string>> = { allow: "Allow", escalate: "Escalate", block: "Block" };
export const EFFECT_PAST: Readonly<Record<ActionEffect, string>> = { allow: "Allowed", escalate: "Held for a person", block: "Blocked" };
export const EFFECT_TONE: Readonly<Record<ActionEffect, Tone>> = { allow: "healthy", escalate: "human", block: "failed" };

export const HELD_LABEL: Readonly<Record<HeldState, string>> = { pending: "Waiting", approved: "Approved", denied: "Denied", expired: "Expired · denied", cancelled: "Cancelled" };
export const HELD_TONE: Readonly<Record<HeldState, Tone>> = { pending: "human", approved: "healthy", denied: "failed", expired: "watch", cancelled: "neutral" };

/** `draft` is a submitted version waiting for approval; `approved` is the one in force for its scope. */
export const POLICY_STATE_LABEL: Readonly<Record<PolicyState, string>> = { draft: "Awaiting approval", approved: "Active", superseded: "Superseded", retired: "Retired" };
export const POLICY_STATE_TONE: Readonly<Record<PolicyState, Tone>> = { draft: "human", approved: "healthy", superseded: "quiet", retired: "neutral" };

export const SCOPE_KIND_LABEL: Readonly<Record<PolicyScopeKind, string>> = { tenant: "Tenant-wide", agent_group: "Agent group", agent: "Agent" };
export const SCOPE_SECTION: Readonly<Record<PolicyScopeKind, string>> = { tenant: "Tenant-wide", agent_group: "Agent groups", agent: "Agents" };

/** 409 codes the Action Gate screens explain inline, with their lead-in. */
export const FOUR_EYES_TITLE: Readonly<Record<string, string>> = {
  self_approval: "Four-eyes rule (409 self_approval). ",
  duplicate_approver: "You already approved this (409 duplicate_approver). ",
};

/** "15 min", "1 h", "24 h" for hold timeouts and cap windows. */
export function windowLabel(seconds: number): string {
  if (seconds % 86400 === 0) return seconds === 86400 ? "a day" : `${seconds / 86400} days`;
  if (seconds % 3600 === 0) return seconds === 3600 ? "an hour" : `${seconds / 3600} h`;
  if (seconds % 60 === 0) return seconds === 60 ? "a minute" : `${seconds / 60} min`;
  return `${seconds} s`;
}
