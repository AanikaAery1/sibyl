/**
 * BFF paths the Action Gate screens read (pure, so server pages and client views share them).
 * The held-actions views filter on the server: `state` repeats for several states, and
 * `include=args` adds the scrubbed arguments to each row for callers who can decide (null for
 * the rest). Policies still narrow "current" on the client (`policyInView`).
 */
import type { ActionPolicyRecord, HeldState } from "@/lib/api/action-gate";

export type HeldView = "waiting" | "decided" | "all";

/** The states each view asks the API for (none: every state). */
export const HELD_VIEW_STATES: Readonly<Record<HeldView, readonly HeldState[]>> = {
  waiting: ["pending"],
  decided: ["approved", "denied", "expired", "cancelled"],
  all: [],
};

export function heldListPath(view: HeldView): string {
  const states = HELD_VIEW_STATES[view].map((s) => `&state=${s}`).join("");
  return `/held-actions?limit=100${states}&include=args`;
}

export type PolicyView = "current" | "all";

/** Without `state` the API leaves superseded versions out; `include_history` brings them back. */
export function policyListPath(view: PolicyView): string {
  return view === "all" ? "/action-policies?limit=200&include_history=true" : "/action-policies?limit=200";
}

/** "Current": the version in force and the drafts waiting for approval. */
export function policyInView(p: Pick<ActionPolicyRecord, "state">, view: PolicyView): boolean {
  return view === "all" || p.state === "approved" || p.state === "draft";
}

export const HELD_PENDING_PATH = "/held-actions?state=pending&limit=200";

/** `GET /action-summary`: the last 24 h by default. */
export const ACTION_SUMMARY_PATH = "/action-summary";
