/**
 * Action Gate building blocks: effect and state pills, the scrubbed-arguments view, and who a
 * user id is. Agent-proposed arguments are untrusted content and render as plain text only.
 */
import type { ActionEffect, HeldState, OnBehalfOf, PolicyState } from "@/lib/api/action-gate";
import { actingFor } from "@/lib/action-gate/wire";
import { PERSONAS } from "@/lib/auth/personas";
import { SCRUBBED_RE } from "@/lib/action-gate/detect";
import { EFFECT_LABEL, EFFECT_TONE, HELD_LABEL, HELD_TONE, POLICY_STATE_LABEL, POLICY_STATE_TONE } from "@/lib/action-gate/labels";
import { Pill } from "@/components/ui/StatePill";
import { Icon } from "@/components/ui/Icon";

export function EffectPill({ effect, past = false }: { effect: ActionEffect; past?: boolean }) {
  return (
    <Pill tone={EFFECT_TONE[effect]} dot>
      {past ? { allow: "Allowed", escalate: "Escalated", block: "Blocked" }[effect] : EFFECT_LABEL[effect]}
    </Pill>
  );
}

/**
 * Pill tints are translucent: on the grey page canvas they lose contrast (4.4:1 for "healthy").
 * Header pills sit on an opaque surface so they read the same as inside a panel.
 */
function OnCanvas({ on, children }: { on: boolean; children: React.ReactNode }) {
  return on ? <span style={{ display: "inline-flex", background: "var(--surface)", borderRadius: 999 }}>{children}</span> : <>{children}</>;
}

export function HeldPill({ state, onCanvas = false }: { state: HeldState; onCanvas?: boolean }) {
  return (
    <OnCanvas on={onCanvas}>
      <Pill tone={HELD_TONE[state]} dot={state === "pending"} live={state === "pending"}>
        {HELD_LABEL[state]}
      </Pill>
    </OnCanvas>
  );
}

export function PolicyStatePill({ state, onCanvas = false }: { state: PolicyState; onCanvas?: boolean }) {
  return (
    <OnCanvas on={onCanvas}>
      <Pill tone={POLICY_STATE_TONE[state]} dot={state === "draft" || state === "approved"}>
        {POLICY_STATE_LABEL[state]}
      </Pill>
    </OnCanvas>
  );
}

/** A person's display name; "you" for the viewer; a neutral word for users the console does not know. */
export function personName(userId: string | null | undefined, me: string, fallback = "a colleague"): string {
  if (!userId) return "the agent (no person)";
  if (userId === me) return "you";
  return PERSONAS.find((p) => p.userId === userId)?.fullName ?? fallback;
}

/** "Acting for …": who the agent ran the call for (`on_behalf_of`); that person never approves it. */
export function ActingFor({ obo, me }: { obo: OnBehalfOf | null; me: string }) {
  const text = actingFor(obo, me, (id) => personName(id, me));
  if (!text) return null;
  return (
    <span className="marker" title="The person the agent acted for cannot approve this action" data-testid="acting-for">
      <Icon name="user" size={12} /> {text}
    </span>
  );
}

/** Split text around scrubber placeholders so each one renders as a masked chip. */
function MaskedText({ text }: { text: string }) {
  const parts: React.ReactNode[] = [];
  let last = 0;
  for (const m of text.matchAll(new RegExp(SCRUBBED_RE.source, "g"))) {
    const at = m.index ?? 0;
    if (at > last) parts.push(text.slice(last, at));
    parts.push(
      <span key={at} className="masked" title={`Scrubbed at the enforcement point (${m[0]})`}>
        <Icon name="lock" size={11} /> {m[0].slice(1, m[0].indexOf(":")).toLowerCase().replace("_", " ")} masked
      </span>,
    );
    last = at + m[0].length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return <>{parts}</>;
}

function display(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number") return value.toLocaleString("en-IN");
  return JSON.stringify(value);
}

const escapeToken = (t: string): string => t.replaceAll("~", "~0").replaceAll("/", "~1");

/**
 * The proposed call's arguments, one per row, inside the untrusted-content frame. Rows whose
 * JSON pointer the decision read are marked, so the matched rule's inputs are easy to find.
 */
export function ArgsView({ args, matched = [], label = "Proposed by the agent · secrets scrubbed" }: { args: unknown; matched?: readonly string[]; label?: string }) {
  const entries = args && typeof args === "object" && !Array.isArray(args) ? Object.entries(args as Record<string, unknown>) : [["", args] as [string, unknown]];
  return (
    <div className="untrusted args" data-label={label} data-testid="args-view">
      <dl className="args-list">
        {entries.map(([k, v]) => {
          const pointer = k ? `/${escapeToken(k)}` : "";
          const hit = matched.some((m) => m === pointer || m.startsWith(`${pointer}/`));
          return (
            <div key={k || "value"} data-matched={hit ? "true" : undefined}>
              <dt className="mono">
                {k || "value"}
                {hit ? <span className="tag args-hit">matched</span> : null}
              </dt>
              <dd className="mono">
                <MaskedText text={display(v)} />
              </dd>
            </div>
          );
        })}
      </dl>
    </div>
  );
}

/** One-line argument summary for list rows (masked tokens shown as •••). */
export function argsSummary(args: unknown, max = 3): string {
  if (!args || typeof args !== "object" || Array.isArray(args)) return display(args);
  return Object.entries(args as Record<string, unknown>)
    .slice(0, max)
    .map(([k, v]) => `${k} ${display(v).replace(new RegExp(SCRUBBED_RE.source, "g"), "•••")}`)
    .join(" · ");
}
