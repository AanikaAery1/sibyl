"use client";
/**
 * Decision record for an Action Gate audit row (`action.*`): what was proposed, the rule, the
 * policy version and, for a decision on a held action, the approvals so far.
 */
import Link from "next/link";
import type { ActionEffect } from "@/lib/api/action-gate";
import type { AuditEvent } from "@/lib/api/types";
import { EffectPill } from "@/components/actions/Bits";

const EFFECTS = new Set<ActionEffect>(["allow", "escalate", "block"]);

export function ActionRecord({ event }: { event: AuditEvent }) {
  const d = (event.detail ?? {}) as Record<string, unknown>;
  const str = (k: string): string | null => (typeof d[k] === "string" ? (d[k] as string) : null);
  const num = (k: string): number | null => (typeof d[k] === "number" ? (d[k] as number) : null);
  const raw = str("effect");
  const effect = raw && EFFECTS.has(raw as ActionEffect) ? (raw as ActionEffect) : null;
  const held = str("held_action_id") ?? (event.resource_type === "held_action" ? event.resource_id : null);
  const paths = Array.isArray(d.matched_paths) ? (d.matched_paths as unknown[]).filter((p): p is string => typeof p === "string") : [];
  const approvals = num("approvals");
  const required = num("approvals_required");
  const policy = str("policy_id");
  return (
    <section className="stack" data-testid="action-record" style={{ gap: 12 }}>
      <h3 className="title-sm">Action decision</h3>
      <div className="inset" style={{ overflow: "hidden" }}>
        <dl className="kv">
          <div>
            <dt>Tool</dt>
            <dd className="mono">{str("tool") ?? "—"}</dd>
          </div>
          {effect ? (
            <div>
              <dt>Decision</dt>
              <dd>
                <EffectPill effect={effect} past />
              </dd>
            </div>
          ) : null}
          {str("rule_id") !== null || num("policy_version") !== null ? (
            <div>
              <dt>Rule · policy</dt>
              <dd className="mono">
                {str("rule_id") ?? "default"} · v{num("policy_version") ?? "—"}
              </dd>
            </div>
          ) : null}
          {approvals !== null && required !== null ? (
            <div>
              <dt>Approvals</dt>
              <dd className="num">
                {approvals} of {required}
              </dd>
            </div>
          ) : null}
          {paths.length ? (
            <div>
              <dt>Matched paths</dt>
              <dd className="mono">{paths.join(", ")}</dd>
            </div>
          ) : null}
          {str("args_sha256") ? (
            <div>
              <dt>Args sha256</dt>
              <dd className="hash">{str("args_sha256")?.slice(0, 16)}…</dd>
            </div>
          ) : null}
          {str("source") ? (
            <div>
              <dt>Enforced at</dt>
              <dd>{str("source") === "sdk" ? "SDK" : "Gateway"}</dd>
            </div>
          ) : null}
        </dl>
      </div>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        {held ? (
          <Link href={`/held-actions/${held}`} className="btn btn-sm">
            Open the held action
          </Link>
        ) : null}
        {policy ? (
          <Link href={`/action-policies/${policy}`} className="btn btn-sm">
            Open the policy version
          </Link>
        ) : null}
      </div>
    </section>
  );
}
