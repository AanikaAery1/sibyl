"use client";
/**
 * Four-eyes approval (D13, R36): what is proposed, why, by whom, and the countdown to the
 * timeout policy. Deciders need approvals:decide and must not be the requester (409).
 */
import { useMemo, useState } from "react";
import { useSWRConfig } from "swr";
import type { Approval } from "@/lib/api/types";
import { ProblemError } from "@/lib/api/problem";
import { bffSend } from "@/lib/client/bff";
import { APPROVAL_ACTION_LABEL, label } from "@/lib/labels";
import { Countdown, Clock } from "@/components/ui/Time";
import { Pill } from "@/components/ui/StatePill";
import { Icon } from "@/components/ui/Icon";
import { useToast } from "@/components/ui/Toast";
import { useSession } from "@/components/shell/Session";
import { PERSONAS } from "@/lib/auth/personas";

export function ApprovalCard({ approval, incidentId }: { approval: Approval; incidentId: string }) {
  const s = useSession();
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null);
  const [error, setError] = useState<{ code: string; text: string } | null>(null);
  const idem = useMemo(() => ({ approve: crypto.randomUUID(), deny: crypto.randomUUID() }), []);
  const pending = approval.state === "pending";
  const canDecide = s.can("approvals:decide");
  const evidence = (approval.evidence ?? {}) as Record<string, unknown>;
  const requester = approval.requested_by_kind === "rule" ? "the rule engine (rules/v1)" : approval.requested_by_user_id === s.userId ? "you" : (PERSONAS.find((p) => p.userId === approval.requested_by_user_id)?.fullName ?? "an engineer");

  const decide = async (action: "approve" | "deny"): Promise<void> => {
    setBusy(action);
    setError(null);
    try {
      await bffSend(`/incidents/${incidentId}/actions`, { action, reason: reason.trim() }, { idempotencyKey: idem[action] });
      await mutate(() => true);
      toast.success(action === "approve" ? "Approved" : "Denied", action === "approve" ? "The saga continues at write_routing." : "The agent stays in degraded mode.");
    } catch (err) {
      if (err instanceof ProblemError) setError({ code: err.code, text: err.problem.detail ?? err.problem.title });
      else setError({ code: "error", text: "Not applied." });
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="panel" aria-labelledby="approval-title" data-testid="approval-card" style={pending ? { boxShadow: "0 0 0 1.5px var(--human-dot), var(--sh-panel)" } : undefined}>
      <div className="panel-head">
        <h3 id="approval-title">{pending ? "Approval needed" : `Approval ${approval.state}`}</h3>
        {pending ? (
          <Pill tone="human" dot live>
            <Countdown to={approval.expires_at} /> left
          </Pill>
        ) : (
          <Pill tone={approval.state === "approved" ? "healthy" : approval.state === "expired" ? "watch" : "neutral"}>{approval.state}</Pill>
        )}
      </div>
      <div className="panel-pad stack" style={{ gap: 12 }}>
        <div>
          <div className="title-sm">{label(APPROVAL_ACTION_LABEL, approval.requested_action)}</div>
          <p className="muted" style={{ marginTop: 4 }}>
            Requested by {requester} for a tier-{approval.tier} agent. On timeout: <strong>{approval.timeout_policy === "hold" ? "hold in degraded mode" : "fail safe (move automatically)"}</strong>
            {approval.risk === "pii" ? " — forced to hold because this agent touches PII (D22)." : "."}
          </p>
        </div>
        {Object.keys(evidence).length ? (
          <dl className="kv inset" style={{ background: "var(--sunken)", borderRadius: "var(--r-thumb)" }}>
            {Object.entries(evidence).map(([k, v]) => (
              <div key={k}>
                <dt>{k.replaceAll("_", " ")}</dt>
                <dd>{Array.isArray(v) ? v.join(", ") : String(v)}</dd>
              </div>
            ))}
          </dl>
        ) : null}
        {!pending ? (
          <p className="caption">
            Decided <Clock at={approval.decided_at} />
            {approval.decision_reason ? ` · “${approval.decision_reason}”` : ""}
          </p>
        ) : canDecide ? (
          <>
            <div className="field">
              <label htmlFor="approval-reason">Decision reason</label>
              <textarea id="approval-reason" className="textarea" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Verified the rate-limit trend; approving the move to on-prem." />
            </div>
            {error ? (
              <div className="banner" data-tone={error.code === "self_approval" ? "human" : "failed"} role="alert" data-testid="approval-error">
                <Icon name={error.code === "self_approval" ? "users" : "incident"} size={16} />
                <span>
                  {error.code === "self_approval" ? <strong>Four-eyes rule. </strong> : null}
                  {error.text}
                </span>
              </div>
            ) : null}
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button type="button" className="btn" disabled={reason.trim().length < 10 || busy !== null} onClick={() => void decide("deny")} data-testid="deny">
                {busy === "deny" ? <span className="spinner" aria-hidden /> : null}
                Deny
              </button>
              <button type="button" className="btn btn-primary" disabled={reason.trim().length < 10 || busy !== null} onClick={() => void decide("approve")} data-testid="approve">
                {busy === "approve" ? <span className="spinner" aria-hidden /> : <Icon name="check" size={15} />}
                Approve
              </button>
            </div>
          </>
        ) : (
          <div className="banner" data-tone="info">
            <Icon name="lock" size={16} />
            Your role ({s.roleLabels.join(" + ")}) cannot decide approvals. An admin or security admin will.
          </div>
        )}
      </div>
    </section>
  );
}
