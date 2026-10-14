"use client";
/**
 * One held action: what the agent proposed (scrubbed), why the gate held it (rule, reason,
 * policy version, matched paths), who the agent acted for, and the decision. Approve or deny
 * needs a reason. The person the agent acted for (`on_behalf_of`) cannot approve: the API
 * answers 409 self_approval, shown inline. A four-eyes hold needs two distinct approvers; a
 * second approval by the same person answers 409 duplicate_approver. Sensitive tools need a
 * fresh step-up to approve or deny. The trail and the audit receipt close the loop.
 */
import Link from "next/link";
import { useMemo, useState } from "react";
import { useSWRConfig } from "swr";
import type { ApiActionPolicy, ApiHeldAction, HeldAction, HeldHistoryEntry } from "@/lib/api/action-gate";
import type { AgentSummary } from "@/lib/api/types";
import { ProblemError } from "@/lib/api/problem";
import { bffSend } from "@/lib/client/bff";
import { useBff } from "@/hooks/useBff";
import { FOUR_EYES_TITLE, windowLabel } from "@/lib/action-gate/labels";
import { actingFor, approvalsLeft, onBehalfUser, toHeld } from "@/lib/action-gate/wire";
import { EmptyState, Timeline, type TimelineEntry } from "@/components/ui/Bits";
import { Icon } from "@/components/ui/Icon";
import { Pill, TierBadge } from "@/components/ui/StatePill";
import { Clock, Countdown } from "@/components/ui/Time";
import { DemoMark } from "@/components/ui/DemoMark";
import { useToast } from "@/components/ui/Toast";
import { useSession } from "@/components/shell/Session";
import { ActingFor, ArgsView, HeldPill, personName } from "./Bits";
import { SentinelRecommendation } from "@/components/sentinel/SentinelRecommendation";

const MIN_REASON = 10;

function historyTitle(e: HeldHistoryEntry, me: string): string {
  const who = personName(e.user_id, me);
  const step = e.step_up ? " · step-up" : "";
  switch (e.kind) {
    case "requested":
      return "Held by the Action Gate";
    case "blocked":
      return "Blocked by the control plane";
    case "approval":
      return `First approval by ${who}${e.approvals ? ` (${e.approvals} so far)` : ""}${step}`;
    case "refused":
      return `${e.code === "duplicate_approver" ? "Second approval by the same person refused" : "Self-approval refused"} · ${who}`;
    case "approved":
      return `Approved by ${who}${step}`;
    case "denied":
      return `Denied by ${who}${step}`;
    case "expired":
      return "Expired · denied by default";
    case "cancelled":
      return "Cancelled";
  }
}

function historyEntries(h: HeldAction, me: string): TimelineEntry[] {
  const state = (e: HeldHistoryEntry): TimelineEntry["state"] => (e.kind === "approved" || e.kind === "approval" ? "done" : e.kind === "requested" ? "active" : "warn");
  return h.history.map((e, i) => ({
    key: `${i}-${e.kind}`,
    title: historyTitle(e, me),
    note: e.reason ? `“${e.reason}”` : undefined,
    time: <Clock at={e.at} />,
    state: state(e),
    icon: e.kind === "requested" ? "shield" : e.kind === "refused" ? "users" : undefined,
  }));
}

export function HeldActionDetail({ id, initial }: { id: string; initial: ApiHeldAction | null }) {
  const s = useSession();
  const path = `/held-actions/${id}`;
  const { data, error } = useBff<ApiHeldAction>(s.can("actions:read") ? path : null, initial);
  const held = useMemo(() => (data ? toHeld(data) : null), [data]);
  const { data: agent } = useBff<AgentSummary>(held ? `/agents/${held.agent_id}` : null);
  // The held action names the policy VERSION that held it.
  const { data: policy } = useBff<ApiActionPolicy>(held?.policy_id ? `/action-policies/${held.policy_id}` : null);

  if (!held) {
    return (
      <div className="page">
        <Link href="/held-actions" className="caption">
          ← Held actions
        </Link>
        <div className="panel">
          <EmptyState icon={error instanceof ProblemError && error.status === 403 ? "lock" : "search"} title={error instanceof ProblemError && error.status === 403 ? "Not permitted" : "Held action not found"} />
        </div>
      </div>
    );
  }

  const pending = held.state === "pending";
  return (
    <div className="page">
      <header className="page-head">
        <div style={{ minWidth: 0 }}>
          <Link href="/held-actions" className="eyebrow" style={{ textDecoration: "none", color: "var(--text-2)" }}>
            <Icon name="arrowLeft" size={12} /> Held actions <DemoMark paths={[path]} />
          </Link>
          <h1 className="large-title mono" style={{ overflowWrap: "anywhere" }}>
            {held.tool}
          </h1>
          <p className="lede">
            Proposed by{" "}
            {agent ? (
              <Link href={`/agents/${agent.id}`} style={{ textDecoration: "underline", textUnderlineOffset: 2 }}>
                {agent.name}
              </Link>
            ) : (
              "an agent"
            )} through the {held.source === "sdk" ? "SDK" : "gateway"} <Clock at={held.created_at} />
            {held.on_behalf_of ? `, ${actingFor(held.on_behalf_of, s.userId, (u) => personName(u, s.userId))}` : ""}. The agent is paused until someone decides.
          </p>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10, alignItems: "center" }}>
            {pending ? (
              <Pill tone="human" dot live>
                Auto-deny in <Countdown to={held.expires_at} />
              </Pill>
            ) : (
              <HeldPill state={held.state} onCanvas />
            )}
            {agent ? <TierBadge tier={agent.tier} /> : null}
            <ActingFor obo={held.on_behalf_of} me={s.userId} />
            {held.four_eyes ? (
              <span className="marker" title="Two different people must approve">
                <Icon name="users" size={12} /> Four-eyes · {held.approvals.length} of {held.approvals_required}
              </span>
            ) : null}
            {held.sensitive ? (
              <span className="marker" title="Deciding on a sensitive tool needs a fresh sign-in">
                <Icon name="key" size={12} /> Step-up to decide
              </span>
            ) : null}
            <span className="marker">Hold {windowLabel(held.hold_timeout_s)}</span>
          </div>
        </div>
      </header>

      <div className="grid-split">
        <div className="stack">
          <section className="panel" aria-labelledby="call-title">
            <div className="panel-head">
              <h3 id="call-title">Proposed call</h3>
              <span className="caption mono">call {held.call_id}</span>
            </div>
            <div className="panel-pad stack" style={{ gap: 12 }}>
              {held.args ? (
                <ArgsView args={held.args} matched={held.matched_paths} />
              ) : (
                <p className="caption">The arguments are sealed; they open for people with access to this held action.</p>
              )}
              <p className="caption">
                Secrets were scrubbed where the call was intercepted; Sibyl never stores them. An approval binds to this exact call: args sha256 <span className="mono">{held.args_sha256.slice(0, 16)}…</span>
              </p>
            </div>
          </section>

          <section className="panel" aria-labelledby="why-title">
            <div className="panel-head">
              <h3 id="why-title">Why it was held</h3>
            </div>
            <dl className="kv">
              <div>
                <dt>Rule</dt>
                <dd className="mono" data-testid="held-rule">
                  {held.rule_id ?? "default (no rule matched)"}
                </dd>
              </div>
              <div>
                <dt>Reason</dt>
                <dd>{held.reason}</dd>
              </div>
              <div>
                <dt>Policy</dt>
                <dd>
                  {held.policy_id ? (
                    <Link href={`/action-policies/${held.policy_id}`} data-testid="held-policy">
                      {policy?.name ?? "Policy"} · v{held.policy_version ?? "?"}
                    </Link>
                  ) : (
                    <span>—</span>
                  )}
                </dd>
              </div>
              <div>
                <dt>Matched paths</dt>
                <dd className="mono">{held.matched_paths.join(", ") || "—"}</dd>
              </div>
              {held.counter ? (
                <div>
                  <dt>Cumulative cap</dt>
                  <dd className="num">
                    {held.counter.amount} toward {held.counter.max} per {windowLabel(held.counter.window_s)}
                    {held.counter.applied_at ? " · counted" : ""}
                  </dd>
                </div>
              ) : null}
              <div>
                <dt>The agent acted for</dt>
                <dd data-testid="held-on-behalf">
                  {held.on_behalf_of?.kind === "user" ? personName(held.on_behalf_of.id, s.userId) : held.on_behalf_of?.kind === "external" ? <span className="mono">{held.on_behalf_of.ref}</span> : "nobody (autonomous run)"}
                </dd>
              </div>
            </dl>
          </section>
        </div>

        <div className="stack">
          <DecisionPanel held={held} />
          <SentinelRecommendation subjectKind="held_action" subjectId={held.id} canRead={s.can("sentinel:read")} canAsk={pending && s.can("sentinel:admin")} />
          <section className="panel" aria-labelledby="trail-title">
            <div className="panel-head">
              <h3 id="trail-title">Decision history</h3>
              <Link className="caption" href={`/audit?resource_id=${held.id}`} data-testid="audit-receipt">
                Audit receipt <Icon name="chevronRight" size={12} />
              </Link>
            </div>
            <Timeline items={historyEntries(held, s.userId)} label="Decision history" />
          </section>
        </div>
      </div>
    </div>
  );
}

function DecisionPanel({ held }: { held: HeldAction }) {
  const s = useSession();
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null);
  const [error, setError] = useState<{ code: string; text: string } | null>(null);
  const [receipt, setReceipt] = useState<string | null>(null);
  // One key per attempt: a retry of the same request replays, a new decision (a second approval) is a new request.
  const [idem, setIdem] = useState(() => ({ approve: crypto.randomUUID(), deny: crypto.randomUUID() }));
  const pending = held.state === "pending";
  const forMe = onBehalfUser(held) === s.userId;
  const approvedByMe = held.approvals.some((a) => a.user_id === s.userId);
  const left = approvalsLeft(held);
  const short = reason.trim().length < MIN_REASON;

  const decide = async (action: "approve" | "deny"): Promise<void> => {
    setBusy(action);
    setError(null);
    try {
      const send = (): Promise<ApiHeldAction> => bffSend<ApiHeldAction>(`/held-actions/${held.id}/actions`, { action, reason: reason.trim() }, { idempotencyKey: idem[action], onHeaders: (h) => setReceipt(h.get("x-sibyl-audit-receipt")) });
      const next = toHeld(await (held.sensitive ? s.withStepUp(send) : send()));
      setReason("");
      setIdem({ approve: crypto.randomUUID(), deny: crypto.randomUUID() });
      await mutate((key) => typeof key === "string" && (key.startsWith("/held-actions") || key.startsWith("/audit") || key.startsWith("/action-summary") || key.startsWith("/fleet")));
      if (action === "deny") toast.success("Denied", "The agent receives a refusal and carries on without it.");
      else if (next.state === "approved") toast.success("Approved", "The agent runs the call now, exactly as proposed.");
      else toast.success("Approval recorded", `${approvalsLeft(next)} more approval from someone else is needed.`);
    } catch (err) {
      if (err instanceof ProblemError) setError({ code: err.code, text: err.problem.detail ?? err.problem.title });
      else setError({ code: "error", text: "Not applied." });
      await mutate(`/held-actions/${held.id}`);
    } finally {
      setBusy(null);
    }
  };

  if (!pending) {
    return (
      <section className="panel panel-pad stack" style={{ gap: 8 }} aria-label="Decision" data-testid="held-decided">
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <HeldPill state={held.state} />
          <span className="caption">
            {held.decided_by ? `${personName(held.decided_by, s.userId)} · ` : held.resolved_by_timeout ? "Hold timeout · " : ""}
            <Clock at={held.decided_at} />
          </span>
        </div>
        {held.decision_reason ? <p className="muted">“{held.decision_reason}”</p> : null}
        {receipt ? (
          <p className="caption">
            Recorded in the audit chain · receipt <span className="mono">{receipt}</span>
          </p>
        ) : null}
      </section>
    );
  }

  if (!s.can("actions:decide")) {
    return (
      <section className="panel panel-pad" aria-label="Decision">
        <div className="banner" data-tone="info">
          <Icon name="lock" size={16} />
          Your role ({s.roleLabels.join(" + ")}) cannot decide held actions. An operator, security admin or Admin will.
        </div>
      </section>
    );
  }

  const fourEyesError = error ? FOUR_EYES_TITLE[error.code] : undefined;
  return (
    <section className="panel" aria-labelledby="decide-title" data-testid="held-decision" style={{ boxShadow: "0 0 0 1.5px var(--human-dot), var(--sh-panel)" }}>
      <div className="panel-head">
        <h3 id="decide-title">Decide</h3>
        <span className="caption">
          Denied automatically in <Countdown to={held.expires_at} />
        </span>
      </div>
      <div className="panel-pad stack" style={{ gap: 12 }}>
        {forMe ? (
          <p className="muted" style={{ fontSize: "var(--fs-callout)" }} data-testid="held-for-me">
            <strong style={{ color: "var(--text)" }}>The agent acted for you.</strong> Someone else must approve it; you can still deny it.
          </p>
        ) : null}
        {held.four_eyes ? (
          <p className="muted" style={{ fontSize: "var(--fs-callout)" }} data-testid="held-four-eyes">
            <strong style={{ color: "var(--text)" }}>Four-eyes.</strong> {held.approvals.length} of {held.approvals_required} approvals
            {held.approvals.length ? ` (${held.approvals.map((a) => personName(a.user_id, s.userId)).join(", ")})` : ""}. {approvedByMe ? "You have approved; a second person must complete it." : `${left} more needed from different people.`}
          </p>
        ) : null}
        <div className="field">
          <label htmlFor="held-reason">Decision reason</label>
          <textarea id="held-reason" className="textarea" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Matches claim CLM-204871 and the surveyor's report; payee verified." aria-describedby="held-reason-hint" />
          <span id="held-reason-hint" className="hint">
            Required, at least {MIN_REASON} characters. Shown in the audit log.
          </span>
        </div>
        {error ? (
          <div className="banner" data-tone={fourEyesError ? "human" : "failed"} role="alert" data-testid="held-error" data-code={error.code}>
            <Icon name={fourEyesError ? "users" : "incident"} size={16} />
            <span>
              {fourEyesError ? <strong>{fourEyesError}</strong> : null}
              {error.text}
            </span>
          </div>
        ) : null}
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", flexWrap: "wrap" }}>
          <button type="button" className="btn" disabled={short || busy !== null} onClick={() => void decide("deny")} data-testid="held-deny">
            {busy === "deny" ? <span className="spinner" aria-hidden /> : null}
            Deny
          </button>
          <button type="button" className="btn btn-primary" disabled={short || busy !== null} onClick={() => void decide("approve")} data-testid="held-approve">
            {busy === "approve" ? <span className="spinner" aria-hidden /> : <Icon name={held.sensitive ? "key" : "check"} size={15} />}
            {left > 1 ? "Approve (first of two)" : "Approve"}
            {held.sensitive ? " with step-up" : ""}
          </button>
        </div>
      </div>
    </section>
  );
}
