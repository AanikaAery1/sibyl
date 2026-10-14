"use client";
/**
 * Held actions (Action Gate, for the On-call Operator): every tool call a policy escalated,
 * waiting first and soonest-to-expire first. Each row carries the countdown to the automatic
 * deny, the agent, the tool, who the agent acted for, the approvals so far, and the rule,
 * reason and policy version that held it. The list asks for `include=args`: people who can
 * decide get the scrubbed arguments on each row (masked tokens shown as •••); for everyone else
 * the API returns null and the row shows the call id and what the rule read. The view filters on
 * the server (`state` repeated); filters live in the URL.
 */
import Link from "next/link";
import { useMemo } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import type { ApiHeldAction } from "@/lib/api/action-gate";
import type { AgentSummary, Page } from "@/lib/api/types";
import { useBff } from "@/hooks/useBff";
import { heldListPath, type HeldView } from "@/lib/action-gate/paths";
import { heldOrder, toHeld } from "@/lib/action-gate/wire";
import { EmptyState } from "@/components/ui/Bits";
import { Icon } from "@/components/ui/Icon";
import { Pill, TierBadge } from "@/components/ui/StatePill";
import { Ago, Countdown } from "@/components/ui/Time";
import { DemoMark } from "@/components/ui/DemoMark";
import { useSession } from "@/components/shell/Session";
import { ActingFor, HeldPill, argsSummary } from "./Bits";

type View = HeldView;

export function HeldActionsView({ initial, view }: { initial: Page<ApiHeldAction> | null; view: View }) {
  const s = useSession();
  const router = useRouter();
  const params = useSearchParams();
  const path = heldListPath(view);
  const { data, error } = useBff<Page<ApiHeldAction>>(s.can("actions:read") ? path : null, initial);
  const { data: agents } = useBff<Page<AgentSummary>>("/agents?limit=200");
  const byId = new Map((agents?.data ?? []).map((a) => [a.id, a]));
  // The API lists newest first; waiting rows go first here, soonest deadline first.
  const rows = useMemo(() => (data?.data ?? []).map(toHeld).sort(heldOrder), [data]);
  const waiting = rows.filter((h) => h.state === "pending").length;

  const setView = (v: View): void => {
    const next = new URLSearchParams(params.toString());
    if (v === "waiting") next.delete("view");
    else next.set("view", v);
    router.replace(`/held-actions${next.toString() ? `?${next}` : ""}`, { scroll: false });
  };

  if (!s.can("actions:read")) {
    return (
      <div className="page">
        <h1 className="large-title">Held actions</h1>
        <div className="panel">
          <EmptyState icon="lock" title="Held actions are restricted">
            Your role ({s.roleLabels.join(" + ") || "none"}) cannot read the Action Gate.
          </EmptyState>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <div className="eyebrow">
            Action Gate · held for a person <DemoMark paths={[path]} />
          </div>
          <h1 className="large-title">Held actions</h1>
          <p className="lede num">
            {view === "waiting"
              ? waiting
                ? `${waiting} ${waiting === 1 ? "action is" : "actions are"} waiting. If nobody decides before the deadline, the action is denied.`
                : "Nothing is waiting. Escalated actions arrive here before they run."
              : `${rows.length} ${view === "decided" ? "decided" : "held"} actions.`}
          </p>
        </div>
        <Link className="btn" href="/action-policies">
          <Icon name="shield" size={15} /> Action policies
        </Link>
      </header>

      <section className="section" aria-label="Filter">
        <div className="seg" role="group" aria-label="Show">
          {(
            [
              ["waiting", "Waiting"],
              ["decided", "Decided"],
              ["all", "All"],
            ] as const
          ).map(([v, l]) => (
            <button key={v} type="button" aria-pressed={view === v} onClick={() => setView(v)} data-testid={`held-view-${v}`}>
              {l}
              {v === "waiting" && view === "waiting" ? <span className="count">{waiting}</span> : null}
            </button>
          ))}
        </div>
      </section>

      <section className="panel" aria-label="Held actions">
        {error ? (
          <EmptyState icon="lock" title="Not permitted" />
        ) : rows.length === 0 ? (
          <EmptyState icon="shield" title={view === "waiting" ? "No actions waiting" : "No held actions"}>
            When a policy escalates a tool call, the agent pauses and the call waits here with its arguments, the rule that held it and a deadline.
          </EmptyState>
        ) : (
          rows.map((h) => {
            const agent = byId.get(h.agent_id);
            return (
              <Link key={h.id} href={`/held-actions/${h.id}`} className="row" data-testid="held-row" style={{ alignItems: "flex-start" }}>
                {agent ? <TierBadge tier={agent.tier} /> : <span className="rule-index" aria-hidden>?</span>}
                <div className="grow" style={{ minWidth: 0, display: "flex", flexDirection: "column", gap: 5 }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
                    <span className="title-sm mono">{h.tool}</span>
                    <span className="muted">{agent?.name ?? "Agent"}</span>
                  </div>
                  <div className="caption mono truncate">
                    call {h.call_id}
                    {h.counter ? ` · ${h.counter.amount} toward a cap of ${h.counter.max}` : ""}
                    {h.matched_paths.length ? ` · read ${h.matched_paths.join(", ")}` : ""}
                  </div>
                  {h.args ? (
                    <div className="caption mono truncate" data-testid="held-args" title="Arguments as proposed, secrets scrubbed">
                      <span className="sr-only">Arguments: </span>
                      {argsSummary(h.args, 4)}
                    </div>
                  ) : null}
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                    <span className="tag mono">
                      {h.rule_id ?? "default"} · v{h.policy_version ?? "?"}
                    </span>
                    <span className="caption">{h.reason}</span>
                    <ActingFor obo={h.on_behalf_of} me={s.userId} />
                    {h.four_eyes ? (
                      <span className="marker">
                        <Icon name="users" size={12} /> {h.state === "pending" ? `${h.approvals.length} of ${h.approvals_required} approvals` : "Two approvers"}
                      </span>
                    ) : null}
                    {h.sensitive ? (
                      <span className="marker">
                        <Icon name="key" size={12} /> Step-up
                      </span>
                    ) : null}
                  </div>
                </div>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 6, flex: "none" }}>
                  {h.state === "pending" ? (
                    <Pill tone="human" dot live>
                      Auto-deny in <Countdown to={h.expires_at} />
                    </Pill>
                  ) : (
                    <HeldPill state={h.state} />
                  )}
                  <span className="caption">
                    <Ago at={h.decided_at ?? h.created_at} />
                  </span>
                </div>
              </Link>
            );
          })
        )}
      </section>
    </div>
  );
}
