"use client";
/** Action policies (Admin / Security admin): per tenant, agent group and agent, with version and approval state. */
import Link from "next/link";
import { useMemo } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import type { ApiActionPolicy, PolicyScopeKind } from "@/lib/api/action-gate";
import type { Page } from "@/lib/api/types";
import { useBff } from "@/hooks/useBff";
import { policyInView, policyListPath, type PolicyView } from "@/lib/action-gate/paths";
import { SCOPE_SECTION } from "@/lib/action-gate/labels";
import { POLICY_STATE_ORDER, toPolicy } from "@/lib/action-gate/wire";
import { EmptyState } from "@/components/ui/Bits";
import { Icon } from "@/components/ui/Icon";
import { Ago } from "@/components/ui/Time";
import { DemoMark } from "@/components/ui/DemoMark";
import { useSession } from "@/components/shell/Session";
import { PolicyStatePill } from "./Bits";

const KINDS: PolicyScopeKind[] = ["tenant", "agent_group", "agent"];

export function PoliciesView({ initial, view }: { initial: Page<ApiActionPolicy> | null; view: PolicyView }) {
  const s = useSession();
  const router = useRouter();
  const params = useSearchParams();
  const path = policyListPath(view);
  const { data } = useBff<Page<ApiActionPolicy>>(s.can("actions:read") ? path : null, initial);
  const rows = useMemo(
    () =>
      (data?.data ?? [])
        .map(toPolicy)
        .filter((r) => policyInView(r, view))
        .sort((a, b) => a.name.localeCompare(b.name) || POLICY_STATE_ORDER[a.state] - POLICY_STATE_ORDER[b.state] || b.version_no - a.version_no),
    [data, view],
  );
  const active = rows.filter((r) => r.state === "approved").length;
  const drafts = rows.filter((r) => r.state === "draft").length;
  const setView = (v: PolicyView): void => {
    const next = new URLSearchParams(params.toString());
    if (v === "current") next.delete("view");
    else next.set("view", v);
    router.replace(`/action-policies${next.toString() ? `?${next}` : ""}`, { scroll: false });
  };

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <div className="eyebrow">
            Action Gate · signed into the policy snapshot <DemoMark paths={[path]} />
          </div>
          <h1 className="large-title">Action policies</h1>
          <p className="lede num">
            {active} active, {drafts} awaiting approval. Evaluated before a tool runs, at the gateway and in the SDK; the most restrictive decision wins.
          </p>
        </div>
        {s.can("action_policies:write") ? (
          <Link className="btn btn-primary" href="/action-policies/new" data-testid="policy-new">
            <Icon name="plus" size={15} /> New policy
          </Link>
        ) : null}
      </header>
      <section className="section" aria-label="Filter">
        <div className="seg" role="group" aria-label="Show">
          <button type="button" aria-pressed={view === "current"} onClick={() => setView("current")}>
            Current
          </button>
          <button type="button" aria-pressed={view === "all"} onClick={() => setView("all")}>
            All versions
          </button>
        </div>
      </section>
      {rows.length === 0 ? (
        <div className="panel">
          <EmptyState icon="shield" title="No action policies">
            Without a policy, sensitive tools are blocked and everything else runs.
          </EmptyState>
        </div>
      ) : (
        KINDS.map((kind) => {
          const items = rows.filter((r) => r.scope_kind === kind);
          if (!items.length) return null;
          return (
            <section className="section" key={kind} aria-labelledby={`sec-${kind}`}>
              <div className="section-title">
                <h2 id={`sec-${kind}`}>{SCOPE_SECTION[kind]}</h2>
              </div>
              <div className="panel">
                {items.map((r) => (
                  <Link key={r.id} href={`/action-policies/${r.id}`} className="row" data-testid="policy-row">
                    <span className="rule-index">v{r.version_no}</span>
                    <div className="grow" style={{ minWidth: 0 }}>
                      <div className="title-sm">{r.name}</div>
                      <div className="caption truncate">
                        {r.scope.label} · {r.rules.length} rules · default {r.default_effect}
                        {r.change_note ? ` · ${r.change_note}` : ""}
                      </div>
                    </div>
                    {r.approval_four_eyes ? (
                      <span className="marker hide-sm" title="A tier-1 agent is in scope: the author cannot approve a version">
                        <Icon name="users" size={12} /> Four-eyes approval
                      </span>
                    ) : null}
                    {r.four_eyes ? (
                      <span className="marker hide-sm" title="Held actions under this policy need two approvers">
                        <Icon name="hand" size={12} /> Two approvers
                      </span>
                    ) : null}
                    <PolicyStatePill state={r.state} />
                    <span className="caption hide-sm" style={{ minWidth: 70, textAlign: "right" }}>
                      <Ago at={r.approved_at ?? r.created_at} />
                    </span>
                  </Link>
                ))}
              </div>
            </section>
          );
        })
      )}
    </div>
  );
}
