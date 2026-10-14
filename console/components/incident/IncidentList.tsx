"use client";
/** Incidents: decisions first (approvals with countdowns), then what is in effect, then history. */
import Link from "next/link";
import type { Page } from "@/lib/api/types";
import { useBff } from "@/hooks/useBff";
import { KIND_LABEL, SAGA_LABEL } from "@/lib/labels";
import { EmptyState, SectionTitle } from "@/components/ui/Bits";
import { Pill, RoutingPill, TierBadge } from "@/components/ui/StatePill";
import { Ago, Countdown } from "@/components/ui/Time";
import { Icon } from "@/components/ui/Icon";
import type { IncidentView } from "./types";
import { DemoMark } from "@/components/ui/DemoMark";

function Row({ inc }: { inc: IncidentView }) {
  const x = inc.x_console;
  const waiting = inc.state === "waiting_approval" && inc.approval?.state === "pending";
  return (
    <Link href={`/incidents/${inc.id}`} className="row" data-testid={`incident-row-${x?.agent_slug ?? inc.agent_id}`}>
      <TierBadge tier={x?.tier ?? 3} />
      <div className="grow">
        <div className="title-sm truncate">{x?.agent_name ?? inc.agent_id}</div>
        <div className="muted truncate">
          {KIND_LABEL[inc.kind]} · {x?.reason ?? ""}
        </div>
      </div>
      {waiting && inc.approval ? (
        <Pill tone="human" dot live>
          Decide in <Countdown to={inc.approval.expires_at} />
        </Pill>
      ) : (
        <RoutingPill state={inc.routing.state} holdUntil={inc.routing.operator_hold_until} live={false} />
      )}
      <span className="caption hide-sm" style={{ width: 84, textAlign: "right" }}>
        <Ago at={inc.created_at} />
      </span>
      <Icon name="chevronRight" size={14} className="hide-sm" />
    </Link>
  );
}

export function IncidentList({ initial }: { initial: Page<IncidentView> | null }) {
  const { data } = useBff<Page<IncidentView>>("/incidents?limit=100", initial);
  const all = data?.data ?? [];
  const decide = all.filter((i) => i.state === "waiting_approval" && i.approval?.state === "pending");
  const inEffect = all.filter((i) => !decide.includes(i) && i.transition && i.routing.last_transition?.failover_id === i.id && i.routing.state !== "active");
  const history = all.filter((i) => !decide.includes(i) && !inEffect.includes(i)).slice(0, 25);

  return (
    <div className="page">
      <header>
        <div className="eyebrow">Failover sagas · one per agent move <DemoMark paths={["/incidents"]} /></div>
        <h1 className="large-title">Incidents</h1>
        <p className="lede">
          {decide.length ? `${decide.length} waiting for a human decision. ` : "Nothing is waiting for a decision. "}
          {inEffect.length} in effect right now.
        </p>
      </header>

      <section className="section" aria-labelledby="decide-title">
        <SectionTitle id="decide-title" title="Needs a decision" meta="Tier-1 moves wait for four-eyes approval (D13)" />
        <div className="panel">{decide.length ? decide.map((i) => <Row key={i.id} inc={i} />) : <EmptyState icon="check" title="No pending approvals">Approvals appear here with a countdown; on timeout the plan&apos;s policy applies (hold or fail safe).</EmptyState>}</div>
      </section>

      <section className="section" aria-labelledby="effect-title">
        <SectionTitle id="effect-title" title="In effect" meta="Routing changed by these incidents and not yet reversed" />
        <div className="panel">{inEffect.length ? inEffect.map((i) => <Row key={i.id} inc={i} />) : <p className="row muted">Every agent is on its primary route.</p>}</div>
      </section>

      <section className="section" aria-labelledby="hist-title">
        <SectionTitle id="hist-title" title="History" meta={`${history.length} most recent`} />
        <div className="panel">
          {history.length ? (
            history.map((i) => (
              <Link key={i.id} href={`/incidents/${i.id}`} className="row">
                <TierBadge tier={i.x_console?.tier ?? 3} />
                <div className="grow">
                  <div className="title-sm truncate">{i.x_console?.agent_name}</div>
                  <div className="muted truncate">{KIND_LABEL[i.kind]}</div>
                </div>
                <Pill tone={i.state === "done" ? "quiet" : i.state === "cancelled" ? "neutral" : "failed"}>{SAGA_LABEL[i.state]}</Pill>
                <span className="caption hide-sm" style={{ width: 84, textAlign: "right" }}>
                  <Ago at={i.created_at} />
                </span>
              </Link>
            ))
          ) : (
            <p className="row muted">No earlier incidents.</p>
          )}
        </div>
      </section>
    </div>
  );
}
