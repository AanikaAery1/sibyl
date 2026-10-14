"use client";
/** Operator queue (B6): tasks by priority and deadline, packet alongside (sheet on narrow screens). */
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import type { HandoffTaskSummary, Page } from "@/lib/api/types";
import { useBff } from "@/hooks/useBff";
import { FAILURE_MODE_LABEL, HANDOFF_LABEL, label } from "@/lib/labels";
import { EmptyState } from "@/components/ui/Bits";
import { FidelityBadge, Pill, TierBadge } from "@/components/ui/StatePill";
import { Countdown } from "@/components/ui/Time";
import { Layer } from "@/components/ui/Layer";
import { useSession } from "@/components/shell/Session";
import { PacketView } from "./PacketView";
import { DemoMark } from "@/components/ui/DemoMark";

type QueuePage = Page<HandoffTaskSummary> & { x_console?: { completed_despite_failure: number } };

function useWide(): boolean {
  const [wide, setWide] = useState(true);
  useEffect(() => {
    const mq = window.matchMedia("(min-width: 961px)");
    const on = (): void => setWide(mq.matches);
    on();
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);
  return wide;
}

export function QueueView({ initial }: { initial: QueuePage | null }) {
  const s = useSession();
  const router = useRouter();
  const params = useSearchParams();
  const wide = useWide();
  const { data } = useBff<QueuePage>("/queue?limit=100", initial);
  const tasks = data?.data ?? [];
  const selected = params.get("task") ?? (wide ? tasks[0]?.id : undefined) ?? null;
  const select = (id: string | null): void => router.replace(id ? `/queue?task=${id}` : "/queue", { scroll: false });
  const done = data?.x_console?.completed_despite_failure ?? 0;
  const mine = tasks.filter((t) => t.claimed_by === s.userId).length;

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <div className="eyebrow">Handoff packets · one queue <DemoMark paths={["/queue"]} /></div>
          <h1 className="large-title">Operator queue</h1>
          <p className="lede num">
            {tasks.length} waiting{mine ? `, ${mine} claimed by you` : ""}. <strong style={{ color: "var(--text)" }}>{done}</strong> tasks completed despite an agent failure.
          </p>
        </div>
      </header>
      {tasks.length === 0 ? (
        <div className="panel">
          <EmptyState icon="inbox" title="Queue is clear">
            When an agent cannot finish a task, the work arrives here as a handoff packet with its goal, steps done and the next action.
          </EmptyState>
        </div>
      ) : (
        <div className="grid-split" style={{ gridTemplateColumns: wide ? "minmax(0, 0.9fr) minmax(0, 1.4fr)" : undefined }}>
          <section className="panel" aria-label="Tasks" style={{ position: wide ? "sticky" : undefined, top: "calc(var(--toolbar-h) + 16px)" }}>
            {tasks.map((t) => (
              <button key={t.id} type="button" className="row" aria-current={t.id === selected ? "true" : undefined} onClick={() => select(t.id)} data-testid="queue-row" style={{ alignItems: "flex-start" }}>
                <TierBadge tier={t.priority} />
                <div className="grow">
                  <div className="title-sm" style={{ lineHeight: 1.35 }}>
                    {t.summary}
                  </div>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 6, alignItems: "center" }}>
                    <FidelityBadge fidelity={t.fidelity} />
                    <span className="caption">{label(FAILURE_MODE_LABEL, t.failure_mode)}</span>
                  </div>
                </div>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 6 }}>
                  <Pill tone={t.state === "claimed" ? "human" : "watch"}>{HANDOFF_LABEL[t.state]}</Pill>
                  <span className="caption">
                    <Countdown to={t.deadline_at} />
                  </span>
                </div>
              </button>
            ))}
          </section>
          {wide ? <div>{selected ? <PacketView key={selected} taskId={selected} /> : null}</div> : null}
        </div>
      )}
      {!wide ? (
        <Layer open={Boolean(params.get("task"))} onClose={() => select(null)} title="Handoff packet" variant="sheet">
          {selected ? <PacketView taskId={selected} /> : null}
        </Layer>
      ) : null}
    </div>
  );
}
