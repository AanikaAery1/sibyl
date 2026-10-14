"use client";
/**
 * Discovered agents (D50, B37): agents Sibyl saw in telemetry but nobody registered (lifecycle
 * `discovered`). Each row says how ingest first saw it (`discovered_via`), links the first trace
 * that named it (`first_trace_id`) and, once an admin confirms it (`POST /agents/{id}/claim`,
 * audited `asset.updated`), when (`confirmed_at`). Until then it is never routed or failed over;
 * the Action Gate, quarantine and kill switch still apply.
 */
import Link from "next/link";
import { useState } from "react";
import { useSWRConfig } from "swr";
import type { AgentSummary, Page } from "@/lib/api/types";
import type { FleetAgent } from "@/components/fleet/types";
import { ProblemError } from "@/lib/api/problem";
import { bffSend } from "@/lib/client/bff";
import { useBff } from "@/hooks/useBff";
import { PROVIDER_LABEL, label } from "@/lib/labels";
import { DISCOVERED_PATH, discoveredOnly } from "@/lib/onboarding/instrument";
import { DISCOVERED_VIA_LABEL, awaitingConfirmation, discoveryState, tracePagePath } from "@/lib/agents/discovery";
import { EmptyState } from "@/components/ui/Bits";
import { Icon } from "@/components/ui/Icon";
import { Pill, TierBadge } from "@/components/ui/StatePill";
import { DateTime } from "@/components/ui/Time";
import { DemoMark } from "@/components/ui/DemoMark";
import { useToast } from "@/components/ui/Toast";
import { useSession } from "@/components/shell/Session";

/** In-text links need an underline (axe link-in-text-block); base.css removes it globally. */
const IN_TEXT_LINK = { textDecoration: "underline", textUnderlineOffset: 2 } as const;

function Provenance({ a }: { a: FleetAgent }) {
  if (!a.discovered_via && !a.first_trace_id && !a.confirmed_at) return null;
  return (
    <div className="caption" data-testid="discovery-provenance">
      {a.discovered_via ? <span data-testid="discovered-via">Seen via {DISCOVERED_VIA_LABEL[a.discovered_via].toLowerCase()}</span> : null}
      {a.first_trace_id ? (
        <>
          {" · first in "}
          <Link href={tracePagePath(a.first_trace_id)} className="mono" style={IN_TEXT_LINK} data-testid="first-trace">
            trace {a.first_trace_id.slice(0, 12)}…
          </Link>
        </>
      ) : null}
      {a.confirmed_at ? (
        <span data-testid="confirmed-at">
          {" · confirmed "}
          <DateTime at={a.confirmed_at} />
        </span>
      ) : null}
    </div>
  );
}

export function DiscoveredAgents({ initial, compact = false }: { initial?: Page<AgentSummary> | null; compact?: boolean }) {
  const s = useSession();
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const { data } = useBff<Page<FleetAgent>>(DISCOVERED_PATH, initial as Page<FleetAgent> | null | undefined);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<{ id: string; text: string } | null>(null);
  const rows = discoveredOnly(data?.data ?? []) as FleetAgent[];
  const canClaim = s.can("agents:write");

  const claim = async (a: AgentSummary): Promise<void> => {
    setBusy(a.id);
    setError(null);
    try {
      await bffSend(`/agents/${a.id}/claim`, {});
      await mutate((key) => typeof key === "string" && key.startsWith("/agents"));
      toast.success("Agent confirmed", `${a.name} can now be routed and failed over like any registered agent.`);
    } catch (err) {
      setError({ id: a.id, text: err instanceof ProblemError ? (err.problem.detail ?? err.problem.title) : "Not confirmed." });
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="panel" aria-labelledby="discovered-title" data-testid="discovered-agents">
      <div className="panel-head">
        <h3 id="discovered-title">
          Discovered agents <DemoMark paths={[DISCOVERED_PATH]} />
        </h3>
        <span className="caption">{rows.filter(awaitingConfirmation).length} waiting for confirmation</span>
      </div>
      {!compact ? (
        <p className="row muted" style={{ paddingTop: 0 }}>
          Seen in telemetry (a gateway header, a span attribute or a handoff inside a run tree) but not registered. Until you confirm one, Sibyl never routes or fails it over; the Action Gate, quarantine and kill switch still apply.
        </p>
      ) : null}
      {rows.length === 0 ? (
        <EmptyState icon="search" title="Nothing discovered">
          Agents that call the gateway or appear in a run tree without being registered show up here.
        </EmptyState>
      ) : (
        rows.map((a) => {
          const state = discoveryState(a);
          return (
            <div className="row" key={a.id} data-testid={`discovered-${a.slug}`} data-discovery={state ?? "unknown"} style={{ flexWrap: "wrap" }}>
              <TierBadge tier={a.tier} />
              <div className="grow" style={{ minWidth: 180 }}>
                <Link href={`/agents/${a.id}`} className="title-sm" style={{ color: "var(--text)" }}>
                  {a.name}
                </Link>
                <div className="caption mono">
                  {a.slug}
                  {a.x_console ? ` · ${label(PROVIDER_LABEL, a.x_console.provider)} ${a.x_console.model}` : ""}
                </div>
                {a.x_console?.description ? <div className="caption">{a.x_console.description}</div> : null}
                <Provenance a={a} />
                {error?.id === a.id ? (
                  <div className="caption" role="alert" style={{ color: "var(--failed)" }}>
                    {error.text}
                  </div>
                ) : null}
              </div>
              <span style={{ display: "flex", gap: 8, alignItems: "center", flex: "none" }}>
                {state === "awaiting" ? (
                  <Pill tone="watch" dot>
                    Unconfirmed · not routed
                  </Pill>
                ) : state === "confirmed" ? (
                  <Pill tone="healthy" dot>
                    Confirmed
                  </Pill>
                ) : (
                  // Discovered before the API recorded discovery fields: the source is not known.
                  <Pill tone="quiet">Source not recorded</Pill>
                )}
                {/* The claim endpoint is the authority: it confirms a provisional agent, else 409. */}
                {canClaim && state !== "confirmed" && a.is_provisional ? (
                  <button type="button" className="btn btn-sm btn-primary" disabled={busy !== null} onClick={() => void claim(a)} data-testid={`claim-${a.slug}`}>
                    {busy === a.id ? <span className="spinner" aria-hidden /> : <Icon name="check" size={13} />} Confirm
                  </button>
                ) : null}
              </span>
            </div>
          );
        })
      )}
    </section>
  );
}
