/** Semantic pills: health band, routing state, severity, tier, fidelity. Color = state only. */
import type { AlertSeverity, Band, Fidelity, RoutingStateName } from "@/lib/api/types";
import { BAND_LABEL, FIDELITY_LABEL, ROUTING_LABEL, ROUTING_TONE, SEVERITY_TONE, type Tone } from "@/lib/labels";

interface PillProps {
  tone?: Tone;
  dot?: boolean;
  live?: boolean;
  children: React.ReactNode;
  title?: string;
}

export function Pill({ tone = "neutral", dot = false, live = false, children, title }: PillProps) {
  return (
    <span className="pill" data-tone={tone} data-live={live ? "true" : undefined} title={title}>
      {dot ? <span className="dot" aria-hidden /> : null}
      {children}
    </span>
  );
}

export function BandPill({ band, provisional = false }: { band: Band | null | undefined; provisional?: boolean }) {
  if (!band) return <Pill tone="quiet">Not scored yet</Pill>;
  return (
    <Pill tone={provisional ? "quiet" : band} dot title={provisional ? "Provisional: not enough history yet" : undefined}>
      {BAND_LABEL[band]}
      {provisional ? " · provisional" : ""}
    </Pill>
  );
}

export function RoutingPill({ state, holdUntil, live }: { state: RoutingStateName; holdUntil?: string | null; live?: boolean }) {
  const held = Boolean(holdUntil) && state !== "killed";
  return (
    <Pill tone={ROUTING_TONE[state]} dot={state !== "active"} live={live ?? (state === "awaiting_approval" || state === "failing_back")}>
      {ROUTING_LABEL[state]}
      {held ? " · held" : ""}
    </Pill>
  );
}

export function SeverityPill({ severity }: { severity: AlertSeverity }) {
  return (
    <Pill tone={SEVERITY_TONE[severity]} dot>
      {severity[0]?.toUpperCase()}
      {severity.slice(1)}
    </Pill>
  );
}

export function TierBadge({ tier }: { tier: number }) {
  return (
    <span className="tier" data-tier={tier} title={`Tier ${tier}${tier === 1 ? " (highest criticality)" : ""}`}>
      <span className="sr-only">Tier </span>T{tier}
    </span>
  );
}

export function FidelityBadge({ fidelity }: { fidelity: Fidelity }) {
  return (
    <Pill tone={fidelity === "checkpoint" ? "accent" : "watch"} title={fidelity === "request_only" ? "Gateway-only agent: Sibyl knows the last request, not the agent's state" : "SDK checkpoints: the packet resumes from the last step"}>
      {FIDELITY_LABEL[fidelity]} handoff
    </Pill>
  );
}
