"use client";
/**
 * The console frame: floating glass sidebar, sticky glass toolbar (hairline appears only once
 * content scrolls beneath), incident banner, command palette, mobile navigation sheet.
 */
import { useEffect, useRef, useState, type ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { FleetHealth, Page, Provider } from "@/lib/api/types";
import { useBff } from "@/hooks/useBff";
import { Icon } from "@/components/ui/Icon";
import { Layer } from "@/components/ui/Layer";
import { useLive } from "@/components/live/LiveProvider";
import { CommandPalette, useCommandPalette } from "./CommandPalette";
import { DemoMenu } from "./DemoMenu";
import { KillSwitchButton } from "./KillSwitch";
import { PersonaMenu } from "./PersonaMenu";
import { useSession } from "./Session";
import { Brand, NavList, Sidebar } from "./Sidebar";

const TITLES: [string, string][] = [
  ["/fleet", "Fleet"],
  ["/agents", "Agent"],
  ["/incidents", "Incidents"],
  ["/queue", "Operator queue"],
  ["/alerts", "Alerts"],
  ["/audit", "Audit"],
  ["/onboarding", "Onboarding"],
  ["/settings", "Settings"],
];

function LiveChip() {
  const live = useLive();
  const label = live.state === "live" ? "Live" : live.state === "reconnecting" ? "Reconnecting" : "Connecting";
  return (
    <span className="glass-chip" role="status" aria-live="polite" title="Server-sent events from the control plane">
      <span className="live-dot" data-state={live.state === "live" ? "live" : "paused"} aria-hidden />
      <span className="hide-md">{label}</span>
    </span>
  );
}

function IncidentBanner({ fleet }: { fleet: FleetHealth | null | undefined }) {
  const open = fleet?.provider_incidents ?? [];
  const { data: providers } = useBff<Page<Provider>>(open.length ? "/providers" : null);
  useEffect(() => {
    document.body.dataset.fleet = open.length ? "incident" : "calm";
  }, [open.length]);
  const first = open[0];
  if (!first) return null;
  return (
    <div style={{ padding: "10px var(--gutter) 0" }}>
      <Link href="/incidents" className="banner" data-tone="failed" style={{ textDecoration: "none" }} data-testid="incident-banner">
        <span className="pill" data-tone="failed" data-live="true">
          <span className="dot" />
          Provider incident
        </span>
        <span className="grow">
          <strong>{providers?.data.find((p) => p.id === first.provider_id)?.name ?? "A provider"} is down</strong> · {first.affected_agent_ids.length} agents affected, one incident. Failover is running by tier.
        </span>
        <Icon name="chevronRight" size={16} />
      </Link>
    </div>
  );
}

export function AppShell({ fleet, children }: { fleet: FleetHealth | null; children: ReactNode }) {
  const s = useSession();
  const pathname = usePathname();
  const palette = useCommandPalette();
  const [navOpen, setNavOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const { data: liveFleet } = useBff<FleetHealth>("/fleet/health", fleet);
  const mainRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const onScroll = (): void => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const title = TITLES.find(([p]) => pathname.startsWith(p))?.[1] ?? "Sibyl";

  return (
    <div className="shell">
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <Sidebar fleet={fleet} />
      <div className="main">
        <header className="toolbar" data-scrolled={scrolled ? "true" : "false"}>
          <button type="button" className="btn btn-icon btn-sm menu-toggle" aria-label="Open navigation" onClick={() => setNavOpen(true)} data-testid="menu-toggle">
            <Icon name="menu" size={18} />
          </button>
          <div className="crumbs">
            <span className="truncate hide-sm">{s.tenantName}</span>
            <span className="hide-sm" aria-hidden>
              /
            </span>
            <strong className="truncate">{title}</strong>
          </div>
          <div className="toolbar-spacer" />
          <button type="button" className="glass-chip" onClick={() => palette.setOpen(true)} aria-label="Search (Command K)" data-testid="open-palette">
            <Icon name="search" size={15} />
            <span className="hide-md">Search</span>
            <kbd className="hide-md">⌘K</kbd>
          </button>
          <LiveChip />
          <DemoMenu />
          <KillSwitchButton />
        </header>
        <IncidentBanner fleet={liveFleet} />
        <main id="main" ref={mainRef} tabIndex={-1} style={{ outline: "none" }}>
          {children}
        </main>
      </div>
      <CommandPalette key={palette.generation} open={palette.open} onClose={() => palette.setOpen(false)} />
      <Layer open={navOpen} onClose={() => setNavOpen(false)} title="Navigation" variant="sheet-left" bare>
        <div style={{ display: "flex", flexDirection: "column", height: "100%", padding: "14px 10px 10px" }}>
          <Brand />
          <NavList fleet={liveFleet} onNavigate={() => setNavOpen(false)} />
          <div className="sidebar-foot">
            <PersonaMenu />
          </div>
        </div>
      </Layer>
    </div>
  );
}
