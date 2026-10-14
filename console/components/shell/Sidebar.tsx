"use client";
/** Floating glass sidebar: brand, tenant, navigation with meaningful counts, persona. */
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { FleetHealth, Page, Alert } from "@/lib/api/types";
import { useBff } from "@/hooks/useBff";
import type { HeldAction } from "@/lib/api/action-gate";
import { HELD_PENDING_PATH } from "@/lib/action-gate/paths";
import type { DriftPage } from "@/lib/api/monitor";
import type { AgentSummary } from "@/lib/api/types";
import { DRIFT_FLEET_PATH } from "@/lib/drift/view";
import { DISCOVERED_PATH, discoveredOnly } from "@/lib/onboarding/instrument";
import { awaitingConfirmation } from "@/lib/agents/discovery";
import { Icon, type IconName } from "@/components/ui/Icon";
import { PersonaMenu } from "./PersonaMenu";
import { useSession } from "./Session";

interface NavItem {
  href: string;
  label: string;
  icon: IconName;
  badge?: { value: number; tone?: "human" | "failed" } | null;
  testId: string;
}

export function useNavItems(fleet: FleetHealth | null | undefined, unverdicted: number, held = 0, drift = 0, discovered = 0): { group: string; items: NavItem[] }[] {
  const approvals = fleet?.pending_approvals ?? 0;
  const queue = fleet?.queue_depth ?? 0;
  const alerts = fleet?.open_alerts ?? 0;
  return [
    {
      group: "Operate",
      items: [
        { href: "/fleet", label: "Fleet", icon: "fleet", testId: "nav-fleet" },
        { href: "/incidents", label: "Incidents", icon: "incident", badge: approvals ? { value: approvals, tone: "human" } : null, testId: "nav-incidents" },
        { href: "/held-actions", label: "Held actions", icon: "hand", badge: held ? { value: held, tone: "human" } : null, testId: "nav-held" },
        { href: "/queue", label: "Operator queue", icon: "inbox", badge: queue ? { value: queue } : null, testId: "nav-queue" },
        { href: "/alerts", label: "Alerts", icon: "bell", badge: alerts + unverdicted ? { value: alerts + unverdicted, tone: alerts ? "failed" : undefined } : null, testId: "nav-alerts" },
      ],
    },
    {
      group: "Monitor",
      items: [
        { href: "/runs", label: "Runs", icon: "branch", testId: "nav-runs" },
        { href: "/drift", label: "Model drift", icon: "activity", badge: drift ? { value: drift } : null, testId: "nav-drift" },
        { href: "/sentinel", label: "Sentinel", icon: "sparkle", testId: "nav-sentinel" },
        { href: "/monitors", label: "Monitors", icon: "eye", testId: "nav-monitors" },
      ],
    },
    {
      group: "Govern",
      items: [
        { href: "/action-policies", label: "Action policies", icon: "shield", testId: "nav-action-policies" },
        { href: "/audit", label: "Audit", icon: "audit", testId: "nav-audit" },
      ],
    },
    {
      group: "Set up",
      items: [
        { href: "/onboarding", label: "Onboarding", icon: "sparkle", testId: "nav-onboarding" },
        { href: "/discovered", label: "Discovered agents", icon: "search", badge: discovered ? { value: discovered, tone: "human" } : null, testId: "nav-discovered" },
        { href: "/settings", label: "Settings", icon: "settings", testId: "nav-settings" },
      ],
    },
  ];
}

export function NavList({ fleet, onNavigate }: { fleet: FleetHealth | null | undefined; onNavigate?: () => void }) {
  const pathname = usePathname();
  const { data: unv } = useBff<Page<Alert>>("/alerts?unverdicted=true&limit=200");
  const s = useSession();
  const { data: held } = useBff<Page<HeldAction>>(s.can("actions:read") ? HELD_PENDING_PATH : null);
  const { data: driftPage } = useBff<DriftPage>(s.can("drift:read") ? DRIFT_FLEET_PATH : null);
  const { data: disc } = useBff<Page<AgentSummary>>(DISCOVERED_PATH);
  const driftCount = driftPage ? (driftPage.summary?.drift ?? 0) + (driftPage.summary?.identity_changed ?? 0) : 0;
  const discoveredCount = discoveredOnly(disc?.data ?? []).filter(awaitingConfirmation).length;
  const groups = useNavItems(fleet, unv?.data.length ?? 0, held?.data.length ?? 0, driftCount, discoveredCount);
  return (
    <nav aria-label="Primary">
      {groups.map((g) => (
        <div className="nav-group" key={g.group}>
          <div className="nav-label">{g.group}</div>
          {g.items.map((it) => {
            const current = pathname === it.href || pathname.startsWith(`${it.href}/`) || (it.href === "/incidents" && pathname.startsWith("/incidents"));
            return (
              <Link key={it.href} href={it.href} className="nav-item" aria-current={current ? "page" : undefined} onClick={onNavigate} data-testid={it.testId}>
                <Icon name={it.icon} size={18} />
                <span>{it.label}</span>
                {it.badge ? (
                  <span className="badge" data-tone={it.badge.tone} aria-label={`${it.badge.value} pending`}>
                    {it.badge.value}
                  </span>
                ) : null}
              </Link>
            );
          })}
        </div>
      ))}
    </nav>
  );
}

export function Brand() {
  const s = useSession();
  return (
    <Link href="/fleet" className="brand" aria-label="Sibyl home">
      <span className="brand-mark" aria-hidden>
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
          <circle cx="12" cy="12" r="3.2" />
          <path d="M12 3.5v2.2M12 18.3v2.2M3.5 12h2.2M18.3 12h2.2" />
          <path d="M6.2 6.2a8.2 8.2 0 0 1 11.6 0" opacity="0.6" />
        </svg>
      </span>
      <span style={{ display: "flex", flexDirection: "column", lineHeight: 1.15, minWidth: 0 }}>
        <span className="brand-name">Sibyl</span>
        <span className="caption truncate">{s.tenantName}</span>
      </span>
    </Link>
  );
}

export function Sidebar({ fleet }: { fleet: FleetHealth | null }) {
  const { data } = useBff<FleetHealth>("/fleet/health", fleet);
  return (
    <aside className="sidebar" aria-label="Sidebar">
      <div className="sidebar-inner">
        <Brand />
        <NavList fleet={data} />
        <div className="sidebar-foot">
          <PersonaMenu />
        </div>
      </div>
    </aside>
  );
}
