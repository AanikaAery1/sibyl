"use client";
/** ⌘K / Ctrl+K palette: jump to any screen or agent, switch persona or tenant, change theme. */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import type { AgentSummary, Page } from "@/lib/api/types";
import { useBff } from "@/hooks/useBff";
import { Layer } from "@/components/ui/Layer";
import { Icon, type IconName } from "@/components/ui/Icon";
import { TierBadge } from "@/components/ui/StatePill";
import { useSession } from "./Session";
import { setThemePref } from "./ThemeChoice";

interface Command {
  id: string;
  label: string;
  hint?: string;
  icon: IconName;
  group: string;
  tier?: number;
  run: () => void;
}

export function useCommandPalette() {
  const [open, setOpenState] = useState(false);
  // Each opening remounts the palette (key = generation) so the query starts empty.
  const [generation, setGeneration] = useState(0);
  const setOpen = useCallback((next: boolean | ((v: boolean) => boolean)) => {
    setOpenState((prev) => {
      const value = typeof next === "function" ? next(prev) : next;
      if (value && !prev) setGeneration((g) => g + 1);
      return value;
    });
  }, []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setOpen]);
  return { open, setOpen, generation };
}

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const router = useRouter();
  const s = useSession();
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const { data: agents } = useBff<Page<AgentSummary>>(open ? "/agents?limit=200" : null);

  const commands = useMemo<Command[]>(() => {
    const go = (href: string) => () => {
      onClose();
      router.push(href);
    };
    const screens: Command[] = [
      { id: "s-fleet", label: "Fleet overview", icon: "fleet", group: "Go to", run: go("/fleet") },
      { id: "s-inc", label: "Incidents", icon: "incident", group: "Go to", run: go("/incidents") },
      { id: "s-queue", label: "Operator queue", icon: "inbox", group: "Go to", run: go("/queue") },
      { id: "s-alerts", label: "Alerts", icon: "bell", group: "Go to", run: go("/alerts") },
      { id: "s-unv", label: "Unverdicted alerts", icon: "bell", group: "Go to", run: go("/alerts?view=unverdicted") },
      { id: "s-audit", label: "Audit log", icon: "audit", group: "Go to", run: go("/audit") },
      { id: "s-runs", label: "Runs", hint: "Run trees from the SDK", icon: "branch", group: "Go to", run: go("/runs") },
      { id: "s-sentinel", label: "Sentinel findings", hint: "Advisory, with external monitors", icon: "sparkle", group: "Go to", run: go("/sentinel") },
      { id: "s-monitors", label: "Monitors", hint: "External monitor agents", icon: "eye", group: "Go to", run: go("/monitors") },
      { id: "s-onb", label: "Onboarding", icon: "sparkle", group: "Go to", run: go("/onboarding") },
      { id: "s-set", label: "Settings · API keys", icon: "key", group: "Go to", run: go("/settings") },
    ];
    const agentCmds: Command[] = (agents?.data ?? []).map((a) => ({ id: `a-${a.id}`, label: a.name, hint: a.slug, icon: "route", group: "Agents", tier: a.tier, run: go(`/agents/${a.id}`) }));
    const people: Command[] =
      s.mode === "demo"
        ? s.personas
            .filter((p) => p.id !== s.personaId)
            .map((p) => ({ id: `p-${p.id}`, label: `Switch to ${p.fullName}`, hint: p.title, icon: "user" as IconName, group: "Session", run: () => {
              onClose();
              void s.switchTo({ persona: p.id });
            } }))
        : [];
    const tenants: Command[] = s.tenants
      .filter((t) => t.slug !== s.tenant)
      .map((t) => ({ id: `t-${t.slug}`, label: `Open ${t.name}`, hint: t.blurb, icon: "layers" as IconName, group: "Session", run: () => {
        onClose();
        void s.switchTo({ tenant: t.slug });
      } }));
    const theme: Command[] = [
      { id: "th-l", label: "Light appearance", icon: "sun", group: "Appearance", run: () => (setThemePref("light"), onClose()) },
      { id: "th-d", label: "Dark appearance", icon: "moon", group: "Appearance", run: () => (setThemePref("dark"), onClose()) },
    ];
    return [...screens, ...agentCmds, ...people, ...tenants, ...theme];
  }, [agents, onClose, router, s]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return commands.filter((c) => c.group !== "Agents").concat(commands.filter((c) => c.group === "Agents").slice(0, 6));
    return commands.filter((c) => `${c.label} ${c.hint ?? ""}`.toLowerCase().includes(needle)).slice(0, 30);
  }, [commands, q]);


  const onKey = (e: React.KeyboardEvent): void => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => Math.min(filtered.length - 1, i + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => Math.max(0, i - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      filtered[active]?.run();
    }
  };

  let lastGroup = "";
  return (
    <Layer open={open} onClose={onClose} title="Command palette" variant="palette" bare testId="palette">
      <div style={{ display: "flex", flexDirection: "column", maxHeight: "70dvh" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "14px 18px", borderBottom: "1px solid var(--hairline)" }}>
          <Icon name="search" size={18} />
          <input
            ref={input}
            autoFocus
            className="grow"
            style={{ border: 0, outline: "none", background: "transparent", fontSize: 17 }}
            placeholder="Search screens, agents, actions…"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setActive(0);
            }}
            onKeyDown={onKey}
            role="combobox"
            aria-expanded="true"
            aria-controls="palette-list"
            aria-activedescendant={filtered[active] ? `cmd-${filtered[active].id}` : undefined}
            aria-label="Search commands"
          />
          <kbd>esc</kbd>
        </div>
        <ul id="palette-list" role="listbox" aria-label="Commands" style={{ overflowY: "auto", padding: 6 }}>
          {filtered.length === 0 ? <li className="muted" style={{ padding: 16 }}>No matches for “{q}”.</li> : null}
          {filtered.map((c, i) => {
            const header = c.group !== lastGroup ? c.group : null;
            lastGroup = c.group;
            return (
              <li key={c.id} role="presentation">
                {header ? <div className="menu-label">{header}</div> : null}
                <div
                  id={`cmd-${c.id}`}
                  role="option"
                  aria-selected={i === active}
                  className="menu-item"
                  style={{ background: i === active ? "var(--accent-tint)" : undefined, cursor: "pointer" }}
                  onMouseEnter={() => setActive(i)}
                  onClick={c.run}
                >
                  <Icon name={c.icon} size={17} />
                  <span className="grow truncate">{c.label}</span>
                  {c.tier ? <TierBadge tier={c.tier} /> : null}
                  {c.hint ? <span className="caption mono hide-sm">{c.hint}</span> : null}
                </div>
              </li>
            );
          })}
        </ul>
      </div>
    </Layer>
  );
}
