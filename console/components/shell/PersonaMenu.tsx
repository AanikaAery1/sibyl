"use client";
/** Persona + tenant switcher with theme choice (sidebar foot). Demo personas only in demo mode. */
import { usePopover } from "@/hooks/usePopover";
import { Icon } from "@/components/ui/Icon";
import { useSession } from "./Session";
import { ThemeChoice } from "./ThemeChoice";

export function PersonaMenu({ placement = "up" }: { placement?: "up" | "down" }) {
  const s = useSession();
  const { open: popOpen, toggle: popToggle, close: popClose, rootRef, triggerRef } = usePopover();
  const persona = s.personas.find((p) => p.id === s.personaId);
  return (
    <div ref={rootRef} style={{ position: "relative" }}>
      <button
        ref={triggerRef}
        type="button"
        className="nav-item"
        style={{ width: "100%", border: 0, background: popOpen ? "var(--surface)" : "transparent", minHeight: 48, textAlign: "left" }}
        aria-haspopup="menu"
        aria-expanded={popOpen}
        onClick={popToggle}
        data-testid="persona-menu"
      >
        <span className="avatar" data-persona={s.personaId}>
          {s.initials}
        </span>
        <span className="grow" style={{ display: "flex", flexDirection: "column", lineHeight: 1.25 }}>
          <span className="truncate" style={{ fontWeight: 600, color: "var(--text)" }}>
            {s.fullName}
          </span>
          <span className="truncate caption">{s.roleLabels.join(" + ") || "No membership"}</span>
        </span>
        <Icon name="chevronDown" size={14} />
      </button>
      <div className="popover" data-open={popOpen} role="menu" aria-label="Switch persona and tenant" style={{ left: 0, right: 0, ...(placement === "up" ? { bottom: "calc(100% + 8px)" } : { top: "calc(100% + 8px)" }), minWidth: 260 }}>
        <div className="menu-label">Signed in as{s.mode === "demo" ? " (demo personas)" : ""}</div>
        {s.mode === "live" ? (
          <div className="menu-item" aria-disabled="true" style={{ cursor: "default" }} data-testid="signed-in-as">
            <span className="avatar" data-persona={s.personaId ?? undefined}>
              {s.initials}
            </span>
            <span className="grow" style={{ minWidth: 0 }}>
              <span className="truncate" style={{ display: "block", fontWeight: 600 }}>{s.fullName}</span>
              <span className="caption truncate" style={{ display: "block" }}>{s.email ?? s.roleLabels.join(" + ")}</span>
            </span>
          </div>
        ) : null}
        {s.personas.map((p) => (
          <button
            key={p.id}
            type="button"
            role="menuitemradio"
            aria-checked={p.id === s.personaId}
            className="menu-item"
            disabled={s.mode !== "demo" || s.switching}
            onClick={() => {
              popClose(false);
              void s.switchTo({ persona: p.id });
            }}
            data-testid={`persona-${p.id}`}
          >
            <span className="avatar" data-persona={p.id}>
              {p.initials}
            </span>
            <span className="grow">
              <span style={{ display: "block", fontWeight: 600 }}>{p.fullName}</span>
              <span className="caption">{p.title}</span>
            </span>
            <span className="check">
              <Icon name="check" size={16} />
            </span>
          </button>
        ))}
        <div className="menu-sep" />
        <div className="menu-label">{s.mode === "live" ? "Workspace" : `Tenant${persona ? ` · ${persona.name} has ${persona.tenants.length}` : ""}`}</div>
        {s.tenants.map((t) => (
          <button
            key={t.slug}
            type="button"
            role="menuitemradio"
            aria-checked={t.slug === s.tenant}
            className="menu-item"
            disabled={s.switching}
            onClick={() => {
              popClose(false);
              if (t.slug !== s.tenant) void s.switchTo({ tenant: t.slug });
            }}
            data-testid={`tenant-${t.slug}`}
          >
            <span className="grow">
              <span style={{ display: "block", fontWeight: 600 }}>{t.name}</span>
              <span className="caption">{t.blurb}</span>
            </span>
            <span className="check">
              <Icon name="check" size={16} />
            </span>
          </button>
        ))}
        {s.mode === "live" ? (
          <a role="menuitem" className="menu-item" href="/login?switch=1" data-testid="switch-workspace">
            <Icon name="layers" size={16} />
            <span className="grow">Sign in to another workspace…</span>
          </a>
        ) : null}
        <div className="menu-sep" />
        <div style={{ padding: "6px 8px 4px" }}>
          <ThemeChoice />
        </div>
        {s.mode === "live" ? (
          <>
            <div className="menu-sep" />
            <button
              type="button"
              role="menuitem"
              className="menu-item"
              onClick={() => {
                popClose(false);
                void s.signOut();
              }}
              data-testid="sign-out"
            >
              <Icon name="logout" size={16} />
              <span className="grow">Sign out</span>
            </button>
          </>
        ) : null}
      </div>
    </div>
  );
}
