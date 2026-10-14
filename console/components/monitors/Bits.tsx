"use client";
/**
 * External monitor building blocks: kind, state and webhook-delivery pills, the one-time secret
 * box (monitor keys and webhook signing secrets are shown exactly once) and the setup snippets
 * for sibyl-mcp and the Python SDK's monitor client.
 */
import { useState } from "react";
import type { Monitor, MonitorKind, MonitorState, WebhookDeliveryStatus } from "@/lib/api/external-monitors";
import { MONITOR_KIND_LABEL, MONITOR_STATE_LABEL, MONITOR_STATE_TONE, WEBHOOK_HEALTH_LABEL, WEBHOOK_HEALTH_TONE, setupSnippets, type SnippetId, type WebhookHealth } from "@/lib/monitors/view";
import { Icon, type IconName } from "@/components/ui/Icon";
import { Pill } from "@/components/ui/StatePill";

/** Where the snippets point: the Caddy origin that serves /api/v1 (override per deployment). */
export const MONITOR_API_URL = process.env.NEXT_PUBLIC_SIBYL_API_URL ?? "https://localhost:8443";

const KIND_ICON: Readonly<Record<MonitorKind, IconName>> = { mcp: "sparkle", webhook: "link", api: "terminal" };

export function MonitorKindTag({ kind }: { kind: MonitorKind }) {
  return (
    <span className="tag" data-testid="monitor-kind" style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
      <Icon name={KIND_ICON[kind]} size={12} /> {MONITOR_KIND_LABEL[kind]}
    </span>
  );
}

export function MonitorStatePill({ state }: { state: MonitorState }) {
  return (
    <Pill tone={MONITOR_STATE_TONE[state]} dot={state !== "revoked"}>
      <span data-testid="monitor-state">{MONITOR_STATE_LABEL[state]}</span>
    </Pill>
  );
}

export function DeliveryPill({ status, code }: { status: WebhookHealth | WebhookDeliveryStatus; code?: number | null }) {
  return (
    <Pill tone={WEBHOOK_HEALTH_TONE[status]} dot={status === "delivered" || status === "retrying" || status === "dead"}>
      {WEBHOOK_HEALTH_LABEL[status]}
      {code ? ` · ${code}` : ""}
    </Pill>
  );
}

function useCopy(): [boolean, (text: string) => Promise<void>] {
  const [copied, setCopied] = useState(false);
  const copy = async (text: string): Promise<void> => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  };
  return [copied, copy];
}

/** A secret shown exactly once, with copy and the warning; null means an idempotent replay. */
export function OneTimeSecret({ label, secret, testId }: { label: string; secret: string | null | undefined; testId: string }) {
  const [copied, copy] = useCopy();
  return (
    <div className="inset panel-pad stack" style={{ gap: 10 }} data-testid={testId}>
      <div className="banner" data-tone="watch" role="note" style={{ margin: 0 }}>
        <Icon name="key" size={16} />
        <span>
          <strong>Shown once.</strong> Sibyl stores only a keyed hash of this {label}; it cannot show it again. Copy it into your secret store now.
        </span>
      </div>
      {secret ? (
        <>
          <code className="mono" style={{ wordBreak: "break-all", fontSize: 13, lineHeight: 1.6 }} data-testid={`${testId}-value`}>
            {secret}
          </code>
          <button type="button" className="btn btn-sm" onClick={() => void copy(secret)} style={{ alignSelf: "flex-start" }} aria-live="polite" data-testid={`${testId}-copy`}>
            <Icon name={copied ? "check" : "copy"} size={14} /> {copied ? "Copied" : `Copy ${label}`}
          </button>
        </>
      ) : (
        <p className="muted" data-testid={`${testId}-gone`}>
          This request was already answered once, so the {label} is not shown again. If you did not store it, issue a new one and revoke the old.
        </p>
      )}
    </div>
  );
}

/** Ready-to-paste setup for a monitor of this kind; the key is inlined only while it is shown. */
export function SetupSnippets({ kind, secret }: { kind: Monitor["kind"]; secret: string | null }) {
  const snippets = setupSnippets(kind, { apiUrl: MONITOR_API_URL, secret });
  const [active, setActive] = useState<SnippetId>(snippets[0]?.id ?? "python");
  const [copied, copy] = useCopy();
  const snip = snippets.find((s) => s.id === active) ?? snippets[0];
  if (!snip) return null;
  return (
    <div className="stack" style={{ gap: 10 }} data-testid="monitor-snippets">
      <div className="seg" role="tablist" aria-label="Connect with">
        {snippets.map((s) => (
          <button key={s.id} type="button" role="tab" aria-selected={s.id === snip.id} onClick={() => setActive(s.id)} data-testid={`snippet-${s.id}`}>
            {s.label}
          </button>
        ))}
      </div>
      <div className="snippet">
        <pre className="code" tabIndex={0} aria-label={`${snip.label} setup`} data-testid="snippet-code">
          {snip.code}
        </pre>
        <button type="button" className="btn btn-sm copy" onClick={() => void copy(snip.code)} aria-live="polite">
          <Icon name={copied ? "check" : "copy"} size={13} /> {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <p className="caption">
        Env names as in <span className="mono">sibyl-mcp</span>: <span className="mono">SIBYL_API_URL</span> and <span className="mono">SIBYL_MONITOR_KEY</span>. Behind a TLS-inspecting proxy, add <span className="mono">SIBYL_CA_FILE</span>; never turn verification off.
      </p>
    </div>
  );
}
