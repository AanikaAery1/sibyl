"use client";
/**
 * Settings: API keys (secret shown once; rotate/revoke), tenant keys (metadata only; rotation
 * behind step-up) and members. Sections a role cannot read show a designed restricted state.
 */
import { useRouter, useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";
import { useSWRConfig } from "swr";
import type { AgentSummary, ApiKey, ApiKeyCreated, ApiKeyScope, AppUser, Membership, Page, TenantKey, TenantKeyPurpose } from "@/lib/api/types";
import { ProblemError } from "@/lib/api/problem";
import { roleLabel } from "@/lib/auth/roles";
import { bffSend } from "@/lib/client/bff";
import { useBff } from "@/hooks/useBff";
import { EmptyState } from "@/components/ui/Bits";
import { Pill } from "@/components/ui/StatePill";
import { Ago, DateTime } from "@/components/ui/Time";
import { Icon } from "@/components/ui/Icon";
import { Layer } from "@/components/ui/Layer";
import { useToast } from "@/components/ui/Toast";
import { useSession } from "@/components/shell/Session";
import { KeyReveal } from "./KeyReveal";

type Tab = "api-keys" | "tenant-keys" | "members";

export function SettingsView() {
  const params = useSearchParams();
  const router = useRouter();
  const tab = (["api-keys", "tenant-keys", "members"].includes(params.get("tab") ?? "") ? params.get("tab") : "api-keys") as Tab;
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <div className="eyebrow">Tenant configuration</div>
          <h1 className="large-title">Settings</h1>
        </div>
        <div className="seg" role="tablist" aria-label="Settings sections">
          {(
            [
              ["api-keys", "API keys"],
              ["tenant-keys", "Tenant keys"],
              ["members", "Members"],
            ] as const
          ).map(([t, l]) => (
            <button key={t} type="button" role="tab" aria-selected={tab === t} onClick={() => router.replace(t === "api-keys" ? "/settings" : `/settings?tab=${t}`, { scroll: false })} data-testid={`tab-${t}`}>
              {l}
            </button>
          ))}
        </div>
      </header>
      {tab === "api-keys" ? <ApiKeys /> : tab === "tenant-keys" ? <TenantKeys /> : <Members />}
    </div>
  );
}

function Restricted({ what, who }: { what: string; who: string }) {
  return (
    <div className="panel">
      <EmptyState icon="lock" title={`${what} are restricted`}>
        {who}
      </EmptyState>
    </div>
  );
}

const PRESETS: { id: string; label: string; scopes: ApiKeyScope[]; bound?: boolean; note: string }[] = [
  { id: "gateway", label: "Gateway (zero-code)", scopes: ["gateway:proxy"], note: "For OpenAI-compatible clients pointed at the gateway." },
  { id: "sdk", label: "SDK, bound to one agent", scopes: ["ingest:write", "routing:read", "handoff:write"], bound: true, note: "Required for tier-1 agents (D32). The key can only speak for its agent." },
  { id: "registry", label: "Registry automation", scopes: ["agents:read", "agents:write"], note: "CI jobs that register agents and versions." },
  { id: "breakglass", label: "Break-glass kill", scopes: ["killswitch:pull"], note: "Pull-only, kept offline, at most two per tenant. Needs step-up." },
];

function ApiKeys() {
  const s = useSession();
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const allowed = s.can("apikeys:manage") || s.can("apikeys:manage_agent");
  const { data: keys } = useBff<Page<ApiKey>>(allowed ? "/api-keys?limit=100" : null);
  const { data: agents } = useBff<Page<AgentSummary>>(allowed ? "/agents?limit=200" : null);
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<ApiKeyCreated | null>(null);
  const [revoking, setRevoking] = useState<ApiKey | null>(null);
  if (!allowed) return <Restricted what="API keys" who={`Admins and workspace admins manage keys; engineers manage keys bound to their agents. Your role: ${s.roleLabels.join(" + ")}.`} />;
  const agentName = (id?: string | null): string => (id ? (agents?.data.find((a) => a.id === id)?.name ?? id.slice(-6)) : "Tenant-wide");

  const rotate = async (k: ApiKey): Promise<void> => {
    try {
      const next = await bffSend<ApiKeyCreated>(`/api-keys/${k.id}/rotate`, { grace_s: 3600 });
      setCreated(next);
      await mutate(() => true);
    } catch (err) {
      toast.error(err);
    }
  };

  return (
    <section className="section" aria-label="API keys">
      <div className="section-title">
        <span className="meta">Keys carry machine scopes only. Secrets are shown once and stored as a keyed hash.</span>
        <button type="button" className="btn btn-primary btn-sm" onClick={() => setCreating(true)} data-testid="new-key">
          <Icon name="plus" size={14} /> New key
        </button>
      </div>
      <div className="panel table-wrap">
        <table className="table stack">
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Scopes</th>
              <th scope="col" className="hide-sm">Bound to</th>
              <th scope="col">Status</th>
              <th scope="col" className="hide-sm">Last used</th>
              <th scope="col" className="r">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {(keys?.data ?? []).map((k) => (
              <tr key={k.id} data-testid={`key-row-${k.name}`}>
                <td>
                  <div style={{ fontWeight: 600 }}>{k.name}</div>
                  <div className="caption mono">sbl_{k.env}_{k.prefix}_…</div>
                </td>
                <td>
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                    {k.scopes.map((sc) => (
                      <span key={sc} className="tag mono" style={sc === "killswitch:pull" ? { background: "var(--failed-tint)", color: "var(--failed)" } : undefined}>
                        {sc}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="hide-sm">{agentName(k.agent_id)}</td>
                <td>
                  <Pill tone={k.status === "active" ? "healthy" : k.status === "rotating" ? "watch" : "neutral"} dot={k.status !== "revoked"}>
                    {k.status}
                  </Pill>
                </td>
                <td className="hide-sm caption">{k.last_used_at ? <Ago at={k.last_used_at} /> : "Never"}</td>
                <td className="r" style={{ whiteSpace: "nowrap" }}>
                  {k.status === "active" ? (
                    <>
                      <button type="button" className="btn btn-sm btn-plain" onClick={() => void rotate(k)}>
                        Rotate
                      </button>
                      <button type="button" className="btn btn-sm btn-plain" style={{ color: "var(--failed)" }} onClick={() => setRevoking(k)} data-testid="revoke-key">
                        Revoke
                      </button>
                    </>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {creating ? <NewKeyDialog agents={agents?.data ?? []} onClose={() => setCreating(false)} onCreated={(k) => setCreated(k)} /> : null}
      {revoking ? <RevokeDialog k={revoking} onClose={() => setRevoking(null)} /> : null}
      <KeyReveal created={created} onClose={() => setCreated(null)} />
    </section>
  );
}

function NewKeyDialog({ agents, onClose, onCreated }: { agents: AgentSummary[]; onClose: () => void; onCreated: (k: ApiKeyCreated) => void }) {
  const s = useSession();
  const { mutate } = useSWRConfig();
  const [preset, setPreset] = useState(PRESETS[0]?.id ?? "gateway");
  const [name, setName] = useState("");
  const [agent, setAgent] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const idem = useMemo(() => crypto.randomUUID(), []);
  const p = PRESETS.find((x) => x.id === preset) ?? PRESETS[0];
  const submit = async (): Promise<void> => {
    if (!p) return;
    setBusy(true);
    setError(null);
    try {
      const key = await s.withStepUp(() => bffSend<ApiKeyCreated>("/api-keys", { name: name.trim(), env: s.keyEnv, scopes: p.scopes, ...(p.bound && agent ? { agent_id: agent } : {}) }, { idempotencyKey: idem }));
      await mutate(() => true);
      onClose();
      onCreated(key);
    } catch (err) {
      setError(err instanceof ProblemError ? (err.problem.detail ?? err.problem.title) : "Not created.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <Layer
      open
      onClose={onClose}
      title="New API key"
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button type="button" className="btn btn-primary" disabled={busy || !name.trim() || (Boolean(p?.bound) && !agent)} onClick={() => void submit()} data-testid="create-key">
            {busy ? <span className="spinner" aria-hidden /> : null}Create key
          </button>
        </>
      }
    >
      <div className="stack">
        <div className="field">
          <label htmlFor="nk-name">Name</label>
          <input id="nk-name" className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. claims-triage-prod" />
        </div>
        <fieldset className="inset" style={{ border: 0, padding: 0, margin: 0, overflow: "hidden", boxShadow: "0 0 0 1px var(--hairline)" }}>
          <legend className="sr-only">Purpose</legend>
          {PRESETS.map((x) => (
            <label key={x.id} className="choice">
              <input type="radio" name="preset" checked={preset === x.id} onChange={() => setPreset(x.id)} />
              <span>
                <span className="title-sm">{x.label}</span>
                <span className="muted" style={{ display: "block" }}>
                  <span className="mono">{x.scopes.join(" ")}</span> · {x.note}
                </span>
              </span>
            </label>
          ))}
        </fieldset>
        {p?.bound ? (
          <div className="field">
            <label htmlFor="nk-agent">Agent</label>
            <select id="nk-agent" className="select" value={agent} onChange={(e) => setAgent(e.target.value)}>
              <option value="">Choose an agent…</option>
              {agents.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </div>
        ) : null}
        {error ? (
          <div className="banner" data-tone="failed" role="alert">
            <Icon name="incident" size={16} />
            {error}
          </div>
        ) : null}
      </div>
    </Layer>
  );
}

function RevokeDialog({ k, onClose }: { k: ApiKey; onClose: () => void }) {
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const [busy, setBusy] = useState(false);
  const submit = async (): Promise<void> => {
    setBusy(true);
    try {
      await bffSend(`/api-keys/${k.id}/revoke`, { reason: "Revoked from the console" });
      await mutate(() => true);
      toast.success("Key revoked", "Gateways drop it within about 2 seconds.");
      onClose();
    } catch (err) {
      toast.error(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Layer
      open
      onClose={onClose}
      title={`Revoke ${k.name}?`}
      description="Anything still using this key starts getting 401 within seconds. This cannot be undone; mint a new key instead."
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Keep key
          </button>
          <button type="button" className="btn btn-danger" disabled={busy} onClick={() => void submit()} data-testid="revoke-submit">
            Revoke
          </button>
        </>
      }
    >
      <p className="muted mono">sbl_live_{k.prefix}_…</p>
    </Layer>
  );
}

function TenantKeys() {
  const s = useSession();
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const allowed = s.can("keys:read");
  const { data } = useBff<Page<TenantKey>>(allowed ? "/tenant-keys" : null);
  const [rotating, setRotating] = useState<TenantKeyPurpose | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const idem = useMemo(() => crypto.randomUUID(), []);
  if (!allowed) return <Restricted what="Tenant keys" who={`Only admins and security admins can see key metadata (keys:read). Your role: ${s.roleLabels.join(" + ")}.`} />;
  const rotate = async (): Promise<void> => {
    if (!rotating) return;
    setBusy(true);
    try {
      await s.withStepUp(() => bffSend(`/tenant-keys/${rotating}/rotate`, { reason: reason.trim() }, { idempotencyKey: idem }));
      await mutate(() => true);
      toast.success(`${rotating} key rotated`, "New writes use the new version; existing data is re-wrapped in the background.");
      setRotating(null);
      setReason("");
    } catch (err) {
      toast.error(err);
    } finally {
      setBusy(false);
    }
  };
  const purposes: TenantKeyPurpose[] = ["payload", "credential", "config"];
  return (
    <section className="section" aria-label="Tenant keys">
      <p className="muted" style={{ padding: "0 4px" }}>
        Envelope-encryption keys for this tenant. Metadata only: key material never leaves the KMS. Shredding a key is how erasure works (D17).
      </p>
      <div className="panel">
        {purposes.map((purpose) => {
          const versions = (data?.data ?? []).filter((k) => k.purpose === purpose);
          const active = versions.find((k) => k.state === "active");
          return (
            <div className="row" key={purpose} style={{ alignItems: "flex-start" }}>
              <Icon name="key" size={18} style={{ marginTop: 2 }} />
              <div className="grow">
                <div className="title-sm" style={{ textTransform: "capitalize" }}>
                  {purpose}
                </div>
                <div className="muted">
                  {active ? (
                    <>
                      v{active.version} · {active.algorithm} · {active.kek_id} · active since <DateTime at={active.activated_at} />
                    </>
                  ) : (
                    "No active key"
                  )}
                </div>
                <div className="caption" style={{ marginTop: 4 }}>
                  {versions
                    .filter((k) => k.state !== "active")
                    .map((k) => `v${k.version} ${k.state}`)
                    .join(" · ") || "No earlier versions"}
                </div>
              </div>
              {s.can("keys:rotate") ? (
                <button type="button" className="btn btn-sm" onClick={() => setRotating(purpose)} data-testid={`rotate-${purpose}`}>
                  <Icon name="lock" size={13} /> Rotate
                </button>
              ) : null}
            </div>
          );
        })}
      </div>
      <Layer
        open={Boolean(rotating)}
        onClose={() => setRotating(null)}
        title={`Rotate the ${rotating ?? ""} key`}
        description="Needs a fresh sign-in. Rotation is audited as tenant_key.rotated; at most 6 per hour."
        footer={
          <>
            <button type="button" className="btn" onClick={() => setRotating(null)}>
              Cancel
            </button>
            <button type="button" className="btn btn-primary" disabled={busy || reason.trim().length < 10} onClick={() => void rotate()} data-testid="rotate-submit">
              {busy ? <span className="spinner" aria-hidden /> : null}Rotate
            </button>
          </>
        }
      >
        <div className="field">
          <label htmlFor="rot-reason">Reason</label>
          <textarea id="rot-reason" className="textarea" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Quarterly rotation per key policy" />
        </div>
      </Layer>
    </section>
  );
}

function RolePills({ userId, embedded }: { userId: string; embedded?: Membership[] }) {
  const { data } = useBff<AppUser & { memberships?: Membership[] }>(embedded ? null : `/users/${encodeURIComponent(userId)}`);
  const memberships = embedded ?? data?.memberships ?? [];
  const roles = [...new Set(memberships.map((m) => m.role_name))];
  return (
    <div style={{ display: "flex", gap: 4, flexWrap: "wrap", justifyContent: "flex-end" }}>
      {roles.map((r) => (
        <Pill key={r} tone={r === "owner" ? "accent" : "quiet"}>
          {roleLabel(r)}
        </Pill>
      ))}
    </div>
  );
}

function Members() {
  const s = useSession();
  const { data } = useBff<Page<AppUser & { memberships?: Membership[] }>>("/users?limit=100");
  // The live list does not embed memberships (only GET /users/{id} does); fetch per row then.
  return (
    <section className="section" aria-label="Members">
      <div className="section-title">
        <span className="meta">People come from your identity provider (OIDC); roles are tenant memberships.</span>
        <button type="button" className="btn btn-sm" disabled={!s.can("users:manage")} title={s.can("users:manage") ? undefined : "Needs users:manage"}>
          <Icon name="plus" size={14} /> Invite
        </button>
      </div>
      <div className="panel">
        {(data?.data ?? []).map((u) => (
          <div className="row" key={u.id}>
            <span className="avatar" data-persona={s.personas.find((p) => p.fullName === u.display_name)?.id}>
              {(u.display_name ?? "?")
                .split(" ")
                .map((x) => x[0])
                .join("")
                .slice(0, 2)}
            </span>
            <div className="grow">
              <div className="title-sm">{u.display_name}</div>
              <div className="muted">{u.email}</div>
            </div>
            <RolePills userId={u.id} embedded={u.memberships} />
            <span className="caption hide-sm" style={{ width: 90, textAlign: "right" }}>
              {u.last_login_at ? <Ago at={u.last_login_at} /> : "Never"}
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}
