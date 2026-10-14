"use client";
/**
 * Onboarding (quickstart §1.2–1.4, demo beat 1:00–3:00): capture policy first (D12, `full`
 * pre-selected, secrets scrubbing always on), then a gateway key shown once, then the zero-code
 * snippet, then the agent appearing as `discovered` with the request-only badge.
 */
import Link from "next/link";
import { useMemo, useState } from "react";
import { useSWRConfig } from "swr";
import type { AgentSummary, ApiKeyCreated, CaptureMode, CapturePolicy, Page } from "@/lib/api/types";
import { ProblemError } from "@/lib/api/problem";
import { bffSend } from "@/lib/client/bff";
import { useBff } from "@/hooks/useBff";
import { HealthRing } from "@/components/ui/HealthRing";
import { FidelityBadge, Pill, TierBadge } from "@/components/ui/StatePill";
import { Icon } from "@/components/ui/Icon";
import { useToast } from "@/components/ui/Toast";
import { useSession } from "@/components/shell/Session";
import { KeyReveal } from "./KeyReveal";
import { InstrumentStep } from "@/components/onboarding/InstrumentStep";
import { DiscoveredAgents } from "@/components/onboarding/DiscoveredAgents";

/** Where the snippets point (the dev compose stack; a deployment overrides with NEXT_PUBLIC_SIBYL_GATEWAY_URL). */
const GATEWAY_URL = process.env.NEXT_PUBLIC_SIBYL_GATEWAY_URL ?? "https://localhost:8444";
const INGEST_URL = process.env.NEXT_PUBLIC_SIBYL_INGEST_URL ?? "https://localhost:8443";

const MODES: { mode: CaptureMode; title: string; body: string }[] = [
  { mode: "full", title: "Full", body: "Prompts and responses are stored encrypted for 30 days so handoff packets carry the real input. Best for debugging and human handoff." },
  { mode: "redacted", title: "Redacted", body: "PII detectors run before storage; packets show redacted text. Use when agents see customer data." },
  { mode: "metadata", title: "Metadata only", body: "No content is stored: latency, tokens, cost and errors only. Packets become request-only summaries." },
];

function Step({ n, title, done, children }: { n: number; title: string; done: boolean; children: React.ReactNode }) {
  return (
    <section className="panel" aria-labelledby={`step-${n}`}>
      <div className="panel-head">
        <h3 id={`step-${n}`} style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span className="tier" data-tier={done ? "1" : "3"} aria-hidden>
            {done ? <Icon name="check" size={12} strokeWidth={2.6} /> : n}
          </span>
          {title}
        </h3>
        {done ? <Pill tone="healthy">Done</Pill> : null}
      </div>
      <div className="panel-pad stack">{children}</div>
    </section>
  );
}

const DEMO_REDACTION_PROFILE = "0192aaaa-0000-7000-8000-00000000000a";

export function OnboardingView({ initialPolicies, initialAgents }: { initialPolicies: Page<CapturePolicy> | null; initialAgents: Page<AgentSummary> | null }) {
  const s = useSession();
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const { data: policies } = useBff<Page<CapturePolicy>>("/capture-policies", initialPolicies);
  const [created, setCreated] = useState<ApiKeyCreated | null>(null);
  const [lastKey, setLastKey] = useState<ApiKeyCreated | null>(null);
  const { data: agents } = useBff<Page<AgentSummary>>("/agents?limit=50", initialAgents);
  const policy = policies?.data.find((p) => p.scope_kind === "tenant" && !p.superseded_by) ?? null;
  // Live: the policy must name a redaction profile that exists in this tenant (the demo seeds one id).
  const { data: profiles } = useBff<Page<{ id: string; name?: string }>>(s.mode === "live" && s.tenant === "sandbox" ? "/redaction-profiles?limit=50" : null);
  const redactionProfileId = s.mode === "live" ? (profiles?.data[0]?.id ?? null) : DEMO_REDACTION_PROFILE;
  const canJoinSandbox = s.mode === "live" || s.tenants.some((t) => t.slug === "sandbox");
  const [mode, setMode] = useState<CaptureMode>("full");
  const [days, setDays] = useState(30);
  const [ack, setAck] = useState(false);
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [keyName, setKeyName] = useState("admin-laptop");
  const [keyError, setKeyError] = useState<{ code: string; text: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const idem = useMemo(() => ({ policy: crypto.randomUUID() }), []);
  const canCapture = s.can("capture:write");
  const canKeys = s.can("apikeys:manage");
  const worker = agents?.data.find((a) => a.slug === "quote-worker");

  if (s.tenant !== "sandbox") {
    return (
      <div className="page">
        <header>
          <div className="eyebrow">Quickstart · 10 minutes</div>
          <h1 className="large-title">Onboarding</h1>
          <p className="lede">Onboarding runs in the empty sandbox tenant so you can watch your own agent appear from nothing.</p>
        </header>
        <div className="panel panel-pad" style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
          <span className="grow">{canJoinSandbox ? (s.mode === "live" ? "Sign in to the sandbox workspace to start." : "Switch to the sandbox tenant to start.") : `${s.personaId ? `The ${s.name}` : s.name} has no membership in the sandbox tenant (only the Platform Admin and the Compliance Auditor do).`}</span>
          {canJoinSandbox ? (
            <button type="button" className="btn btn-primary" onClick={() => void s.switchTo({ tenant: "sandbox" })} data-testid="go-sandbox">
              Open sandbox
            </button>
          ) : null}
        </div>
        <section className="panel" aria-labelledby="instrument-title">
          <div className="panel-head">
            <h3 id="instrument-title">Instrument your agents</h3>
            <span className="caption">One line, zero code, or the gateway</span>
          </div>
          <div className="panel-pad">
            <InstrumentStep keyHint={`sbl_${s.keyEnv}_…`} gateway={GATEWAY_URL} endpoint={INGEST_URL} />
          </div>
        </section>
        <DiscoveredAgents />
      </div>
    );
  }

  const savePolicy = async (): Promise<void> => {
    setBusy("policy");
    setPolicyError(null);
    try {
      if (!redactionProfileId) throw new ProblemError(409, "redaction_profile_missing", "No redaction profile", "This workspace has no redaction profile yet; an administrator creates one first.");
      // "*" only creates the first policy; replacing one names the version being replaced.
      await bffSend("/capture-policies", { scope_kind: "tenant", capture_mode: mode, redaction_profile_id: redactionProfileId, payload_retention_days: days, consequences_version: "2026-10", acknowledged: ack }, { idempotencyKey: idem.policy, ifMatch: policy ? `"${policy.version_no}"` : "*" });
      await mutate(() => true);
      toast.success("Capture policy saved", `${mode} capture · ${days} days · secrets always scrubbed.`);
    } catch (err) {
      setPolicyError(err instanceof ProblemError ? (err.problem.detail ?? err.problem.title) : "Not saved.");
    } finally {
      setBusy(null);
    }
  };

  const mintKey = async (): Promise<void> => {
    setBusy("key");
    setKeyError(null);
    try {
      const key = await bffSend<ApiKeyCreated>("/api-keys", { name: keyName.trim(), env: s.keyEnv, scopes: ["gateway:proxy"] });
      setCreated(key);
      setLastKey(key);
      await mutate(() => true);
    } catch (err) {
      setKeyError(err instanceof ProblemError ? { code: err.code, text: err.problem.detail ?? err.problem.title } : { code: "error", text: "Not created." });
    } finally {
      setBusy(null);
    }
  };

  const keyHint = lastKey?.secret ? `${lastKey.secret.slice(0, 22)}…` : `sbl_${s.keyEnv}_…`;
  const snippet = `from openai import OpenAI

client = OpenAI(
    base_url="https://localhost:8444/v1",   # the Sibyl gateway
    api_key="${keyHint}",                   # your Sibyl key, not the provider key
    default_headers={"X-Sibyl-Agent": "quote-worker"},
)

resp = client.chat.completions.create(
    model="gpt-5-mini",
    messages=[{"role": "user", "content": "Quote 40 tonnes of OPC 43 to Jaipur."}],
)`;

  return (
    <div className="page" style={{ maxWidth: 880 }}>
      <header>
        <div className="eyebrow">Quickstart · sandbox</div>
        <h1 className="large-title">Govern your first agent</h1>
        <p className="lede">Zero code: point an existing OpenAI client at the gateway. Sibyl registers the agent on its first call, scores it, and can fail it over.</p>
      </header>

      <Step n={1} title="Choose what Sibyl may capture" done={Boolean(policy)}>
        {policy ? (
          <p className="subtle" data-testid="policy-summary">
            <strong style={{ color: "var(--text)" }}>{policy.capture_mode === "full" ? "Full" : policy.capture_mode === "redacted" ? "Redacted" : "Metadata only"} capture</strong> · payloads kept {policy.payload_retention_days} days · secrets scrubbed regardless · policy v{policy.version_no}.
          </p>
        ) : (
          <>
            <p className="muted">There is no default (D12). Sibyl refuses telemetry and keys until you choose.</p>
            <fieldset className="inset" style={{ border: 0, margin: 0, padding: 0, overflow: "hidden", boxShadow: "0 0 0 1px var(--hairline)" }} disabled={!canCapture}>
              <legend className="sr-only">Capture mode</legend>
              {MODES.map((m) => (
                <label className="choice" key={m.mode}>
                  <input type="radio" name="capture" value={m.mode} checked={mode === m.mode} onChange={() => setMode(m.mode)} data-testid={`capture-${m.mode}`} />
                  <span>
                    <span className="title-sm">{m.title}</span>
                    <span className="muted" style={{ display: "block", marginTop: 2 }}>
                      {m.body}
                    </span>
                  </span>
                </label>
              ))}
              <div className="choice" style={{ cursor: "default" }} aria-disabled="true">
                <input type="checkbox" checked readOnly disabled aria-label="Secrets scrubbing is always on" />
                <span>
                  <span className="title-sm">Secrets scrubbing</span>
                  <span className="muted" style={{ display: "block", marginTop: 2 }}>
                    Always on, in every mode: API keys, tokens and passwords become <span className="mono">[SECRET:hash8]</span> before anything is stored.
                  </span>
                </span>
              </div>
            </fieldset>
            <div style={{ display: "flex", gap: 16, flexWrap: "wrap", alignItems: "flex-end" }}>
              <div className="field" style={{ width: 160 }}>
                <label htmlFor="retention">Payload retention (days)</label>
                <input id="retention" className="input" type="number" min={1} max={365} value={days} onChange={(e) => setDays(Number(e.target.value))} />
              </div>
              <label style={{ display: "flex", gap: 8, alignItems: "center", minHeight: 44 }}>
                <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} style={{ width: 16, height: 16, accentColor: "var(--accent)" }} data-testid="capture-ack" />
                <span className="subtle">I understand what this mode stores</span>
              </label>
              <span className="grow" />
              <button type="button" className="btn btn-primary" disabled={!canCapture || busy !== null} onClick={() => void savePolicy()} data-testid="save-policy">
                {busy === "policy" ? <span className="spinner" aria-hidden /> : null}Save policy
              </button>
            </div>
            {policyError ? (
              <div className="banner" data-tone="failed" role="alert">
                <Icon name="incident" size={16} />
                {policyError}
              </div>
            ) : null}
          </>
        )}
      </Step>

      <Step n={2} title="Mint a gateway key" done={Boolean(lastKey)}>
        <p className="muted">Tenant-level key with one scope, <span className="mono">gateway:proxy</span>. The secret is shown once.</p>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "flex-end" }}>
          <div className="field grow" style={{ minWidth: 200 }}>
            <label htmlFor="key-name">Key name</label>
            <input id="key-name" className="input" value={keyName} onChange={(e) => setKeyName(e.target.value)} />
          </div>
          <button type="button" className="btn btn-primary" disabled={!canKeys || busy !== null} onClick={() => void mintKey()} data-testid="mint-key">
            {busy === "key" ? <span className="spinner" aria-hidden /> : <Icon name="key" size={15} />}Create key
          </button>
        </div>
        {keyError ? (
          <div className="banner" data-tone={keyError.code === "capture_policy_missing" ? "watch" : "failed"} role="alert" data-testid="key-error">
            <Icon name="lock" size={16} />
            <span>
              <strong className="mono">{keyError.code}</strong> · {keyError.text}
            </span>
          </div>
        ) : null}
        {lastKey ? (
          <p className="caption" data-testid="key-created">
            Created <span className="mono">{lastKey.prefix}</span> · expires in 365 days.
          </p>
        ) : null}
      </Step>

      <Step n={3} title="Point your client at the gateway" done={Boolean(worker)}>
        <p className="muted">Change the base URL and the key, add one header. The request body stays byte-for-byte OpenAI.</p>
        <pre className="code" tabIndex={0}>{snippet}</pre>
      </Step>

      <Step n={4} title="Or instrument your agents with the SDK" done={false}>
        <InstrumentStep keyHint={keyHint} gateway={GATEWAY_URL} endpoint={INGEST_URL} />
      </Step>

      <Step n={5} title="Watch it arrive" done={Boolean(worker)}>
        {worker ? (
          <Link href={`/agents/${worker.id}`} className="row inset" style={{ boxShadow: "0 0 0 1px var(--hairline)" }} data-testid="discovered-agent">
            <HealthRing score={worker.health.score} band={worker.health.band ?? null} size={36} provisional />
            <div className="grow">
              <div className="title-sm">{worker.name}</div>
              <div className="caption mono">{worker.slug}</div>
            </div>
            <TierBadge tier={worker.tier} />
            <Pill tone="quiet">discovered</Pill>
            <FidelityBadge fidelity="request_only" />
            <Icon name="chevronRight" size={14} />
          </Link>
        ) : (
          <div className="row" style={{ paddingInline: 0, color: "var(--text-2)" }}>
            <span className="pill" data-tone="neutral" data-live="true">
              <span className="dot" />
              Waiting for the first call
            </span>
            <span className="muted">{s.mode === "demo" ? "In demo mode a first call is simulated about 5 seconds after you create the key." : "Run the snippet; the agent appears within about 5 seconds."}</span>
          </div>
        )}
        {worker ? <p className="muted">Next: give it an owner, tier 2 and a continuity plan (alternate model → alternate provider → human queue). Gateway-only agents can only ever produce request-only handoff packets.</p> : null}
      </Step>
      {worker ? <DiscoveredAgents compact /> : null}
      <KeyReveal created={created} onClose={() => setCreated(null)} />
    </div>
  );
}
