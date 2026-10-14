"use client";
/**
 * Monitor admin dialogs: revoke (terminal, reason required), add a signed webhook (the
 * `whsec_` secret is shown once) and issue another key (shown once).
 */
import { useState } from "react";
import type { ApiKeyCreated } from "@/lib/api/types";
import type { Monitor, MonitorWebhookCreated, WebhookEventType } from "@/lib/api/external-monitors";
import { ProblemError } from "@/lib/api/problem";
import { bffSend, route } from "@/lib/client/bff";
import { EMPTY_WEBHOOK, EVENT_LABEL, EVENT_TYPES, MIN_REASON, monitorProblemText, revokeReasonError, toWebhookCreate, validateWebhook, type WebhookForm } from "@/lib/monitors/view";
import { Layer } from "@/components/ui/Layer";
import { Icon } from "@/components/ui/Icon";
import { useSession } from "@/components/shell/Session";
import { OneTimeSecret, SetupSnippets } from "./Bits";

function problemText(err: unknown, fallback: string): string {
  if (err instanceof ProblemError) return monitorProblemText(err.status, err.code) ?? err.problem.detail ?? err.problem.title;
  return fallback;
}

function ErrorBanner({ text, testId }: { text: string | null; testId: string }) {
  if (!text) return null;
  return (
    <div className="banner" data-tone="failed" role="alert" data-testid={testId}>
      <Icon name="incident" size={16} />
      {text}
    </div>
  );
}

export function RevokeDialog({ monitor, open, onClose, onDone }: { monitor: Monitor; open: boolean; onClose: () => void; onDone: (m: Monitor) => void }) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const invalid = revokeReasonError(reason);
  const submit = async (): Promise<void> => {
    if (invalid) return;
    setBusy(true);
    setError(null);
    try {
      const out = await bffSend<Monitor>(route("/monitors/{monitor_id}/revoke", { monitor_id: monitor.id }), { reason: reason.trim() });
      setReason("");
      onDone(out);
    } catch (err) {
      setError(problemText(err, "The monitor was not revoked."));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Layer
      open={open}
      onClose={onClose}
      title={`Revoke ${monitor.name}?`}
      description="Revoking is permanent: its keys stop working at once and its webhooks are disabled. Its findings stay on record."
      testId="monitor-revoke"
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button type="button" className="btn btn-danger" disabled={Boolean(invalid) || busy} onClick={() => void submit()} data-testid="monitor-revoke-confirm">
            {busy ? <span className="spinner" aria-hidden /> : null}Revoke monitor
          </button>
        </>
      }
    >
      <div className="stack" style={{ gap: 12, padding: "4px 0" }}>
        <div className="field">
          <label htmlFor="revoke-reason">Reason</label>
          <textarea id="revoke-reason" className="textarea" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Replaced by the v2 reviewer; the laptop was reimaged." aria-describedby="revoke-reason-hint" />
          <span id="revoke-reason-hint" className="hint">
            Required, at least {MIN_REASON} characters; written to the audit log.
          </span>
        </div>
        <ErrorBanner text={error} testId="monitor-revoke-error" />
      </div>
    </Layer>
  );
}

export function WebhookDialog({ monitor, open, onClose, onDone }: { monitor: Monitor; open: boolean; onClose: () => void; onDone: () => void }) {
  const [form, setForm] = useState<WebhookForm>(EMPTY_WEBHOOK);
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<MonitorWebhookCreated | null>(null);
  const errors = validateWebhook(form);
  const valid = Object.keys(errors).length === 0;
  const close = (): void => {
    setForm(EMPTY_WEBHOOK);
    setTouched(false);
    setError(null);
    setCreated(null);
    onClose();
  };
  const toggle = (e: WebhookEventType): void => setForm((f) => ({ ...f, events: f.events.includes(e) ? f.events.filter((x) => x !== e) : [...f.events, e] }));
  const submit = async (): Promise<void> => {
    setTouched(true);
    if (!valid) return;
    setBusy(true);
    setError(null);
    try {
      const out = await bffSend<MonitorWebhookCreated>(route("/monitors/{monitor_id}/webhooks", { monitor_id: monitor.id }), toWebhookCreate(form));
      setCreated(out);
      onDone();
    } catch (err) {
      setError(problemText(err, "The webhook was not added."));
    } finally {
      setBusy(false);
    }
  };

  if (created) {
    return (
      <Layer
        open={open}
        onClose={close}
        title="Webhook added"
        description={<span className="mono" style={{ overflowWrap: "anywhere" }}>{created.url}</span>}
        testId="webhook-created"
        footer={
          <button type="button" className="btn btn-primary" onClick={close} data-testid="webhook-created-done">
            I&apos;ve stored the secret
          </button>
        }
      >
        <div className="stack" style={{ gap: 14 }}>
          <OneTimeSecret label="signing secret" secret={created.secret} testId="webhook-secret" />
          <p className="muted">
            Every delivery carries <span className="mono">Sibyl-Signature: t=…,v1=…</span> (HMAC-SHA256 of <span className="mono">t.body</span>). Verify it over the raw body and reject stale timestamps; non-2xx answers are retried with backoff, then dead-lettered.
          </p>
          <SetupSnippets kind="webhook" secret={null} />
        </div>
      </Layer>
    );
  }

  return (
    <Layer
      open={open}
      onClose={close}
      title="Add a webhook"
      description="Sibyl signs each delivery. Payloads carry references and states only, never prompts or arguments."
      testId="webhook-add"
      footer={
        <>
          <button type="button" className="btn" onClick={close}>
            Cancel
          </button>
          <button type="button" className="btn btn-primary" disabled={busy || (touched && !valid)} onClick={() => void submit()} data-testid="webhook-add-submit">
            {busy ? <span className="spinner" aria-hidden /> : <Icon name="plus" size={14} />} Add webhook
          </button>
        </>
      }
    >
      <div className="stack" style={{ gap: 14, padding: "4px 0" }}>
        <div className="field">
          <label htmlFor="hook-url">Receiver URL</label>
          <input id="hook-url" className="input mono" value={form.url} onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))} placeholder="https://hooks.example.com/sibyl" inputMode="url" autoComplete="off" aria-invalid={Boolean(touched && errors.url)} aria-describedby="hook-url-hint" />
          <span id="hook-url-hint" className={touched && errors.url ? "error" : "hint"}>
            {(touched && errors.url) || "https only, on a public address (and the deployment's allowlist, if it sets one)."}
          </span>
        </div>
        <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
          <legend className="label">Events</legend>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: 8 }}>
            {EVENT_TYPES.map((e) => (
              <label key={e} className="check">
                <input type="checkbox" checked={form.events.includes(e)} onChange={() => toggle(e)} data-testid={`hook-event-${e}`} /> {EVENT_LABEL[e]}
              </label>
            ))}
          </div>
          {touched && errors.events ? <span className="error">{errors.events}</span> : null}
        </fieldset>
        <div className="field">
          <label htmlFor="hook-reason">Reason (optional)</label>
          <input id="hook-reason" className="input" value={form.reason} onChange={(e) => setForm((f) => ({ ...f, reason: e.target.value }))} placeholder="e.g. Page the claims on-call on held payouts" />
          {touched && errors.reason ? <span className="error">{errors.reason}</span> : null}
        </div>
        <ErrorBanner text={error} testId="webhook-add-error" />
      </div>
    </Layer>
  );
}

export function IssueKeyDialog({ monitor, open, onClose, onDone }: { monitor: Monitor; open: boolean; onClose: () => void; onDone: () => void }) {
  const s = useSession();
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<ApiKeyCreated | null>(null);
  const close = (): void => {
    setName("");
    setError(null);
    setCreated(null);
    onClose();
  };
  const submit = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const out = await bffSend<ApiKeyCreated>(route("/monitors/{monitor_id}/keys", { monitor_id: monitor.id }), { env: s.keyEnv, ...(name.trim() ? { name: name.trim() } : {}) });
      setCreated(out);
      onDone();
    } catch (err) {
      setError(problemText(err, "No key was issued."));
    } finally {
      setBusy(false);
    }
  };
  if (created) {
    return (
      <Layer
        open={open}
        onClose={close}
        title="New monitor key"
        description={`${created.name} · monitor:read + findings:write`}
        testId="monitor-key-created"
        footer={
          <button type="button" className="btn btn-primary" onClick={close} data-testid="monitor-key-done">
            I&apos;ve stored the key
          </button>
        }
      >
        <div className="stack" style={{ gap: 14 }}>
          <OneTimeSecret label="monitor key" secret={created.secret} testId="monitor-key" />
          <SetupSnippets kind={monitor.kind} secret={created.secret ?? null} />
        </div>
      </Layer>
    );
  }
  return (
    <Layer
      open={open}
      onClose={close}
      title="Issue another key"
      description="For a second machine or a rotation. Revoke old keys from Settings → API keys once the new one works."
      testId="monitor-key-issue"
      footer={
        <>
          <button type="button" className="btn" onClick={close}>
            Cancel
          </button>
          <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void submit()} data-testid="monitor-key-submit">
            {busy ? <span className="spinner" aria-hidden /> : <Icon name="key" size={14} />} Issue key
          </button>
        </>
      }
    >
      <div className="stack" style={{ gap: 12, padding: "4px 0" }}>
        <div className="field">
          <label htmlFor="key-name">Key name (optional)</label>
          <input id="key-name" className="input" value={name} maxLength={80} onChange={(e) => setName(e.target.value)} placeholder="e.g. claude-desktop-backup" autoComplete="off" />
        </div>
        <ErrorBanner text={error} testId="monitor-key-error" />
      </div>
    </Layer>
  );
}
