"use client";
/**
 * Sentinel setup (sentinel:admin): on/off, provider, model, a write-only key (never shown back,
 * only its hint), daily budget, sampling rate, tasks, and a connection test. Saving sends the
 * GET's ETag for the version you edited as `If-Match` (`"0"` before the first save) and needs a
 * fresh step-up; a reason goes to the audit log. A failed test (`ok: false`) is explained from its
 * documented `error` code and HTTP status; 409 (not set up) and 503 (no key vault) are explained too.
 */
import Link from "next/link";
import { useState } from "react";
import { useSWRConfig } from "swr";
import type { SentinelConfig, SentinelConfigTestResult, SentinelProvider } from "@/lib/api/monitor";
import { ProblemError } from "@/lib/api/problem";
import { bffGetWithEtag, bffSend, lastEtag } from "@/lib/client/bff";
import { useBff } from "@/hooks/useBff";
import { ADVISORY_COPY, ALL_TASKS, DEFAULT_MODEL, KIND_LABEL, PROVIDER_NAME, TASK_HELP, formFromConfig, formatUsd, ifMatchFor, sentinelProblemText, testFailureText, toPut, validateForm, type FormErrors, type SentinelForm } from "@/lib/sentinel/view";
import { EmptyState } from "@/components/ui/Bits";
import { Icon } from "@/components/ui/Icon";
import { Pill } from "@/components/ui/StatePill";
import { DateTime } from "@/components/ui/Time";
import { DemoMark } from "@/components/ui/DemoMark";
import { useToast } from "@/components/ui/Toast";
import { useSession } from "@/components/shell/Session";
import { AdvisoryMark, BudgetMeter } from "./Bits";

const PATH = "/sentinel/config";

function problemOf(err: unknown, fallback: string): { code: string; text: string } {
  if (!(err instanceof ProblemError)) return { code: "error", text: fallback };
  return { code: err.code, text: sentinelProblemText(err.status, err.code) ?? err.problem.detail ?? err.problem.title };
}

export function SentinelSettings({ initial }: { initial: SentinelConfig | null }) {
  const s = useSession();
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const { data: cfg } = useBff<SentinelConfig>(s.can("sentinel:read") ? PATH : null, initial);
  // The server's view until the person edits; then their draft (never overwritten by a refresh).
  const [draft, setDraftState] = useState<SentinelForm | null>(null);
  // The version (and the GET's ETag) the draft was started from: sent back as If-Match.
  const [base, setBase] = useState<{ version: number; etag: string | null } | null>(null);
  const form = draft ?? formFromConfig(cfg ?? initial);
  const setDraft = (next: SentinelForm | null): void => {
    if (next && !draft) setBase({ version: (cfg ?? initial)?.version ?? 0, etag: lastEtag(PATH) });
    if (!next) setBase(null);
    setDraftState(next);
  };
  const [errors, setErrors] = useState<FormErrors>({});
  const [busy, setBusy] = useState<"save" | "test" | null>(null);
  const [problem, setProblem] = useState<{ code: string; text: string } | null>(null);
  const [test, setTest] = useState<SentinelConfigTestResult | null>(null);
  const admin = s.can("sentinel:admin");

  if (!s.can("sentinel:read")) {
    return (
      <div className="page">
        <h1 className="large-title">Sentinel</h1>
        <div className="panel">
          <EmptyState icon="lock" title="Sentinel settings are restricted" />
        </div>
      </div>
    );
  }

  const set = <K extends keyof SentinelForm>(k: K, v: SentinelForm[K]): void => {
    setDraft({ ...form, [k]: v });
  };

  const save = async (): Promise<void> => {
    const errs = validateForm(form, Boolean(cfg?.has_key));
    setErrors(errs);
    setProblem(null);
    if (Object.keys(errs).length) return;
    setBusy("save");
    try {
      let receipt: string | null = null;
      const ifMatch = await editedEtag();
      const send = (): Promise<SentinelConfig> => bffSend<SentinelConfig>(PATH, toPut(form), { method: "PUT", ifMatch, onHeaders: (h) => (receipt = h.get("x-sibyl-audit-receipt")) });
      const next = await s.withStepUp(send);
      await mutate((key) => typeof key === "string" && key.startsWith("/sentinel"));
      setDraft(null);
      toast.success("Sentinel saved", `${next.enabled ? "On" : "Off"} · ${next.provider ? PROVIDER_NAME[next.provider] : ""} ${next.model ?? ""}${receipt ? ` · receipt ${receipt}` : ""}`);
    } catch (err) {
      setProblem(problemOf(err, "Not saved."));
    } finally {
      setBusy(null);
    }
  };

  /**
   * The ETag of the version the draft started from. Normally recorded by the GET; if the page
   * has not read it yet, read it now, and if the configuration moved on meanwhile, refuse like
   * the API would (412) rather than overwrite a change the person never saw.
   */
  const editedEtag = async (): Promise<string> => {
    const from = base ?? { version: (cfg ?? initial)?.version ?? 0, etag: lastEtag(PATH) };
    if (from.etag) return from.etag;
    const fresh = await bffGetWithEtag<SentinelConfig>(PATH);
    if (fresh.data.version !== from.version) throw new ProblemError(412, "precondition_failed", "Changed by someone else", sentinelProblemText(412, "precondition_failed") ?? undefined);
    return ifMatchFor(fresh.data, fresh.etag);
  };

  const runTest = async (): Promise<void> => {
    setBusy("test");
    setTest(null);
    setProblem(null);
    try {
      // A fresh key per click: a replayed key would return the first result, not a new test.
      setTest(await bffSend<SentinelConfigTestResult>(`${PATH}/test`, {}, { idempotencyKey: crypto.randomUUID() }));
    } catch (err) {
      setProblem(problemOf(err, "Test failed."));
    } finally {
      setBusy(null);
    }
  };

  const err = (k: keyof FormErrors) =>
    errors[k] ? (
      <span className="hint" role="alert" style={{ color: "var(--failed)" }}>
        {errors[k]}
      </span>
    ) : null;

  return (
    <div className="page" style={{ maxWidth: 880 }}>
      <header>
        <Link href="/sentinel" className="eyebrow" style={{ textDecoration: "none", color: "var(--text-2)" }}>
          <Icon name="arrowLeft" size={12} /> Sentinel <DemoMark paths={[PATH]} />
        </Link>
        <h1 className="large-title">Sentinel setup</h1>
        <p className="lede">Sentinel runs on your own model key, egress-allowlisted, within a daily budget. Content follows your capture policy: metadata-only tenants send no prompts or outputs.</p>
      </header>

      <div className="banner" data-tone="advisory" role="note" data-testid="advisory-note">
        <Icon name="sparkle" size={16} />
        <span>{ADVISORY_COPY}</span>
      </div>

      {cfg?.configured ? (
        <section className="panel panel-pad stack" style={{ gap: 10 }} aria-label="Today">
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <h3 className="title-sm grow">Today</h3>
            <Pill tone={cfg.enabled ? "advisory" : "quiet"} dot={cfg.enabled}>
              {cfg.enabled ? "On" : "Off"}
            </Pill>
            <span className="caption">
              v{cfg.version} · updated <DateTime at={cfg.updated_at} />
            </span>
          </div>
          <BudgetMeter config={cfg} />
        </section>
      ) : null}

      <section className="panel" aria-labelledby="sentinel-form">
        <div className="panel-head">
          <h3 id="sentinel-form">Configuration</h3>
          <AdvisoryMark text="advisory · never enforces" />
        </div>
        <fieldset className="panel-pad stack" style={{ border: 0, margin: 0, gap: 16 }} disabled={!admin || busy !== null}>
          <legend className="sr-only">Sentinel configuration</legend>
          <label className="choice inset" style={{ boxShadow: "0 0 0 1px var(--hairline)", borderRadius: "var(--r-thumb)" }}>
            <input type="checkbox" checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)} data-testid="sentinel-enabled" />
            <span>
              <span className="title-sm">Turn Sentinel on</span>
              <span className="muted" style={{ display: "block", marginTop: 2 }}>
                Explanations and reviews start with the next incident or hold. Turning it off stops all calls to your provider.
              </span>
            </span>
          </label>

          <div className="field">
            <span className="caption" id="provider-label" style={{ fontWeight: 600 }}>
              Provider
            </span>
            <div className="seg" role="radiogroup" aria-labelledby="provider-label">
              {(Object.keys(PROVIDER_NAME) as SentinelProvider[]).map((p) => (
                <button
                  key={p}
                  type="button"
                  role="radio"
                  aria-checked={form.provider === p}
                  onClick={() => {
                    setDraft({ ...form, provider: p, model: form.provider === p ? form.model : DEFAULT_MODEL[p] });
                  }}
                  data-testid={`provider-${p}`}
                >
                  {PROVIDER_NAME[p]}
                </button>
              ))}
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 16 }}>
            <div className="field">
              <label htmlFor="sentinel-model">Model</label>
              <input id="sentinel-model" className="input mono" value={form.model} onChange={(e) => set("model", e.target.value)} />
              {err("model")}
            </div>
            <div className="field">
              <label htmlFor="sentinel-key">API key</label>
              <input id="sentinel-key" className="input mono" type="password" autoComplete="off" spellCheck={false} value={form.apiKey} onChange={(e) => set("apiKey", e.target.value)} placeholder={cfg?.has_key ? `Vaulted ${cfg.key_hint ?? ""} · leave blank to keep` : "Paste your provider key"} aria-describedby="key-hint" data-testid="sentinel-key" />
              <span id="key-hint" className="hint">
                Write-only. Sealed in the tenant vault; never shown again or written to the audit log.
                {cfg?.key_updated_at ? (
                  <>
                    {" "}
                    Last changed <DateTime at={cfg.key_updated_at} />.
                  </>
                ) : null}
              </span>
              {err("apiKey")}
            </div>
            <div className="field">
              <label htmlFor="sentinel-budget">Daily budget (USD)</label>
              <input id="sentinel-budget" className="input num" inputMode="decimal" value={form.budget} onChange={(e) => set("budget", e.target.value)} />
              <span className="hint">Sentinel pauses for the day when it is spent.</span>
              {err("budget")}
            </div>
            <div className="field">
              <label htmlFor="sentinel-sampling">Sampling rate (%)</label>
              <input id="sentinel-sampling" className="input num" inputMode="decimal" value={form.samplingPct} onChange={(e) => set("samplingPct", e.target.value)} />
              <span className="hint">Share of runs read for semantic drift.</span>
              {err("samplingPct")}
            </div>
          </div>

          <fieldset className="inset" style={{ border: 0, margin: 0, padding: 0, overflow: "hidden", boxShadow: "0 0 0 1px var(--hairline)", borderRadius: "var(--r-thumb)" }}>
            <legend className="caption" style={{ fontWeight: 600, padding: "0 0 6px" }}>
              Tasks
            </legend>
            {ALL_TASKS.map((t) => (
              <label className="choice" key={t}>
                <input type="checkbox" checked={form.tasks.includes(t)} onChange={(e) => set("tasks", e.target.checked ? [...form.tasks, t] : form.tasks.filter((x) => x !== t))} data-testid={`task-${t}`} />
                <span>
                  <span className="title-sm">{KIND_LABEL[t]}</span>
                  <span className="muted" style={{ display: "block", marginTop: 2 }}>
                    {TASK_HELP[t]}
                  </span>
                </span>
              </label>
            ))}
          </fieldset>
          {err("tasks")}

          <div className="field">
            <label htmlFor="sentinel-reason">Reason for the change</label>
            <textarea id="sentinel-reason" className="textarea" value={form.reason} onChange={(e) => set("reason", e.target.value)} placeholder="e.g. Pilot Sentinel on Gemini Flash with a $5 daily cap." />
            <span className="hint">Required. Saving asks you to sign in again (step-up).</span>
            {err("reason")}
          </div>

          {problem ? (
            <div className="banner" data-tone={problem.code === "precondition_failed" || problem.code === "not_active" ? "watch" : "failed"} role="alert" data-testid="sentinel-problem">
              <Icon name="incident" size={16} />
              <span>
                <strong className="mono">{problem.code}</strong> · {problem.text}
              </span>
            </div>
          ) : null}
          {test ? (
            <div className="banner" data-tone={test.ok ? "moved" : "failed"} role="status" data-testid="sentinel-test-result" data-ok={test.ok ? "true" : "false"}>
              <Icon name={test.ok ? "check" : "incident"} size={16} />
              {test.ok ? (
                <span>
                  Connected: {PROVIDER_NAME[test.provider]} {test.model} answered HTTP {test.http_status} in {test.latency_ms} ms
                  {test.cost_usd ? ` · cost ${formatUsd(test.cost_usd)}` : ""}
                </span>
              ) : (
                <span>
                  <strong>Connection failed.</strong> {testFailureText(test)}
                  <span className="caption" style={{ display: "block", marginTop: 2, color: "inherit" }} data-testid="sentinel-test-detail">
                    {PROVIDER_NAME[test.provider]} · <span className="mono">{test.model}</span> · {test.http_status ? `HTTP ${test.http_status}` : "no response"} · {test.latency_ms} ms
                    {test.error ? (
                      <>
                        {" "}
                        · code <span className="mono">{test.error}</span>
                      </>
                    ) : null}
                  </span>
                </span>
              )}
            </div>
          ) : null}

          {admin ? (
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", flexWrap: "wrap" }}>
              <button type="button" className="btn" disabled={!cfg?.has_key || busy !== null} onClick={() => void runTest()} data-testid="sentinel-test">
                {busy === "test" ? <span className="spinner" aria-hidden /> : <Icon name="link" size={15} />}Test connection
              </button>
              <button type="button" className="btn btn-primary" disabled={busy !== null} onClick={() => void save()} data-testid="sentinel-save">
                {busy === "save" ? <span className="spinner" aria-hidden /> : <Icon name="key" size={15} />}Save with step-up
              </button>
            </div>
          ) : (
            <div className="banner" data-tone="quiet">
              <Icon name="lock" size={16} />
              Your role can read this setup; an Admin, Workspace admin or Security admin changes it.
            </div>
          )}
        </fieldset>
      </section>
    </div>
  );
}
