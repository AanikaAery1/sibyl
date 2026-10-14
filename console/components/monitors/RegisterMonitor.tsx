"use client";
/**
 * Register an external monitor (`POST /monitors`, monitors:admin). The first key is issued with
 * the registration and shown exactly once, next to ready-to-paste setup for its kind.
 */
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useSWRConfig } from "swr";
import type { AgentGroup, MonitorCreated, MonitorKind } from "@/lib/api/external-monitors";
import type { Page } from "@/lib/api/types";
import { ProblemError } from "@/lib/api/problem";
import { bffSend } from "@/lib/client/bff";
import { useBff } from "@/hooks/useBff";
import { AGENT_GROUPS_PATH, EMPTY_REGISTER, MIN_REASON, MONITOR_KIND_HELP, MONITOR_KIND_LABEL, monitorProblemText, toCreate, validateRegister, type RegisterForm } from "@/lib/monitors/view";
import { Layer } from "@/components/ui/Layer";
import { Icon } from "@/components/ui/Icon";
import { useSession } from "@/components/shell/Session";
import { OneTimeSecret, SetupSnippets } from "./Bits";

const KINDS: readonly MonitorKind[] = ["mcp", "webhook", "api"];

export function RegisterMonitor({ open, onClose }: { open: boolean; onClose: () => void }) {
  const s = useSession();
  const router = useRouter();
  const { mutate } = useSWRConfig();
  const { data: groups } = useBff<Page<AgentGroup>>(open ? AGENT_GROUPS_PATH : null);
  const [form, setForm] = useState<RegisterForm>(EMPTY_REGISTER);
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<MonitorCreated | null>(null);
  const errors = validateRegister(form);
  const valid = Object.keys(errors).length === 0;
  const show = (k: keyof typeof errors): string | undefined => (touched ? errors[k] : undefined);
  const set = <K extends keyof RegisterForm>(k: K, v: RegisterForm[K]): void => setForm((f) => ({ ...f, [k]: v }));

  const close = (): void => {
    const done = created;
    setForm(EMPTY_REGISTER);
    setTouched(false);
    setError(null);
    setCreated(null);
    onClose();
    if (done) router.push(`/monitors/${done.id}`);
  };

  const submit = async (): Promise<void> => {
    setTouched(true);
    if (!valid) return;
    setBusy(true);
    setError(null);
    try {
      const out = await bffSend<MonitorCreated>("/monitors", toCreate(form, s.keyEnv));
      setCreated(out);
      await mutate((key) => typeof key === "string" && key.startsWith("/monitors"));
    } catch (err) {
      setError(err instanceof ProblemError ? (monitorProblemText(err.status, err.code) ?? err.problem.detail ?? err.problem.title) : "The monitor was not registered.");
    } finally {
      setBusy(false);
    }
  };

  const toggleGroup = (id: string): void => set("groupIds", form.groupIds.includes(id) ? form.groupIds.filter((g) => g !== id) : [...form.groupIds, id]);

  if (created) {
    return (
      <Layer
        open={open}
        onClose={close}
        title={`${created.name} is registered`}
        description="Connect your agent with the key below. It reads fleet metadata in the watched groups and submits advisory findings; it cannot act."
        testId="monitor-created"
        footer={
          <button type="button" className="btn btn-primary" onClick={close} data-testid="monitor-created-done">
            I&apos;ve stored the key
          </button>
        }
      >
        <div className="stack" style={{ gap: 16 }}>
          <OneTimeSecret label="monitor key" secret={created.api_key?.secret} testId="monitor-key" />
          <p className="caption">
            Scopes <span className="mono">monitor:read</span> and <span className="mono">findings:write</span> only · {created.rate_limit_per_min} findings per minute · prefix <span className="mono">{created.api_key?.prefix ?? "—"}</span>
          </p>
          <SetupSnippets kind={created.kind} secret={created.api_key?.secret ?? null} />
        </div>
      </Layer>
    );
  }

  return (
    <Layer
      open={open}
      onClose={close}
      title="Register a monitor"
      description="An outside agent that watches the fleet and reports advisory findings. Sentinel is the built-in one."
      testId="monitor-register"
      footer={
        <>
          <button type="button" className="btn" onClick={close}>
            Cancel
          </button>
          <button type="button" className="btn btn-primary" disabled={busy || (touched && !valid)} onClick={() => void submit()} data-testid="monitor-register-submit">
            {busy ? <span className="spinner" aria-hidden /> : <Icon name="plus" size={14} />} Register and issue key
          </button>
        </>
      }
    >
      <div className="stack" style={{ gap: 14, padding: "4px 0" }}>
        <div className="field">
          <label htmlFor="mon-name">Name</label>
          <input id="mon-name" className="input" value={form.name} maxLength={128} onChange={(e) => set("name", e.target.value)} placeholder="e.g. Claude ops reviewer" aria-invalid={Boolean(show("name"))} aria-describedby={show("name") ? "mon-name-err" : undefined} autoComplete="off" />
          {show("name") ? (
            <span id="mon-name-err" className="error">
              {show("name")}
            </span>
          ) : null}
        </div>

        <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
          <legend className="label">How it connects</legend>
          <div className="seg" role="radiogroup" aria-label="How it connects">
            {KINDS.map((k) => (
              <button key={k} type="button" role="radio" aria-checked={form.kind === k} onClick={() => set("kind", k)} data-testid={`mon-kind-${k}`}>
                {MONITOR_KIND_LABEL[k]}
              </button>
            ))}
          </div>
          <span className="hint">{MONITOR_KIND_HELP[form.kind]}</span>
        </fieldset>

        <div className="field">
          <label htmlFor="mon-desc">Description (optional)</label>
          <textarea id="mon-desc" className="textarea" value={form.description} maxLength={2000} onChange={(e) => set("description", e.target.value)} placeholder="What it watches and who runs it" />
        </div>

        <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
          <legend className="label">Watches</legend>
          <label className="check">
            <input type="checkbox" checked={form.allGroups} onChange={(e) => set("allGroups", e.target.checked)} data-testid="mon-all-groups" /> All agent groups (needed for fleet-wide findings)
          </label>
          {!form.allGroups ? (
            <div className="subpanel" data-testid="mon-groups">
              {(groups?.data ?? []).length === 0 ? <span className="caption">No agent groups yet; create one, or watch all groups.</span> : null}
              {(groups?.data ?? []).map((g) => (
                <label key={g.id} className="check">
                  <input type="checkbox" checked={form.groupIds.includes(g.id)} onChange={() => toggleGroup(g.id)} /> {g.name}
                  <span className="caption mono">{g.slug}</span>
                </label>
              ))}
            </div>
          ) : null}
          {show("groups") ? <span className="error">{show("groups")}</span> : null}
        </fieldset>

        <div className="field">
          <label htmlFor="mon-rate">Findings per minute</label>
          <input id="mon-rate" className="input" inputMode="numeric" value={form.rateLimit} onChange={(e) => set("rateLimit", e.target.value)} style={{ maxWidth: 140 }} aria-describedby="mon-rate-hint" aria-invalid={Boolean(show("rateLimit"))} />
          <span id="mon-rate-hint" className={show("rateLimit") ? "error" : "hint"}>
            {show("rateLimit") ?? "Past this, POST /findings answers 429. 1 to 600."}
          </span>
        </div>

        <div className="field">
          <label htmlFor="mon-reason">Reason</label>
          <textarea id="mon-reason" className="textarea" value={form.reason} onChange={(e) => set("reason", e.target.value)} placeholder="e.g. Second opinion on held payouts from the on-call Claude." aria-describedby="mon-reason-hint" aria-invalid={Boolean(show("reason"))} />
          <span id="mon-reason-hint" className={show("reason") ? "error" : "hint"}>
            {show("reason") ?? `Required, at least ${MIN_REASON} characters; written to the audit log.`}
          </span>
        </div>

        {error ? (
          <div className="banner" data-tone="failed" role="alert" data-testid="monitor-register-error">
            <Icon name="incident" size={16} />
            {error}
          </div>
        ) : null}
      </div>
    </Layer>
  );
}
