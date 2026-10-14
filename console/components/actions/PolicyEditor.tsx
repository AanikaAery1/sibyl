"use client";
/**
 * The rule editor: a structured form (never raw JSON) over the `sibyl-action-policy/1` model:
 * tool glob, argument conditions (≤ limit, in allowlist, regex…), cumulative caps, data-class
 * blocks, effect and reason. The read-only JSON and simulate preview the draft. Simulate runs on
 * the control plane (`POST /action-policies/simulate`, an unsaved document) when the console is
 * live, and in the console's own evaluator in demo mode or when the control plane is
 * unreachable. Submitting creates a draft version that waits for approval.
 */
import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import { useSWRConfig } from "swr";
import type { ActionEffect, ActionPolicyRecord, ApiActionPolicy, PolicyScopeKind, SimulateResult } from "@/lib/api/action-gate";
import { DRAFT_POLICY_ID, PII_DETECTOR_IDS } from "@/lib/api/action-gate";
import type { Page } from "@/lib/api/types";
import type { components } from "@/lib/api/schema.gen";
import { ProblemError } from "@/lib/api/problem";
import { bffSend } from "@/lib/client/bff";
import { serverNow } from "@/lib/client/sources";
import { useBff } from "@/hooks/useBff";
import { evaluate, type Counters } from "@/lib/action-gate/evaluate";
import { LEAF_OPS, OP_LABEL, emptyCondition, formToDocument, isListOp, isNumericOp, policyToForm, type Condition, type PolicyForm, type RuleForm } from "@/lib/action-gate/predicate-form";
import { CLAIMS_TEMPLATE } from "@/lib/action-gate/templates";
import { createBody, draftDocument, draftSimulateBody, simulateAnswer, toPolicy } from "@/lib/action-gate/wire";
import type { FleetAgent } from "@/components/fleet/types";
import { Icon } from "@/components/ui/Icon";
import { useToast } from "@/components/ui/Toast";
import { useSession } from "@/components/shell/Session";
import { SimulatePanel } from "./SimulatePanel";

type AgentGroup = components["schemas"]["AgentGroup"];

const list = (v: string): string[] => v.split(",").map((x) => x.trim()).filter(Boolean);
const EFFECTS: ActionEffect[] = ["allow", "escalate", "block"];
const LOCAL_NOTE = "Evaluated in the console against this draft";
const SERVER_NOTE = "Evaluated by the control plane against this unsaved draft";
const OFFLINE_NOTE = "Control plane unreachable: evaluated in the console against this draft";

function blankRule(n: number): RuleForm {
  return { rule_id: `rule-${n}`, tool: "payments.transfer", when: { kind: "group", combinator: "all", grouped: false, conditions: [emptyCondition()] }, cap: { enabled: false, measure: "sum", sum: "/amount", max: "", window_s: "86400", per: "", on_exceed: "escalate", onExceedExplicit: false }, dataClass: { enabled: false, secrets: true, pii: [] }, effect: "escalate", reason: "" };
}

/** The control plane could not answer (as opposed to refusing the draft). */
const unreachable = (err: unknown): boolean => !(err instanceof ProblemError) || err.status >= 500;

export function PolicyEditor({ from }: { from: ActionPolicyRecord | null }) {
  const s = useSession();
  const router = useRouter();
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const live = s.mode === "live";
  const { data: agents } = useBff<Page<FleetAgent>>("/agents?limit=200");
  const { data: agentGroups } = useBff<Page<AgentGroup>>(live ? "/agent-groups?limit=200" : null);
  const [name, setName] = useState(from?.name ?? "");
  const [kind, setKind] = useState<PolicyScopeKind>(from?.scope_kind ?? "agent");
  const [scopeId, setScopeId] = useState<string>(from?.scope_id ?? "");
  const [fourEyes, setFourEyes] = useState<boolean>(from?.four_eyes ?? false);
  const [note, setNote] = useState("");
  const [form, setForm] = useState<PolicyForm>(() => policyToForm(from?.document ?? CLAIMS_TEMPLATE));
  const [preview, setPreview] = useState<"json" | "simulate">("json");
  const [simNote, setSimNote] = useState(live ? SERVER_NOTE : LOCAL_NOTE);
  const [busy, setBusy] = useState(false);
  const [serverError, setServerError] = useState<string | null>(null);
  const built = useMemo(() => formToDocument(form), [form]);
  // Live agents name their group (`agent_group_id`, names from /agent-groups); demo agents carry it under x_console.
  const groups = useMemo(() => {
    const m = new Map<string, string>();
    for (const g of agentGroups?.data ?? []) m.set(g.id, g.name);
    for (const a of agents?.data ?? []) if (a.x_console?.group_id) m.set(a.x_console.group_id, a.x_console.process);
    return [...m.entries()];
  }, [agents, agentGroups]);

  const setRule = (i: number, r: RuleForm): void => setForm((f) => ({ ...f, rules: f.rules.map((x, j) => (j === i ? r : x)) }));
  const ready = built.ok && name.trim().length >= 3 && note.trim().length >= 10 && (kind === "tenant" || scopeId);

  const submit = async (): Promise<void> => {
    if (!built.ok) return;
    setBusy(true);
    setServerError(null);
    try {
      const body = createBody({ name, scopeKind: kind, scopeId: kind === "tenant" ? null : scopeId, document: built.value, changeNote: note, fourEyes, basedOnId: from?.id ?? null });
      const rec = toPolicy(await bffSend<ApiActionPolicy>("/action-policies", body));
      // The lists (and this lineage's versions) are cached from the pages before; refresh them.
      await mutate((k) => typeof k === "string" && (k.startsWith("/action-policies") || k.startsWith("/audit")));
      toast.success(`Version ${rec.version_no} submitted`, rec.approval_four_eyes ? "A second person must approve it (four-eyes)." : "It takes effect once approved.");
      router.push(`/action-policies/${rec.id}`);
    } catch (err) {
      setServerError(err instanceof ProblemError ? (err.problem.detail ?? err.problem.title) : err instanceof Error ? err.message : "Not saved.");
      toast.error(err);
    } finally {
      setBusy(false);
    }
  };

  const simulateLocally = (tool: string, args: Record<string, unknown>, counters: Counters): SimulateResult => {
    if (!built.ok) throw new ProblemError(422, "validation_failed", "The draft is not valid", "Fix the highlighted fields first.");
    const d = evaluate(draftDocument(built.value), tool, args, counters);
    return simulateAnswer(d, counters, null, new Date(serverNow()).toISOString());
  };

  const simulate = async (tool: string, args: Record<string, unknown>, counters: Counters): Promise<SimulateResult> => {
    if (!built.ok) return simulateLocally(tool, args, counters);
    if (!live) return simulateLocally(tool, args, counters);
    try {
      const body = draftSimulateBody({ document: built.value, scopeKind: kind, scopeId: kind === "tenant" ? null : scopeId || null, tool, args, counters });
      const answer = await bffSend<SimulateResult>("/action-policies/simulate", body);
      setSimNote(SERVER_NOTE);
      return answer;
    } catch (err) {
      if (!unreachable(err)) throw err;
      setSimNote(OFFLINE_NOTE);
      return simulateLocally(tool, args, counters);
    }
  };

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <div className="eyebrow">Action Gate · {from ? `new version of ${from.name} v${from.version_no}` : "new policy"}</div>
          <h1 className="large-title">{from ? `Revise ${from.name}` : "New action policy"}</h1>
          <p className="lede">Rules are checked in order and the first match wins. Submitting creates a version that waits for approval{from?.approval_four_eyes ? " by a second person" : ""}.</p>
        </div>
      </header>

      <div className="grid-split">
        <div className="stack">
          <section className="panel" aria-labelledby="basics-title">
            <div className="panel-head">
              <h3 id="basics-title">Basics</h3>
            </div>
            <div className="panel-pad stack" style={{ gap: 12 }}>
              <div className="field-row">
                <div className="field">
                  <label htmlFor="pol-name">Name</label>
                  <input id="pol-name" className="input" value={name} onChange={(e) => setName(e.target.value)} data-testid="pol-name" />
                </div>
                <div className="field">
                  <label htmlFor="pol-kind">Applies to</label>
                  <select id="pol-kind" className="select" value={kind} disabled={Boolean(from)} onChange={(e) => (setKind(e.target.value as PolicyScopeKind), setScopeId(""))}>
                    <option value="agent">One agent</option>
                    <option value="agent_group">An agent group</option>
                    <option value="tenant">Every agent (tenant-wide)</option>
                  </select>
                </div>
                {kind !== "tenant" ? (
                  <div className="field">
                    <label htmlFor="pol-scope">{kind === "agent" ? "Agent" : "Group"}</label>
                    <select id="pol-scope" className="select" value={scopeId} disabled={Boolean(from)} onChange={(e) => setScopeId(e.target.value)} data-testid="pol-scope">
                      <option value="">Choose…</option>
                      {kind === "agent"
                        ? (agents?.data ?? []).map((a) => (
                            <option key={a.id} value={a.id}>
                              {a.name} · T{a.tier}
                            </option>
                          ))
                        : groups.map(([id, label]) => (
                            <option key={id} value={id}>
                              {label}
                            </option>
                          ))}
                    </select>
                  </div>
                ) : null}
              </div>
              <div className="field">
                <label htmlFor="pol-note">What changes, and why</label>
                <input id="pol-note" className="input" value={note} onChange={(e) => setNote(e.target.value)} placeholder="e.g. Lower the review threshold to ₹40,000 after the October audit" data-testid="pol-note" />
                <span className="hint">At least 10 characters; recorded with the version and in the audit log.</span>
              </div>
              <label className="check">
                <input type="checkbox" checked={fourEyes} onChange={(e) => setFourEyes(e.target.checked)} data-testid="pol-four-eyes" />
                Held actions need two different approvers (four-eyes)
              </label>
            </div>
          </section>

          <section className="panel" aria-labelledby="defaults-title">
            <div className="panel-head">
              <h3 id="defaults-title">Defaults</h3>
            </div>
            <div className="panel-pad stack" style={{ gap: 12 }}>
              <div className="field-row">
                <div className="field">
                  <span className="label" id="def-label">When no rule matches</span>
                  <div className="seg" role="group" aria-labelledby="def-label">
                    {(["allow", "escalate"] as const).map((e) => (
                      <button key={e} type="button" aria-pressed={form.default_effect === e} onClick={() => setForm({ ...form, default_effect: e })}>
                        {e === "allow" ? "Allow" : "Escalate"}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="field">
                  <label htmlFor="pol-hold">Hold for (seconds), then deny</label>
                  <input id="pol-hold" className="input num" inputMode="numeric" value={form.hold_timeout_s} onChange={(e) => setForm({ ...form, hold_timeout_s: e.target.value })} />
                </div>
              </div>
              <div className="field-row">
                <div className="field">
                  <label htmlFor="pol-sensitive">Sensitive tools (deciding needs step-up)</label>
                  <input id="pol-sensitive" className="input mono" value={form.sensitive_tools.join(", ")} onChange={(e) => setForm({ ...form, sensitive_tools: list(e.target.value) })} />
                </div>
                <div className="field">
                  <label htmlFor="pol-external">External tools (data leaves the company)</label>
                  <input id="pol-external" className="input mono" value={form.external_tools.join(", ")} onChange={(e) => setForm({ ...form, external_tools: list(e.target.value) })} />
                </div>
              </div>
              <label className="check">
                <input type="checkbox" checked={form.tool_allowlist_enforced} onChange={(e) => setForm({ ...form, tool_allowlist_enforced: e.target.checked, tool_allowlist: e.target.checked ? (form.tool_allowlist ?? []) : form.tool_allowlist })} />
                Block any tool not on the allowlist
              </label>
              {form.tool_allowlist_enforced ? (
                <div className="field">
                  <label htmlFor="pol-allow">Tool allowlist</label>
                  <input id="pol-allow" className="input mono" value={(form.tool_allowlist ?? []).join(", ")} onChange={(e) => setForm({ ...form, tool_allowlist: list(e.target.value) })} />
                </div>
              ) : null}
            </div>
          </section>

          <section className="panel" aria-labelledby="rules-title">
            <div className="panel-head">
              <h3 id="rules-title">Rules · first match wins</h3>
              <button type="button" className="btn btn-sm" onClick={() => setForm({ ...form, rules: [...form.rules, blankRule(form.rules.length + 1)] })} data-testid="rule-add">
                <Icon name="plus" size={13} /> Add rule
              </button>
            </div>
            {form.rules.map((r, i) => (
              <RuleEditor key={i} index={i} rule={r} count={form.rules.length} onChange={(x) => setRule(i, x)} onMove={(d) => setForm((f) => {
                const rules = [...f.rules];
                const [it] = rules.splice(i, 1);
                rules.splice(i + d, 0, it as RuleForm);
                return { ...f, rules };
              })} onRemove={() => setForm((f) => ({ ...f, rules: f.rules.filter((_, j) => j !== i) }))} />
            ))}
          </section>
        </div>

        <div className="stack" style={{ position: "sticky", top: "calc(var(--toolbar-h) + 16px)" }}>
          <section className="panel" aria-labelledby="preview-title">
            <div className="panel-head">
              <h3 id="preview-title">Preview</h3>
              <div className="seg" role="group" aria-label="Preview">
                <button type="button" aria-pressed={preview === "json"} onClick={() => setPreview("json")}>
                  JSON
                </button>
                <button type="button" aria-pressed={preview === "simulate"} onClick={() => setPreview("simulate")} data-testid="editor-simulate">
                  Simulate
                </button>
              </div>
            </div>
            {preview === "json" ? (
              <div className="panel-pad">
                {built.ok ? (
                  <pre className="code" tabIndex={0} style={{ maxHeight: 420 }} data-testid="editor-json">
                    {JSON.stringify(built.value, null, 2)}
                  </pre>
                ) : (
                  <ul className="error-list" role="alert" data-testid="editor-errors">
                    {built.errors.map((e) => (
                      <li key={`${e.path}${e.message}`}>
                        <span className="mono">{e.path}</span> · {e.message}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            ) : null}
          </section>
          {preview === "simulate" && built.ok ? <SimulatePanel doc={{ policy_id: DRAFT_POLICY_ID, rules: built.value.rules }} note={simNote} run={simulate} /> : null}
          <section className="panel panel-pad stack" style={{ gap: 10 }}>
            {serverError ? (
              <div className="banner" data-tone="failed" role="alert" data-testid="policy-submit-error">
                {serverError}
              </div>
            ) : null}
            <button type="button" className="btn btn-primary" disabled={!ready || busy || !s.can("action_policies:write")} onClick={() => void submit()} data-testid="policy-submit">
              {busy ? <span className="spinner" aria-hidden /> : <Icon name="shield" size={15} />} Submit for approval
            </button>
            <p className="caption">Nothing changes for agents until a version is approved and the next signed snapshot carries it.</p>
          </section>
        </div>
      </div>
    </div>
  );
}

function RuleEditor({ index, rule, count, onChange, onMove, onRemove }: { index: number; rule: RuleForm; count: number; onChange: (r: RuleForm) => void; onMove: (d: -1 | 1) => void; onRemove: () => void }) {
  const id = `r${index}`;
  const when = rule.when;
  const setCond = (j: number, c: Condition): void => {
    if (when.kind !== "group") return;
    onChange({ ...rule, when: { ...when, conditions: when.conditions.map((x, k) => (k === j ? c : x)) } });
  };
  return (
    <div className="rule" data-testid="rule-editor">
      <div className="rule-head">
        <span className="rule-index">{index + 1}</span>
        <span className="title-sm mono">{rule.rule_id || "new rule"}</span>
        <span className="grow" />
        <button type="button" className="btn btn-icon btn-sm" aria-label={`Move rule ${index + 1} up`} disabled={index === 0} onClick={() => onMove(-1)}>
          <Icon name="chevronDown" size={14} style={{ transform: "rotate(180deg)" }} />
        </button>
        <button type="button" className="btn btn-icon btn-sm" aria-label={`Move rule ${index + 1} down`} disabled={index === count - 1} onClick={() => onMove(1)}>
          <Icon name="chevronDown" size={14} />
        </button>
        <button type="button" className="btn btn-icon btn-sm" aria-label={`Remove rule ${index + 1}`} onClick={onRemove}>
          <Icon name="x" size={14} />
        </button>
      </div>
      <div className="field-row">
        <div className="field">
          <label htmlFor={`${id}-id`}>Rule id</label>
          <input id={`${id}-id`} className="input mono" value={rule.rule_id} onChange={(e) => onChange({ ...rule, rule_id: e.target.value })} />
        </div>
        <div className="field">
          <label htmlFor={`${id}-tool`}>Tool or glob</label>
          <input id={`${id}-tool`} className="input mono" value={rule.tool} onChange={(e) => onChange({ ...rule, tool: e.target.value })} />
        </div>
      </div>

      <div className="subpanel">
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <span className="label" style={{ fontWeight: 600, fontSize: "var(--fs-callout)" }}>
            When the arguments match
          </span>
          {when.kind === "group" && when.conditions.length > 1 ? (
            <div className="seg" role="group" aria-label={`Rule ${index + 1} combinator`}>
              {(["all", "any"] as const).map((c) => (
                <button key={c} type="button" aria-pressed={when.combinator === c} onClick={() => onChange({ ...rule, when: { ...when, combinator: c } })}>
                  {c === "all" ? "All" : "Any"}
                </button>
              ))}
            </div>
          ) : null}
        </div>
        {when.kind === "advanced" ? (
          <>
            <pre className="code" tabIndex={0}>{JSON.stringify(when.json, null, 2)}</pre>
            <p className="caption">Nested conditions are kept exactly as written; the form shows them read-only.</p>
          </>
        ) : when.kind === "group" ? (
          when.conditions.map((c, j) => <ConditionRow key={j} id={`${id}-c${j}`} c={c} onChange={(x) => setCond(j, x)} onRemove={() => onChange({ ...rule, when: when.conditions.length === 1 ? { kind: "none" } : { ...when, conditions: when.conditions.filter((_, k) => k !== j) } })} />)
        ) : (
          <p className="caption">Every call to this tool matches.</p>
        )}
        {when.kind !== "advanced" ? (
          <button type="button" className="btn btn-sm" style={{ alignSelf: "flex-start" }} onClick={() => onChange({ ...rule, when: when.kind === "group" ? { ...when, conditions: [...when.conditions, emptyCondition()] } : { kind: "group", combinator: "all", grouped: false, conditions: [emptyCondition()] } })}>
            <Icon name="plus" size={13} /> Condition
          </button>
        ) : null}
      </div>

      <label className="check">
        <input type="checkbox" checked={rule.cap.enabled} onChange={(e) => onChange({ ...rule, cap: { ...rule.cap, enabled: e.target.checked } })} />
        Cumulative cap
      </label>
      {rule.cap.enabled ? (
        <div className="field-row">
          <div className="field">
            <label htmlFor={`${id}-measure`}>Count</label>
            <select id={`${id}-measure`} className="select" value={rule.cap.measure} onChange={(e) => onChange({ ...rule, cap: { ...rule.cap, measure: e.target.value as "sum" | "count" } })}>
              <option value="sum">Sum of a field</option>
              <option value="count">Number of calls</option>
            </select>
          </div>
          {rule.cap.measure === "sum" ? (
            <div className="field">
              <label htmlFor={`${id}-sum`}>Field</label>
              <input id={`${id}-sum`} className="input mono" value={rule.cap.sum} onChange={(e) => onChange({ ...rule, cap: { ...rule.cap, sum: e.target.value } })} />
            </div>
          ) : null}
          <div className="field">
            <label htmlFor={`${id}-max`}>At most</label>
            <input id={`${id}-max`} className="input num" value={rule.cap.max} onChange={(e) => onChange({ ...rule, cap: { ...rule.cap, max: e.target.value } })} />
          </div>
          <div className="field">
            <label htmlFor={`${id}-win`}>Per (seconds)</label>
            <input id={`${id}-win`} className="input num" value={rule.cap.window_s} onChange={(e) => onChange({ ...rule, cap: { ...rule.cap, window_s: e.target.value } })} />
          </div>
          <div className="field">
            <label htmlFor={`${id}-exceed`}>Over the cap</label>
            <select id={`${id}-exceed`} className="select" value={rule.cap.on_exceed} onChange={(e) => onChange({ ...rule, cap: { ...rule.cap, on_exceed: e.target.value as "escalate" | "block", onExceedExplicit: true } })}>
              <option value="escalate">Escalate</option>
              <option value="block">Block</option>
            </select>
          </div>
        </div>
      ) : null}

      <label className="check">
        <input type="checkbox" checked={rule.dataClass.enabled} onChange={(e) => onChange({ ...rule, dataClass: { ...rule.dataClass, enabled: e.target.checked } })} />
        Data class: match secrets or personal data sent to an external tool
      </label>
      {rule.dataClass.enabled ? (
        <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
          <label className="check">
            <input type="checkbox" checked={rule.dataClass.secrets} onChange={(e) => onChange({ ...rule, dataClass: { ...rule.dataClass, secrets: e.target.checked } })} />
            Secrets
          </label>
          {PII_DETECTOR_IDS.map((p) => (
            <label key={p} className="check">
              <input type="checkbox" checked={rule.dataClass.pii.includes(p)} onChange={(e) => onChange({ ...rule, dataClass: { ...rule.dataClass, pii: e.target.checked ? [...rule.dataClass.pii, p] : rule.dataClass.pii.filter((x) => x !== p) } })} />
              {p.replace("_", " ")}
            </label>
          ))}
        </div>
      ) : null}

      <div className="field-row">
        <div className="field">
          <span className="label" id={`${id}-eff`}>Then</span>
          <div className="seg" role="group" aria-labelledby={`${id}-eff`}>
            {EFFECTS.map((e) => (
              <button key={e} type="button" aria-pressed={rule.effect === e} onClick={() => onChange({ ...rule, effect: e })}>
                {e[0]?.toUpperCase()}
                {e.slice(1)}
              </button>
            ))}
          </div>
        </div>
      </div>
      <div className="field">
        <label htmlFor={`${id}-reason`}>Reason (shown to people and recorded in the audit)</label>
        <input id={`${id}-reason`} className="input" value={rule.reason} onChange={(e) => onChange({ ...rule, reason: e.target.value })} />
      </div>
    </div>
  );
}

function ConditionRow({ id, c, onChange, onRemove }: { id: string; c: Condition; onChange: (c: Condition) => void; onRemove: () => void }) {
  return (
    <div className="cond">
      <input aria-label="Argument (JSON pointer)" className="input mono" value={c.path} onChange={(e) => onChange({ ...c, path: e.target.value })} />
      <select aria-label="Comparison" className="select" value={c.op} onChange={(e) => {
        const op = e.target.value as Condition["op"];
        onChange({ ...c, op, valueType: isNumericOp(op) ? "number" : op === "matches" ? "string" : c.valueType });
      }}>
        {LEAF_OPS.map((op) => (
          <option key={op} value={op}>
            {OP_LABEL[op]}
          </option>
        ))}
      </select>
      {c.op === "exists" ? (
        <span />
      ) : isListOp(c.op) ? (
        <input aria-label="Values, comma separated" className="input mono" value={c.list.join(", ")} onChange={(e) => onChange({ ...c, list: e.target.value.split(",").map((x) => x.trim()) })} />
      ) : (
        <input aria-label={c.op === "matches" ? "Pattern" : "Value"} className="input mono" value={c.value} onChange={(e) => onChange({ ...c, value: e.target.value })} />
      )}
      <div className="cond-flags">
        <label className="check" title="Negate">
          <input id={`${id}-not`} type="checkbox" checked={c.negate} onChange={(e) => onChange({ ...c, negate: e.target.checked })} />
          not
        </label>
        <button type="button" className="btn btn-icon btn-sm" aria-label="Remove condition" onClick={onRemove}>
          <Icon name="x" size={13} />
        </button>
      </div>
    </div>
  );
}
