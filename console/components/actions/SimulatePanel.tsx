"use client";
/**
 * Simulate: paste or edit sample arguments and see allow / block / escalate with the matched
 * rule, paths and the cumulative counter. Presets are built from the policy's own rules so each
 * one exercises a rule. A cap's current window total is an input: the simulate routes take
 * `counters` keyed `<policy version id>/<rule_id>[/hash]` and never read the live counters.
 */
import { useState } from "react";
import type { ActionPolicyDocument, Predicate, Scalar, SimulateResult } from "@/lib/api/action-gate";
import { ProblemError } from "@/lib/api/problem";
import { EFFECT_PAST, windowLabel } from "@/lib/action-gate/labels";
import { counterKey, toNumber, type Counters } from "@/lib/action-gate/evaluate";
import { Icon } from "@/components/ui/Icon";

type Doc = Pick<ActionPolicyDocument, "policy_id" | "rules">;

export type SimulateRun = (tool: string, args: Record<string, unknown>, counters: Counters) => Promise<SimulateResult>;

function sampleValue(node: Predicate, out: Record<string, Scalar>): void {
  const set = (p: string, v: Scalar): void => {
    const key = p.split("/")[1];
    if (key) out[key] = v;
  };
  if ("all" in node) node.all.forEach((n) => sampleValue(n, out));
  else if ("any" in node) sampleValue(node.any[0] as Predicate, out);
  else if ("le" in node) set(node.le[0], node.le[1]);
  else if ("lt" in node) set(node.lt[0], node.lt[1] - 1);
  else if ("gt" in node) set(node.gt[0], node.gt[1] * 2.5);
  else if ("ge" in node) set(node.ge[0], node.ge[1]);
  else if ("eq" in node) set(node.eq[0], node.eq[1]);
  else if ("in" in node) set(node.in[0], node.in[1][0] ?? null);
  else if ("matches" in node) set(node.matches[0], "CLM-204871");
  else if ("exists" in node) set(node.exists, "present");
}

export function presetsFor(doc: Pick<ActionPolicyDocument, "rules">): { label: string; tool: string; args: Record<string, Scalar> }[] {
  return doc.rules.slice(0, 4).map((r) => {
    const args: Record<string, Scalar> = {};
    if (r.when) sampleValue(r.when, args);
    if (r.cumulative?.sum) args[r.cumulative.sum.slice(1)] ??= 1200;
    if (r.data_class) args.body = "Customer mobile +91 98200 12345";
    if ("amount" in args && !("currency" in args)) args.currency = "INR";
    const tool = r.tool.includes("*") ? r.tool.replace("*", r.tool === "*" ? "email.send_external" : "send_external") : r.tool;
    return { label: r.rule_id, tool, args };
  });
}

/** Window totals for every cumulative rule, keyed as the control plane keys them for these arguments. */
export function countersFor(doc: Doc, args: unknown, used: Readonly<Record<string, string>>): Counters {
  const out: Record<string, number> = {};
  for (const rule of doc.rules) {
    if (!rule.cumulative) continue;
    out[counterKey(doc, rule, args)] = toNumber((used[rule.rule_id] ?? "").replace(/,/g, "")) ?? 0;
  }
  return out;
}

export function SimulatePanel({ doc, run, note }: { doc: Doc; run: SimulateRun; note: string }) {
  const presets = presetsFor(doc);
  const first = presets[0];
  const caps = doc.rules.filter((r) => r.cumulative);
  const [tool, setTool] = useState(first?.tool ?? "");
  const [text, setText] = useState(JSON.stringify(first?.args ?? {}, null, 2));
  const [used, setUsed] = useState<Record<string, string>>({});
  const [result, setResult] = useState<SimulateResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const simulate = async (t = tool, raw = text): Promise<void> => {
    setError(null);
    let args: unknown;
    try {
      args = JSON.parse(raw);
    } catch {
      setError("The arguments are not valid JSON.");
      return;
    }
    if (!args || typeof args !== "object" || Array.isArray(args)) {
      setError("The arguments are a JSON object.");
      return;
    }
    setBusy(true);
    try {
      setResult(await run(t, args as Record<string, unknown>, countersFor(doc, args, used)));
    } catch (err) {
      setError(err instanceof ProblemError ? (err.problem.detail ?? err.problem.title) : "Simulation failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel" aria-labelledby="sim-title" data-testid="simulate">
      <div className="panel-head">
        <h3 id="sim-title">Simulate</h3>
        <span className="caption" data-testid="sim-note">
          {note}
        </span>
      </div>
      <div className="panel-pad stack" style={{ gap: 12 }}>
        {presets.length ? (
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }} role="group" aria-label="Sample calls">
            {presets.map((p) => (
              <button
                key={p.label}
                type="button"
                className="btn btn-sm"
                onClick={() => {
                  const raw = JSON.stringify(p.args, null, 2);
                  setTool(p.tool);
                  setText(raw);
                  void simulate(p.tool, raw);
                }}
              >
                {p.label}
              </button>
            ))}
          </div>
        ) : null}
        <div className="field">
          <label htmlFor="sim-tool">Tool</label>
          <input id="sim-tool" className="input mono" value={tool} onChange={(e) => setTool(e.target.value)} data-testid="sim-tool" />
        </div>
        <div className="field">
          <label htmlFor="sim-args">Arguments (JSON)</label>
          <textarea id="sim-args" className="textarea mono" style={{ minHeight: 140, fontSize: 12.5 }} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} data-testid="sim-args" />
        </div>
        {caps.length ? (
          <div className="field-row">
            {caps.map((r) => (
              <div className="field" key={r.rule_id}>
                <label htmlFor={`sim-used-${r.rule_id}`}>
                  Already used · <span className="mono">{r.rule_id}</span>
                </label>
                <input id={`sim-used-${r.rule_id}`} className="input num" inputMode="decimal" placeholder="0" value={used[r.rule_id] ?? ""} onChange={(e) => setUsed({ ...used, [r.rule_id]: e.target.value })} data-testid={`sim-used-${r.rule_id}`} />
              </div>
            ))}
          </div>
        ) : null}
        {error ? (
          <div className="banner" data-tone="failed" role="alert">
            <Icon name="incident" size={16} /> {error}
          </div>
        ) : null}
        <div style={{ display: "flex", justifyContent: "flex-end" }}>
          <button type="button" className="btn btn-primary" onClick={() => void simulate()} disabled={busy || !tool.trim()} data-testid="sim-run">
            {busy ? <span className="spinner" aria-hidden /> : <Icon name="play" size={14} />} Simulate
          </button>
        </div>
      </div>
      {result ? (
        <div className="verdict" data-effect={result.effect} data-testid="sim-result" role="status">
          <div className="verdict-effect">
            <span className="glyph">
              <Icon name={result.effect === "allow" ? "check" : result.effect === "block" ? "x" : "hand"} size={16} />
            </span>
            {EFFECT_PAST[result.effect]}
          </div>
          <dl className="kv inset" style={{ background: "var(--sunken)", borderRadius: "var(--r-thumb)" }}>
            <div>
              <dt>Rule</dt>
              <dd className="mono" data-testid="sim-rule">
                {result.rule_id ?? "default"}
              </dd>
            </div>
            <div>
              <dt>Reason</dt>
              <dd>{result.reason}</dd>
            </div>
            <div>
              <dt>Matched paths</dt>
              <dd className="mono">{(result.matched_paths ?? []).join(", ") || "—"}</dd>
            </div>
            {result.counter ? (
              <div>
                <dt>Counter</dt>
                <dd className="num" data-testid="sim-counter">
                  {result.counter.value ?? "?"} + {result.counter.amount} of {result.counter.max} per {windowLabel(result.counter.window_s)}
                </dd>
              </div>
            ) : null}
            <div>
              <dt>Sensitive tool</dt>
              <dd>{result.sensitive ? "Yes · deciding needs step-up" : "No"}</dd>
            </div>
          </dl>
          <p className="caption">Simulation writes nothing: no counter moves and no audit row is recorded.</p>
        </div>
      ) : null}
    </section>
  );
}
