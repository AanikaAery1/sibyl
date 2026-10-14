"use client";
/**
 * Run tree (D50) for one run: its child runs, the agent each ran as, model calls (requested vs
 * served model, flagged when the API reports `model_mismatch`), tool calls, handoffs to other
 * agents, and Action Gate outcomes linking to the held action, in step order. Read from
 * `GET /runs/{run_id}`; the API builds the tree and says `truncated` when a bound cut it.
 */
import Link from "next/link";
import type { RunDetail } from "@/lib/api/monitor";
import type { AgentSummary, Page } from "@/lib/api/types";
import { ProblemError } from "@/lib/api/problem";
import { useBff } from "@/hooks/useBff";
import { RUN_STATUS_LABEL, runPath, runTree, type GateEffect, type ModelCall, type RunItem, type RunView, type ToolCall } from "@/lib/runs/tree";
import { RUN_BOUNDS } from "@/lib/runs/project";
import { discoveryState } from "@/lib/agents/discovery";
import { PROVIDER_LABEL, label, type Tone } from "@/lib/labels";
import { EmptyState } from "@/components/ui/Bits";
import { Icon } from "@/components/ui/Icon";
import { Pill } from "@/components/ui/StatePill";
import { Clock, DateTime } from "@/components/ui/Time";
import { DemoMark } from "@/components/ui/DemoMark";

const GATE: Readonly<Record<GateEffect, { label: string; tone: Tone }>> = {
  allow: { label: "Allowed", tone: "quiet" },
  approved: { label: "Held · approved", tone: "healthy" },
  block: { label: "Blocked", tone: "failed" },
  held: { label: "Held for a person", tone: "human" },
  denied: { label: "Held · denied", tone: "failed" },
};

type AgentIndex = ReadonlyMap<string, AgentSummary>;

const ms = (v: number | null): string => (v === null ? "—" : v >= 1000 ? `${(v / 1000).toFixed(1)} s` : `${Math.round(v)} ms`);

function StatusPill({ status, errorType }: { status: string | null; errorType?: string | null }) {
  if (!status || status === "ok") return null;
  if (status === "running") return <Pill tone="moved" dot live>Running</Pill>;
  const text = status in RUN_STATUS_LABEL ? RUN_STATUS_LABEL[status as keyof typeof RUN_STATUS_LABEL] : status;
  return <Pill tone={status === "error" ? "failed" : "neutral"}>{errorType ? `${text} · ${errorType}` : text}</Pill>;
}

function AgentRef({ id, refName, agents }: { id: string | null; refName: string; agents: AgentIndex }) {
  const agent = id ? agents.get(id) : [...agents.values()].find((a) => a.slug === refName || a.id === refName);
  const href = id ?? agent?.id;
  return href ? <Link href={`/agents/${href}`}>{agent?.name ?? refName}</Link> : <span className="mono">{refName}</span>;
}

function ModelRow({ m }: { m: ModelCall }) {
  return (
    <div className="rt-row" data-testid="rt-model" data-mismatch={m.mismatch === true ? "true" : undefined}>
      <span className="rt-step">{m.step ?? ""}</span>
      <span className="rt-glyph" data-kind="model" aria-hidden>
        <Icon name="cpu" size={13} />
      </span>
      <span className="rt-main">
        <span>Model call</span>
        <span className="caption mono">
          {m.provider ? `${label(PROVIDER_LABEL, m.provider)} · ` : ""}
          {m.requested ?? "?"}
          {m.served ? ` → served ${m.served}` : ""}
        </span>
        {m.mismatch === true ? (
          <span className="identity-flag" data-testid="rt-model-mismatch">
            <Icon name="cpu" size={12} /> Served a different model: asked for {m.requested}, got {m.served}
          </span>
        ) : null}
      </span>
      <span className="rt-meta">
        <span className="num">{ms(m.latencyMs)}</span>
        {m.tokensIn !== null ? <span className="num">{m.tokensIn + (m.tokensOut ?? 0)} tok</span> : null}
        {m.finish && m.finish !== "stop" ? <span className="tag">{m.finish}</span> : null}
        <StatusPill status={m.status} />
      </span>
    </div>
  );
}

function GateMark({ t }: { t: ToolCall }) {
  const g = t.gate;
  if (!g) return null;
  if (!g.effect || g.effect === "allow") return <Pill tone="quiet">{g.effect ? "Gate: allowed" : "Gate: recorded"}</Pill>;
  const pill = (
    <Pill tone={GATE[g.effect].tone} dot>
      {GATE[g.effect].label}
    </Pill>
  );
  return g.heldActionId ? (
    <Link href={`/held-actions/${g.heldActionId}`} data-testid="rt-held-link" aria-label={`${GATE[g.effect].label}: open the held action`} style={{ textDecoration: "none" }}>
      {pill}
    </Link>
  ) : (
    pill
  );
}

function ToolRow({ t, agents }: { t: ToolCall; agents: AgentIndex }) {
  return (
    <div className="rt-row" data-testid="rt-tool" data-gate={t.gate?.effect ?? undefined}>
      <span className="rt-step">{t.step ?? ""}</span>
      <span className="rt-glyph" data-kind={t.handoffTo ? "handoff" : "tool"} aria-hidden>
        <Icon name={t.handoffTo ? "route" : "wrench"} size={13} />
      </span>
      <span className="rt-main">
        <span className="mono">{t.tool}</span>
        {t.handoffTo ? (
          <span className="caption">
            Handoff to <AgentRef id={t.handoffAgentId} refName={t.handoffTo} agents={agents} />
          </span>
        ) : null}
        {t.gate?.ruleId ? <span className="tag mono">{t.gate.ruleId}</span> : null}
      </span>
      <span className="rt-meta">
        <span className="num">{ms(t.latencyMs)}</span>
        <GateMark t={t} />
        {t.gate?.effect !== "block" ? <StatusPill status={t.status} /> : null}
      </span>
    </div>
  );
}

function RunHeader({ r, agents, step }: { r: RunView; agents: AgentIndex; step: number | null }) {
  const agent = r.agentId ? agents.get(r.agentId) : undefined;
  const discovery = agent ? discoveryState(agent) : null;
  return (
    <div className="rt-row" data-testid="rt-run">
      <span className="rt-step">{step ?? ""}</span>
      <span className="rt-glyph" data-kind={r.handoffTo ? "handoff" : "run"} aria-hidden>
        <Icon name={r.handoffTo ? "route" : "branch"} size={13} />
      </span>
      <span className="rt-main">
        <span>{r.agentName}</span>
        {agent && agent.name !== r.agentName ? (
          <Link href={`/agents/${agent.id}`} className="caption" style={{ fontWeight: 500 }}>
            {agent.name}
          </Link>
        ) : null}
        {discovery === "awaiting" ? (
          <span data-testid="rt-discovered">
            <Pill tone="watch">discovered · awaiting confirmation</Pill>
          </span>
        ) : null}
      </span>
      <span className="rt-meta" style={{ fontWeight: 400 }}>
        {r.durationMs !== null ? <span className="num">{ms(r.durationMs)}</span> : null}
        {r.startedAt ? (
          <span>
            <Clock at={r.startedAt} />
          </span>
        ) : null}
        <StatusPill status={r.status} errorType={r.errorType} />
      </span>
    </div>
  );
}

function Items({ items, agents }: { items: readonly RunItem[]; agents: AgentIndex }) {
  return (
    <ul className="runtree">
      {items.map((it) => (
        <li key={it.id} className={it.kind === "run" ? "rt-run" : undefined}>
          {it.kind === "run" ? (
            <>
              <RunHeader r={it.run} agents={agents} step={it.step} />
              {it.run.items.length ? <Items items={it.run.items} agents={agents} /> : null}
            </>
          ) : it.kind === "model" ? (
            <ModelRow m={it} />
          ) : (
            <ToolRow t={it} agents={agents} />
          )}
        </li>
      ))}
    </ul>
  );
}

export function RunTreeView({ runId, initial }: { runId: string; initial: RunDetail | null }) {
  const path = runPath(runId);
  const { data, error } = useBff<RunDetail>(path, initial);
  const { data: agentsPage } = useBff<Page<AgentSummary>>("/agents?limit=200");
  const agents: AgentIndex = new Map((agentsPage?.data ?? []).map((a) => [a.id, a]));

  if (!data) {
    return (
      <div className="page">
        <Link href="/fleet" className="caption">
          ← Fleet
        </Link>
        <div className="panel">
          <EmptyState icon={error instanceof ProblemError && error.status === 403 ? "lock" : "search"} title={error ? "Run not found" : "Loading run…"}>
            {error ? "No telemetry for this run in your workspace (it may be past retention)." : undefined}
          </EmptyState>
        </div>
      </div>
    );
  }

  const tree = runTree(data);
  const root = tree.root;
  const rootAgent = root.agentId ? agents.get(root.agentId) : undefined;
  const back = root.parentId ? { href: runPath(root.parentId), text: "Parent run" } : { href: rootAgent ? `/agents/${rootAgent.id}` : "/fleet", text: rootAgent?.name ?? "Fleet" };
  return (
    <div className="page">
      <header className="page-head">
        <div style={{ minWidth: 0 }}>
          <Link href={back.href} className="eyebrow" style={{ textDecoration: "none", color: "var(--text-2)" }}>
            <Icon name="arrowLeft" size={12} /> {back.text} <DemoMark paths={[path]} />
          </Link>
          <h1 className="large-title">Run tree</h1>
          <p className="lede num">
            {root.agentName} · {root.startedAt ? <DateTime at={root.startedAt} /> : null} · {tree.totals.runs} runs, {tree.totals.models} model calls, {tree.totals.tools} tool calls
            {tree.totals.handoffs ? `, ${tree.totals.handoffs} handoffs` : ""}.
          </p>
          <p className="caption mono" style={{ overflowWrap: "anywhere" }}>
            run {root.id}
            {root.traceId ? ` · trace ${root.traceId}` : ""}
          </p>
        </div>
        <StatusPill status={root.status} errorType={root.errorType} />
      </header>

      {tree.truncated ? (
        <div className="banner" data-tone="watch" role="status" data-testid="run-truncated">
          <Icon name="incident" size={16} />
          <span>
            <strong>Part of this tree is not shown.</strong> The tree is capped at {RUN_BOUNDS.runs} runs, {RUN_BOUNDS.steps.toLocaleString("en-US")} steps and {RUN_BOUNDS.depth} levels; {tree.runCount} runs were loaded. Open a child run to see the rest of its subtree.
          </span>
        </div>
      ) : null}

      <section className="panel" aria-label="Run summary">
        <div className="stats">
          <Stat k="Runs" v={tree.totals.runs} />
          <Stat k="Model calls" v={tree.totals.models} small={tree.totals.mismatched ? `${tree.totals.mismatched} served a different model` : undefined} />
          <Stat k="Tool calls" v={tree.totals.tools} />
          <Stat k="Handoffs" v={tree.totals.handoffs} />
          <Stat k="Held by the gate" v={tree.totals.held} tone={tree.totals.held ? "human" : undefined} />
          <Stat k="Blocked by the gate" v={tree.totals.blocked} tone={tree.totals.blocked ? "failed" : undefined} />
        </div>
      </section>

      <section className="panel" aria-label="Steps" data-testid="run-tree" style={{ paddingLeft: "var(--row-x)" }}>
        <ul className="runtree">
          <li className="rt-run">
            <RunHeader r={root} agents={agents} step={root.step} />
            {root.items.length ? <Items items={root.items} agents={agents} /> : null}
          </li>
        </ul>
      </section>
      <p className="caption">Steps are numbered by step index within their run. Content is never shown here: only metadata (models, tools, latency, tokens, gate outcomes).</p>
    </div>
  );
}

function Stat({ k, v, small, tone }: { k: string; v: number; small?: string; tone?: "failed" | "human" }) {
  return (
    <div className="stat" data-tone={tone}>
      <span className="k">{k}</span>
      <span className="v">
        {v}
        {small ? <small> {small}</small> : null}
      </span>
    </div>
  );
}
