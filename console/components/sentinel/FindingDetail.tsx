"use client";
/**
 * One finding from either source (`GET /findings/{id}`): summary, the structured detail, the
 * recommendation, provenance and feedback. A Sentinel finding also reads Sentinel's own record
 * for the prompt hash. An external monitor's text is untrusted: plain text in a fenced frame,
 * never HTML, markdown or links. Advisory only.
 */
import Link from "next/link";
import type { Finding } from "@/lib/api/external-monitors";
import type { SentinelFinding } from "@/lib/api/monitor";
import type { AgentSummary } from "@/lib/api/types";
import { ProblemError } from "@/lib/api/problem";
import { useBff } from "@/hooks/useBff";
import { ADVICE_LABEL, ADVISORY_COPY } from "@/lib/sentinel/view";
import { FINDING_SUBJECT_LABEL, MONITOR_ADVISORY_COPY, findingPath, findingSubjectHref, plainText, sourceLabel } from "@/lib/monitors/view";
import { EmptyState } from "@/components/ui/Bits";
import { Icon } from "@/components/ui/Icon";
import { Pill } from "@/components/ui/StatePill";
import { DateTime } from "@/components/ui/Time";
import { DemoMark } from "@/components/ui/DemoMark";
import { useSession } from "@/components/shell/Session";
import { AdvisoryMark, ExternalBody, FeedbackButtons, FindingBody, KindPill, Provenance, SeverityTag, SourceTag } from "./Bits";

const linkStyle = { textDecoration: "underline", textUnderlineOffset: 2 } as const;

export function FindingDetail({ id, initial }: { id: string; initial: Finding | null }) {
  const s = useSession();
  const can = s.can("sentinel:read");
  const path = findingPath(id);
  const { data: f, error } = useBff<Finding>(can ? path : null, initial);
  const sentinel = f?.source === "sentinel";
  const { data: own } = useBff<SentinelFinding>(can && sentinel ? `/sentinel/findings/${encodeURIComponent(id)}` : null);
  const { data: agent } = useBff<AgentSummary>(f?.agent_id ? `/agents/${f.agent_id}` : null);

  if (!f) {
    const forbidden = (error instanceof ProblemError && error.status === 403) || !can;
    return (
      <div className="page">
        <Link href="/sentinel" className="caption">
          ← Findings
        </Link>
        <div className="panel">
          <EmptyState icon={forbidden ? "lock" : "search"} title={forbidden ? "Not permitted" : "Finding not found"} />
        </div>
      </div>
    );
  }
  const href = findingSubjectHref(f);
  const who = sourceLabel(f);
  const external = f.source === "external";
  const summary = external ? plainText(f.summary, 2000) : f.summary;
  const recommendation = f.recommendation ? (external ? plainText(f.recommendation, 2000) : f.recommendation.replace(/^Advisory: \w+\.\s*/, "")) : null;

  return (
    <div className="page" style={{ maxWidth: 980 }}>
      <header>
        <Link href="/sentinel" className="eyebrow" style={{ textDecoration: "none", color: "var(--text-2)" }}>
          <Icon name="arrowLeft" size={12} /> Findings <DemoMark paths={[path]} />
        </Link>
        <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap", margin: "8px 0" }}>
          <AdvisoryMark text={external ? "Monitor · advisory" : "Sentinel · advisory"} />
          <SourceTag finding={f} />
          <KindPill finding={f} />
          <SeverityTag severity={f.severity} />
        </div>
        <h1 className="large-title" style={{ fontSize: "var(--fs-title1)", overflowWrap: "anywhere" }} data-testid="finding-summary">
          {summary}
        </h1>
        <p className="lede">
          {FINDING_SUBJECT_LABEL[f.subject_kind]}
          {agent ? ` · ${agent.name}` : ""} · <DateTime at={f.created_at} />
          {href ? (
            <>
              {" · "}
              <Link href={href} data-testid="finding-subject" style={linkStyle}>
                Open the {FINDING_SUBJECT_LABEL[f.subject_kind].toLowerCase()}
              </Link>
            </>
          ) : null}
          {external && f.monitor_id ? (
            <>
              {" · "}
              <Link href={`/monitors/${f.monitor_id}`} data-testid="finding-monitor" style={linkStyle}>
                Open the monitor
              </Link>
            </>
          ) : null}
        </p>
      </header>

      <div className="banner" data-tone="advisory" role="note">
        <Icon name={external ? "eye" : "sparkle"} size={16} />
        <span>{external ? MONITOR_ADVISORY_COPY : ADVISORY_COPY}</span>
      </div>

      <div className="grid-split">
        <section className="advisory-card" aria-labelledby="finding-body-title">
          <div className="advisory-head">
            <h3 id="finding-body-title">What {external ? "the monitor" : "Sentinel"} found</h3>
          </div>
          <div className="advisory-body">{external ? <ExternalBody f={f} /> : <FindingBody f={f} />}</div>
        </section>
        <div className="stack">
          {recommendation || f.advice ? (
            <section className="advisory-card" aria-labelledby="rec-title" data-testid="finding-recommendation">
              <div className="advisory-head">
                <h3 id="rec-title">Recommendation</h3>
                <AdvisoryMark text="advisory" />
              </div>
              <div className="advisory-body">
                {f.advice ? (
                  <div>
                    <Pill tone="advisory">{ADVICE_LABEL[f.advice]}</Pill>
                  </div>
                ) : null}
                {recommendation ? <p style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{recommendation}</p> : null}
                <p className="caption">A person decides. {external ? who : "Sentinel"} cannot act on this.</p>
              </div>
            </section>
          ) : null}
          <section className="panel panel-pad stack" style={{ gap: 12 }} aria-label="Provenance and feedback">
            <h3 className="title-sm">Provenance</h3>
            <Provenance f={{ ...f, prompt_sha256: own?.prompt_sha256 ?? null, cost_estimated: own?.cost_estimated ?? null }} />
            {own?.prompt_sha256 ? (
              <p className="caption mono" style={{ overflowWrap: "anywhere" }}>
                prompt sha256 {own.prompt_sha256}
              </p>
            ) : null}
            {f.alert_id ? (
              <Link className="caption" href="/alerts" style={linkStyle}>
                Opened a watch-only {external ? "external_finding" : "sentinel_finding"} alert
              </Link>
            ) : null}
            <div className="hairline-top" style={{ paddingTop: 12 }}>
              <FeedbackButtons f={f} />
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
