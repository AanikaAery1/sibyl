"use client";
/**
 * The latest advisory findings about one incident or held action, for the screens where a person
 * decides: Sentinel's, and the latest from each external monitor, from the unified
 * `GET /findings`. Rendered as advisory cards (indigo, dashed edge, "advisory" mark) so they are
 * never mistaken for the human decision next to them; each says who wrote it. Monitor text is
 * untrusted and shown as plain text. Renders nothing without `sentinel:read` or a finding;
 * Sentinel admins can ask Sentinel for one on demand.
 */
import Link from "next/link";
import { useState } from "react";
import { useSWRConfig } from "swr";
import type { SentinelConfig, SentinelSubjectKind } from "@/lib/api/monitor";
import type { Finding } from "@/lib/api/external-monitors";
import type { Page } from "@/lib/api/types";
import { ProblemError } from "@/lib/api/problem";
import { bffSend } from "@/lib/client/bff";
import { useBff } from "@/hooks/useBff";
import { ADVICE_LABEL } from "@/lib/sentinel/view";
import { latestBySource, plainText, sourceLabel, subjectFindingsPath } from "@/lib/monitors/view";
import { Pill } from "@/components/ui/StatePill";
import { Icon } from "@/components/ui/Icon";
import { Ago } from "@/components/ui/Time";
import { AdvisoryMark, FeedbackButtons, Provenance } from "./Bits";

export const recommendationPath = subjectFindingsPath;

function Card({ f, subjectKind }: { f: Finding; subjectKind: "incident" | "held_action" }) {
  const external = f.source === "external";
  const who = sourceLabel(f);
  const title = external ? `${who.replace(/^Monitor: /, "")}'s ${subjectKind === "incident" ? "note" : "review"}` : subjectKind === "incident" ? "Sentinel's explanation" : "Sentinel's review";
  const rec = f.recommendation ? (external ? plainText(f.recommendation, 1200) : f.recommendation.replace(/^Advisory: \w+\.\s*/, "")) : null;
  return (
    <section className="advisory-card" aria-labelledby={`finding-${f.id}`} data-testid={external ? "monitor-recommendation" : "sentinel-recommendation"} data-source={f.source}>
      <div className="advisory-head">
        <h3 id={`finding-${f.id}`} style={{ overflowWrap: "anywhere" }}>
          {title}
        </h3>
        <AdvisoryMark text={external ? "Monitor · advisory" : "Sentinel · advisory"} />
      </div>
      <div className="advisory-body">
        <p style={{ fontWeight: 550, overflowWrap: "anywhere" }}>{external ? plainText(f.summary, 600) : f.summary}</p>
        {f.advice ? (
          <div>
            <Pill tone="advisory">{ADVICE_LABEL[f.advice]}</Pill>
          </div>
        ) : null}
        {rec ? (
          <p className="muted" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
            {rec}
          </p>
        ) : null}
        <p className="caption">
          Advisory only: {external ? "a monitor" : "Sentinel"} cannot approve, deny, fail over or change policy. <Ago at={f.created_at} /> ·{" "}
          <Link href={`/sentinel/${f.id}`} data-testid={external ? "monitor-open" : "sentinel-open"} style={{ textDecoration: "underline", textUnderlineOffset: 2 }}>
            Full finding
          </Link>
        </p>
        <Provenance f={f} />
        <FeedbackButtons f={f} />
      </div>
    </section>
  );
}

export function SentinelRecommendation({ subjectKind, subjectId, canRead, canAsk }: { subjectKind: Extract<SentinelSubjectKind, "incident" | "held_action">; subjectId: string; canRead: boolean; canAsk: boolean }) {
  const { mutate } = useSWRConfig();
  const path = subjectFindingsPath(subjectKind, subjectId);
  const { data } = useBff<Page<Finding>>(canRead ? path : null);
  const { data: config } = useBff<SentinelConfig>(canRead && canAsk ? "/sentinel/config" : null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!canRead) return null;
  const { sentinel, external } = latestBySource(data?.data ?? []);

  const ask = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      await bffSend("/sentinel/explain", { subject_kind: subjectKind, subject_id: subjectId });
      await mutate(path);
    } catch (err) {
      setError(err instanceof ProblemError ? (err.problem.detail ?? err.problem.title) : "Sentinel did not answer.");
    } finally {
      setBusy(false);
    }
  };

  const askCard =
    !sentinel && canAsk && config?.enabled ? (
      <section className="advisory-card" aria-label="Sentinel" data-testid="sentinel-ask">
        <div className="advisory-head">
          <h3>Second opinion</h3>
          <AdvisoryMark />
        </div>
        <div className="advisory-body">
          <p className="muted">Ask Sentinel to {subjectKind === "incident" ? "explain this incident" : "review this held action"}. It advises; you decide.</p>
          <div>
            <button type="button" className="btn btn-sm" disabled={busy} onClick={() => void ask()} data-testid="sentinel-ask-button">
              {busy ? <span className="spinner" aria-hidden /> : <Icon name="sparkle" size={14} />} Ask Sentinel
            </button>
          </div>
          {error ? (
            <p className="caption" role="alert" style={{ color: "var(--failed)" }}>
              {error}
            </p>
          ) : null}
        </div>
      </section>
    ) : null;

  if (!sentinel && !external.length && !askCard) return null;
  return (
    <>
      {sentinel ? <Card f={sentinel} subjectKind={subjectKind} /> : askCard}
      {external.map((f) => (
        <Card key={f.id} f={f} subjectKind={subjectKind} />
      ))}
    </>
  );
}
