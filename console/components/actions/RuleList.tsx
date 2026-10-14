/** Read-only rules of a policy document, in evaluation order. */
import type { PolicyDocumentBody } from "@/lib/api/action-gate";
import { describeCondition, predicateToForm } from "@/lib/action-gate/predicate-form";
import { windowLabel } from "@/lib/action-gate/labels";
import { EffectPill } from "./Bits";

export function RuleList({ doc }: { doc: Pick<PolicyDocumentBody, "rules"> }) {
  return (
    <>
      {doc.rules.map((r, i) => {
        const when = predicateToForm(r.when);
        const cap = r.cumulative;
        return (
          <div className="rule" key={r.rule_id} data-testid="rule">
            <div className="rule-head">
              <span className="rule-index">{i + 1}</span>
              <span className="title-sm mono">{r.rule_id}</span>
              <span className="tag mono">{r.tool}</span>
              <span className="grow" />
              <EffectPill effect={r.effect} />
            </div>
            <div className="rule-lines">
              {when.kind === "group" ? (
                <div>
                  <span className="k">When</span>
                  {when.conditions.map(describeCondition).join(when.combinator === "all" ? " and " : " or ")}
                </div>
              ) : when.kind === "advanced" ? (
                <div>
                  <span className="k">When</span>
                  <span className="mono">{JSON.stringify(when.json)}</span>
                </div>
              ) : null}
              {cap ? (
                <div>
                  <span className="k">Cap</span>
                  {cap.count ? `${cap.max} calls` : `${cap.sum} totals ${cap.max.toLocaleString("en-IN")}`} per {windowLabel(cap.window_s)}
                  {cap.per ? ` per ${cap.per}` : ""}, then {cap.on_exceed ?? "escalate"}
                </div>
              ) : null}
              {r.data_class ? (
                <div>
                  <span className="k">Data</span>
                  {[r.data_class.secrets ? "secrets" : null, ...r.data_class.pii].filter(Boolean).join(", ")} to an external tool
                </div>
              ) : null}
              <div>
                <span className="k">Reason</span>
                {r.reason}
              </div>
            </div>
          </div>
        );
      })}
    </>
  );
}
