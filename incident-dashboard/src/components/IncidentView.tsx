import { useState } from "react";
import type { Conclusion, Incident } from "../types";
import { tacticClass } from "../tactics";

type Props = {
  incident: Incident;
};

export default function IncidentView({ incident }: Props) {
  if (incident.conclusions.length === 0) {
    return (
      <div className="empty-note">
        No conclusions fired — the activity in this dataset appears benign.
        <span className="mono">ZERO FINDINGS · NOTHING TO RECONSTRUCT</span>
      </div>
    );
  }

  // Parent lookups: by unique conclusion_id first, with a rule_id fallback in
  // case older backend payloads still reference rules in parent_conclusion_id.
  const byId = new Map(incident.conclusions.map((c) => [c.conclusion_id, c]));
  const byRule = new Map(incident.conclusions.map((c) => [c.rule_id, c]));
  const resolveParent = (pid: string): Conclusion | undefined =>
    byId.get(pid) ?? byRule.get(pid);

  return (
    <div className="cards-grid">
      {incident.conclusions.map((conclusion, index) => (
        <ConclusionCard
          key={conclusion.conclusion_id}
          conclusion={conclusion}
          index={index}
          resolveParent={resolveParent}
        />
      ))}
    </div>
  );
}

type CardProps = {
  conclusion: Conclusion;
  index: number;
  resolveParent: (parentId: string) => Conclusion | undefined;
};

function ConclusionCard({ conclusion, index, resolveParent }: CardProps) {
  const [open, setOpen] = useState(false);
  const totalEvents = conclusion.evidence.reduce(
    (n, ev) => n + ev.event_ids.length,
    0,
  );

  return (
    <article
      className={`concl-card ${tacticClass(conclusion.tactic)}`}
      style={{ animationDelay: `${Math.min(index, 6) * 60}ms` }}
    >
      <header className="cc-head">
        <span className="cc-idx">{String(index + 1).padStart(2, "0")}</span>
        <span className="tech-badge">{conclusion.technique_id}</span>
        <span className="tactic-chip">
          <span className="tactic-dot" aria-hidden="true" />
          {conclusion.tactic}
        </span>
        {conclusion.severity && (
          <span className={`sev-badge sev-${conclusion.severity}`}>
            {conclusion.severity}
          </span>
        )}
        {typeof conclusion.confidence === "number" && (
          <span className="conf-badge" title="Rule confidence">
            {Math.round(conclusion.confidence * 100)}% conf
          </span>
        )}
        <span className="cc-rule">{conclusion.rule_id}</span>
      </header>

      <p className="cc-desc">{conclusion.description}</p>
      {conclusion.hosts && conclusion.hosts.length > 0 && (
        <p className="cc-hosts">
          <span className="parent-label">HOST</span> {conclusion.hosts.join(", ")}
        </p>
      )}

      <footer className="cc-foot">
        <button
          type="button"
          className={`ev-toggle${open ? " open" : ""}`}
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
        >
          Evidence · {conclusion.evidence.length}{" "}
          {conclusion.evidence.length === 1 ? "item" : "items"} · {totalEvents}{" "}
          {totalEvents === 1 ? "event" : "events"}
          <svg
            className="chev"
            width="10"
            height="10"
            viewBox="0 0 10 10"
            fill="none"
            aria-hidden="true"
          >
            <path
              d="M1.5 3.5L5 7l3.5-3.5"
              stroke="currentColor"
              strokeWidth="1.6"
              strokeLinecap="round"
            />
          </svg>
        </button>

        <div className={`ev-collapse${open ? " open" : ""}`}>
          <div className="ev-inner">
            <div className="ev-list">
              {conclusion.evidence.map((ev, i) => {
                const parent = ev.parent_conclusion_id
                  ? resolveParent(ev.parent_conclusion_id)
                  : undefined;
                return (
                  <div className="ev-item" key={`${i}-${ev.explanation}`}>
                    <p className="ev-expl">{ev.explanation}</p>
                    <div className="event-ids">
                      {ev.event_ids.map((id) => (
                        <code className="event-chip" key={`${i}-${id}`}>
                          {id}
                        </code>
                      ))}
                    </div>
                    {ev.parent_conclusion_id && (
                      <div className="parent-link">
                        <span className="parent-label">DERIVED FROM</span>
                        <span>
                          {parent
                            ? `${parent.rule_id} · ${parent.technique_id}`
                            : ev.parent_conclusion_id}
                        </span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </footer>
    </article>
  );
}
