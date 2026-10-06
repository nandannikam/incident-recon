import { useState } from "react";
import UploadForm from "./components/UploadForm";
import IncidentView from "./components/IncidentView";
import AttackChain from "./components/AttackChain";
import { API_HOST } from "./api";
import { tacticClass } from "./tactics";
import type { Incident } from "./types";

type Tab = "conclusions" | "chain";

export default function App() {
  const [incident, setIncident] = useState<Incident | null>(null);
  const [tab, setTab] = useState<Tab>("conclusions");

  function handleAnalyzed(next: Incident) {
    setIncident(next);
    setTab("conclusions");
  }

  function reset() {
    setIncident(null);
    setTab("conclusions");
  }

  return (
    <div className="site-shell">
      <Header hasIncident={incident !== null} onReset={reset} />

      <main className="container">
        {incident ? (
          <ResultView incident={incident} tab={tab} onTabChange={setTab} />
        ) : (
          <Landing onAnalyzed={handleAnalyzed} />
        )}
      </main>

      <footer className="app-footer">
        <div className="container app-footer-inner">
          <span className="micro-caps">
            IncidentRecon · Incident Reconstruction Console
          </span>
          <span className="micro-caps mono">API · {API_HOST}</span>
        </div>
      </footer>
    </div>
  );
}

/* ---------- chrome ---------- */

function ChainMark() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 18 18"
      fill="none"
      aria-hidden="true"
    >
      <rect
        x="1.4"
        y="6"
        width="9.4"
        height="6"
        rx="3"
        stroke="currentColor"
        strokeWidth="1.5"
      />
      <rect
        x="7.2"
        y="6"
        width="9.4"
        height="6"
        rx="3"
        stroke="currentColor"
        strokeWidth="1.5"
      />
    </svg>
  );
}

function Header({
  hasIncident,
  onReset,
}: {
  hasIncident: boolean;
  onReset: () => void;
}) {
  return (
    <header className="app-header">
      <div className="container app-header-inner">
        <div className="brand">
          <span className="brand-mark">
            <ChainMark />
          </span>
          <span className="brand-name">IncidentRecon </span>
          <span className="brand-sub">Incident Reconstruction Console</span>
        </div>
        <div className="header-right">
          {hasIncident && (
            <button type="button" className="btn btn-ghost" onClick={onReset}>
              New Analysis
            </button>
          )}
          <span className="status-pill">
            <span className="pulse-dot" aria-hidden="true" />
            LIVE SESSION
          </span>
        </div>
      </div>
    </header>
  );
}

/* ---------- landing (no incident yet) ---------- */

const STEPS = [
  {
    num: "01",
    title: "Upload raw logs",
    body: "Drop a CSV or NDJSON export straight from the endpoint — no preprocessing required.",
  },
  {
    num: "02",
    title: "Reconstruct the graph",
    body: "The engine rebuilds the event graph and forward-chains correlated evidence into findings.",
  },
  {
    num: "03",
    title: "Review & verify",
    body: "Read each ATT&CK-mapped conclusion, then walk the full attack path in the interactive chain.",
  },
];

function Landing({ onAnalyzed }: { onAnalyzed: (incident: Incident) => void }) {
  return (
    <section className="hero">
      <div className="hero-eyebrow-row anim-rise">
        <span className="eyebrow">
          AI-Powered Incident Reconstruction &amp; Analysis
        </span>
        <span className="hero-eyebrow-rule" aria-hidden="true" />
      </div>

      <h1 className="hero-title anim-rise anim-rise-1">
        Reconstruct the attack,
        <br />
        <span className="chip-lime">link by link</span>.
      </h1>

      <p className="hero-sub anim-rise anim-rise-2">
        Feed raw <strong>CSV</strong> or <strong>NDJSON</strong> security logs
        to the reconstruction engine. It rebuilds the event graph, chains
        correlated evidence into MITRE ATT&amp;CK conclusions, and maps the full
        attack path — every claim cited by event ID.
      </p>

      <div className="anim-rise anim-rise-3">
        <UploadForm onAnalyzed={onAnalyzed} />
      </div>

      <div className="steps anim-rise anim-rise-4">
        <div className="steps-grid">
          {STEPS.map((step) => (
            <div className="step-card" key={step.num}>
              <span className="step-num">{step.num}</span>
              <h3 className="step-title">{step.title}</h3>
              <p className="step-body">{step.body}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ---------- result view (incident present) ---------- */

function ResultView({
  incident,
  tab,
  onTabChange,
}: {
  incident: Incident;
  tab: Tab;
  onTabChange: (tab: Tab) => void;
}) {
  const evidenceCount = incident.conclusions.reduce(
    (n, c) => n + c.evidence.length,
    0,
  );
  const citedEvents = new Set(
    incident.conclusions.flatMap((c) =>
      c.evidence.flatMap((ev) => ev.event_ids),
    ),
  ).size;

  const tacticsPresent = [
    ...new Set(incident.conclusions.map((c) => c.tactic)),
  ];

  return (
    <section className="result">
      <div className="result-head">
        <div className="result-status-row">
          <span className="status-chip">Reconstructed</span>
          <span className="incident-id">INCIDENT #{incident.id}</span>
        </div>
        <SummaryBlock text={incident.summary} />
        <div className="stats-row">
          <div className="stat">
            <span className="stat-num">{incident.conclusions.length}</span>
            <span className="stat-label micro-caps">Conclusions</span>
          </div>
          <div className="stat">
            <span className="stat-num">{evidenceCount}</span>
            <span className="stat-label micro-caps">Evidence Chains</span>
          </div>
          <div className="stat">
            <span className="stat-num">{citedEvents}</span>
            <span className="stat-label micro-caps">Cited Events</span>
          </div>
        </div>
      </div>

      <div className="tab-row">
        <div className="tabs" role="tablist" aria-label="Result views">
          <TabButton
            label="Conclusions"
            active={tab === "conclusions"}
            onClick={() => onTabChange("conclusions")}
          />
          <TabButton
            label="Attack Chain"
            active={tab === "chain"}
            onClick={() => onTabChange("chain")}
          />
        </div>

        {tacticsPresent.length > 0 && (
          <div className="legend">
            <span className="micro-caps legend-label">Tactic Key</span>
            {tacticsPresent.map((tactic) => (
              <span
                key={tactic}
                className={`legend-chip ${tacticClass(tactic)}`}
              >
                <span className="tactic-dot" aria-hidden="true" />
                {tactic}
              </span>
            ))}
          </div>
        )}
      </div>

      <div key={tab} role="tabpanel">
        {tab === "conclusions" ? (
          <IncidentView incident={incident} />
        ) : (
          <AttackChain key={incident.id} incident={incident} />
        )}
      </div>
    </section>
  );
}

function TabButton({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      className={`tab-btn${active ? " active" : ""}`}
      onClick={onClick}
    >
      {label}
    </button>
  );
}

/* Short lead line; the full kill-chain narrative sits in a collapsible block. */
function SummaryBlock({ text }: { text: string }) {
  const LIMIT = 240;
  const [first, ...rest] = text.split("\n");
  const tooLong = first.length > LIMIT;
  const cut = first.lastIndexOf(" ", LIMIT);
  const lead = tooLong ? first.slice(0, cut > 0 ? cut : LIMIT) + "…" : first;
  const hasMore = tooLong || rest.some((line) => line.trim() !== "");

  return (
    <div className="summary-block">
      <p className="summary-lead">{lead}</p>
      {hasMore && (
        <details className="summary-details">
          <summary>Show full narrative</summary>
          <pre className="summary-body">{text}</pre>
        </details>
      )}
    </div>
  );
}
