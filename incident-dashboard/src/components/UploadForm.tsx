import { useRef, useState } from "react";
import type { ChangeEvent, DragEvent } from "react";
import { analyzeCsv } from "../api";
import type { Incident } from "../types";

const MAX_BYTES = 50 * 1024 * 1024; // mirrors the backend's 50 MB upload limit
const ACCEPTED_EXTS = [".csv", ".ndjson"];

type Props = {
  onAnalyzed: (incident: Incident) => void;
};

function formatMB(bytes: number): string {
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function UploadForm({ onAnalyzed }: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function analyze(file: File) {
    setBusy(true);
    setError(null);
    try {
      const incident = await analyzeCsv(file);
      onAnalyzed(incident);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unexpected error while analyzing the file.",
      );
    } finally {
      setBusy(false);
    }
  }

  function handleFile(file: File | undefined) {
    if (!file || busy) return;
    const name = file.name.toLowerCase();
    if (!ACCEPTED_EXTS.some((ext) => name.endsWith(ext))) {
      setError(
        `Unsupported file type. Accepted formats: ${ACCEPTED_EXTS.join(", ")}.`,
      );
      return;
    }
    if (file.size > MAX_BYTES) {
      setError(
        `This file is ${formatMB(file.size)} — the analysis server accepts up to 50 MB.`,
      );
      return;
    }
    void analyze(file);
  }

  function onInputChange(e: ChangeEvent<HTMLInputElement>) {
    handleFile(e.target.files?.[0]);
    e.target.value = ""; // allow re-selecting the same file after a failure
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragging(false);
    handleFile(e.dataTransfer.files?.[0]);
  }

  return (
    <div>
      <div
        className={`upload-zone${dragging ? " dragging" : ""}${busy ? " busy" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          e.dataTransfer.dropEffect = "copy";
          if (!busy) setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".csv,.ndjson"
          onChange={onInputChange}
          disabled={busy}
          aria-label="Log file to analyze"
          className="visually-hidden-input"
        />

        <div className="upload-grid">
          <div className="upload-copy">
            <div className="upload-kicker">
              <LogGlyph />
              <span className="micro-caps">Reconstruction Input</span>
            </div>
            <h2 className="upload-title">
              {busy
                ? "Reconstructing the attack chain…"
                : "Drop a log file to begin"}
            </h2>
            <p className="upload-caption">
              Raw endpoint or network logs go straight into the engine — no
              preprocessing required.
            </p>
            <div className="fmt-chips">
              <span className="fmt-chip">.CSV</span>
              <span className="fmt-chip">.NDJSON</span>
              <span className="fmt-chip">MAX 50 MB</span>
            </div>
          </div>

          <div className="upload-actions">
            <button
              type="button"
              className="btn btn-inverted"
              onClick={() => inputRef.current?.click()}
              disabled={busy}
            >
              {busy ? (
                <>
                  <span className="spinner" aria-hidden="true" />
                  Analyzing…
                </>
              ) : (
                "Select File & Analyze"
              )}
            </button>
            <p className="sample-hint">
              Try a sample: <code>attack_sample.csv</code> from{" "}
              <code>src/data/</code>
            </p>
          </div>
        </div>

        <div className="scanline" aria-hidden="true" />
      </div>

      {error && (
        <div className="error-banner" role="alert">
          <span className="error-title micro-caps">Analysis Failed</span>
          <p>{error}</p>
        </div>
      )}
    </div>
  );
}

/** Document outline with a tiny evidence graph inside — the input metaphor. */
function LogGlyph() {
  return (
    <svg
      width="44"
      height="44"
      viewBox="0 0 52 52"
      fill="none"
      aria-hidden="true"
      style={{ flex: "none", color: "var(--accent-violet-mid)" }}
    >
      <path
        d="M14 5h16l10 10v30a2 2 0 0 1-2 2H14a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2z"
        stroke="currentColor"
        strokeWidth="1.8"
      />
      <path
        d="M30 5v10h10"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path
        d="M21 32l7-7 8 4m-8 3l-7 6"
        stroke="var(--accent-violet-bright)"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="21" cy="32" r="2.4" fill="var(--accent-violet-bright)" />
      <circle cx="28" cy="25" r="2.4" fill="var(--accent-violet-bright)" />
      <circle cx="36" cy="29" r="2.4" fill="var(--accent-violet-bright)" />
      <circle cx="21" cy="41" r="2.4" fill="var(--accent-violet-bright)" />
    </svg>
  );
}
