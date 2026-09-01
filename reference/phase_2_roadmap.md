# Phase 2 Roadmap — Real Data, API Hardening & Dashboard
## AI-Powered Cybersecurity Incident Reconstruction & Analysis System

> **Status:** Draft (Phase 2)
> **Scope:** Finish the backend for real-world data, harden the API, then add an 80% frontend dashboard.
> **Ordering:** Backend first, frontend last (per team decision — backend is the priority).
> **Audience:** Project team (junior-to-mid on the stack). Every step has a goal, a todo checklist, illustrative code snippets, and a "done when" criterion.

---

## 0. What Phase 2 Is (and what it is not)

Phase 1 delivered a **working demo pipeline on hand-crafted CSV**: `attack_sample.csv → /analyze → Events → Graph → 3 rules → Incident with evidence` (53 tests passing). That proves the *idea*.

Phase 2 has two goals:

1. **Make the backend real.** Phase 1 parses only our own CSVs. The project pitch is "reconstruct incidents from *real* security logs" — so Phase 2 adds a real-log parser (Mordor/Sysmon), makes the API production-usable (CORS, upload endpoint, input validation), and fixes a couple of correctness shortcuts.
2. **Add a dashboard.** An 80% frontend: upload a log file, see the reconstructed incident as a readable list of conclusions + an interactive attack-chain graph. Skip the remaining 20% (auth, routing, global state, frontend tests, theming, deployment).

**Target: ~80% of the full project** (not 100%). The skipped 20% is listed explicitly at the end.

---

## 1. Honest Audit — What Phase 1 Actually Left (not "100% done")

My earlier "backend 100%" was wrong. Reading the code, here is the true remaining state:

### ✅ Genuinely done (verified)
- Parser (CSV) with provenance IDs + UTC normalization + bad-row policy
- Graph builder (NetworkX: `followed_by` / `spawned` / `same_object`)
- Reasoning engine (forward chaining, dedup, max-iterations)
- 3 rules (`REG-PERSIST-01`, `PSH-STAGING-01`, chained `PERSIST-ESTABLISHED-01`)
- Orchestrator + CLI, SQLite storage, FastAPI `/analyze` + `/incident/{id}`
- 53 passing tests

### ❌ Genuinely missing / weak (this is what Phase 2 fixes)

| # | Gap | Severity | Why it matters |
|---|---|---|---|
| G1 | **Mordor/real-log parsing** | 🔴 High | `parser.py` reads CSV only. The `Message` blob → structured Event extraction for real Windows/Sysmon logs was never built. Without it, "real logs" is just a slide claim. |
| G2 | **Graph is never visualized** | 🔴 High | The graph exists in memory but is never rendered. The demo has no visual — the single most impressive artifact for an exhibition is missing. |
| G3 | **No CORS** | 🟠 Medium | The frontend literally cannot call the API (browser blocks cross-origin). Blocks everything in Part B. |
| G4 | **`POST /upload` missing** | 🟠 Medium | The roadmap listed `POST /upload`, `POST /analyze`, `GET /incident/{id}`; only the latter two exist. `/analyze` does a raw multipart upload to `/tmp/{filename}` with a path-collision bug. |
| G5 | **Only 3 rules, hardcoded** | 🟠 Medium | `file_creation`, `network_connection`, `log_deletion` event types are defined but **no rule uses them**. The knowledge base is functions, not data. |
| G6 | **`parent_conclusion_id` = rule ID, not unique ID** | 🟡 Low | Chained evidence points at `"PSH-STAGING-01"` (a rule ID), not a unique conclusion instance. Fine with one conclusion per rule; subtly wrong otherwise. |
| G7 | **No input validation on upload** | 🟡 Low | A huge file is read fully into memory; no size/type limit. |

> Postgres, auth, Docker, deployment were intentionally deferred from Phase 1 and stay deferred (see §6).

---

## 2. Corrected Phase 2 Step Sequence

**Backend first (Steps 1–5), then frontend (Steps 6–9).**

| # | Step | Fixes gap | Part |
|---|---|---|---|
| 1 | Real-Log Parser (Mordor NDJSON → Event) | G1 | Backend |
| 2 | Real Dataset Integration (download + wire atomic datasets) | G1 | Backend |
| 3 | Graph Visualization (matplotlib PNG / GraphML export) | G2 | Backend |
| 4 | API Hardening (CORS, `/upload`, input validation, path fix) | G3, G4, G7 | Backend |
| 5 | Expand Knowledge Base (network + log-deletion rules) + provenance fix | G5, G6 | Backend |
| 6 | Frontend Scaffold (Vite + React + TS) | — | Frontend |
| 7 | API Client + Upload Form | G3 (consumed) | Frontend |
| 8 | Incident View (conclusions + evidence list) | — | Frontend |
| 9 | Attack-Chain Visualization (React Flow + dagre) | G2 (frontend side) | Frontend |

**Dependencies:** 2 depends on 1; 7 depends on 4 (CORS) + 6; 9 depends on 7. Steps 1, 3, 4, 5 are largely independent of each other and can be parallelized if the team splits up.

---

## 3. Step-by-Step Roadmap

---

### Step 1 — Real-Log Parser (Mordor NDJSON → Event)

**Goal:** Extend the parser so it reads real Mordor/OTRF NDJSON (newline-delimited JSON, one Windows/Sysmon event per line) and maps it to our `Event` model — instead of only our hand-written CSVs.

**Todo checklist:**
- [ ] Understand the Mordor schema: `SourceName, ProviderGuid, Level, Keywords, Channel, Hostname, TimeCreated, @timestamp, EventID, Message, Task`.
- [ ] Map Windows/Sysmon EventIDs → our `EventType` (see table below).
- [ ] Write `parse_mordor(file_path) -> ParseResult` that reads NDJSON line-by-line.
- [ ] Extract clean fields from the `Message` blob (standard Sysmon `Key: Value` lines, e.g. `Image:`, `CommandLine:`, `ProcessId:`, `ParentProcessId:`).
- [ ] Reuse the existing `Event` model + provenance scheme (`event_id = f"{file}:{line}"`).
- [ ] Reuse the bad-row policy: skip + count malformed lines, never silently blank metadata.
- [ ] Write `test_mordor_parser.py` against one real downloaded atomic dataset.

**EventID → EventType mapping (Sysmon + Windows Event Log):**
| EventID | Source | Our `EventType` |
|---|---|---|
| 1 | Sysmon Process Create | `process_execution` |
| 3 | Sysmon Network connection | `network_connection` |
| 11 | Sysmon File Create | `file_creation` / `file_download` |
| 12/13 | Sysmon Registry (Set/Delete) | `registry_modification` |
| 4104 | Windows PowerShell ScriptBlock | `powershell_execution` |
| 1102 | Windows log cleared | `log_deletion` |
| 4688 | Windows Process Creation | `process_execution` |

**Code snippet — extracting the `Message` blob:**
```python
import json

def _parse_sysmon_message(message: str) -> dict:
    """Sysmon Message is multi-line 'Key: Value'. Split into a dict."""
    fields = {}
    for line in message.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()
    return fields

def _event_type_from_event_id(event_id: int, source: str) -> EventType:
    mapping = {
        1: EventType.PROCESS_EXECUTION,
        3: EventType.NETWORK_CONNECTION,
        11: EventType.FILE_CREATION,   # refine to FILE_DOWNLOAD via metadata
        12: EventType.REGISTRY_MODIFICATION,
        13: EventType.REGISTRY_MODIFICATION,
        4104: EventType.POWERSHELL_EXECUTION,
        1102: EventType.LOG_DELETION,
        4688: EventType.PROCESS_EXECUTION,
    }
    return mapping[event_id]  # raise/ skip unknown IDs

def parse_mordor(file_path: str) -> ParseResult:
    events, skipped, errors = [], 0, []
    with open(file_path, encoding="utf-8") as f:
        for line_no, line in enumerate(f):
            try:
                raw = json.loads(line)
                msg = _parse_sysmon_message(raw.get("Message", ""))
                timestamp = _normalize_timestamp(raw.get("TimeCreated") or raw.get("@timestamp"))
                events.append(Event(
                    event_id=f"{file_path}:{line_no}",
                    timestamp=timestamp,
                    source=raw.get("Hostname") or raw.get("SourceName"),
                    event_type=_event_type_from_event_id(int(raw["EventID"]), raw.get("SourceName", "")),
                    actor=msg.get("User") or msg.get("ProcessId") or raw.get("Hostname"),
                    target=msg.get("Image") or msg.get("TargetFilename") or msg.get("DestinationIp"),
                    metadata={**raw, **msg},   # keep everything for evidence
                ))
            except Exception as exc:
                skipped += 1
                errors.append(f"line {line_no}: {exc}")
    events.sort(key=lambda e: e.timestamp)
    return ParseResult(events=events, skipped=skipped, total_rows=line_no + 1, errors=errors)
```

**Done when:** `parse_mordor` on a real Mordor file produces `Event` objects with correct `event_type`, non-empty `metadata`, provenance IDs that resolve to source lines, and a skip count for malformed lines. Test passes.

---

### Step 2 — Real Dataset Integration

**Goal:** Download 3–5 Mordor atomic datasets covering all 7 event types and prove the pipeline runs on real data end-to-end.

**Todo checklist:**
- [ ] Pick 3–5 atomic datasets that together cover the 7 event types (see Phase 1 dataset section — Mordor is the chosen source).
- [ ] Download into `src/data/mordor/` (git-ignored except `.gitkeep`).
- [ ] Wire one through `run_analysis` and confirm conclusions fire (or deliberately log "no conclusions" for a benign dataset).
- [ ] Document which dataset maps to which event type in `data/mordor/README.md`.
- [ ] Add a `data/mordor/README.md` explaining the datasets + license (MIT).

**Coverage checklist (pick datasets to hit all 7):**
| Event type | Mordor dataset example |
|---|---|
| `powershell_execution` | a `psh_*` dataset (e.g. PowerShell payload execution) |
| `registry_modification` | a `reg_*` dataset (e.g. `reg_disable_eventlog_service_startuptype_modification_via_registry`) |
| `log_deletion` | a `cmd_wevtutil_*` dataset |
| `file_download` | a `bitsadmin` dataset |
| `network_connection` | a Sysmon EventID 3 dataset |
| `process_execution` / `file_creation` | present in almost all of the above |

**Done when:** at least one real dataset runs through `run_analysis` without crashing, produces correct `EventType`s, and the log shows the graph + engine ran.

---

### Step 3 — Graph Visualization (matplotlib PNG / GraphML)

**Goal:** Render the event graph so the demo has a *visual* even before the frontend exists.

**Todo checklist:**
- [ ] Write `visualize(graph, output_path="graph.png")` using NetworkX + matplotlib.
- [ ] Color nodes by `event_type` (7 distinct colors), draw edges with arrowheads.
- [ ] Label nodes by `event_type` + short target; annotate edges with `kind`.
- [ ] Optionally export GraphML (`nx.write_graphml`) so the frontend can load the raw graph later.
- [ ] Call it from the CLI: `python -m app.orchestrator src/data/attack_sample.csv --viz`.

**Code snippet:**
```python
import matplotlib.pyplot as plt
import networkx as nx
from app.models import EventType

TYPE_COLORS = {
    EventType.PROCESS_EXECUTION: "#4c72b0",
    EventType.FILE_DOWNLOAD: "#dd8452",
    EventType.FILE_CREATION: "#55a868",
    EventType.REGISTRY_MODIFICATION: "#c44e52",
    EventType.NETWORK_CONNECTION: "#8172b3",
    EventType.POWERSHELL_EXECUTION: "#937860",
    EventType.LOG_DELETION: "#ccb974",
}

def visualize(graph: nx.DiGraph, output_path: str = "graph.png") -> None:
    pos = nx.kamada_kawai_layout(graph)
    node_colors = [
        TYPE_COLORS[graph.nodes[n]["event"].event_type] for n in graph.nodes
    ]
    labels = {n: graph.nodes[n]["event"].event_type.value for n in graph.nodes}
    nx.draw(graph, pos, node_color=node_colors, labels=labels,
            node_size=800, font_size=7, arrows=True, edge_color="gray")
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
```

**Done when:** `--viz` produces a `graph.png` with 7 colored node types and directed edges; GraphML export loads back in NetworkX.

---

### Step 4 — API Hardening (CORS, `/upload`, validation, path fix)

**Goal:** Make the API frontend-ready and fix the upload bugs. **This step is a hard prerequisite for the entire frontend (Steps 6–9).**

**Todo checklist:**
- [ ] Add `CORSMiddleware` with the Vite dev origin (`http://localhost:5173`).
- [ ] Add `POST /upload` (returns a stored file id) to match the original API spec.
- [ ] Fix the `/tmp/{filename}` path-collision bug — generate a unique temp filename (e.g. `uuid4().hex + ".csv"`).
- [ ] Add upload size limit + file-type check (reject non-CSV/NDJSON).
- [ ] Return parse diagnostics (skipped rows, errors) in the `/analyze` response, not just the `Incident`.
- [ ] Add `GET /incident/{id}` still works after changes.

**Code snippet — CORS + fixed upload:**
```python
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uuid

app = FastAPI(title="Cybersecurity Incident Reconstruction API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB

@app.post("/analyze")
async def analyze_endpoint(file: UploadFile = File(...)):
    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File too large (max 50 MB)")
    path = f"/tmp/{uuid.uuid4().hex}_{file.filename}"   # no collision
    with open(path, "wb") as f:
        f.write(contents)
    incident = run_analysis(path)
    save_incident(incident)
    return incident
```

**Gotchas (verified):**
- CORS origin strings must have **no trailing slash**.
- `allow_origins=["*"]` + `allow_credentials=True` is invalid — list explicit origins.
- The frontend must **not** set a manual `Content-Type` on the multipart upload.

**Done when:** a browser at `localhost:5173` can POST to `/analyze` without CORS errors; two same-named uploads don't collide; oversize uploads are rejected with 413.

---

### Step 5 — Expand Knowledge Base + Provenance Fix

**Goal:** Use the three currently-ignored event types and make the evidence chain unambiguous.

**Todo checklist:**
- [ ] Add a `network_connection` rule (e.g. `C2-BEACON-01`, T1071 — outbound connection to suspicious IP after process execution).
- [ ] Add a `log_deletion` rule (e.g. `LOG-CLEAR-01`, T1070 — evidence of defense evasion).
- [ ] (Optional) Add a `file_creation` rule or fold it into existing download/staging rules.
- [ ] Fix G6: give each `Conclusion` a stable unique `conclusion_id` (e.g. `uuid` or a deterministic hash), and make `parent_conclusion_id` reference that ID, not the rule ID.
- [ ] Update tests: attack sample triggers the new rules; benign sample still yields zero; chained rule's `parent_conclusion_id` now resolves to a real prior conclusion.

**Code snippet — unique conclusion IDs:**
```python
class Conclusion(BaseModel):
    conclusion_id: str          # NEW: unique per conclusion instance
    rule_id: str
    technique_id: str
    tactic: str
    description: str
    evidence: list[Evidence]

# In each rule:
import uuid
Conclusion(
    conclusion_id=uuid.uuid4().hex,   # stable unique id
    rule_id="REG-PERSIST-01",
    ...
)
# Chained rule sets parent_conclusion_id = the PRIOR conclusion's conclusion_id,
# not the literal string "PSH-STAGING-01".
```

**Done when:** 5 rules total; `network_connection` and `log_deletion` events actually drive conclusions; `parent_conclusion_id` points at a unique prior `conclusion_id`; all tests green.

---

### Step 6 — Frontend Scaffold (Vite + React + TypeScript)

**Goal:** A minimal React + TS app skeleton that can talk to the backend.

**Todo checklist:**
- [ ] Scaffold: `npm create vite@latest incident-dashboard -- --template react-ts` (requires Node 20.19+).
- [ ] Install deps: `npm install @xyflow/react @dagrejs/dagre`.
- [ ] Add `types.ts` mirroring the backend `Incident`/`Conclusion`/`Evidence` models.
- [ ] Add `api.ts` with `analyzeCsv(file)` and `getIncident(id)`.
- [ ] Add `VITE_API_BASE_URL` env var (default `http://localhost:8000`).
- [ ] Strip the boilerplate (logo, counter, default CSS).

**Scaffold commands:**
```bash
npm create vite@latest incident-dashboard -- --template react-ts
cd incident-dashboard
npm install
npm install @xyflow/react @dagrejs/dagre
npm run dev   # → http://localhost:5173
```

**`types.ts`:**
```ts
export interface Evidence {
  event_ids: string[];
  explanation: string;
  parent_conclusion_id: string | null;
}
export interface Conclusion {
  conclusion_id?: string;   // optional until Step 5 lands
  rule_id: string;
  technique_id: string;
  tactic: string;
  description: string;
  evidence: Evidence[];
}
export interface Incident {
  id: string;
  summary: string;
  conclusions: Conclusion[];
}
```

**Done when:** `npm run dev` serves the app; `types.ts` and `api.ts` exist; the app compiles clean.

---

### Step 7 — API Client + Upload Form

**Goal:** Upload a CSV from the browser and receive the `Incident` JSON. **Requires Step 4 (CORS).**

**Todo checklist:**
- [ ] Build `UploadForm.tsx`: `<input type="file" accept=".csv">` + submit + loading spinner + error banner.
- [ ] In `api.ts`, POST the file as `FormData` (do **not** set `Content-Type` manually).
- [ ] Store the returned `Incident` in `App.tsx` state (`useState<Incident | null>`).
- [ ] Handle errors (network/CORS/413) with a visible banner.

**`api.ts`:**
```ts
const API = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

export async function analyzeCsv(file: File): Promise<Incident> {
  const formData = new FormData();
  formData.append("file", file);            // 'file' matches the backend param name
  const res = await fetch(`${API}/analyze`, { method: "POST", body: formData });
  if (!res.ok) throw new Error(`Analysis failed: ${res.status}`);
  return res.json();
}
```

**Done when:** uploading `attack_sample.csv` from the browser returns the incident and stores it in state; the loading spinner and error banner work.

---

### Step 8 — Incident View (conclusions + evidence list)

**Goal:** Show the reconstructed incident as a readable, evidence-backed list.

**Todo checklist:**
- [ ] Build `IncidentView.tsx` rendering the `summary` + a card per `Conclusion`.
- [ ] Each card: `technique_id` badge (e.g. `T1547.001`), `tactic`, `rule_id`, `description`.
- [ ] Expandable `Evidence` list: `event_ids` + `explanation`, with `parent_conclusion_id` shown when chained.
- [ ] Color-code by tactic (Persistence, Execution, Defense Evasion, etc.).

**Code sketch:**
```tsx
function IncidentView({ incident }: { incident: Incident }) {
  return (
    <div>
      <p>{incident.summary}</p>
      {incident.conclusions.map((c) => (
        <ConclusionCard key={c.conclusion_id ?? c.rule_id} conclusion={c} />
      ))}
    </div>
  );
}
```

**Done when:** the incident renders as a clear list with badges, descriptions, and expandable evidence; chained conclusions visibly show their parent link.

---

### Step 9 — Attack-Chain Visualization (React Flow + dagre)

**Goal:** The centerpiece — an interactive left-to-right attack-chain graph.

**Todo checklist:**
- [ ] Build `AttackChain.tsx` using `@xyflow/react` (v12) + `@dagrejs/dagre`.
- [ ] Conclusions = nodes; `parent_conclusion_id` relationships = animated edges with arrowheads.
- [ ] Use `rankdir: 'LR'` for a left-to-right timeline layout.
- [ ] **Import the CSS yourself:** `import '@xyflow/react/dist/style.css';` (v11+ requirement).
- [ ] Add `Background`, `Controls`, `MiniMap`, `fitView`.
- [ ] (Optional) Color nodes by `tactic`; show `event_ids.length` as the edge label.

**Code sketch (the key parts):**
```tsx
import { ReactFlow, Background, Controls, MiniMap, MarkerType,
         useNodesState, useEdgesState, type Node, type Edge } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import dagre from '@dagrejs/dagre';

function layoutLR(nodes: Node[], edges: Edge[]) {
  const g = new dagre.graphlib.Graph().setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: 'LR' });              // left-to-right
  nodes.forEach((n) => g.setNode(n.id, { width: 180, height: 70 }));
  edges.forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);
  return nodes.map((n) => ({ ...n, position: { x: g.node(n.id).x - 90, y: g.node(n.id).y - 35 } }));
}

export function AttackChain({ incident }: { incident: Incident }) {
  const nodes: Node[] = incident.conclusions.map((c) => ({
    id: c.conclusion_id ?? c.rule_id,
    data: { label: `${c.technique_id} · ${c.tactic}\n${c.description}` },
  }));
  const edges: Edge[] = incident.conclusions.flatMap((c) =>
    c.evidence.filter((e) => e.parent_conclusion_id).map((e) => ({
      id: `${e.parent_conclusion_id}->${c.conclusion_id ?? c.rule_id}`,
      source: e.parent_conclusion_id!,
      target: c.conclusion_id ?? c.rule_id,
      label: `${e.event_ids.length} events`,
      markerEnd: { type: MarkerType.ArrowClosed },
      animated: true,
    })),
  );
  const [ns, , onNodesChange] = useNodesState(layoutLR(nodes, edges));
  const [es, , onEdgesChange] = useEdgesState(edges);
  return (
    <div style={{ height: '70vh' }}>
      <ReactFlow nodes={ns} edges={es} onNodesChange={onNodesChange}
                 onEdgesChange={onEdgesChange} fitView colorMode="system">
        <Background /><Controls /><MiniMap />
      </ReactFlow>
    </div>
  );
}
```

**⚠️ Breaking-change watch:**
- The package renamed twice: `react-flow-renderer` → `reactflow` → **`@xyflow/react`**. Old tutorials importing `'reactflow'` are stale.
- You **must** import `@xyflow/react/dist/style.css` yourself.
- `parent_conclusion_id` must match a **node id** — which is exactly why Step 5's unique `conclusion_id` fix matters (right now it's the rule ID, which collides if a rule fires twice).

**Done when:** uploading `attack_sample.csv` renders a left-to-right graph where `REG-PERSIST-01` and `PSH-STAGING-01` flow into `PERSIST-ESTABLISHED-01` via animated arrowheads; pan/zoom/minimap work.

---

## 4. Definition of Done (Phase 2, 80% target)

```
Real Mordor NDJSON → parse_mordor → structured Events (all 7 types) →
  Event Graph → 5 rules via forward chaining → Incident with unique
  conclusion IDs + evidence → CORS-enabled FastAPI → React dashboard:
  upload form → readable incident view → interactive attack-chain graph.

benign input → zero conclusions (still true on real data).

The full pipeline is demonstrable end-to-end from a browser.
```

---

## 5. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| **Mordor `Message` parsing is fiddly** | Standard Sysmon `Key: Value` format is well-documented; test against one real file early (Step 1's test). Don't aim for 100% field coverage — map the fields your rules need. |
| **CORS blocks the frontend** | Verify with a browser (not `curl`, which bypasses CORS). Exact origins, no trailing slash. |
| **React Flow v12 rename confusion** | Only import from `@xyflow/react`; import the CSS manually; ignore `reactflow`/`react-flow-renderer` tutorials. |
| **`parent_conclusion_id` collision** | Fixed in Step 5 (unique `conclusion_id`). Do Step 5 *before* Step 9, or the graph edges will be wrong when a rule fires twice. |
| **Scope creep in frontend** | Stick to 3 components (upload, incident view, graph). No routing, no state lib, no tests. |
| **Real data produces "no conclusions"** | That's a legitimate result if the chosen dataset is benign — pick datasets with documented attack procedures so conclusions *do* fire for the demo. |

---

## 6. What's Skipped (the 20%, explicitly)

| Skip | Why it's safe |
|---|---|
| Auth / login | Localhost demo, no data sensitivity. |
| React Router | Two views → one `useState` toggle. |
| Global state (Redux/Zustand/Context) | One `incident` object. |
| React Query / SWR | Two endpoints, one-shot requests. |
| Frontend tests (Jest/Vitest/RTL) | Backend is the testable core; frontend is presentational. |
| i18n / theming / design tokens | One dark "SOC dashboard" look via plain CSS. |
| Postgres migration | SQLite is fine at this scale. |
| Docker / deployment / CI | Manual run for the demo. |
| WebSockets / live updates | Analysis is request/response. |
| D3.js hand-rolled extras | React Flow covers the graph. |

---

## 7. Recommended Build Order (suggested day plan)

If the team is small, do the backend steps **in order**, then the frontend:

1. **Steps 1–2** (real parser + data) — the "real logs" story, biggest credibility win.
2. **Step 4** (CORS + upload) — unblocks the frontend.
3. **Step 3** (matplotlib viz) — a visual *now*, before any React exists.
4. **Step 5** (rules + provenance) — makes the demo's evidence chain airtight.
5. **Steps 6–9** (frontend) — scaffold → upload → incident view → attack chain.

Parallelize if possible: one person on Steps 1–2 (backend data), one on Step 4 (API), one on Steps 6–7 (frontend scaffold) — then converge on Steps 3, 5, 8, 9.

---

*This roadmap is based on an honest line-by-line audit of the Phase 1 code plus verified 2026 frontend research (Vite 9.2, React Flow `@xyflow/react` 12.11.x, D3 7.9, FastAPI CORS/StaticFiles docs).*
