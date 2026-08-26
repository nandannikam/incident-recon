# Phase 1 Roadmap — Backend Foundation

## AI-Powered Cybersecurity Incident Reconstruction & Analysis System

> **Status:** Finalised
> **Scope:** Phase 1 only — a minimal but demonstrable end-to-end backend pipeline.
> **Audience:** Project team (junior-to-mid on the stack). Every step has a goal, a todo checklist, illustrative code snippets, and a "done when" criterion.

---

## 0. What This Project Is (read first)

We are building a system that takes **fragmented security logs** (process, file, network, registry, PowerShell) and reconstructs a **coherent, explainable incident timeline** using **Symbolic AI** — rule-based reasoning with forward chaining — **not** neural networks or LLMs.

The core thesis: **every conclusion must trace back to source evidence.** If the "why?" trace-back works end-to-end, the project succeeds even with three rules. If it doesn't, fifty rules won't save it.

**Phase 1 deliverable:** `attack_sample.csv → /analyze → structured Events → Event Graph → reasoning → incident with evidence and rule.`

### Tech Stack (Phase 1 backend only)

| Layer           | Technology                           | Why                                   |
| --------------- | ------------------------------------ | ------------------------------------- |
| Language        | Python 3.11+                         | Ecosystem for data + rules            |
| Data validation | Pydantic v2                          | Typed contracts, auto schema          |
| Log parsing     | Pandas                               | CSV/JSON ingestion + cleaning         |
| Graph           | NetworkX                             | Event-relationship graph              |
| Reasoning       | Plain Python (rule functions + loop) | No DSL, no framework — boring code    |
| API             | FastAPI                              | Thin REST wrapper                     |
| Storage         | SQLite (or in-memory dict)           | `GET /incident/{id}` without Postgres |
| Knowledge base  | MITRE ATT&CK                         | Attack-technique grounding            |

**Deferred to later phases:** auth, Docker, CI, config management, Postgres, the React frontend. Do NOT build these in Phase 1.

---

## 1. Dataset Selection (decide BEFORE step 3)

The dataset choice drives every downstream step. We researched four candidates in depth. **Pick Mordor.**

### Comparison at a glance

| Criterion             | **Mordor** ✅ | BETH           | TON_IoT       | LANL            |
| --------------------- | ------------- | -------------- | ------------- | --------------- |
| Format                | NDJSON        | CSV            | CSV           | CSV             |
| 7 event types covered | **7/7**       | 1.5/7          | 1/7           | 2/7 (unlabeled) |
| MITRE ATT&CK mapped   | **Yes**       | No             | No            | No              |
| Labeled attacks       | Yes           | Yes (evil/sus) | Yes           | Partial         |
| Laptop-scale          | **Yes (MBs)** | Yes (42MB)     | Yes           | **No (12GB)**   |
| License               | **MIT**       | CC0            | Academic-only | CC0             |
| Real attack sequences | **Yes**       | Yes            | Yes           | Yes             |

---

### 🏆 Recommendation 1 — Mordor / OTRF Security-Datasets (PRIMARY)

- **Source:** https://github.com/OTRF/Security-Datasets (docs: https://securitydatasets.com)
- **What it is:** Pre-recorded Windows host event logs (Sysmon + Windows Event Log) and network data (Zeek/PCAP) from **real adversarial technique simulations** (Empire, Metasploit, Cobalt Strike, etc.) run in controlled lab VMs.
- **Format:** NDJSON (newline-delimited JSON — one event per line). Verified fields: `SourceName, ProviderGuid, Level, Keywords, Channel, Hostname, TimeCreated, @timestamp, EventID, Message, Task`. The `Message` field holds structured key/value detail (e.g. Sysmon Process Create with `Image`, `CommandLine`, `ProcessId`, `ParentProcessId`).
- **Labeled:** Each dataset ships a **metadata YAML** declaring the MITRE ATT&CK **technique + tactic** (e.g. `T1562.002 / TA0005`), a description, and the simulation procedure.
- **Size:** Atomic per-technique datasets are small (~1.3 MB zip / ~25k records). Compound campaigns exist (APT29 Day1 = 367 MB) for full multi-stage timelines.
- **License:** MIT (verified from repo LICENSE file — "Copyright (c) 2021 Open Threat Research Forge").

**Mapping to our 7 event types — ALL 7 COVERED:**
| Our event type | Mordor source |
|---|---|
| `process_execution` | Sysmon EventID 1 (Process Create) / Windows 4688 |
| `file_download` | Sysmon EventID 11; datasets like `cmd_bitsadmin_download_psh_script` |
| `file_creation` | Sysmon EventID 11 |
| `registry_modification` | Sysmon EventID 12/13; `reg_*` datasets |
| `network_connection` | Sysmon EventID 3 + Zeek/PCAP |
| `powershell_execution` | Windows EventID 4104 (ScriptBlock); `psh_*` datasets |
| `log_deletion` | Windows EventID 1102 (log clear); `cmd_wevtutil_*` datasets |

**Pros:**

- Only candidate covering all 7 of our event types — decisive.
- Pre-aligned with MITRE ATT&CK — our rule engine's grounding is essentially pre-built.
- Real attack sequences with benign background noise — ideal for forward-chaining detection.
- NDJSON parses trivially into our `Event` model.
- Laptop-scale; MIT license — zero friction.

**Cons:**

- `Message` is a semi-structured text blob — must parse key/value lines inside it (standard Sysmon format, one-time step).
- Requires light domain knowledge (Sysmon EventID meanings) — manageable with the metadata YAMLs as a guide.
- No single "one big labeled CSV" — you assemble datasets per technique/campaign.

**Verdict:** ✅ **USE THIS.** Start with 3–5 atomic Windows datasets covering all 7 event types, then use the APT29 compound campaign for the incident-reconstruction showcase.

---

### 🥈 Recommendation 2 — BETH Dataset (Kaggle) — RUNNER-UP / FALLBACK

- **Source:** https://www.kaggle.com/datasets/katehighnam/beth-dataset
- **What it is:** Real honeypot data from 23 Linux cloud servers (~5 hours). Kernel-level process logs + DNS traffic. ~8M events.
- **Format:** CSV, 15 files, ~42 MB. Fields: `timestamp, processId, threadId, parentProcessId, userId, mountNamespace, processName, hostname, eventId, eventName, argsNum, returnValue, stackAddresses, args, sus, evil`.
- **Labeled:** Two binary labels — `sus` (suspicious) and `evil` (known malicious). Attacks: botnet setup, cryptomining, lateral movement.
- **License:** CC0-1.0 (Public Domain).

**Pros:**

- Clean, real, labeled data with a peer-reviewed paper (ICML UDL 2021).
- CSV format — easiest to ingest.
- CC0 license — zero friction.

**Cons (decisive for THIS project):**

- **It is Linux host data, not Windows.** 5 of our 7 event types are Windows-centric (`registry_modification`, `powershell_execution`, `log_deletion` are Windows concepts) and are **simply absent**.
- No MITRE ATT&CK mapping provided.
- No file/registry/powershell/log-deletion events — the rule engine would have almost nothing to reconstruct a multi-stage Windows-style incident from.
- 8M rows is heavier than needed.

**Verdict:** ⚠️ Use **only** if you drastically narrow scope to process-execution detection, or as a secondary/complementary dataset. Not viable as the primary for the full 7-event-type pipeline.

---

### Recommendation 3 — TON_IoT (UNSW Canberra)

- **Source:** https://research.unsw.edu.au/projects/toniot-datasets (also IEEE DataPort, Kaggle mirrors)
- **What it is:** Heterogeneous IIoT dataset — network traffic (Zeek/Bro + Argus CSV flows, ~211k flows / ~30 MB), Windows 7/10 OS traces, Linux traces, IoT sensor telemetry.
- **Format:** Network = CSV flows (44 features); Windows = Performance Monitor `.blg` → CSV (perf counters, NOT security event logs).
- **Labeled:** Yes — 9 attack types (DoS, DDoS, ransomware, XSS, injection, scanning, backdoor).
- **License:** Academic/research use only (commercial requires contacting authors).

**Pros:**

- Clean labeled CSV network flows; well-documented, widely cited.

**Cons (decisive):**

- Windows "OS" data is **Performance Monitor telemetry, not security event logs** — no process-creation, registry, PowerShell, file, or log-deletion events.
- No MITRE ATT&CK mapping (labels are generic types, not techniques).
- Academic-use license adds friction vs MIT/CC0.

**Verdict:** ❌ Not as primary. Good network-flow data but host-side logs are the wrong kind for our event-type model.

---

### Recommendation 4 — LANL Comprehensive, Multi-Source Cyber-Security Events

- **Source:** https://csr.lanl.gov/data/cyber1/ (Los Alamos National Laboratory)
- **What it is:** 58 days of enterprise data — Windows auth events, process start/stop, DNS lookups, network flows, red-team events. Plain-text CSV.
- **Size:** ~12 GB compressed, **1.6 billion events**. Access must be requested from LANL.
- **License:** CC0.

**Pros:**

- Real enterprise-scale data, CC0, well-documented.

**Cons (decisive):**

- **1.6 billion events / 12 GB** — completely impractical for a laptop-based college project.
- Sparse labeling — only red-team auth events are ground truth; no ATT&CK mapping.
- Covers only ~2 of our 7 event types, mostly unlabeled.

**Verdict:** ❌ Too large, too sparsely labeled, wrong event coverage.

---

### Final dataset decision

**Use Mordor/OTRF Security-Datasets as the primary dataset.** It is the only option that maps cleanly to all 7 of our event types, is pre-aligned with MITRE ATT&CK, is laptop-scale, and is permissively licensed — so the team won't have to switch datasets mid-project.

**Practical start:** Download 3–5 atomic Windows datasets that together exercise all 7 event types:

1. A `psh_*` PowerShell dataset (e.g. `psh_powershell_payload_execution`)
2. A `reg_*` registry dataset (e.g. `reg_disable_eventlog_service_startuptype_modification_via_registry`)
3. A `cmd_wevtutil_*` log-deletion dataset
4. A `bitsadmin` file-download dataset
5. A network dataset (Sysmon EventID 3)

Then for the incident-reconstruction showcase, use the **APT29 compound campaign** (Day 1, 367 MB) — a complete, documented multi-stage attack timeline with host + network + Zeek data.

---

## 2. Corrected Phase 1 Step Sequence

The original PDF had three ordering defects, two duplicated steps, and ~5 missing micro-steps. Below is the **finalised, corrected sequence**. Each step is independently testable.

> **Why the reordering (summary):**
>
> - Event Types must be defined **before** the Parser (the parser maps _to_ the taxonomy).
> - "Define relationships" and "build the graph" are one deliverable — merged.
> - "Implement reasoning engine" and "implement forward chaining" overlap — merged, then split along matcher → fixpoint loop → evidence capture.
> - Added missing steps: Setup, Sample Data, Output Models, Pipeline Orchestrator, Persistence.
> - Circular dependency broken: name demo rules in Step 2, write them fully in Step 6, craft sample data in Step 3 to trigger them.

| #   | Step                                                                             | Old PDF step            |
| --- | -------------------------------------------------------------------------------- | ----------------------- |
| 1   | Project Setup                                                                    | _(new)_                 |
| 2   | Data Contracts (Event + Output models, event types, provenance, name demo rules) | merge old 1+3, plus new |
| 3   | Sample Data (`attack_sample.csv`, `benign_sample.csv`)                           | _(new)_                 |
| 4   | Log Parser (CSV/JSON → validated Events)                                         | old 2                   |
| 5   | Graph Builder (edge semantics + NetworkX)                                        | merge old 4+5           |
| 6   | Knowledge Base (3–5 machine-readable rules)                                      | old 6                   |
| 7   | Reasoning Engine (matcher → fixpoint loop → evidence capture)                    | merge old 7+8           |
| 8   | Pipeline Orchestrator (one callable function, CLI-runnable)                      | _(new)_                 |
| 9   | Persistence (in-memory or SQLite)                                                | _(new, minimal)_        |
| 10  | FastAPI (thin wrapper)                                                           | old 9                   |
| 11  | End-to-End Test (DoD scenario + negative case)                                   | old 10, narrowed        |

---

## 2.5 Current Status

**Must-do (critical path, ~5–7 hrs):**

- **Step 5 — Graph builder** (~1–2 hrs): NetworkX, `followed_by`/`spawned`/`same_object` edges.
- **Step 6 — Rules** (~1–2 hrs): 3 rule functions — `REG-PERSIST-01`, `PSH-STAGING-01`, chained `PERSIST-ESTABLISHED-01` (intents already in `models.py`).
- **Step 7 — Engine** (~2 hrs): forward-chaining loop with dedup + max iterations.
- **Step 8 — Orchestrator + CLI** (~1 hr): `run_analysis()` + `python -m app.orchestrator src/data/attack_sample.csv` → **the demo output**.

**Bonus (if time remains):**

- **Step 9 — Storage** (~30 min): SQLite, tiny.
- **Step 10 — FastAPI** (~1–2 hrs): thin wrapper, `/docs` page is a nice wow.

**Skip:** Mordor datasets, README polish, formal E2E test file.

**Expected demo output:**

```
$ python -m app.orchestrator src/data/attack_sample.csv
→ Parsed 17 events, skipped 0
→ Incident: 3 conclusions
  • REG-PERSIST-01 (T1547.001, Persistence) — evidence: [event_ids...]
  • PSH-STAGING-01 (T1059.001, Execution) — evidence: [event_ids...]
  • PERSIST-ESTABLISHED-01 (chained!) — evidence: [event_ids + parent conclusion]
```

Plus the negative case: `benign_sample.csv → 0 conclusions` — proves the engine doesn't fire on everything.

---

## 3. Step-by-Step Roadmap

---

### Step 1 — Project Setup

**Goal:** A reproducible dev environment so no one burns a day on venv/dependency issues.

**Todo checklist:**

- [ ] Create git repo (`git init`), add `.gitignore` (Python: `__pycache__/`, `.venv/`, `*.db`, `.env`).
- [ ] Create folder structure (see below).
- [ ] Create virtual environment: `python -m venv .venv && source .venv/bin/activate`.
- [ ] Create `requirements.txt` with pinned versions.
- [ ] Install deps: `pip install -r requirements.txt`.
- [ ] Add a `README.md` with a one-paragraph project description + run instructions.
- [ ] Set up Python logging (to console + `app.log`), not `print()`.

**Folder structure:**

```
project-root/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI entrypoint (Step 10)
│   ├── models.py            # Pydantic contracts (Step 2)
│   ├── parser.py            # Log parser (Step 4)
│   ├── graph.py             # Graph builder (Step 5)
│   ├── rules/               # Knowledge base (Step 6)
│   │   ├── __init__.py
│   │   └── registry.py
│   ├── engine.py            # Reasoning engine (Step 7)
│   ├── orchestrator.py      # Pipeline (Step 8)
│   └── storage.py           # Persistence (Step 9)
├── data/
│   ├── attack_sample.csv    # (Step 3)
│   └── benign_sample.csv
├── tests/
│   ├── test_parser.py
│   ├── test_graph.py
│   └── test_engine.py
├── requirements.txt
├── .gitignore
└── README.md
```

**`requirements.txt` (illustrative — pin exact versions):**

```
fastapi
uvicorn[standard]
pydantic>=2
pandas
networkx
pytest
```

**Logging snippet:**

```python
import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("app.log")],
)
log = logging.getLogger("incident")
```

**Done when:** `pip install -r requirements.txt` succeeds, `python -c "import fastapi, pandas, networkx, pydantic"` works, repo has its first commit.

---

### Step 2 — Data Contracts

**Goal:** Define every typed contract the pipeline uses — input Event, event-type taxonomy, output Incident/Conclusion/Evidence, provenance IDs, and **name** (don't write yet) the 2–3 demo rules.

> This is the most important step. Every downstream step depends on these contracts. Doing contracts first means FastAPI gets request/response schemas for free later.

**Todo checklist:**

- [ ] Define the `Event` Pydantic model (fields: `event_id`, `timestamp`, `source`, `event_type`, `actor`, `target`, `metadata`).
- [ ] Define the `EventType` enum (the 7 types).
- [ ] Define the `Incident` output model (id, summary, list of `Conclusion`).
- [ ] Define the `Conclusion` model (rule_id, technique_id, tactic, description, list of `Evidence`).
- [ ] Define the `Evidence` model (event_ids used, explanation, parent_conclusion_id for derived facts).
- [ ] Define the provenance scheme: `event_id` = `"{source_file}:{row_number}"` assigned at parse time.
- [ ] Define edge-type vocabulary + default time window (e.g. `followed_by`, `spawned`, `same_object`; window = ±5 min).
- [ ] **Name** 2–3 demo rules (names + one-line intent only, e.g. `REG-PERSIST-01` = registry persistence). Full encoding happens in Step 6.
- [ ] Write a unit test that constructs an `Event` from a dict and validates it.

**Code snippet — the core contracts:**

```python
from pydantic import BaseModel
from enum import Enum
from datetime import datetime

class EventType(str, Enum):
    PROCESS_EXECUTION = "process_execution"
    FILE_DOWNLOAD = "file_download"
    FILE_CREATION = "file_creation"
    REGISTRY_MODIFICATION = "registry_modification"
    NETWORK_CONNECTION = "network_connection"
    POWERSHELL_EXECUTION = "powershell_execution"
    LOG_DELETION = "log_deletion"

class Event(BaseModel):
    event_id: str            # "{source}:{row}" — assigned at parse time
    timestamp: datetime
    source: str              # log source / hostname
    event_type: EventType
    actor: str               # user / process that acted
    target: str              # object acted upon (file, reg key, dest IP...)
    metadata: dict           # everything else (commandline, parentpid, etc.)

class Evidence(BaseModel):
    event_ids: list[str]
    explanation: str
    parent_conclusion_id: str | None = None   # for derived/chained facts

class Conclusion(BaseModel):
    rule_id: str
    technique_id: str        # MITRE ATT&CK technique, e.g. "T1547.001"
    tactic: str              # e.g. "Persistence"
    description: str
    evidence: list[Evidence]

class Incident(BaseModel):
    id: str
    summary: str
    conclusions: list[Conclusion]
```

**Edge vocabulary (define here, use in Step 5):**

```python
# Edge types — keep to THREE in Phase 1 (avoids clique explosion)
# followed_by : temporal adjacency within TIME_WINDOW (±5 min)
# spawned     : parent/child process relationship
# same_object : two events touch the same file/registry key/IP
TIME_WINDOW_MINUTES = 5
```

**Demo rules to name now (write fully in Step 6):**

- `REG-PERSIST-01` — registry persistence (process execution + registry modification within window)
- `PSH-STAGING-01` — PowerShell staging (powershell execution + file download within window)
- `PERSIST-ESTABLISHED-01` — **chained**: staging + registry modification → "persistence established" (this is the two-level chain that proves forward chaining works)

**Done when:** `models.py` exists, `pytest tests/test_models.py` passes (construct + validate an Event), all output models defined, demo rules named.

---

### Step 3 — Sample Data

**Goal:** Hand-craft small CSV files that trigger the demo rules, so every downstream step is testable without the real dataset. Also pull the first Mordor atomic datasets.

> The original DoD references `attack_sample.csv` but no step created it. Every downstream step is untestable without it.

**Todo checklist:**

- [ ] Create `data/attack_sample.csv` — ~15–20 rows forming a mini attack chain that triggers all 3 demo rules (download → powershell → registry mod → log deletion).
- [ ] Create `data/benign_sample.csv` — ~10 rows of normal activity that should trigger **zero** conclusions (the negative case).
- [ ] Use a consistent column schema that maps to the `Event` model (see snippet).
- [ ] Download 3–5 Mordor atomic datasets into `data/mordor/` for later real-data testing.
- [ ] Document the expected attack narrative in a `data/README.md`.

**`attack_sample.csv` columns (illustrative rows):**

```csv
timestamp,source,event_type,actor,target,metadata
2024-01-01T10:00:00Z,HOST01,file_download,SYSTEM,C:\temp\invoice.zip,"{'url':'http://malicious.example/invoice.zip'}"
2024-01-01T10:00:30Z,HOST01,file_creation,SYSTEM,C:\temp\invoice.exe,"{'parent':'zip_extract'}"
2024-01-01T10:01:00Z,HOST01,process_execution,USER01,invoice.exe,"{'parentpid':1024,'pid':2048}"
2024-01-01T10:01:30Z,HOST01,powershell_execution,USER01,powershell.exe,"{'scriptblock':'Set-MpPreference -DisableRealtimeMonitoring $true'}"
2024-01-01T10:02:00Z,HOST01,registry_modification,USER01,HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\Updater,"{'value':'C:\\temp\\invoice.exe'}"
2024-01-01T10:02:30Z,HOST01,network_connection,invoice.exe,185.220.101.1,"{'port':443}"
2024-01-01T10:03:00Z,HOST01,log_deletion,USER01,Security.evtx,"{'method':'wevtutil cl'}"
```

**Done when:** both CSVs exist, `data/README.md` documents the narrative, Mordor datasets downloaded.

---

### Step 4 — Log Parser

**Goal:** Read CSV/JSON → produce validated `Event` objects, chronologically sorted, with provenance IDs and a bad-row policy.

**Todo checklist:**

- [ ] Write `parse_log(file_path: str) -> list[Event]` using Pandas.
- [ ] Map CSV columns → `Event` fields (handle the `metadata` dict from a JSON column or key=value parsing).
- [ ] Assign `event_id = f"{source_file}:{row_index}"` at parse time.
- [ ] Convert timestamps to UTC `datetime`; sort events chronologically.
- [ ] Implement bad-row policy: skip malformed rows, count them, return count in a `ParseResult`.
- [ ] Write `test_parser.py`: 10 rows → 10 Events; 1 bad row → 9 Events + skip count = 1.
- [ ] (Stretch) Add a Mordor NDJSON parser that extracts fields from the `Message` blob.

**Code snippet:**

```python
import pandas as pd
from app.models import Event, EventType
from datetime import datetime

def parse_log(file_path: str) -> list[Event]:
    df = pd.read_csv(file_path)              # or read_json for NDJSON
    df = df.sort_values("timestamp").reset_index(drop=True)
    events = []
    skipped = 0
    for i, row in df.iterrows():
        try:
            events.append(Event(
                event_id=f"{file_path}:{i}",
                timestamp=datetime.fromisoformat(row["timestamp"]),
                source=row["source"],
                event_type=EventType(row["event_type"]),
                actor=row["actor"],
                target=row["target"],
                metadata=eval(row["metadata"]) if isinstance(row["metadata"], str) else {},
            ))
        except Exception:
            skipped += 1
    log.info(f"Parsed {len(events)} events, skipped {skipped}")
    return events
```

**Done when:** `pytest tests/test_parser.py` passes — 10 valid rows → 10 Events; bad rows skipped + counted; events sorted by timestamp.

---

### Step 5 — Graph Builder

**Goal:** Build a NetworkX graph where events are nodes and relationships are edges, using the edge vocabulary + time window defined in Step 2.

**Todo checklist:**

- [ ] Write `build_graph(events: list[Event]) -> nx.DiGraph`.
- [ ] Add `followed_by` edges between events within `TIME_WINDOW_MINUTES` (±5 min).
- [ ] Add `spawned` edges for parent/child process relationships (from `metadata.parentpid`).
- [ ] Add `same_object` edges for events touching the same file/registry key/IP.
- [ ] **Do NOT** add `same_user` or `same_host` as edges (causes cliques) — keep them as rule-matchable fields.
- [ ] Write `test_graph.py`: A→B→C chain exists; isolated event has no edges.

**Code snippet:**

```python
import networkx as nx
from app.models import Event
from datetime import timedelta

TIME_WINDOW = timedelta(minutes=5)

def build_graph(events: list[Event]) -> nx.DiGraph:
    g = nx.DiGraph()
    for e in events:
        g.add_node(e.event_id, event=e)

    # followed_by: temporal adjacency
    for i, a in enumerate(events):
        for b in events[i+1:]:
            if b.timestamp - a.timestamp > TIME_WINDOW:
                break  # sorted, so no further matches
            g.add_edge(a.event_id, b.event_id, kind="followed_by")

    # spawned: parent/child process
    by_pid = {e.metadata.get("pid"): e for e in events if "pid" in e.metadata}
    for e in events:
        ppid = e.metadata.get("parentpid")
        if ppid in by_pid:
            g.add_edge(by_pid[ppid].event_id, e.event_id, kind="spawned")

    # same_object: shared file/reg key/IP
    # (group events by target, add edges within each group)
    # ... similar grouping logic ...
    return g
```

**Done when:** `pytest tests/test_graph.py` passes — A→B→C `followed_by` chain present; isolated node has degree 0; no `same_user` edges exist.

---

### Step 6 — Knowledge Base

**Goal:** Encode 3–5 machine-readable rules grounded in MITRE ATT&CK. **Timebox this** — juniors will disappear into MITRE research for two weeks. Bound it: 3–5 rules, one page each, citing technique ID.

**Todo checklist:**

- [ ] Research the MITRE ATT&CK techniques behind each demo rule (technique ID, tactic, required events, conditions).
- [ ] Encode each rule as a **plain Python function** (NOT a DSL) that takes a graph neighborhood and returns a `Conclusion` or `None`.
- [ ] Register rules in `rules/registry.py` (a list of rule functions).
- [ ] Each rule must declare: `rule_id`, `technique_id`, `tactic`, required event types, condition logic, and produce `Evidence` with concrete event IDs.
- [ ] Include at least one **two-level chain** rule (e.g. `PERSIST-ESTABLISHED-01` consumes a prior conclusion).
- [ ] Write `test_rules.py`: feed a known attack neighborhood → expected conclusion; feed benign → `None`.

**Rule schema (declarative + function):**

```python
from app.models import Conclusion, Evidence, EventType

# A rule is just a function — boring code, no DSL, no framework
def detect_registry_persistence(neighborhood: list, graph) -> Conclusion | None:
    """
    REG-PERSIST-01 — Registry Persistence (MITRE T1547.001)
    Fires when: process_execution + registry_modification within TIME_WINDOW
    """
    proc_exec = [e for e in neighborhood if e.event_type == EventType.PROCESS_EXECUTION]
    reg_mod   = [e for e in neighborhood if e.event_type == EventType.REGISTRY_MODIFICATION]

    for p in proc_exec:
        for r in reg_mod:
            if abs((p.timestamp - r.timestamp).total_seconds()) <= 300:  # 5 min
                return Conclusion(
                    rule_id="REG-PERSIST-01",
                    technique_id="T1547.001",
                    tactic="Persistence",
                    description="Possible registry-based persistence established.",
                    evidence=[Evidence(
                        event_ids=[p.event_id, r.event_id],
                        explanation=f"Process {p.actor} executed, then registry key {r.target} modified within 5 min.",
                    )],
                )
    return None
```

**Registry:**

```python
# rules/registry.py
RULES = [detect_registry_persistence, detect_powershell_staging, detect_persistence_established]
```

**Done when:** 3–5 rules encoded; each cites a MITRE technique ID; `test_rules.py` passes (attack → conclusion, benign → None); at least one rule consumes a prior conclusion (chaining).

---

### Step 7 — Reasoning Engine

**Goal:** Apply rules via forward chaining until no new inferences, capturing evidence for every conclusion.

> **Highest risk: scope creep.** Keep the engine boring — a simple loop over rule functions. No generic engine, no mini-DSL, no custom syntax. 5 rules max.

**Todo checklist:**

- [ ] Write `analyze(graph, rules) -> list[Conclusion]`.
- [ ] Implement the **matcher**: for each event node, gather its graph neighborhood (within the time window) and run each rule against it.
- [ ] Implement the **fixpoint loop**: `facts → apply_rules → new_facts` until no new conclusions OR max iterations reached.
- [ ] Implement **evidence capture**: every `Conclusion` carries concrete `event_ids` and (for derived facts) `parent_conclusion_id`.
- [ ] Add **deduplication**: new facts deduplicated by identity hash so the loop converges.
- [ ] Add **max-iteration safety cap** (e.g. 10) so the loop always terminates.
- [ ] Match **graph-locally** (a rule fires over a node's neighborhood), NOT rules × all-events cross-products.
- [ ] Write `test_engine.py`: attack graph → expected conclusions including the chained one; benign graph → empty list.

**Code snippet:**

```python
from app.models import Conclusion
import networkx as nx

MAX_ITERATIONS = 10

def analyze(graph: nx.DiGraph, rules: list) -> list[Conclusion]:
    conclusions: list[Conclusion] = []
    seen_hashes: set[str] = set()

    for _ in range(MAX_ITERATIONS):
        new_conclusions = []
        for node_id in graph.nodes:
            event = graph.nodes[node_id]["event"]
            # gather neighborhood within time window (graph-local matching)
            neighborhood = get_neighborhood(graph, node_id)
            for rule in rules:
                result = rule(neighborhood, graph)
                if result:
                    h = hash_conclusion(result)
                    if h not in seen_hashes:
                        seen_hashes.add(h)
                        new_conclusions.append(result)
        if not new_conclusions:
            break  # fixpoint reached
        conclusions.extend(new_conclusions)
    return conclusions

def get_neighborhood(graph, node_id):
    """Return events within TIME_WINDOW of the given node, via graph edges."""
    # walk followed_by / spawned / same_object edges within the window
    ...

def hash_conclusion(c: Conclusion) -> str:
    return f"{c.rule_id}:{sorted(c.evidence[0].event_ids)}"
```

**Done when:** `pytest tests/test_engine.py` passes — attack graph yields the expected conclusions (including the chained `PERSIST-ESTABLISHED-01`); benign graph yields zero conclusions; loop terminates within max iterations.

---

### Step 8 — Pipeline Orchestrator

**Goal:** One callable function that chains parser → graph → engine, runnable from CLI without HTTP. This is the heart of the DoD.

> Without this, Step 10 (FastAPI) secretly becomes "write API _and_ integrate everything" — too much for one step, and forces the first end-to-end run through HTTP (the worst way to debug a pipeline).

**Todo checklist:**

- [ ] Write `run_analysis(file_path: str) -> Incident` in `orchestrator.py`.
- [ ] Chain: `parse_log → build_graph → analyze → assemble Incident`.
- [ ] Add a CLI entrypoint: `python -m app.orchestrator data/attack_sample.csv`.
- [ ] Print the resulting `Incident` as formatted JSON to stdout.
- [ ] Verify the DoD scenario works end-to-end from CLI **before** touching FastAPI.

**Code snippet:**

```python
import json
from app.parser import parse_log
from app.graph import build_graph
from app.engine import analyze
from app.rules.registry import RULES
from app.models import Incident
import uuid

def run_analysis(file_path: str) -> Incident:
    events = parse_log(file_path)
    graph = build_graph(events)
    conclusions = analyze(graph, RULES)
    return Incident(
        id=str(uuid.uuid4()),
        summary=f"Analyzed {len(events)} events, found {len(conclusions)} conclusions.",
        conclusions=conclusions,
    )

if __name__ == "__main__":
    import sys
    incident = run_analysis(sys.argv[1])
    print(json.dumps(incident.model_dump(), indent=2, default=str))
```

**Done when:** `python -m app.orchestrator data/attack_sample.csv` prints an `Incident` with conclusions + evidence; `benign_sample.csv` prints an Incident with empty conclusions.

---

### Step 9 — Persistence (minimal)

**Goal:** Store incidents so `GET /incident/{id}` works. **No Postgres in Phase 1.** Use in-memory dict or SQLite.

**Todo checklist:**

- [ ] Decide: SQLite (persists across restarts) or in-memory dict (simpler, lost on restart). Recommend SQLite for demo-day reliability.
- [ ] Write `save_incident(incident)` and `get_incident(id) -> Incident`.
- [ ] If SQLite: one table `incidents(id TEXT PRIMARY KEY, data TEXT)` storing JSON.
- [ ] Wire the orchestrator to save the incident after analysis.

**Code snippet (SQLite):**

```python
import sqlite3, json
from app.models import Incident

def _conn():
    return sqlite3.connect("incidents.db")

def save_incident(incident: Incident):
    with _conn() as c:
        c.execute("CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, data TEXT)")
        c.execute("INSERT INTO incidents VALUES (?, ?)", (incident.id, incident.model_dump_json()))

def get_incident(incident_id: str) -> Incident | None:
    with _conn() as c:
        row = c.execute("SELECT data FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return Incident.model_validate_json(row[0]) if row else None
```

**Done when:** save then get returns the same Incident; restart survives (if SQLite).

---

### Step 10 — FastAPI (thin wrapper)

**Goal:** Expose the orchestrator via REST. This is a **thin wrapper** — no business logic here. Correct to keep it late.

**Todo checklist:**

- [ ] Write `app/main.py` with FastAPI app.
- [ ] `POST /upload` — accept a CSV file, save it, return a file id.
- [ ] `POST /analyze` — take a file id, call `run_analysis`, save incident, return the `Incident`.
- [ ] `GET /incident/{id}` — call `get_incident`, return the `Incident`.
- [ ] Note: request/response schemas come **for free** from the Pydantic contracts defined in Step 2.
- [ ] Run: `uvicorn app.main:app --reload`.
- [ ] Test endpoints via the auto-docs at `http://localhost:8000/docs`.

**Code snippet:**

```python
from fastapi import FastAPI, UploadFile, File, HTTPException
from app.orchestrator import run_analysis
from app.storage import save_incident, get_incident
from app.models import Incident

app = FastAPI(title="Cybersecurity Incident Reconstruction API")

@app.post("/analyze", response_model=Incident)
async def analyze_endpoint(file: UploadFile = File(...)):
    path = f"/tmp/{file.filename}"
    with open(path, "wb") as f:
        f.write(await file.read())
    incident = run_analysis(path)
    save_incident(incident)
    return incident

@app.get("/incident/{incident_id}", response_model=Incident)
def get_incident_endpoint(incident_id: str):
    incident = get_incident(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident
```

**Done when:** `POST /analyze` with `attack_sample.csv` returns an Incident with conclusions; `GET /incident/{id}` retrieves it; auto-docs render the schemas.

---

### Step 11 — End-to-End Test (Definition of Done)

**Goal:** Prove the full pipeline works on the DoD scenario + the negative case.

**Todo checklist:**

- [ ] Write `tests/test_e2e.py`.
- [ ] Test 1 (DoD): `attack_sample.csv → /analyze → Incident with ≥1 Conclusion, each with Evidence + rule_id`.
- [ ] Test 2 (negative): `benign_sample.csv → /analyze → Incident with zero Conclusions`.
- [ ] Test 3 (provenance): every `Evidence.event_ids` resolves back to a real parsed Event.
- [ ] Test 4 (chaining): the two-level chain (`PERSIST-ESTABLISHED-01`) fires only when its prerequisite conclusion exists.
- [ ] Run full suite: `pytest -v`.
- [ ] (Stretch) Run against one Mordor atomic dataset to prove real-data viability.

**Done when:** all tests pass; the DoD scenario produces an incident with evidence and rule; the benign case produces no conclusions.

---

## 4. Definition of Done (Phase 1)

```
attack_sample.csv → POST /analyze →
  structured Events → Event Graph → reasoning →
  Incident with Conclusions, each carrying Evidence (event_ids) + rule_id.

benign_sample.csv → POST /analyze →
  Incident with zero Conclusions.

Every Evidence.event_ids resolves to a real source Event.
The two-level forward-chaining rule fires only when its prerequisite exists.
```

---

## 5. Risks & Mitigations

| Risk                                              | Mitigation                                                                                                                                                  |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Rule engine scope creep** (highest)             | Rules as plain functions in a simple loop. No DSL, no framework. 5 rules max. Boring code.                                                                  |
| **Forward chaining doesn't terminate / explodes** | Deduplicate new facts by identity hash; add `MAX_ITERATIONS=10` safety cap.                                                                                 |
| **Demo doesn't actually demonstrate chaining**    | Include at least one two-level chain (staging → persistence-established). Depth > breadth: one chained pair proves the paradigm better than ten flat rules. |
| **Edge explosion** (same-user cliques)            | Restrict Phase 1 edges to `followed_by`, `spawned`, `same_object`. Keep user/host as rule-matchable fields, NOT edges.                                      |
| **Matching cost** (rules × all-events)            | Match graph-locally — a rule fires over a node's neighborhood within the time window, not a global cross-product.                                           |
| **Provenance retrofitted late**                   | Assign `event_id` at parse time (Step 4). The project thesis is evidence trace-back; retrofitting IDs after the engine exists is painful.                   |
| **MITRE research rabbit hole**                    | Timebox Step 6: 3–5 rules, one page each, citing technique ID. Don't build a generic knowledge base.                                                        |
| **"Close timestamps" unimplementable**            | Concrete `TIME_WINDOW_MINUTES=5` parameter defined in Step 2, used in Step 5 and Step 6.                                                                    |

**Guiding principle when time runs short:** Prioritize the evidence chain over rule count. If the "why?" trace-back works end-to-end with three rules, the project succeeds. If it doesn't, fifty rules won't save it.

---

## 6. Quick Reference — The 7 Event Types

| Event type              | Example trigger             | Mordor source                      |
| ----------------------- | --------------------------- | ---------------------------------- |
| `process_execution`     | A process starts            | Sysmon EID 1 / Win 4688            |
| `file_download`         | File fetched from network   | Sysmon EID 11 / bitsadmin datasets |
| `file_creation`         | File written to disk        | Sysmon EID 11                      |
| `registry_modification` | Registry key/value changed  | Sysmon EID 12/13                   |
| `network_connection`    | Outbound/inbound connection | Sysmon EID 3 / Zeek                |
| `powershell_execution`  | PowerShell script block     | Win EID 4104                       |
| `log_deletion`          | Event log cleared           | Win EID 1102 / wevtutil            |

---

## 7. What's NOT in Phase 1 (deferred)

- Authentication / authorization
- Docker / containerization
- CI/CD pipelines
- Config management (use constants for now)
- PostgreSQL (SQLite is enough)
- React frontend (Phase 2+)
- D3.js / React Flow visualization (Phase 2+)
- A generic rule DSL or rule editor
- Real-time log streaming (batch only in Phase 1)

---

_This roadmap was synthesised from the project summary draft, the original Phase 1 PDF, an architectural ordering review, and deep dataset research. Follow the steps in order — each is independently testable and the Definition of Done falls out naturally at the end._
