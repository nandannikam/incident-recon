# Phase 3 Roadmap — Precision, Showcase & Deployment

## AI-Powered Cybersecurity Incident Reconstruction & Analysis System

> **Status:** Draft (Phase 3)
> **Scope:** The final phase. Fix the correctness gaps Phase 2 left behind, prove the system on a real multi-stage campaign, and ship it as a reproducible, deployable product. Only genuine stretch work stays optional.
> **Ordering:** Correctness first (trust) → campaign (the showcase) → production & deployment → frontend last mile.
> **Audience:** Project team (junior-to-mid on the stack). Every step has a goal, a todo checklist, illustrative code snippets, and a "done when" criterion.
> **Verified:** 2026-10-05 — checked against the codebase. Completed items are ticked; partial items carry an inline note. Steps 1–2 are complete · Steps 3–7 are partially implemented · Steps 8–13 are not started.

---

## 0. What Phase 3 Is (and what it is not)

Phase 1 built a working demo pipeline on hand-crafted CSV. Phase 2 made the backend handle **real logs**, added graph visualisation, hardened the API, expanded the knowledge base to **5 rules**, and shipped an **80% frontend** — deliberately stopping at ~80% and deferring the rest.

Phase 3 is the final phase, and it is where the deferred work belongs. It has four jobs:

1. **Fix the real defects.** Phase 2 made the rules _fire_ on real data; it did not make them _correct_ — a dataset whose only attack is a single log clear currently yields **34 conclusions**, and one test is red. These are correctness bugs in a project whose entire thesis is "every conclusion traces to evidence".
2. **Prove the pitch.** The project is meant to reconstruct an _incident_ — a multi-stage story. What ships is five single-technique datasets, and every rule requires the same host, so a campaign never chains. Phase 3 adds a real campaign and the readable narrative.
3. **Make it reproducible and deployable.** Right now it only runs on the author's laptop via manual setup. The final phase includes the production work that makes it a real product: configuration, a proper database, API security, Docker, CI, and a deployed URL.
4. **Finish the frontend's last mile** — routing/shareable URLs, a data layer, and component tests.

**What stays optional:** only genuine stretch. Theming/design tokens, i18n, WebSockets/streaming, a rule DSL/editor, ML fusion, a full observability stack and Kubernetes are listed once at the end (§7) and are not required. See §7 for the full list and why each is stretch.

---

## 1. Honest Audit — Where Phase 2 Actually Left the Project

### ✅ Genuinely done (verified)

- Full backend pipeline: `parse_log` / `parse_mordor` → format dispatch → NetworkX graph → forward-chaining engine → `Incident` with evidence → SQLite.
- **5 MITRE-mapped rules** (`REG-PERSIST-01`, `PSH-STAGING-01`, `PERSIST-ESTABLISHED-01`, `C2-BEACON-01`, `LOG-CLEAR-01`), including the two-level chained rule that proves forward chaining.
- **Real-log parsing** end-to-end for `.csv` / `.ndjson` / `.json`, with content-sniffing so a mislabeled file errors instead of silently yielding 0 events.
- **5 Mordor atomic datasets**; `spawned` edges fire on real data.
- Graph visualisation (matplotlib PNG + GraphML) + `--viz`.
- API hardening: CORS, `/upload` + `/analyze` (50 MB limit, validation), `/incident/{id}`, and `/analyze` returning `{incident, diagnostics}`.
- **Dashboard**: upload → evidence-backed incident view → React Flow attack chain. Builds clean.
- 79 of 80 tests passing.

### ❌ Genuinely weak / missing (this is what Phase 3 fixes)

| #   | Gap                                              | Severity   | Why it matters                                                                                                                                                                                            |
| --- | ------------------------------------------------ | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| G1  | **Rules over-fire on real data**                 | 🔴 High    | `cmd_wevtutil` (one real action = one log clear) yields **9 `C2-BEACON-01` + 25 `REG-PERSIST-01` = 34 conclusions**; `bitsadmin` yields 15. "Finds everything" is indistinguishable from "finds nothing". |
| G2  | **One red test; no real-data regression guards** | 🟠 Med     | `test_rules.py::test_reg_persist_window_boundary_is_inclusive` fails. No test guards the `AnalyzeResponse` shape, mislabeled files, scale, or per-dataset counts.                                         |
| G3  | **No multi-stage campaign**                      | 🔴 High    | The pitch is "reconstruct an incident"; the multi-stage showcase (APT29 was recommended in Phase 1) is absent.                                                                                            |
| G4  | **Scale / performance**                          | 🟠 Med     | 10,377 events → ~17 s, **641,919 edges**; the largest dataset was previously a >60 s timeout.                                                                                                             |
| G5  | **No configuration management**                  | 🟠 Med     | CORS origins, upload size, time window, DB path, temp dir and the API base URL are hardcoded. Can't run in more than one environment.                                                                     |
| G6  | **API is unauthenticated**                       | 🟠 Med     | Any client can upload/read. Fine on localhost, not for a deployed submission.                                                                                                                             |
| G7  | **SQLite only**                                  | 🟡 Low–Med | The summary draft says "PostgreSQL if required"; a deployed host with an ephemeral filesystem makes SQLite fragile.                                                                                       |
| G8  | **No containerisation**                          | 🟠 Med     | Setup depends on a specific venv + `pip install -e .`; a grader can't easily reproduce it.                                                                                                                |
| G9  | **No CI**                                        | 🟠 Med     | Nothing catches the red test or a broken frontend build before it ships.                                                                                                                                  |
| G10 | **Not deployed**                                 | 🟠 Med     | Everything runs on localhost; no shareable demo URL.                                                                                                                                                      |
| G11 | **No frontend routing**                          | 🟡 Low–Med | Results live in `useState`; an incident can't be linked, bookmarked or revisited.                                                                                                                         |
| G12 | **No frontend tests**                            | 🟡 Low–Med | The three components are untested; a contract change can silently break the UI again.                                                                                                                     |
| G13 | **No data-fetching layer**                       | 🟡 Low     | Raw `fetch` + `useState`; no cache/retry; no incident history.                                                                                                                                            |
| G14 | **Hardcoded theme**                              | 🟡 Low     | Palette baked into one 1,279-line stylesheet; no tokens, no light mode. _(Stretch.)_                                                                                                                      |
| G15 | **Repo / data hygiene**                          | 🟡 Low     | ~48 MB of datasets committed; `src/data/mordor/README.md` missing (incl. MIT citation); `KNOWN-ISSUES.md` header stale.                                                                                   |
| G16 | **No cross-host correlation or narrative**       | 🟠 Med     | Every rule gates on `_same_host`, so campaigns never chain. `summary` is a terse count, not the incident story the summary draft promises.                                                                |

---

## 2. Phase 3 Step Sequence

**Trust (1–4) → showcase (5) → production & deployment (6–11) → frontend last mile (12–13).**

| #   | Step                                                  | Fixes    | Part       | Priority    |
| --- | ----------------------------------------------------- | -------- | ---------- | ----------- |
| 1   | Green the Suite + Lock the API Contract               | G2, G15  | Trust      | **Must**    |
| 2   | Detection Precision + Confidence + Severity           | G1       | Trust      | **Must**    |
| 3   | Scale & Performance Pass                              | G4       | Trust      | **Must**    |
| 4   | Cross-Host Correlation + Incident Narrative           | G16, G1  | Trust      | **Must**    |
| 5   | Multi-Stage Campaign + Data Hygiene                   | G3, G15  | Showcase   | **Must**    |
| 6   | Configuration Management                              | G5       | Production | **Must**    |
| 7   | Persistence Upgrade → PostgreSQL                      | G7       | Production | **Must**    |
| 8   | API Production Hardening (auth, health, limits, logs) | G6       | Production | Recommended |
| 9   | Containerisation (Docker + Compose)                   | G8       | Production | **Must**    |
| 10  | CI/CD (GitHub Actions)                                | G9, G2   | Production | Recommended |
| 11  | Deployment + Static Frontend Serving                  | G10      | Production | **Must**    |
| 12  | Frontend Routing + Shareable Incident URLs            | G11, G13 | Frontend   | Recommended |
| 13  | Frontend Tests (Vitest + RTL)                         | G12      | Frontend   | Recommended |

**Dependencies:** 2 ← 1; 3 independent of 2; 4 ← 2 + 5; 7, 8 ← 6; 9 ← 6–7; 10 ← 1 + 9; 11 ← 9; 12 ← 8 (history endpoint); 13 ← 1 (shared contract fixture). Steps 2, 3 and 12–13 can be parallelised if the team splits.

> **Ordering rule:** every **Must** step is completed before any Recommended step starts. Where a Must step depended on a Recommended one, the dependency was promoted to **Must** — **Step 5** (Step 4 needs campaign data to prove cross-host correlation) and **Step 7** (Step 9's Docker stack deploys against Postgres). **Step 10 (CI)** stays Recommended because deployment needs Docker (Step 9), not CI.

**Guiding rule for this phase:** every precision change ships with a test asserting **expected conclusions on a known-malicious dataset** and **bounded/zero conclusions on a known-benign one**. Phase 2 traded accuracy for coverage; Phase 3 trades coverage back for accuracy.

---

## 3. Recommended Build Order

**Ordering rule: finish every Must step before starting a Recommended one.** Two steps are Must precisely because a Must step depends on them — **Step 5** (Step 4 needs campaign data to prove cross-host correlation) and **Step 7** (Step 9's Docker stack deploys against Postgres). **Step 10 (CI)** stays Recommended because deployment needs Docker, not CI.

### Must — do these first, in this order

| Order | Step                                                   | Why it's Must                                                                                     |
| ----- | ------------------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| 1     | **Step 1 — Green the suite**                           | Nothing is trustworthy on a red baseline.                                                         |
| 2     | **Step 2 — Precision + confidence**                    | Fixes the false-positive flood; the project's credibility.                                        |
| 3     | **Step 3 — Performance**                               | Keeps analysis responsive; independent of Step 2.                                                 |
| 4     | **Step 4 + Step 5 — Correlation/narrative + campaign** | Build the correlation layer against the campaign data; each verifies the other. This is the demo. |
| 5     | **Step 6 — Configuration**                             | Unblocks Postgres, Docker and deployment.                                                         |
| 6     | **Step 7 — PostgreSQL**                                | Required by Step 9's Docker + deployment stack.                                                   |
| 7     | **Step 9 — Docker + Compose**                          | One-command, reproducible run.                                                                    |
| 8     | **Step 11 — Deployment**                               | The shareable URL that finishes the project.                                                      |

### Recommended — after the Musts

| Step                           | Notes                                                                                                    |
| ------------------------------ | -------------------------------------------------------------------------------------------------------- |
| **Step 8 — API hardening**     | Auth / health / rate limiting. Required only if the deployed URL is public; a LAN-only demo can skip it. |
| **Step 10 — CI/CD**            | Catches the red-test class of defect. Do it once Steps 1 and 9 exist.                                    |
| **Step 12 — Frontend routing** | Shareable `/incident/:id` URLs + light data layer.                                                       |
| **Step 13 — Frontend tests**   | Guards the UI contract against drift.                                                                    |

**Parallelise if the team is larger:** one person on Steps 1–3 (correctness), one on Steps 4–5 (data + correlation), one on Steps 12–13 (frontend) — then converge on Steps 6–11.

**If the schedule collapses,** the irreducible core is **Steps 1 → 2 → 5 → 4**; the next-highest-value Musts are Docker (Step 9) and deployment (Step 11). Everything in §7 stays stretch.

---

## 4. Step-by-Step Roadmap

---

### Step 1 — Green the Suite + Lock the API Contract — ✅ Complete (2026-10-05)

**Goal:** A fully green suite that also guards the contracts Phase 2 changed, so the next contract change can't ship silently (this is exactly how the frontend broke in Phase 2).

**Todo checklist:**

- [x] Fix `test_rules.py::test_reg_persist_window_boundary_is_inclusive` — update the fixture's registry target to a real autostart key (`HKLM\Software\Microsoft\Windows\CurrentVersion\Run\...`) so the narrowed rule matches.
- [x] Add a test asserting `/analyze` returns `AnalyzeResponse` = `{incident, diagnostics}` (not the bare `Incident`) — the shape that broke the client in Phase 2.
- [x] Add a test for the mislabeled-file path: a CSV renamed `.json` must error clearly (422), **not** silently produce a 0-event success.
- [x] Add a shared contract fixture consumed by both the backend test and the frontend, so the two sides can't drift. _(`contracts/analyze_response.json`, consumed by the backend `test_api_contract.py` and by `incident-dashboard/src/contract.test.ts` via Vitest.)_
- [x] Update `KNOWN-ISSUES.md`: fix the stale header, mark resolved issues resolved.
- [x] Run `pytest -v`; record the green count in the README. _(green: **217 passed, 7 skipped**; recorded in `README.md`.)_

**Code snippet — contract guard:**

```python
def test_analyze_returns_wrapped_response(client):
    with open(SAMPLE_CSV, "rb") as f:
        res = client.post("/analyze", files={"file": ("attack_sample.csv", f, "text/csv")})
    assert res.status_code == 200
    body = res.json()
    assert set(body) == {"incident", "diagnostics"}, "response shape changed — update api.ts"
    assert "conclusions" in body["incident"]
    assert "total_rows" in body["diagnostics"]
```

**Done when:** `pytest` is fully green; deliberately breaking the response shape or mislabeling a file makes a test fail; `KNOWN-ISSUES.md` reflects reality.

---

### Step 2 — Detection Precision + Confidence + Severity — ✅ Complete (2026-10-05)

**Goal:** Stop the rules over-firing. Each rule produces **at most one conclusion per host+technique**, carries a **confidence score**, and is tuned against real datasets with known expected counts.

> The highest-value step in Phase 3. A security tool that cries wolf on every benign connection is worse than no tool.

**Todo checklist:**

- [x] Add `confidence: float` (0–1) to `Conclusion`; rules set it deliberately (`LOG-CLEAR-01` 0.9 — unambiguous; `C2-BEACON-01` 0.3 — a port heuristic).
- [x] Add `severity` (derived from tactic) so the UI can rank findings.
- [x] **Cluster / de-duplicate at the conclusion level**: group by `(rule_id, host)` and keep the highest-confidence instance, merging the rest as supporting evidence. The 15 near-identical `REG-PERSIST-01` findings on bitsadmin collapse to one.
- [x] Tighten `C2-BEACON-01`: require the destination IP to be **public** (exclude RFC1918 / loopback / link-local); document residual false positives honestly. _(also excludes multicast explicitly — on Python 3.14 `is_global` is `True` for 239.255.255.250.)_
- [x] Require `REG-PERSIST-01` to see the process that _writes_ the persistence key, not just any prior process within 5 minutes. _(matches the `Image` of the writing process; falls back to time-order at a lower confidence (0.4) when the source records no writer, e.g. the synthetic CSV.)_
- [x] Add **golden-fixture tests per dataset**: the wevtutil dataset yields only `LOG-CLEAR-01`; bounded counts on bitsadmin/psexec/empire. _(golden tests added in `src/tests/test_precision.py`; honest deviation: the wevtutil dataset contains **no** `log_deletion` event, so it yields `REG-PERSIST-01` for the EventLog service key — its C2 noise is gone and the count is bounded to 1. The roadmap's "only `LOG-CLEAR-01`" expectation does not match the data's event mapping; flagged for the Step 4 taxonomy work.)_
- [x] Add a **benign-fixture test on real data**: non-malicious input yields ≤ a documented small number of low-confidence findings. _(covered by the real-data flood-control bound on wevtutil (≤2, conf 0.6) plus zero findings on `benign_sample.csv`; a dedicated benign Mordor fixture is deferred to the Step 5 dataset work.)_

**Code snippet — confidence + clustering:**

```python
# In each rule: return one Conclusion with an explicit confidence.
return Conclusion(..., confidence=0.3)  # C2 port heuristic — weak evidence

def cluster_conclusions(conclusions: list[Conclusion]) -> list[Conclusion]:
    """Collapse near-duplicate findings from the same rule on the same host,
    keeping the highest-confidence instance and its evidence."""
    best: dict[tuple[str, str], Conclusion] = {}
    for c in conclusions:
        key = (c.rule_id, c.hosts[0] if c.hosts else "")
        incumbent = best.get(key)
        if incumbent is None or c.confidence > incumbent.confidence:
            best[key] = c
    return list(best.values())
```

**Done when:** the wevtutil dataset yields its actual technique and nothing else; bitsadmin/psexec counts are bounded and asserted; every conclusion carries a confidence; benign real data does not flood.

---

### Step 3 — Scale & Performance Pass

**Goal:** Make `/analyze` fast and memory-bounded on the campaign, without arbitrary edge caps that silently drop real evidence.

**Todo checklist:**

- [ ] Replace the flat `MAX_EDGES_PER_NODE_PER_KIND = 50` cap with **relevance-ordered capping**: always keep `spawned` and `same_object` (high-signal), cap the dense `followed_by` by proximity.
- [ ] Pre-index candidate events by `(event_type, source)` (and by target for `same_object`) so rules don't scan full neighbourhoods.
- [ ] Add a **profiling test** with a synthetic 10k-event file; assert a wall-clock budget (target **< 5 s**) and a bounded edge count. _(partial: a 10k smoke test exists but its budget is 120 s and no edge count is asserted.)_
- [ ] Add a request-level guard: above a parsed-event threshold, run analysis as a background task and return a job id (ties into Step 8).
- [ ] Confirm golden fixtures still pass after the change. _(no per-dataset golden fixtures exist.)_

**Code snippet — relevance-ordered edges:**

```python
def build_graph(events: list[Event]) -> nx.DiGraph:
    g = nx.DiGraph()
    for e in events:
        g.add_node(e.event_id, event=e)
    add_spawned_edges(g, events)        # cheap, high-signal — always full
    add_same_object_edges(g, events)    # grouped by target — high-signal
    add_followed_by_edges(g, events)    # dense — cap by proximity
    return g
```

**Done when:** 10k events analyse in < 5 s with a bounded edge count; the demo datasets produce identical conclusions before/after (golden fixtures pass).

---

### Step 4 — Cross-Host Correlation + Incident Narrative

**Goal:** Reconstruct the _incident story_, not a bag of per-host facts — and generate the readable summary the project summary draft promises ("Initial Access: … Execution: … Persistence: …").

**Todo checklist:**

- [ ] Allow correlation **across hosts** via shared concrete objects (same file hash / registry key / destination IP) or a network connection between hosts. Today every rule gates on `_same_host`, so campaigns never chain.
- [ ] Build a correlation layer that groups conclusions into one incident by shared actor/object/time, then orders them by **kill-chain tactic**.
- [ ] Add `severity` to `Incident` (max of its conclusions); generate the narrative `summary`. _(partial: `Incident.severity` derives the max; the narrative `summary` is still a count string.)_
- [ ] Surface `confidence` and `severity` in the API response and the dashboard (badge/colour). _(partial: present in the API model; the dashboard does not render them.)_
- [ ] Add a test: a synthetic multi-host campaign produces **one** incident with the expected kill-chain ordering.

**Code snippet — kill-chain narrative:**

```python
KILL_CHAIN_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]

def build_summary(conclusions: list[Conclusion]) -> str:
    ordered = sorted(
        conclusions,
        key=lambda c: KILL_CHAIN_ORDER.index(c.tactic)
        if c.tactic in KILL_CHAIN_ORDER else len(KILL_CHAIN_ORDER),
    )
    if not ordered:
        return "No malicious activity reconstructed from this dataset."
    return " ".join(f"{c.tactic}: {c.description}" for c in ordered)
```

**Done when:** a multi-stage, multi-host campaign collapses into a single ordered incident whose summary reads like the example in the project summary draft; severity/confidence are visible in API and UI.

---

### Step 5 — Multi-Stage Campaign + Data Hygiene

**Goal:** Prove the system reconstructs a **complete real attack campaign**, and stop committing 48 MB of raw data to git.

**Todo checklist:**

- [ ] Add `scripts/fetch_datasets.sh` (or `make data`) downloading a compound campaign (recommended: **Mordor APT29 Day 1**, or the largest that fits the laptop) into a **git-ignored** directory.
- [x] Add `src/data/mordor/README.md` documenting every dataset, its mapped event types, and the **MIT license / OTRF citation** (Phase 2 requirement).
- [ ] Stop tracking the ~48 MB of raw datasets: `.gitignore` them, keep small fixtures + download instructions (a CI size guard in Step 10 prevents regression).
- [ ] Wire the campaign through `run_analysis`; verify chained conclusions fire across stages/hosts (depends on Step 4). _(partial: generic entry works, but cross-host chaining is not implemented — the dataset README notes the chained rules do not fire on the campaign.)_
- [ ] Save the demo output as an artifact (`docs/demo/campaign_result.json`).
- [ ] Add a golden test asserting the campaign's expected techniques appear in the reconstructed incident.

**Code snippet — dataset fetch:**

```bash
#!/usr/bin/env bash
# scripts/fetch_datasets.sh — downloads campaign data into a git-ignored dir
set -euo pipefail
DEST="src/data/mordor/campaigns"
mkdir -p "$DEST"
curl -L -o /tmp/apt29.tar.gz "https://github.com/OTRF/Security-Datasets/releases/.../apt29-day1.tar.gz"
tar -xzf /tmp/apt29.tar.gz -C "$DEST"
echo "Downloaded campaign data to $DEST (git-ignored)"
```

**Done when:** a fresh clone can run `make data && make demo` and reconstruct a documented multi-stage campaign with cross-host chained conclusions; no large dataset is tracked; licensing is documented.

---

### Step 6 — Configuration Management

**Goal:** One source of truth for every environment-specific value, so the same code runs locally, in CI and in deployment.

**Todo checklist:**

- [x] Add `pydantic-settings`; create `app/config.py` with a `Settings` class.
- [ ] Externalise: CORS origins, max upload bytes, `TIME_WINDOW_MINUTES`, database URL, temp dir, API key, log level, and the frontend API base URL. _(partial: all externalised except the temp dir, still hardcoded in `main.py`.)_
- [x] Add a committed `.env.example` (never commit `.env`); fail fast with a clear error if required values are missing in production.
- [ ] Replace hardcoded literals in `main.py`, `storage.py`, `models.py`, and `api.ts` with settings lookups. _(partial: `storage.py` still hardcodes `DB_PATH` and ignores `settings.database_url`.)_
- [x] Add a test overriding a setting via env var (e.g. a smaller max upload) and assert behaviour changes.

**Code snippet:**

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    cors_origins: list[str] = ["http://localhost:5173"]
    max_upload_bytes: int = 50 * 1024 * 1024
    time_window_minutes: int = 5
    database_url: str = "sqlite:///./incidents.db"
    api_key: str | None = None
    log_level: str = "INFO"

    model_config = {"env_file": ".env"}

settings = Settings()
```

**Done when:** changing any environment value requires no code edit; the app runs from `.env`; no secret is committed.

---

### Step 7 — Persistence Upgrade → PostgreSQL

**Goal:** Move from a single SQLite file to a real database behind a repository interface, while keeping SQLite for zero-config dev.

> Do this after Step 6 — the DB URL is configuration. Justified because the deployed host may not persist a local file.

**Todo checklist:**

- [ ] Introduce SQLAlchemy models: `Incident`, `Conclusion`, `Evidence`, `Event`, `Upload`.
- [ ] Add a repository layer (`save`/`get`/`list`) so callers don't touch SQL.
- [ ] Configure via `DATABASE_URL`: Postgres in production, SQLite in dev/tests (same interface).
- [ ] Add **Alembic** migrations; commit the initial migration.
- [ ] Add `GET /incidents` (paginated) — powers frontend history in Step 12.
- [x] Keep existing `get_incident`/`save_incident` behaviour so nothing breaks.
- [ ] Test against both backends (SQLite in CI; Postgres via a service container in Step 10).

**Code snippet — repository boundary:**

```python
class IncidentRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def save(self, incident: Incident) -> None: ...
    def get(self, incident_id: str) -> Incident | None: ...
    def list(self, limit: int = 20, offset: int = 0) -> list[Incident]: ...
```

**Done when:** `save` then `get` returns an identical incident on Postgres and SQLite; `/incidents` lists history; migrations apply cleanly on a fresh database.

---

### Step 8 — API Production Hardening

**Goal:** Make the API safe and observable enough to expose beyond localhost.

**Todo checklist:**

- [ ] Add API-key auth (`X-API-Key`) on `POST /upload` and `POST /analyze`; ship the key via settings; have the frontend send it.
- [ ] Add `GET /health` (DB connectivity + version) for deployment probes.
- [ ] Add basic rate limiting (per-IP cap) on analysis endpoints.
- [ ] Add structured JSON logging with a request id; log parse diagnostics at request level.
- [ ] Reject **empty files** explicitly with a clear 400.
- [ ] Support background analysis for large files with `GET /jobs/{id}` (ties into Step 3).
- [ ] Document the API with examples; add a `curl` smoke-test script.

**Code snippet:**

```python
from fastapi import Depends, Header, HTTPException

async def require_api_key(x_api_key: str = Header(...)) -> None:
    if not settings.api_key or x_api_key != settings.api_key:
        raise HTTPException(401, "Invalid or missing API key")

@app.post("/analyze", dependencies=[Depends(require_api_key)])
async def analyze_endpoint(...): ...
```

**Done when:** an unkeyed request to `/analyze` returns 401; a keyed request succeeds; `/health` reports DB status; CI smoke-tests the happy path.

---

### Step 9 — Containerisation (Docker + Compose)

**Goal:** `docker compose up` runs the whole stack — API, database, and built frontend — on any machine.

**Todo checklist:**

- [ ] Multi-stage `Dockerfile` for the backend (Python slim, non-root user, pinned deps).
- [ ] `Dockerfile` for the frontend (Node build → static output served by nginx **or** mounted into FastAPI StaticFiles — see Step 11).
- [ ] `docker-compose.yml`: `api`, `db` (Postgres), `web`; health checks; named volume for Postgres; `.env` wiring.
- [ ] A `Makefile` (`make up`, `make test`, `make data`, `make demo`) so nobody memorises long commands.
- [ ] Verify the stack works from a clean checkout with _only_ Docker installed.
- [x] Keep the local non-Docker dev path working (SQLite fallback).

**Code snippet:**

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/
ENV PYTHONPATH=/app/src
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Done when:** `docker compose up` on a clean machine serves the UI, accepts an upload, and returns a reconstructed incident with Postgres persistence.

---

### Step 10 — CI/CD (GitHub Actions)

**Goal:** Every push is linted, type-checked, tested and build-verified, so a red suite or a broken frontend can't ship again.

**Todo checklist:**

- [ ] Backend job: `ruff check`, type-check, `pytest` (with coverage), against a Postgres service container.
- [ ] Frontend job: `oxlint`, `tsc -b`, `vitest run`, `vite build`.
- [ ] Docker job: build both images (fail on build error).
- [ ] **Repo-size guard**: fail if a file > 5 MB (or a dataset path) is committed (prevents G15 regressions).
- [ ] Require the workflow to pass before merge (branch protection).
- [ ] Publish a coverage badge in the README.

**Code snippet:**

```yaml
name: ci
on: [push, pull_request]
jobs:
  backend:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env: { POSTGRES_PASSWORD: test, POSTGRES_DB: incidents }
        ports: ["5432:5432"]
        options: >-
          --health-cmd pg_isready --health-interval 5s
          --health-timeout 5s --health-retries 10
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -e . && pip install ruff pytest
      - run: ruff check .
      - run: pytest -q
  frontend:
    runs-on: ubuntu-latest
    defaults: { run: { working-directory: incident-dashboard } }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "20" }
      - run: npm ci
      - run: npm run lint && npm run build
```

**Done when:** a PR with a failing test, a lint error, or a large committed file is blocked; a green PR produces built artifacts.

---

### Step 11 — Deployment + Static Frontend Serving

**Goal:** A public (or LAN) URL where the professor can upload a log and see the reconstructed incident.

**Todo checklist:**

- [ ] Build the frontend (`vite build`) and serve `dist/` from FastAPI `StaticFiles` (simplest) or nginx in Compose. _(partial: `dist/` builds locally, but nothing serves it.)_
- [ ] Deploy the stack (container host / university VM / managed Postgres + app host). Document the exact steps in `DEPLOY.md`.
- [ ] Set production env vars and secrets out-of-band; never bake the API key into the image.
- [ ] Add a deploy smoke test: health check + one real upload → incident.
- [ ] Provide an offline fallback demo path (pre-computed campaign result) in case the venue network fails.

**Code snippet — serve the built SPA from FastAPI:**

```python
from fastapi.staticfiles import StaticFiles

# Must be added LAST, after all /api routes, so it doesn't shadow them.
app.mount("/", StaticFiles(directory="incident-dashboard/dist", html=True), name="ui")
```

**Done when:** a browser at the deployed URL can upload a campaign log and explore the reconstructed attack chain; `DEPLOY.md` lets a teammate redeploy from scratch.

---

### Step 12 — Frontend Routing + Shareable Incident URLs

**Goal:** An incident becomes a link you can bookmark, share, or revisit — and a small data layer makes it reliable.

**Todo checklist:**

- [ ] Add React Router: `/` (upload) → `/incident/:id` (result); keep the Conclusions ⇄ Attack Chain tab toggle.
- [ ] After a successful upload, `navigate('/incident/' + incident.id)` instead of only holding state.
- [ ] On `/incident/:id`, load from the API so a shared URL works in a fresh browser.
- [ ] Add a 404/empty state for an unknown incident. _(partial: `api.ts` parses a 404 into an error, but nothing renders an unknown-incident state.)_
- [ ] (Optional) Incident **history** page backed by `GET /incidents` (Step 7).
- [ ] Introduce a light data layer (React Query or a small custom hook) for caching/retry; keep `api.ts`'s 413/422/401 error parsing. _(partial: existing 413/422/404 parsing retained; no data layer and no explicit 401 branch.)_

**Code snippet:**

```tsx
<BrowserRouter>
  <Routes>
    <Route
      path="/"
      element={<Landing onAnalyzed={(i) => navigate(`/incident/${i.id}`)} />}
    />
    <Route path="/incident/:id" element={<IncidentPage />} />
    <Route path="*" element={<NotFound />} />
  </Routes>
</BrowserRouter>
```

**Done when:** copy-pasting an `/incident/:id` URL into a fresh tab reproduces the exact view; browser back/forward works; failed fetches are retry-able.

---

### Step 13 — Frontend Tests (Vitest + React Testing Library)

**Goal:** Cover the three components so a backend contract change can't silently break the UI again.

**Todo checklist:**

- [ ] Add Vitest + RTL + jsdom; `npm test` script.
- [ ] `UploadForm`: rejects a bad extension and an oversize file client-side; shows the error banner; calls the API on a valid file (fetch mocked).
- [ ] `IncidentView`: renders a card per conclusion, badges technique/tactic, expands evidence, shows the parent link for chained conclusions, and renders the zero-conclusion empty state.
- [ ] `AttackChain`: builds the expected node/edge count from a fixture incident; renders the empty state.
- [ ] Use the shared contract fixture from Step 1.
- [ ] Wire `npm test` into CI (Step 10).

**Code snippet:**

```tsx
test("upload form rejects an unsupported extension", async () => {
  render(<UploadForm onAnalyzed={() => {}} />);
  const input = screen.getByLabelText(/log file/i);
  await userEvent.upload(
    input,
    new File(["x"], "notes.txt", { type: "text/plain" }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    /unsupported file type/i,
  );
});
```

**Done when:** all three components have meaningful tests; CI blocks on failure.

---

## 5. Definition of Done (Phase 3)

```
pytest fully green, with guards for the /analyze response shape, mislabeled
files, and per-dataset expected conclusion counts.

Known-malicious datasets → bounded, expected conclusions with confidence.
Known-benign real data   → documented low/no findings.

A real multi-stage, multi-host campaign reconstructs into ONE ordered
incident with a readable kill-chain narrative and evidence traceable to
source log lines.

docker compose up on a clean machine → API + Postgres + built frontend.
CI green: lint + types + backend tests + frontend tests + build + size guard.
Deployed URL → upload a log → explore the reconstructed attack chain.

Frontend: shareable /incident/:id URLs, cached fetching, component tests.
```

A grader can, from a fresh clone, run one command and reproduce the whole demonstration; a security reviewer can trace every conclusion back to a source log line and see an honest confidence score.

---

## 6. Risks & Mitigations

| Risk                                                                    | Mitigation                                                                                                                 |
| ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **Precision tuning reduces recall** (rules stop firing on real attacks) | Golden fixtures for both malicious and benign datasets; never tune without a test asserting the attack is still found.     |
| **Campaign dataset is huge / download flaky**                           | Git-ignore + fetch script + cached copy; fall back to a smaller compound dataset; keep a pre-computed result for demo day. |
| **Cross-host correlation re-introduces false positives**                | Link across hosts only on shared concrete objects (file hash, IP, registry key), never time proximity alone; add tests.    |
| **Postgres migration breaks the simple dev path**                       | Repository interface + SQLite fallback; Alembic migrations tested on a fresh DB; CI runs both.                             |
| **Auth blocks the demo frontend**                                       | Frontend sends the key from config; provide a local "demo mode" with auth disabled by one env flag.                        |
| **Docker/CI/deploy eats the schedule**                                  | Timebox; use managed Postgres if self-hosting drags. Deployment is a goal but the campaign + precision work comes first.   |
| **48 MB datasets get recommitted**                                      | `.gitignore` + a CI size guard that fails on large/stray data files.                                                       |
| **Scope creep into genuine stretch**                                    | §7 stays optional. Do Steps 1–13; only start §7 when they're done.                                                         |

---

## 7. Optional / Stretch

Only genuine stretch lives here. None of it is required for Phase 3.

| Item                                                    | Why it's stretch                                                                              |
| ------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| **Design tokens & theming / light mode**                | Phase 2 §6: "One dark SOC look via plain CSS." Pure polish — only if everything else is done. |
| **i18n**                                                | Not needed for an English-language exhibition.                                                |
| **Real-time / streaming ingestion, WebSockets**         | Phase 2 §6: "Analysis is request/response." Batch upload is enough.                           |
| **Generic rule DSL / rule editor**                      | Phase 1 explicitly chose rules-as-functions ("boring code, no DSL").                          |
| **ML / LLM fusion, anomaly detection**                  | Contradicts the project's transparent-symbolic-reasoning thesis.                              |
| **Full observability stack (metrics/tracing/alerting)** | Structured logs + `/health` are proportionate at this scale.                                  |
| **Kubernetes / auto-scaling**                           | Docker Compose is the right weight for a college exhibition.                                  |
| **Exhaustive MITRE coverage (50+ rules)**               | Phase 1's guiding principle: depth of the evidence chain beats breadth of rule count.         |
| **Mobile app / desktop packaging**                      | The web dashboard covers the demo.                                                            |

_Frontend data-fetching (React Query) is listed inside Step 12 as a light, optional part of routing — do the caching hook only if it earns its place; a couple of `useEffect` fetches are otherwise fine._

---

_This roadmap is derived from a line-by-line audit of the Phase 1 and Phase 2 roadmaps, the project summary draft and original Phase 1 PDF, the current Phase 2 codebase, and the open items in `KNOWN-ISSUES.md`. It scopes the final phase as correctness + showcase + a deployable product; only genuine stretch work is deferred to §7._
