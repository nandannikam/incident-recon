# KNOWN ISSUES — Phase 1 (Steps 1–8)

Scope: remaining open issues for the current scope — **Steps 1–8** (per `reference/phase_1_roadmap.md` §2.5 "Current Status"). Steps 9–11 are bonus/skip. All Step 1–4 defects that have been fixed are removed from this file; only what still matters is listed below, ordered by importance.

> ## ⚠️ Setup — every team member must run this ONCE
>
> After cloning the repo / creating the venv, run:
>
> ```
> .venv/bin/python -m pip install -e .
> ```
>
> The package is installed _editable_ into the local venv only — it is **not** committed to git. Without this, `import app` and `python -m app.orchestrator …` fail with `ModuleNotFoundError: No module named 'app'`. Passing `pytest` is **not** proof this is done, because pytest uses a separate `pythonpath` shim in `pyproject.toml`.

---

## 🔴 CRITICAL

### 1. Steps 5–8 — the entire critical path is unimplemented

The must-do work from §2.5 is still empty. The Step 8 demo cannot run until all four exist:

- `src/app/graph.py` — `build_graph(events) -> nx.DiGraph` (nodes + `followed_by`/`spawned`/`same_object` edges).
- `src/app/rules/registry.py` — 3 rule functions: `REG-PERSIST-01`, `PSH-STAGING-01`, chained `PERSIST-ESTABLISHED-01` (intents are already named in `models.py`).
- `src/app/engine.py` — `analyze(graph, rules)` forward-chaining loop with dedup + max-iteration cap.
- `src/app/orchestrator.py` — `run_analysis(file_path)` + the `python -m app.orchestrator …` CLI entrypoint.

## 🟠 HIGH

### 2. `requirements.txt` is still an uncurated `pip freeze` dump with bleeding-edge pins

- It lists transitive dependencies and pins `pandas==3.0.5`, `fastapi==0.141.1`, `starlette==1.6.0`, on a Python 3.14 venv — far ahead of the roadmap's "Python 3.11+, stable pandas 2.x" assumptions.
- pandas 3.x has breaking behaviour vs the 2.x line the templates assume; a teammate on 3.11/3.12 may not reproduce this environment.
- `uvicorn` and `python-multipart` are missing from **both** `requirements.txt` and `pyproject.toml` — only needed if the bonus Step 10 (FastAPI) is attempted.

**Fix:** curate `requirements.txt` to direct dependencies only, pin to a stable pandas 2.x line, and (only if doing Step 10) add `uvicorn[standard]` and `python-multipart`.

## 🟡 MEDIUM — traps for Steps 5–8

### 3. `parse_log` returns `ParseResult`, not `list[Event]`

The Step 8 template does `events = parse_log(file_path)`, but your parser returns a `ParseResult` dataclass. `run_analysis` must unpack it:

```
result = parse_log(path)      # result.events, result.skipped, result.total_rows, result.errors
events = result.events
```

Copying the template verbatim will pass a `ParseResult` into `build_graph` and crash.

### 4. The chained rule has no access to prior conclusions

`PERSIST-ESTABLISHED-01` must consume `PSH-STAGING-01`'s conclusion, but the Step 7 `analyze()` template calls `rule(neighborhood, graph)` and never passes the current fact set. Either add a `facts`/`conclusions` parameter to the rule functions, or run chained rules in a second pass that feeds prior conclusions back. Without this, the two-level chain — the project's core thesis — cannot be implemented.

### 5. `followed_by` edge density (clique risk)

All 18 attack events sit within ~3.5 minutes, so "add an edge between every pair within 5 minutes" produces a near-complete clique. Fine at demo scale, but the engine's graph-local matching + dedup must be built with that in mind, or you'll get duplicate/spurious conclusions (the roadmap already flags this as the "edge explosion" risk).

---

## Removed as fixed (no longer tracked)

All Step 1–4 defects are resolved: logging configuration (#1), `src`-layout packaging (#3), time-window/edge-vocabulary/provenance/demo-rule contracts (#6–#9), output-model tests (#10), sample-data sizes (#11–#12), and the entire parser robustness set — silent read failure, missing `ParseResult`, provenance drift, UTC normalisation, metadata blanking, `"nan"` coercion, JSON metadata, and test coverage (#15–#22).

## Deliberately ignored (per §2.5 "Skip")

README polish, `data/README.md`, Mordor dataset downloads, the formal E2E test file, and lint/type-checker warnings (`RUF100` unused `noqa`, `UP042`, no `[tool.ruff]` config).

---

# KNOWN ISSUES — Phase 2 (Steps 1–5)

Found via an independent audit of the Phase 2 backend (see `reference/phase_2_roadmap.md`). Ordered by importance; each issue notes the Phase 2 step it originates from. Step references are to the roadmap's step numbering (1 = Mordor parser, 2 = real dataset integration, 3 = graph viz, 4 = API hardening, 5 = knowledge-base expansion).

## 🔴 CRITICAL

### 1. Real-log parser is never wired into the pipeline (Step 2, also Steps 4/7)

`parse_mordor` is only called by the standalone `validate_mordor_dataset.py`. The main path (`run_analysis` → `parse_log`) is CSV-only, so:
- `python -m app.orchestrator <real dataset.json>` crashes with a pandas `ParserError`.
- `POST /analyze` with a real NDJSON log → **500 Internal Server Error** (unhandled exception).
- Step 2's "done when" — *at least one real dataset runs through `run_analysis` without crashing* — is **not met**. Real data only works in the validator, not the pipeline.

### 2. Real `.json` datasets can't be uploaded or analyzed (Step 4)

`POST /upload` accepts only `.csv`/`.ndjson`, but every actual Mordor dataset ends in `.json` → **400 "Only .csv or .ndjson files are accepted"**. `/analyze` has no file-type/format dispatch and no type validation, so it accepts `.json`/`.ndjson` but then crashes (see #1). Net effect: neither endpoint can process the real datasets.

## 🟠 HIGH

### 3. Graph edge explosion — pipeline can't scale to real logs (Step 2, amplified by Step 5)

`followed_by` (all in-window pairs) + `same_object` (cliques) produce combinatorial edges on dense real captures. Measured: **1,052 events → 1,105,652 edges** (4.2 s just to build); **10,377 events → `build_graph` times out (>60 s)** and `analyze` would be far worse. Already flagged as Phase 1 KNOWN-ISSUES #5, but only "at demo scale" — on real data this blocks the Step 2 end-to-end goal.

### 4. New rules don't actually drive conclusions on real data (Step 5)

- `C2-BEACON-01` (network) requires `metadata["reason"]` to contain `"c2"` — real Sysmon network events have no such field, so it **never fires on real data** (only on the hand-crafted CSV with a synthetic `reason=c2`). On the real bitsadmin dataset it produced **0** C2 conclusions.
- `PERSIST-ESTABLISHED-01` needs PSH-STAGING first (PowerShell + file_download), which the chosen datasets don't trigger.
- `REG-PERSIST-01` over-fires: **66 conclusions from 89 events** on the bitsadmin dataset (noise). Step 5's "done when" (network + log-deletion events actually drive conclusions on real data) is not met.

## 🟡 MEDIUM

### 5. `/analyze` doesn't return parse diagnostics (Step 4)

Step 4's checklist explicitly asked for skipped-rows/errors in the `/analyze` response; it returns only the `Incident` (`response_model=Incident`).

### 6. Missing `src/data/mordor/README.md` (Step 2)

Step 2's checklist and done-when require a README documenting the datasets + license (MIT). The directory has data but no README.

### 7. ~48 MB of real datasets committed to git (Step 2)

The roadmap says mordor data should be git-ignored (except `.gitkeep`); the team reversed that and committed the actual files, including a 48 MB `cmd_wevtutil_modify_security_eventlog_path.json`. Repo bloat + deviation (not a functional bug).

### 8. `spawned` edges never fire on real data (Step 1 / Step 3)

`graph.py` reads lowercase `metadata["pid"]`/`["parentpid"]`, but Sysmon/Mordor metadata uses `ProcessId`/`ParentProcessId` (capitalized) — so no SPAWNED edges from real logs. Works on `attack_sample.csv` because its CSV metadata uses lowercase pid keys.

## Minor (setup / hygiene)

- **venv under-provisioned (Steps 2–3):** `matplotlib`/`scipy` are in `requirements.txt` but missing from the venv, so tests fail to even collect until installed.
- **Stale KNOWN-ISSUES header (chore):** the top of this file still describes Phase 1 "Steps 1–8" and the 🔴 critical section still claims the critical path is unimplemented, which is no longer true.
