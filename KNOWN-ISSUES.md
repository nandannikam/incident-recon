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
