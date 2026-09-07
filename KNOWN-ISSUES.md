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

## Resolved by the format-dispatch fix (commits `0cac4ef` / `cd63c58` / `0e29960`)

- **#1 — Real-log parser is never wired into the pipeline (Step 2, also Steps 4/7)** — **FIXED.** `run_analysis` now routes through `dispatch.parse_any_log`, so real `.json`/`.ndjson` datasets parse end-to-end; `POST /analyze` and the CLI return a result instead of a `500` `ParserError`.
- **#8 — `spawned` edges never fire on real data (Step 1 / Step 3)** — **FIXED.** `parse_any_log` adds `ProcessId`/`ParentProcessId` → `pid`/`parentpid` metadata aliases, so SPAWNED edges now appear on real Mordor data.

## Resolved by the real-log hardening fix (commit `f4ef633`)

- **#2 — `/upload` rejects real `.json` datasets (Step 4)** — **FIXED.** Both `/upload` and `/analyze` now accept `.csv`, `.ndjson`, and `.json` (verified: `/upload` on a real `.json` → 200).
- **#3 — Graph edge explosion (Step 2, amplified by Step 5)** — **FIXED.** Fan-out is capped (`MAX_EDGES_PER_NODE_PER_KIND = 50` per node per edge kind). Measured after fix: **1,052 events → 1.5 s / 7 conclusions** (was 18 s / 769); **10,377 events → completes in ~17 s** (was >60 s timeout). Residual: ~17 s is still slow for `/analyze` on the largest dataset, and 641,919 edges is still large — acceptable for the demo, not for production.
- **#4 — New rules don't drive conclusions on real data (Step 5)** — **FIXED (partially).** `C2-BEACON-01` no longer depends on the synthetic `reason="c2"` field; it now heuristically flags outbound connections to non-standard ports and **fires on real data** (7 on psexec, 4 on bitsadmin). `REG-PERSIST-01` now requires a known autostart/persistence registry location, cutting bitsadmin from **66 → 15** conclusions. Residual over-firing: see #13.
- **#5 — `/analyze` doesn't return parse diagnostics (Step 4)** — **FIXED.** `/analyze` now returns `AnalyzeResponse` = `{incident, diagnostics}` with `total_rows`, `skipped`, and a capped (50) `errors` list. ⚠️ But see **#11**: this response-shape change broke the frontend client.

## 🔴 CRITICAL

### 11. `/analyze` response contract changed — committed frontend client breaks (Step 4 / Steps 7–9) — NEW

`f4ef633` changed `/analyze`'s response from the `Incident` directly to `{incident, diagnostics}`, but `incident-dashboard/src/api.ts` (`analyzeCsv`) still does `return (await res.json()) as Incident`. On a successful analysis the frontend now receives the wrapper object and treats it as an `Incident` — `incident.conclusions` is `undefined`, so `ResultView`'s `conclusions.reduce(...)` crashes. Verified against the committed frontend (commit `d918b70`): **any successful upload breaks the dashboard**. `getIncident` is unaffected (that endpoint still returns the raw `Incident`).

## 🟠 HIGH

### 12. Test suite is red after the rule change (Step 5) — NEW

`f4ef633` narrowed `REG-PERSIST-01` to persistence-relevant registry keys but did not update the existing rule tests. `tests/test_rules.py::test_reg_persist_window_boundary_is_inclusive` now fails because the fixture's registry target is a bare event id, not an autostart key — **1 failed, 75 passed**. The rule-behavior change needs its fixtures updated (e.g. a `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\...` target) or the allowlist needs to stay test-compatible.

### 9. Silent zero-event misdetection on extension-only routing (Step 4 / Step 1)

`detect_format` routes purely by file extension (`.json`/`.ndjson` → `parse_mordor`) with no content validation, so any non-NDJSON file named `.json`/`.ndjson` is sent to `parse_mordor` and silently yields **0 events** instead of raising a clear error. Verified: a valid CSV renamed `attack_sample.json` parses to 0 events / 19 "malformed" and returns a successful-looking empty Incident. Because `/analyze` returns an empty `errors` list for this case (nothing was "malformed" from the caller's view), the user sees "Analyzed 0 events, 0 conclusions" with no indication the wrong parser ran. The content-sniffing fallback only runs for unknown extensions, so it never catches this case.

## 🟡 MEDIUM

### 13. C2-BEACON-01 heuristic still over-fires on real data (Step 5) — NEW

The port-based heuristic (any outbound connection to a non-common port after a process execution) is loose. On the `cmd_wevtutil_modify_security_eventlog_path.json` dataset — whose only attack is a single `wevtutil` log clear — the pipeline still reports **9 `C2-BEACON-01` + 25 `REG-PERSIST-01` = 34 conclusions**, almost none of which reflect the dataset's actual action. `REG-PERSIST-01` likewise still produces **15 conclusions on the 89-event bitsadmin file**. The rules fire on real data now (improvement over #4) but are far from precise; Step 5's "network + log-deletion events actually drive conclusions" is met in quantity, not quality.

### 6. Missing `src/data/mordor/README.md` (Step 2)

Step 2's checklist and done-when require a README documenting the datasets + license (MIT). The directory has data but no README.

### 7. ~48 MB of real datasets committed to git (Step 2)

The roadmap says mordor data should be git-ignored (except `.gitkeep`); the team reversed that and committed the actual files, including a 48 MB `cmd_wevtutil_modify_security_eventlog_path.json`. Repo bloat + deviation (not a functional bug).

### 10. Regression tests don't cover misdetection or scale (Step 4 / Step 2)

`test_dispatch.py` only asserts happy-path routing on a known-good `.json` dataset and a missing-file error. There is no test for a mislabeled file (a CSV named `.json`, or a `.json` that isn't NDJSON) — so the silent zero-event path (#9) ships unguarded — and it only exercises the tiny bitsadmin dataset (89 events), so the scale problem (#3) and the new rule-noise regression (#13) are never caught. Additionally, no test asserts the new `AnalyzeResponse` shape, which is why #11 slipped through.

## Minor (setup / hygiene)

- **venv under-provisioned (Steps 2–3):** `matplotlib`/`scipy` are in `requirements.txt` but missing from the venv, so tests fail to even collect until installed.
- **Stale KNOWN-ISSUES header (chore):** the top of this file still describes Phase 1 "Steps 1–8" and the 🔴 critical section still claims the critical path is unimplemented, which is no longer true.
- **Stale comment in `graph.py` (cosmetic):** the `followed_by` cap comment says "keep scanning (via `continue`, not `break` on the cap)" but the code uses `break` — behavior is correct either way, the comment is misleading.
