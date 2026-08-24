# KNOWN ISSUES — Phase 1 (Steps 1–4)

Scope: this document audits the current project against the requirements in `reference/phase_1_roadmap.md`, Steps 1 through 4 only (Project Setup → Data Contracts → Sample Data → Log Parser).

Ground rules used for this audit:

- The code blocks in the roadmap are **templates, not correct code**. They are treated as _intent_ only. An issue is logged when the project fails to satisfy the _stated requirement_ (the todo checklist and the "done when" criteria), not merely because the code differs stylistically from the snippet.
- Several roadmap snippets contain latent bugs (e.g. using `eval()`, sorting before assigning row provenance). Where the roadmap snippet is itself wrong, the project is _not_ penalised for matching it — but it _is_ penalised if it reproduces the same bug instead of implementing the correct behaviour the requirement describes.
- Issues are numbered linearly from Step 1 to Step 4, smallest/riskiest included, with a written-language fix (no code).

---

## Step 1 — Project Setup

### 1. Logging is never actually configured

The requirement: "Set up Python logging (to console + `app.log`), not `print()`."

What is wrong:

- `src/app/parser.py` correctly uses `logging.getLogger("incident")` and calls `log.info()`, `log.warning()`, `log.error()` — but **nobody in the project ever calls `logging.basicConfig()`** (or any equivalent handler setup).
- Because no configuration exists, Python falls back to its default "last resort" behaviour: only messages at `WARNING` level or above reach stderr, with a bare format and no timestamps.
- The direct consequence is that every `log.info(...)` line in the parser (e.g. the "Parsed N events, skipped M" summary) is **silently swallowed**. There is also **no `app.log` file ever created**, which is an explicit Step 1 deliverable.
- This will get worse in Steps 8 and 10: when the orchestrator and FastAPI app run, their info/warning logs will also be invisible or inconsistent, and you will not be able to debug the pipeline from a log file.

How to fix:

- Add one `logging.basicConfig(...)` call in `src/app/__init__.py` so it runs exactly once, before any other module logs, and covers every entrypoint (CLI, FastAPI, pytest).
- Configure it with level `INFO`, a format that includes the timestamp, level, and logger name, and two handlers: a stream handler (console) and a file handler writing to `app.log`.
- Add `encoding="utf-8"` to the file handler so Windows-style paths in log messages (like `C:\temp\invoice.exe`) don't raise encoding errors.
- Note that `app.log` will be created in the current working directory and appends across runs — that is fine, and `.gitignore` already excludes `*.log`, so it won't be committed.
- Do **not** put the `basicConfig` call inside `parser.py`; keep it in one central place so it is not duplicated and cannot be missed.

### 2. No README.md

The requirement: "Add a `README.md` with a one-paragraph project description + run instructions."

What is wrong:

- There is no `README.md` anywhere in the project (only unrelated ones inside `.opencode/node_modules`).
- This was previously acknowledged and deferred, but it remains an incomplete Step 1 checklist item.

How to fix:

- Create a `README.md` at the project root with a one-paragraph description of the incident-reconstruction system and the symbolic-AI approach.
- Add a short "run instructions" section covering: create the venv, install `requirements.txt`, run the test suite, and (once Steps 8–10 exist) how to run the CLI and the API.

### 3. `src/` layout has no packaging configuration

The requirement: a reproducible project structure where imports and entrypoints work consistently.

What is wrong:

- The project uses a `src/` layout (code lives under `src/app/`, tests under `src/tests/`), which is a reasonable choice, but there is **no `pyproject.toml`, `setup.py`, or `setup.cfg`** to make the package installable.
- All imports use the form `from src.app.models import ...`, which only works when the _project root_ happens to be on `sys.path`.
- Right now the tests pass only because the empty `conftest.py` at the root tricks pytest into inserting the root directory onto the import path. That is an accidental, undocumented behaviour, not an intentional configuration.
- This **will break later**: Step 8's CLI (`python -m app.orchestrator ...`) and Step 10's FastAPI server (`uvicorn app.main:app`) expect the `app` package to be importable. As written, those commands cannot resolve `app` because it lives under `src/` and nothing installs it.

How to fix:

- Add a minimal `pyproject.toml` that declares the package with a `src/` layout (package root `src`, packages `app` and `app.rules`), and install the project in editable mode into the venv.
- Alternatively, add an explicit pytest import-path setting (a `pythonpath` option in the pytest config) so tests don't rely on the empty `conftest.py`.
- Decide on one import style and keep it consistent — either installable-package imports (`from app.models import ...` after `pip install -e .`) or explicit `src.` prefixed imports with a documented path assumption.
- Document in the README how to install and run so nobody else hits "module not found".

### 4. requirements.txt is an uncurated freeze with bleeding-edge pins

The requirement: "Create `requirements.txt` with pinned versions" (illustrative top-level list: fastapi, uvicorn, pydantic, pandas, networkx, pytest).

What is wrong:

- The file is a full `pip freeze` dump: it mixes direct dependencies (`fastapi`, `pandas`, `networkx`, `pydantic`, `pytest`) with transitive ones (`anyio`, `idna`, `annotated-types`, `sniffio`-style packages, `colorama`, `Pygments`, etc.) that your code never imports directly.
- This makes the file noisy and hard to maintain: it is unclear which packages are intentional and which are incidental.
- The pinned versions are very new and carry upgrade risk: `pandas==3.0.5` (a major-version bump with breaking behaviour changes vs the 2.x line the roadmap examples assume), `numpy==2.5.2`, and a Python 3.14 runtime. The roadmap specifies Python 3.11+; while 3.14 technically satisfies "3.11+", the pinned library stack is far ahead of what the roadmap's snippets and the team's likely environment assume.
- There is a real risk that a teammate on Python 3.11/3.12 cannot reproduce this environment, or that pandas 3.x introduces subtle behaviour differences (e.g. copy-on-write semantics, removed APIs) that only surface in later steps.

How to fix:

- Replace the freeze dump with a short, curated list of the direct dependencies only, each pinned with `==`.
- Freeze transitive dependencies separately if reproducibility is critical (e.g. a `requirements.lock` or a `pip freeze` snapshot kept out of the main file), but keep the main file readable.
- Agree as a team on a target Python version and library major versions, and pin to those (e.g. stay on a stable pandas 2.x line unless you intentionally adopt pandas 3).
- Verify with a clean install on at least one teammate's machine that `import fastapi, pandas, networkx, pydantic` succeeds on the agreed Python version.

### 5. Several modules are empty stubs (tracking note, not yet a defect)

What is wrong:

- `main.py`, `orchestrator.py`, `storage.py`, `engine.py`, `rules/__init__.py`, and `rules/registry.py` are all empty, and `graph.py` holds only a single constant.
- These are Steps 5–10 deliverables, so being empty is expected at this stage. This is logged only so the gaps are visible and tracked.

How to fix:

- No action now beyond continuing the roadmap in order; the empty files are the intended placeholders.
- Note that `graph.py` currently contains `TIME_WINDOW_MINUTES`, which actually belongs in the contracts module (see issue 6).

---

## Step 2 — Data Contracts

### 6. The time-window constant lives in the wrong file

The requirement: define the edge-type vocabulary and the default time window in Step 2, as part of the data contracts.

What is wrong:

- `TIME_WINDOW_MINUTES = 5` is declared in `src/app/graph.py`, which is a Step 5 module.
- The roadmap explicitly puts the time window in the contracts step, alongside the edge vocabulary, because both the graph builder (Step 5) and the rules (Step 6) need to reference the _same_ constant. Scattering it into a later-stage file means the contract and its consumer are split across steps.

How to fix:

- Move the constant into `src/app/models.py` (or a dedicated small constants section/module within the contracts).
- Keep it as a single source of truth so `graph.py` and the rules import it from the contracts, rather than re-defining their own copy (duplicated constants are how the ±5-minute window silently drifts between components).

### 7. The edge-type vocabulary is not defined anywhere

The requirement: "Define edge-type vocabulary" in Step 2 — `followed_by`, `spawned`, `same_object` (and explicitly _not_ `same_user`/`same_host` as edges).

What is wrong:

- Only the time window exists; there is **no definition of the edge types** anywhere in the codebase.
- The decision to keep edges to exactly three types (to avoid clique explosion) and to keep user/host as rule-matchable fields rather than edges is a documented anti-risk measure in the roadmap — but nothing in the code records that decision.

How to fix:

- Define the three edge types as a typed vocabulary (e.g. an enum or a frozen set of allowed strings) in the contracts module.
- Add a short comment capturing the rule: only `followed_by`, `spawned`, and `same_object` may become edges; user and host stay as fields to be matched by rules, never as edges.
- This vocabulary will be imported by the graph builder in Step 5, so defining it now prevents ad-hoc edge strings later.

### 8. The demo rules are not even named

The requirement: in Step 2, **name** (not yet write) two-to-three demo rules with a one-line intent: `REG-PERSIST-01`, `PSH-STAGING-01`, `PERSIST-ESTABLISHED-01`.

What is wrong:

- `rules/registry.py` and `rules/__init__.py` are both empty. The rule IDs, their intent, and the crucial two-level chained rule (`PERSIST-ESTABLISHED-01`) are not recorded anywhere.
- This matters because the chained rule is what proves forward chaining works (the core thesis). If the names aren't fixed now, Step 3's sample data can't be designed to trigger them, and Step 6 has no agreed target.

How to fix:

- Record the three rule IDs and one-line intents in the rules module (or the contracts documentation), exactly as specified.
- Make explicit which rule is the two-level chained one, and that it consumes the output of the other two.

### 9. The provenance scheme is not documented as a contract

The requirement: define `event_id = "{source_file}:{row_number}"` as the provenance scheme in Step 2.

What is wrong:

- The `event_id` format is implemented inside `parser.py` (Step 4) but is never stated as a contract.
- Because it isn't documented, nothing pins down the guarantee that every `event_id` maps back to a unique source line — and (see issue 17) the current implementation actually breaks that guarantee, so the absence of a stated contract hides the defect.

How to fix:

- Document the provenance scheme in the contracts step: every event gets a stable ID built from the source file plus the original row number, assigned once at parse time and never changed.
- State explicitly that the ID must reference the _source_ row, not a re-sorted position.

### 10. Output models have no construction/validation tests

The requirement: "Write a unit test that constructs an `Event` from a dict and validates it" — and, more broadly, all output models should be defined and testable.

What is wrong:

- `test_models.py` only constructs and validates `Event`. There is no test that constructs `Evidence`, `Conclusion`, or `Incident`, even though these are the actual _output_ contracts the whole pipeline exists to produce.
- The `Conclusion` and `Evidence` models include a nullable field (`parent_conclusion_id`) and a nested-list relationship (evidence inside conclusion) that are exactly the kind of structure most likely to have a mistake — and they are currently unverified.

How to fix:

- Extend the models test to construct a full `Incident` containing a `Conclusion` that contains `Evidence`, including a case where `parent_conclusion_id` is `None` and a case where it is set (for derived/chained facts).
- Assert the nested structure round-trips (serialise to a dict and back, or just validate the field values).

---

## Step 3 — Sample Data

### 11. attack_sample.csv is far below the target size

The requirement: "~15–20 rows forming a mini attack chain that triggers all 3 demo rules."

What is wrong:

- `src/data/attack_sample.csv` contains only **6 data rows** (plus the header).
- The content is directionally correct — it includes all seven event types in the right narrative order (download → file creation → process execution → powershell → registry modification → network connection → log deletion), and the timestamps are within the 5-minute window so the rules would fire. But 6 rows is well under the 15–20 target and does not exercise the "multiple events per stage" scenario the roadmap calls for.

How to fix:

- Expand the file to 15–20 rows while keeping the same attack narrative, adding extra events per stage (e.g. multiple registry modifications, an additional network connection, a second file creation, more process executions).
- Keep every row's `event_type` within the seven defined types and keep the whole chain inside the time window so all three demo rules still trigger.

### 12. benign_sample.csv is far below the target size and too weak a negative case

The requirement: "~10 rows of normal activity that should trigger zero conclusions (the negative case)."

What is wrong:

- `src/data/benign_sample.csv` contains only **2 data rows** (plus the header), covering just three event types (process execution, network connection, file creation).
- Two rows is a trivially weak negative case: it does not stress the rules at all. A good negative case should contain _plausibly suspicious-looking but legitimate_ activity — e.g. a PowerShell run that is _not_ followed by a download, or a registry change that is _not_ preceded by a process execution within the window — to prove the rules don't over-fire.
- With only two rows, if a rule has a subtle bug (e.g. firing on any lone process execution), the negative test would still pass and the bug would be missed.

How to fix:

- Expand the file to ~10 rows using normal, non-malicious activity.
- Deliberately include near-miss cases: a powershell event with no download nearby, a registry modification with no process execution in the window, a network connection to a benign IP, etc.
- Keep the events spread out or otherwise outside the rule conditions so the expected result is genuinely zero conclusions.

### 13. No data/README.md documenting the attack narrative

The requirement: "Document the expected attack narrative in a `data/README.md`."

What is wrong:

- There is no `README.md` (or any narrative file) inside the `data` directory.

How to fix:

- Add a `data/README.md` describing the intended attack story that `attack_sample.csv` encodes (who, what, in what order, and which rule each stage is meant to trigger), and what `benign_sample.csv` represents.
- Also describe the CSV column schema and the metadata conventions so future contributors can extend the data without guessing.

### 14. Mordor datasets have not been downloaded

The requirement: "Download 3–5 Mordor atomic datasets into `data/mordor/` for later real-data testing."

What is wrong:

- No `data/mordor/` directory exists and no datasets have been fetched.

How to fix:

- Create `src/data/mordor/` (or `data/mordor/`, matching the project's chosen data location) and download 3–5 atomic Windows datasets that together cover the seven event types: a PowerShell dataset, a registry dataset, a wevtutil log-deletion dataset, a bitsadmin file-download dataset, and a network (Sysmon EventID 3) dataset.
- Track which dataset maps to which event type so Step 4's NDJSON stretch-parser has concrete inputs to target.
- Keep the datasets out of version control (they are large and re-downloadable) — add them to `.gitignore` if needed.

---

## Step 4 — Log Parser

### 15. parse_log silently returns an empty list on unreadable files

The requirement: a bad-row policy that skips and counts malformed rows, but preserves a clear, observable pipeline.

What is wrong:

- `parse_log` wraps `pd.read_csv` in a try/except and returns an empty list on any read failure, logging only an error (which — see issue 1 — currently isn't even visible because logging isn't configured).
- The caller (the orchestrator in Step 8) cannot distinguish "file contained zero valid events" from "file failed to open entirely". A missing or unreadable input would silently produce an empty `Incident` with no error surface, which is a dangerous failure mode for a security tool (a "no findings" result could be caused by a botched parse rather than benign data).

How to fix:

- Do not swallow a file-read failure. Either raise the exception so the caller knows the input was bad, or return a result object that carries an explicit error state.
- Reserve the "empty events" return value strictly for the case where the file was read successfully but contained no valid rows.

### 16. The skip count is not returned

The requirement: "Implement bad-row policy: skip malformed rows, count them, return count in a `ParseResult`."

What is wrong:

- The `skipped` counter is computed but only written to the log; it is never returned. The function signature is just `parse_log(...) -> list[Event]`.
- The roadmap explicitly requires a `ParseResult` (events + skip count) so the caller can surface data-quality information. As written, that information is lost to the orchestrator and cannot be asserted in tests.
- This also makes the "bad rows skipped _and counted_" part of the "done when" criterion untestable.

How to fix:

- Return a result structure (e.g. a small dataclass or Pydantic model) that holds both the parsed events and the skip count.
- Update the parser test to assert both the number of valid events and the number of skipped rows.

### 17. event_id uses the post-sort index, breaking provenance

The requirement: `event_id = "{source_file}:{row_number}"`, assigned at parse time, and every piece of evidence must trace back to a source event. The roadmap snippet sorts first and then indexes — but that snippet is a template and this is exactly the kind of latent bug to correct, not copy.

What is wrong:

- The parser sorts the dataframe by timestamp and resets the index _before_ building `event_id`, then uses that re-sorted position (`f"{file_path}:{index}"`) as the "row number".
- As a result, the `event_id` no longer points to the physical line in the source file. If the input CSV is not already chronologically sorted (which is the norm for real logs and for Mordor data), `attack_sample.csv:0` will not be line 0 of the file.
- This breaks the project's core thesis — "every conclusion must trace back to source evidence". Provenance IDs that silently shift when data is out of order are a subtle, project-fatal defect.

How to fix:

- Capture the _original_ row position before sorting, and build `event_id` from that original position.
- Sort events (for downstream time-window logic) _after_ provenance IDs are assigned, so sorting never mutates the ID-to-source mapping.
- Add a test where the input is deliberately out of chronological order and assert that each event's `event_id` still maps to its correct source line, while the returned list is sorted.

### 18. Timestamps are not normalised to UTC

The requirement: "Convert timestamps to UTC `datetime`; sort events chronologically."

What is wrong:

- The parser calls `datetime.fromisoformat(...)` on the raw string but does **not** normalise to UTC. A value ending in `Z` parses as a timezone-aware UTC datetime; a value without a suffix parses as a naive datetime.
- The code sorts the _string_ column before parsing, which only works because the sample data happens to use a fixed-width ISO format. It is lexicographic sorting, not chronological sorting, and will silently misorder any non-uniform timestamp format.
- Mixing aware and naive datetimes will later raise a `TypeError` when the graph builder compares timestamps (`b.timestamp - a.timestamp`), which is a guaranteed crash the moment one row has a different timezone style than another.

How to fix:

- Parse timestamps to `datetime` first, then normalise them to a single timezone (UTC) — converting naive values to UTC and aware values via `.astimezone(UTC)`.
- Sort on the _parsed datetime values_, not the raw string column.
- Add a test with mixed/offset timestamps (e.g. one with `Z`, one with a `+05:30` offset, one naive) and assert all events end up UTC-normalised and correctly ordered.

### 19. Metadata parse failures silently blank the field

The requirement: a clear bad-row policy for malformed rows.

What is wrong:

- When the `metadata` string cannot be parsed, the code swallows the error and substitutes an empty dict (`{}`), and the row is **not** counted as skipped.
- This silently discards evidence: a corrupt metadata field (e.g. a command line or parent-pid that a rule would later need) is erased without any signal, and the row still produces a valid-looking `Event`.
- For a system whose entire point is evidence trace-back, silently dropping metadata while presenting the event as fine is dangerous.

How to fix:

- Decide and document the policy explicitly: either treat an unparseable metadata field as a malformed row (skip and count it), or keep the row but record the parse failure in the result so it is visible.
- Do not silently convert corrupt metadata to `{}` without any signal to the caller.

### 20. Missing/NaN fields are coerced to the literal string "nan"

The requirement: a robust bad-row policy.

What is wrong:

- `source`, `actor`, and `target` are forced through `str(...)`. If a cell is empty or NaN, `str(nan)` produces the literal string `"nan"`.
- This means a row with a missing actor silently becomes a valid event with `actor="nan"`, rather than being flagged as malformed. Downstream rules comparing actors will treat `"nan"` as a real actor name.

How to fix:

- Explicitly check for missing/NaN values in required fields (`source`, `actor`, `target`, `event_type`, `timestamp`) and treat their absence as a malformed row (skip + count).
- Only coerce a value to string when it is actually present.

### 21. ast.literal_eval will break on JSON-style metadata (Mordor forward-compat)

The requirement: parse metadata and, later, handle Mordor NDJSON whose `Message` blob holds structured detail.

What is wrong:

- The parser uses `ast.literal_eval` to parse metadata strings. That is safe and _correct_ for Python-literal syntax (single or double quotes, `None`/`True`/`False`) — and it is a genuine improvement over the roadmap snippet's unsafe `eval()`.
- However, `ast.literal_eval` does **not** understand JSON keywords: `null`, `true`, `false` (lowercase). Mordor NDJSON and most modern tooling emit JSON, not Python literals. The moment real data uses JSON booleans/null, this parser will silently blank the metadata (per issue 19) or fail.

How to fix:

- Standardise on one metadata serialisation. If the sample CSVs stay in Python-literal format, keep `ast.literal_eval` but note the constraint; if real/Mordor data is JSON, switch to a JSON decoder (`json.loads`).
- Better: attempt JSON parsing first, fall back to `ast.literal_eval`, and treat a total failure as a malformed row rather than blanking it.
- Document the chosen metadata format in the data README so sample and real data stay consistent.

### 22. Parser test coverage has gaps

The requirement: "10 valid rows → 10 Events; bad rows skipped + counted; events sorted by timestamp."

What is wrong:

- `test_parser.py` tests only 2 valid rows + 1 bad row, asserts the event count and one `event_id`, and one metadata field.
- It does not test: chronological sorting of out-of-order input, the skip _count_ (impossible currently, see issue 16), timezone/UTC normalisation (issue 18), provenance mapping for unsorted input (issue 17), or the empty-file / unreadable-file behaviour (issue 15).
- As a result, every defect above would pass the current test suite undetected.

How to fix:

- Add test cases for: a file whose rows are out of chronological order; a file with a known number of malformed rows (assert both events and skip count); timestamps with mixed timezone formats; a row with missing required fields; and an unreadable/nonexistent path.
- Update assertions once the parser returns a `ParseResult` (issue 16) and normalises timestamps (issue 18).

---

## Summary of priority

Highest risk (will silently break the core thesis or later steps):

- Issue 17 (provenance IDs drift on sort)
- Issue 15 (silent empty result on read failure)
- Issue 3 (src layout un-installable → CLI/FastAPI fail)
- Issue 1 (logging invisible)

Medium risk (incomplete deliverables or weak tests):

- Issues 6, 7, 8, 9 (contracts not fully defined/named)
- Issues 11, 12, 13, 14 (sample data incomplete)
- Issues 16, 18, 19, 20, 21, 22 (parser robustness and coverage)

Low risk / deferred:

- Issues 2, 4, 5 (README, dependency hygiene, empty stubs)
