# Mordor / OTRF datasets

Real Windows (Sysmon + Windows Event Log) captures from adversary-technique
simulations, used to prove the pipeline works on real logs, not just on the
hand-written `attack_sample.csv`.

- **Source:** https://github.com/OTRF/Security-Datasets (docs: https://securitydatasets.com)
- **License:** MIT -- Copyright (c) 2021 Open Threat Research Forge.
  Cite as: *OTRF Security-Datasets (Mordor)*.
- **Format:** newline-delimited JSON (one event per line), saved with a `.json`
  extension. The parser is `app/mordor_parser.py`; the format is detected by
  content, not by extension (`app/dispatch.py`).
- **MITRE technique / tactic labels** for each dataset are in the dataset's own
  metadata YAML in the OTRF repository; they are intentionally not copied here.

## Atomic datasets in this folder

Counts below are **events kept by `parse_mordor`**, per our 7 event types.
Everything else in a capture (process exit, image load, handle access, WFP
filtering ...) has no mapping on purpose and is counted as *skipped*
(`unmapped EventID`). Regenerate with
`python -m app.validate_mordor_dataset src/data/mordor`.

| Dataset | Lines | Kept | Skipped | process_execution | file_download | file_creation | registry_modification | network_connection | powershell_execution | log_deletion |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `cmd_bitsadmin_download_psh_script_2020-10-2302365189` | 424 | 89 | 335 | 4 | 1 | 5 | 70 | 8 | 0 | 1 |
| `cmd_wevtutil_modify_security_eventlog_path` | 25,208 | 10,377 | 14,831 | 38 | 0 | 318 | 9,909 | 112 | 0 | 0 |
| `empire_persistence_registry_modification_run_keys_elevated_user_2020-07-22001847` | 657 | 80 | 577 | 0 | 0 | 2 | 32 | 46 | 0 | 0 |
| `empire_psexec_dcerpc_tcp_svcctl_2020-09-20121608` | 4,348 | 1,052 | 3,296 | 13 | 0 | 25 | 1,005 | 8 | 1 | 0 |
| `psh_powershell_httplistener_2020-11-0204130683` | 110 | 29 | 81 | 0 | 0 | 0 | 28 | 0 | 0 | 1 |

All seven event types are covered across the folder. Two things worth knowing:

- Registry events (Sysmon 12/13/14) dominate every capture, so a dataset's
  "interesting" events are a small fraction of what is kept.
- `process_execution` is rare in several datasets; `test_dispatch.py` therefore
  discovers a dataset with 2+ process events instead of assuming one by name.

## Campaign dataset (APT29 Day 1)

A multi-host, multi-stage capture used for the incident-reconstruction showcase.

- Download (13.9 MB zip, ~385 MB once extracted):
  `https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip`
- Extract with `python -m zipfile -e apt29_evals_day1_manual.zip src/data/mordor/`
  (produces `apt29_evals_day1_manual_2020-05-01225525.json`).

Parsing (`parse_any_log`, includes host/IP/hash normalisation): 9 s, ~570 MB peak.

| Lines | Kept | Skipped | Hosts | process_execution | file_creation | registry_modification | network_connection | powershell_execution |
|---:|---:|---:|---|---:|---:|---:|---:|---:|
| 196,081 | 82,902 | 113,179 | 4 (SCRANTON, NASHUA, NEWYORK, UTICA) | 910 | 1,653 | 78,695 | 1,230 | 414 |

Full pipeline (`run_analysis`: parse, graph, reasoning), measured on a laptop:
about 2 to 2.5 minutes and ~2.3 GB peak memory. It produced 2,099 conclusions:
`REG-PERSIST-01` x 1,874 and `C2-BEACON-01` x 225, on all four hosts; every
evidence id resolves to a real event. **No** `PSH-STAGING-01`,
`PERSIST-ESTABLISHED-01` or `LOG-CLEAR-01` fires on this dataset, so the chained
rule is not demonstrated by it. The large REG-PERSIST count is a rule-precision
matter (Phase 3 Step 2), not a parser one.

Run it: `python -m app.orchestrator src/data/mordor/<file>.json > campaign_result.json`
or, as a test, `RUN_CAMPAIGN_PIPELINE=1 pytest tests/test_campaign.py`
(the parse-level checks in that file run by default whenever the file is present).

Notes for anyone consuming this dataset:

- 95% of kept events are registry modifications, and 73% of kept events come from
  a single host (SCRANTON). The graph/engine steps must cope with that volume.
- Windows 4688 (process) and 4104 (PowerShell) events carry their useful values
  in top-level JSON fields, not in the `Message` text. The parser reads both
  (the `Message` text wins on conflict). Multi-part PowerShell blocks
  ("1 of 7") have no script text, so their target falls back to the script
  block id, then the script path. Only 11 kept events (Sysmon 1/3/11/12/13/14
  with no usable field) still have target `UNKNOWN`.
- The raw `Message` text is not stored in `Event.metadata` by default (memory);
  call `parse_mordor(path, keep_raw_message=True)` to keep it. The original line
  is always recoverable from the `event_id` (`<file>:<line number>`).
- The extracted file is large: do not commit it.
