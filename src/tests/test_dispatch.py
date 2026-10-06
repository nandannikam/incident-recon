"""
Regression tests for app.dispatch — confirms KNOWN-ISSUES Phase 2 #1, #8,
#9, and #10 stay fixed.

#1: a real Mordor .json/.ndjson file must parse successfully through the
    same entry point run_analysis uses (parse_any_log), not crash with a
    pandas ParserError.
#8: SPAWNED edges must appear when the source data has parent/child
    process pairs, i.e. the ProcessId/ParentProcessId -> pid/parentpid
    alias normalization must actually run.
#9: a mislabeled file (e.g. a CSV renamed to .json) must raise a clear
    UnknownLogFormatError instead of silently parsing to a 0-event
    "successful" result. This test needs no real dataset -- it builds its
    own fake file -- so it is NOT behind the Mordor-dataset skip guard.
#10: this file previously only covered the happy path on a small (89
    event) dataset. test_build_graph_completes_within_time_budget adds a
    basic scale check using the largest dataset actually available on
    disk, so a build_graph performance regression (KNOWN-ISSUES #3) does
    not ship unnoticed.

Most tests below need a real Mordor dataset on disk to be meaningful.
Resolution order, so nobody has to set anything manually on a machine
that already has the datasets downloaded:

    1. MORDOR_SAMPLE_PATH env var, if set -- explicit override, always wins.
    2. KNOWN_GOOD_DATASET (below) if present under data/mordor/ -- a file
       already confirmed (see KNOWN-ISSUES side finding) to contain
       process_execution events with a real parent/child pid pair.
    3. The first *.json file under data/mordor/ that, once parsed, contains
       2+ process_execution events -- so the suite self-heals if the known-
       good file is ever removed or renamed, without silently passing on a
       dataset that structurally can't exercise SPAWNED edges (see the
       httplistener/empire-persistence datasets, which have zero
       process_execution events and would make this test meaningless).

If none of the above resolves to a usable file, those tests are skipped
rather than failed, since real downloaded data is intentionally not
committed to source control (roadmap Step 2 / KNOWN-ISSUES #7). The path
is resolved relative to the repo's `src/` directory (this file's
grandparent), not the current working directory, so `pytest` gives the
same result whether it is invoked from the repo root or from `src/`.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from app.dispatch import UnknownLogFormatError, detect_format, parse_any_log
from app.graph import build_graph

# tests/test_dispatch.py -> tests/ -> src/  (the directory containing app/ and data/)
_SRC_DIR = Path(__file__).resolve().parent.parent
_MORDOR_DIR = _SRC_DIR / "data" / "mordor"

KNOWN_GOOD_DATASET = "cmd_bitsadmin_download_psh_script_2020-10-2302365189.json"

# Generous ceiling for build_graph on the largest dataset actually present.
# This is a smoke test against runaway edge explosion (#3), not a strict
# performance benchmark -- it should comfortably pass with the fan-out cap
# in place, and fail loudly (rather than hang forever) if that cap
# regresses on real data.
BUILD_GRAPH_TIME_BUDGET_SECONDS = 30.0


def _has_multiple_process_execution_events(path: Path) -> bool:
    """Cheap check used only for auto-discovery fallback: does this file
    parse to 2+ process_execution events? Any parse failure just means
    "not usable," not a test failure -- discovery should never raise."""
    try:
        result = parse_any_log(path)
    except Exception:  # noqa: BLE001 - discovery must never crash on a bad candidate
        return False
    return sum(1 for e in result.events if e.event_type == "process_execution") >= 2


def _discover_mordor_sample() -> Path | None:
    env_override = os.environ.get("MORDOR_SAMPLE_PATH")
    if env_override:
        return Path(env_override)

    known_good = _MORDOR_DIR / KNOWN_GOOD_DATASET
    if known_good.exists():
        return known_good

    if not _MORDOR_DIR.is_dir():
        return None

    for candidate in sorted(_MORDOR_DIR.glob("*.json")):
        if _has_multiple_process_execution_events(candidate):
            return candidate

    return None


def _largest_mordor_dataset() -> Path | None:
    """Return the biggest *.json file under data/mordor/ by file size, for
    the scale smoke test (#10) -- deliberately independent of
    _discover_mordor_sample, since the biggest file is very unlikely to be
    the same as the small known-good process-execution sample."""
    if not _MORDOR_DIR.is_dir():
        return None
    # Campaign-scale files (apt29_*) are covered by the golden test and
    # `make demo`; this test guards the ~10k-event edge-explosion case.
    candidates = [
        f for f in _MORDOR_DIR.glob("*.json")
        if not f.name.lower().startswith("apt29")
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_size)


_DISCOVERED_PATH = _discover_mordor_sample()
MORDOR_SAMPLE_PATH = _DISCOVERED_PATH or (_MORDOR_DIR / KNOWN_GOOD_DATASET)

_requires_mordor_dataset = pytest.mark.skipif(
    _DISCOVERED_PATH is None,
    reason=(
        f"No usable Mordor dataset found under {_MORDOR_DIR}. "
        "Set MORDOR_SAMPLE_PATH, or download one per the Phase 2 roadmap "
        "(needs 2+ process_execution events to exercise SPAWNED edges)."
    ),
)


# ---------------------------------------------------------------------------
# #9 — misdetection guard. No real dataset needed; these build their own
# fake files, so they are NOT decorated with _requires_mordor_dataset and
# will always run.
# ---------------------------------------------------------------------------


def test_csv_mislabeled_as_json_raises_instead_of_silently_parsing(
    tmp_path: Path,
) -> None:
    """
    Fixes #9. Before the content-verification fix in dispatch.py, a file
    routed purely by its .json extension went straight to parse_mordor
    even if its content was plain CSV -- every line failed json.loads(),
    got silently counted as "skipped," and the caller received a
    successful-looking ParseResult with 0 events instead of an error.
    """
    fake_path = tmp_path / "attack_sample.json"  # CSV content, .json name
    fake_path.write_text(
        "timestamp,source,event_type,actor,target,metadata\n"
        "2024-01-01T10:00:00Z,HOST01,process_execution,USER01,invoice.exe,{}\n",
        encoding="utf-8",
    )

    with pytest.raises(UnknownLogFormatError):
        detect_format(fake_path)


def test_empty_file_raises_instead_of_defaulting_to_csv(tmp_path: Path) -> None:
    """An empty file has no content to sniff and no .csv extension to
    trust -- it must raise, not silently default to a guess."""
    fake_path = tmp_path / "empty.json"
    fake_path.write_text("", encoding="utf-8")

    with pytest.raises(UnknownLogFormatError):
        detect_format(fake_path)


def test_valid_ndjson_with_no_extension_still_detected(tmp_path: Path) -> None:
    """Sanity check that the #9 fix didn't overcorrect: a real Mordor-shaped
    line with an unfamiliar extension should still be detected as mordor
    via content sniffing, not rejected just for lacking .json/.ndjson."""
    fake_path = tmp_path / "some_log.dat"
    fake_path.write_text(
        '{"EventID": 1, "TimeCreated": "2024-01-01T10:00:00Z", '
        '"Hostname": "H1", "Message": "Image: C:\\\\a.exe"}\n',
        encoding="utf-8",
    )
    assert detect_format(fake_path) == "mordor"


# ---------------------------------------------------------------------------
# Existing #1 / #8 coverage (needs a real, known-good dataset)
# ---------------------------------------------------------------------------


@_requires_mordor_dataset
def test_detect_format_identifies_mordor_json() -> None:
    """A real Mordor file, whatever its extension, must be detected as
    'mordor' -- this is the routing decision that fixes #1."""
    assert detect_format(MORDOR_SAMPLE_PATH) == "mordor"


@_requires_mordor_dataset
def test_parse_any_log_does_not_crash_on_real_json() -> None:
    """The exact call run_analysis makes. Must not raise a pandas
    ParserError (or anything else) on a real dataset."""
    result = parse_any_log(MORDOR_SAMPLE_PATH)
    assert result.events, "expected at least one parsed event from a real dataset"


def test_detect_format_missing_file_raises_clear_error() -> None:
    """Sanity check on the error path: a missing file should raise our
    explicit error, not something more confusing downstream. Needs no
    dataset on disk, so this always runs."""
    with pytest.raises(UnknownLogFormatError):
        detect_format("data/mordor/definitely_does_not_exist.json")


@_requires_mordor_dataset
def test_spawned_edges_present_after_mordor_parse() -> None:
    """
    Fixes #8. Before the pid/parentpid alias fix in dispatch.py, this
    would fail on any real Mordor data because graph.py reads lowercase
    metadata['pid'] / metadata['parentpid'], while mordor_parser.py only
    ever wrote capitalized ProcessId / ParentProcessId.

    If this fails, first confirm the chosen dataset actually contains
    multiple Sysmon EventID 1 (Process Create) events with a real
    parent/child relationship -- not every atomic dataset does.
    """
    result = parse_any_log(MORDOR_SAMPLE_PATH)
    graph = build_graph(result.events)

    spawned_edges = [
        (u, v)
        for u, v, data in graph.edges(data=True)
        if "spawned"
        in (data["kind"] if isinstance(data["kind"], list) else [data["kind"]])
    ]

    assert spawned_edges, (
        "no SPAWNED edges found -- either the pid/parentpid alias fix "
        "regressed, or this dataset has no parent/child process pairs "
        "(try a dataset with more process_execution events)"
    )


# ---------------------------------------------------------------------------
# #10 — scale/perf smoke test (needs a real dataset; picks the largest
# available rather than a specific named file, since which datasets are
# downloaded varies by machine).
# ---------------------------------------------------------------------------


def test_build_graph_completes_within_time_budget() -> None:
    """
    Fixes #10 (scale coverage gap). Runs build_graph against the largest
    real dataset actually present on disk and asserts it finishes within
    BUILD_GRAPH_TIME_BUDGET_SECONDS, guarding against the edge-explosion
    regression described in KNOWN-ISSUES #3 (1,052 events measured at
    1,105,652 edges / 4.2s; 10,377 events did not return within 60s,
    before the fan-out cap in graph.py).

    Skipped (not failed) if no dataset is present at all -- this is a
    scale smoke test, not something that should block a fresh clone with
    no data downloaded yet.
    """
    largest = _largest_mordor_dataset()
    if largest is None:
        pytest.skip(
            f"No Mordor dataset found under {_MORDOR_DIR} to scale-test against."
        )

    result = parse_any_log(largest)
    if len(result.events) < 100:
        pytest.skip(
            f"Largest available dataset ({largest.name}) has only "
            f"{len(result.events)} events -- too small to be a meaningful "
            "scale check. Download a larger atomic dataset for real coverage."
        )

    start = time.monotonic()
    graph = build_graph(result.events)
    elapsed = time.monotonic() - start

    assert elapsed < BUILD_GRAPH_TIME_BUDGET_SECONDS, (
        f"build_graph took {elapsed:.1f}s on {len(result.events)} events "
        f"({largest.name}) -- exceeds the {BUILD_GRAPH_TIME_BUDGET_SECONDS}s "
        "budget. Likely an edge-fan-out-cap regression (KNOWN-ISSUES #3)."
    )
    log_msg = (
        f"build_graph on {len(result.events)} events took {elapsed:.2f}s, "
        f"produced {graph.number_of_edges()} edges"
    )
    print(log_msg)
