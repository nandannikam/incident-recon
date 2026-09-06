"""
Regression tests for app.dispatch — confirms KNOWN-ISSUES Phase 2 #1 and #8
stay fixed.

#1: a real Mordor .json/.ndjson file must parse successfully through the
    same entry point run_analysis uses (parse_any_log), not crash with a
    pandas ParserError.
#8: SPAWNED edges must appear when the source data has parent/child
    process pairs, i.e. the ProcessId/ParentProcessId -> pid/parentpid
    alias normalization must actually run.

These tests need a real Mordor dataset on disk to be meaningful. Resolution
order, so nobody has to set anything manually on a machine that already has
the datasets downloaded:

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

If none of the above resolves to a usable file, the test is skipped rather
than failed, since real downloaded data is intentionally not committed to
source control (roadmap Step 2 / KNOWN-ISSUES #7). The path is resolved
relative to the repo's `src/` directory (this file's grandparent), not the
current working directory, so `pytest` gives the same result whether it is
invoked from the repo root or from `src/`.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.dispatch import UnknownLogFormatError, detect_format, parse_any_log
from app.graph import build_graph

# tests/test_dispatch.py -> tests/ -> src/  (the directory containing app/ and data/)
_SRC_DIR = Path(__file__).resolve().parent.parent
_MORDOR_DIR = _SRC_DIR / "data" / "mordor"

KNOWN_GOOD_DATASET = "cmd_bitsadmin_download_psh_script_2020-10-2302365189.json"


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


_DISCOVERED_PATH = _discover_mordor_sample()
MORDOR_SAMPLE_PATH = _DISCOVERED_PATH or (_MORDOR_DIR / KNOWN_GOOD_DATASET)

pytestmark = pytest.mark.skipif(
    _DISCOVERED_PATH is None,
    reason=(
        f"No usable Mordor dataset found under {_MORDOR_DIR}. "
        "Set MORDOR_SAMPLE_PATH, or download one per the Phase 2 roadmap "
        "(needs 2+ process_execution events to exercise SPAWNED edges)."
    ),
)


def test_detect_format_identifies_mordor_json() -> None:
    """A real Mordor file, whatever its extension, must be detected as
    'mordor' -- this is the routing decision that fixes #1."""
    assert detect_format(MORDOR_SAMPLE_PATH) == "mordor"


def test_parse_any_log_does_not_crash_on_real_json() -> None:
    """The exact call run_analysis makes. Must not raise a pandas
    ParserError (or anything else) on a real dataset."""
    result = parse_any_log(MORDOR_SAMPLE_PATH)
    assert result.events, "expected at least one parsed event from a real dataset"


def test_detect_format_missing_file_raises_clear_error() -> None:
    """Sanity check on the error path: a missing file should raise our
    explicit error, not something more confusing downstream."""
    with pytest.raises(UnknownLogFormatError):
        detect_format("data/mordor/definitely_does_not_exist.json")


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
