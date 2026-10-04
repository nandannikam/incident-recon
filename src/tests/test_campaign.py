"""Phase 3, Step 5 — the APT29 Day 1 campaign dataset (real, multi-host data).

The 385 MB file is downloaded, not committed (see data/mordor/README.md), so
every test here is skipped when it is absent. The parse-level checks take about
10 seconds and run whenever the file is present. The full-pipeline check takes
about two minutes and ~2.3 GB of memory, so it only runs when you ask for it:

    RUN_CAMPAIGN_PIPELINE=1 pytest tests/test_campaign.py
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

import pytest

from app.dispatch import parse_any_log
from app.models import EventType, Incident
from app.orchestrator import run_analysis_with_diagnostics

MORDOR_DIR = Path(__file__).resolve().parents[1] / "data" / "mordor"
CAMPAIGN_FILES = sorted(MORDOR_DIR.glob("apt29_evals_day1_manual_*.json"))

pytestmark = pytest.mark.skipif(
    not CAMPAIGN_FILES,
    reason="APT29 Day 1 dataset not downloaded (see data/mordor/README.md)",
)

EXPECTED_HOSTS = {"scranton", "nashua", "newyork", "utica"}


@pytest.fixture(scope="module")
def parsed():
    return parse_any_log(CAMPAIGN_FILES[0])


# ---------------------------------------------------------------------------
# Parse level (fast)
# ---------------------------------------------------------------------------


def test_line_and_event_counts_match_the_known_dataset(parsed) -> None:
    assert parsed.total_rows == 196_081
    assert len(parsed.events) == 82_902
    assert parsed.skipped == 113_179


def test_every_skip_is_an_unmapped_event_id_not_a_parse_failure(parsed) -> None:
    # `errors` keeps a bounded sample, so this checks the sample, not every row.
    assert parsed.errors
    assert all("unmapped EventID" in error for error in parsed.errors)


def test_event_type_counts(parsed) -> None:
    counts = Counter(e.event_type for e in parsed.events)

    assert counts[EventType.PROCESS_EXECUTION] == 910
    assert counts[EventType.FILE_CREATION] == 1_653
    assert counts[EventType.REGISTRY_MODIFICATION] == 78_695
    assert counts[EventType.NETWORK_CONNECTION] == 1_230
    assert counts[EventType.POWERSHELL_EXECUTION] == 414


def test_windows_4688_and_4104_events_have_real_targets(parsed) -> None:
    """Regression: these used to be 'UNKNOWN' because the values live in
    top-level JSON fields rather than in the Message text."""
    windows_events = [
        e for e in parsed.events if e.metadata.get("_event_id") in (4688, 4104)
    ]

    assert len(windows_events) == 460 + 414
    assert [e.event_id for e in windows_events if e.target == "UNKNOWN"] == []


def test_all_four_hosts_are_normalised(parsed) -> None:
    assert {e.metadata["_host_norm"] for e in parsed.events} == EXPECTED_HOSTS


def test_provenance_ids_point_back_to_source_lines(parsed) -> None:
    sample = parsed.events[:: len(parsed.events) // 25]
    wanted = {int(e.event_id.rpartition(":")[2]) for e in sample}
    lines: dict[int, str] = {}
    with CAMPAIGN_FILES[0].open(encoding="utf-8") as handle:
        for number, line in enumerate(handle):
            if number in wanted:
                lines[number] = line
                if len(lines) == len(wanted):
                    break

    for event in sample:
        number = int(event.event_id.rpartition(":")[2])
        raw = json.loads(lines[number])
        assert int(raw["EventID"]) == event.metadata["_event_id"]


# ---------------------------------------------------------------------------
# Full pipeline (slow, opt-in)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    os.environ.get("RUN_CAMPAIGN_PIPELINE") != "1",
    reason="set RUN_CAMPAIGN_PIPELINE=1 to run the ~2 minute, ~2.3 GB pipeline test",
)
def test_campaign_runs_through_the_whole_pipeline() -> None:
    """Deliberately does not pin conclusion counts: detection precision work
    (Phase 3 Step 2) is expected to change them. It pins what must always hold."""
    incident, result = run_analysis_with_diagnostics(str(CAMPAIGN_FILES[0]))

    assert isinstance(incident, Incident)
    assert incident.conclusions
    assert incident.severity is not None

    real_ids = {e.event_id for e in result.events}
    for conclusion in incident.conclusions:
        assert conclusion.evidence
        for evidence in conclusion.evidence:
            assert set(evidence.event_ids) <= real_ids

    hosts = {
        {e.event_id: e for e in result.events}[i].metadata["_host_norm"]
        for c in incident.conclusions
        for ev in c.evidence
        for i in ev.event_ids
    }
    assert hosts == EXPECTED_HOSTS

    assert Incident.model_validate_json(incident.model_dump_json()) == incident
