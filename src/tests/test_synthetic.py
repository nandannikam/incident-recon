"""Phase 3, Step 3 — synthetic log generator and the 10k-event scale check."""

from __future__ import annotations

import time
from pathlib import Path

import pandas as pd
import pytest

from app.engine import analyze
from app.graph import build_graph
from app.orchestrator import run_analysis
from app.parser import parse_log
from app.rules.registry import RULES
from app.synthetic import (
    CHAIN_LENGTH,
    COLUMNS,
    generate_synthetic_events,
    write_synthetic_csv,
)

# Targets that exist only in injected attack chains.
CHAIN_TARGETS = {
    r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
    "powershell.exe",
    "C:\\temp\\stage2.ps1",
    "185.220.101.1",
    "Security.evtx",
    "invoice.exe",
}

# Generous ceilings: smoke tests against runaway cost, not benchmarks. Measured
# on a laptop: parse ~1 s, graph ~2 s, reasoning ~7 s for 10,000 events.
PARSE_BUDGET_SECONDS = 30.0
PIPELINE_BUDGET_SECONDS = 120.0


# ---------------------------------------------------------------------------
# The generator itself
# ---------------------------------------------------------------------------


def test_frame_has_exactly_the_requested_rows_and_the_log_schema() -> None:
    frame = generate_synthetic_events(250, seed=1)

    assert list(frame.columns) == COLUMNS
    assert len(frame) == 250


def test_rows_are_sorted_by_timestamp() -> None:
    frame = generate_synthetic_events(300, seed=2)

    assert frame["timestamp"].is_monotonic_increasing


def test_zero_events_gives_an_empty_frame_with_the_schema() -> None:
    frame = generate_synthetic_events(0, attack_chains=0)

    assert frame.empty
    assert list(frame.columns) == COLUMNS


def test_same_seed_gives_identical_files_and_different_seed_differs(
    tmp_path: Path,
) -> None:
    a = write_synthetic_csv(tmp_path / "a.csv", 400, seed=5)
    b = write_synthetic_csv(tmp_path / "b.csv", 400, seed=5)
    c = write_synthetic_csv(tmp_path / "c.csv", 400, seed=6)

    assert a.read_bytes() == b.read_bytes()
    assert a.read_bytes() != c.read_bytes()


def test_written_csv_parses_with_no_skipped_rows(tmp_path: Path) -> None:
    path = write_synthetic_csv(tmp_path / "log.csv", 500, seed=3)

    result = parse_log(str(path))

    assert result.skipped == 0
    assert len(result.events) == 500


def test_write_creates_missing_parent_directories(tmp_path: Path) -> None:
    path = write_synthetic_csv(tmp_path / "deep" / "er" / "log.csv", 50, attack_chains=1)

    assert path.is_file()


def test_each_chain_adds_one_log_deletion_and_noise_adds_none() -> None:
    frame = generate_synthetic_events(400, seed=4, attack_chains=3)

    counts = frame["event_type"].value_counts()
    assert counts["log_deletion"] == 3
    assert counts["powershell_execution"] == 3
    assert counts.sum() == 400


def test_chains_use_distinct_hosts_and_wrap_when_there_are_more_chains() -> None:
    frame = generate_synthetic_events(400, seed=4, hosts=2, attack_chains=3)

    chain_hosts = frame.loc[frame["event_type"] == "log_deletion", "source"].tolist()
    assert sorted(chain_hosts) == ["HOST01", "HOST01", "HOST02"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"n_events": -1},
        {"n_events": 10, "attack_chains": 2},  # 2 chains need 14 events
        {"n_events": 100, "hosts": 0},
        {"n_events": 100, "attack_chains": -1},
        {"n_events": 100, "span_seconds": 0},
    ],
)
def test_invalid_arguments_are_rejected(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        generate_synthetic_events(**kwargs)


def test_chain_length_constant_matches_the_injected_story() -> None:
    frame = generate_synthetic_events(CHAIN_LENGTH, attack_chains=1, hosts=1)

    assert len(frame) == CHAIN_LENGTH
    assert set(frame["event_type"]) == {
        "process_execution",
        "registry_modification",
        "powershell_execution",
        "file_download",
        "network_connection",
        "log_deletion",
        "file_creation",
    }


# ---------------------------------------------------------------------------
# Detection on the synthetic workload
# ---------------------------------------------------------------------------


def test_pure_noise_produces_no_conclusions(tmp_path: Path) -> None:
    path = write_synthetic_csv(tmp_path / "noise.csv", 600, seed=8, attack_chains=0)

    assert run_analysis(str(path)).conclusions == []


def test_injected_chains_are_detected_and_only_chains(tmp_path: Path) -> None:
    path = write_synthetic_csv(
        tmp_path / "attack.csv", 600, seed=9, hosts=4, attack_chains=2
    )
    events = parse_log(str(path)).events
    by_id = {e.event_id: e for e in events}
    chain_hosts = {
        e.source for e in events if e.event_type.value == "log_deletion"
    }

    incident = run_analysis(str(path))

    assert {c.rule_id for c in incident.conclusions} >= {
        "REG-PERSIST-01",
        "PSH-STAGING-01",
        "PERSIST-ESTABLISHED-01",
        "C2-BEACON-01",
        "LOG-CLEAR-01",
    }
    for conclusion in incident.conclusions:
        cited = [by_id[i] for e in conclusion.evidence for i in e.event_ids]
        assert {ev.source for ev in cited} <= chain_hosts
        assert any(ev.target in CHAIN_TARGETS for ev in cited)


# ---------------------------------------------------------------------------
# Scale (Step 3): 10,000 events must parse and analyse within budget
# ---------------------------------------------------------------------------


def test_ten_thousand_events_complete_within_the_time_budget(tmp_path: Path) -> None:
    path = write_synthetic_csv(tmp_path / "10k.csv", 10_000, seed=7)

    start = time.monotonic()
    result = parse_log(str(path))
    parse_seconds = time.monotonic() - start
    assert len(result.events) == 10_000 and result.skipped == 0
    assert parse_seconds < PARSE_BUDGET_SECONDS

    start = time.monotonic()
    conclusions = analyze(build_graph(result.events), RULES)
    pipeline_seconds = time.monotonic() - start

    assert pipeline_seconds < PIPELINE_BUDGET_SECONDS, (
        f"graph + reasoning took {pipeline_seconds:.1f}s on 10,000 events "
        f"(budget {PIPELINE_BUDGET_SECONDS}s)"
    )
    assert conclusions, "the injected attack chains should be detected at scale"
    print(f"10k events: parse {parse_seconds:.2f}s, graph+reasoning {pipeline_seconds:.2f}s")


def test_pandas_round_trip_preserves_the_frame(tmp_path: Path) -> None:
    frame = generate_synthetic_events(120, seed=11)
    path = write_synthetic_csv(tmp_path / "rt.csv", 120, seed=11)

    reread = pd.read_csv(path)

    assert reread.equals(frame)
