"""Phase 3, Step 2 — golden per-dataset precision guards.

These tests assert *intent*, not snapshots: known-malicious datasets must still
produce their technique (recall), while benign/real-world noise must not flood
the incident with near-duplicate findings (precision). The headline guarantee
is that no dataset yields more than one conclusion per ``(rule_id, host)`` pair.

All datasets are committed under ``src/data``; ``run_analysis`` is the same
entry point the API uses. The wevtutil dataset has ~10k events, so every file is
analysed once in a module-scoped fixture and shared across the tests.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from app.orchestrator import run_analysis

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
MORDOR_DIR = DATA_DIR / "mordor"

DATASETS: dict[str, Path] = {
    "wevtutil": MORDOR_DIR / "cmd_wevtutil_modify_security_eventlog_path.json",
    "bitsadmin": (
        MORDOR_DIR / "cmd_bitsadmin_download_psh_script_2020-10-2302365189.json"
    ),
    "psexec": MORDOR_DIR / "empire_psexec_dcerpc_tcp_svcctl_2020-09-20121608.json",
    "persistence": (
        MORDOR_DIR
        / "empire_persistence_registry_modification_run_keys_elevated_user_2020-07-22001847.json"
    ),
    "psh_http": MORDOR_DIR / "psh_powershell_httplistener_2020-11-0204130683.json",
    "attack": DATA_DIR / "attack_sample.csv",
    "benign": DATA_DIR / "benign_sample.csv",
}


@pytest.fixture(scope="module")
def incidents() -> dict[str, object]:
    return {name: run_analysis(str(path)) for name, path in DATASETS.items()}


def _rule_counts(incident) -> Counter:
    return Counter(c.rule_id for c in incident.conclusions)


def test_no_dataset_repeats_a_rule_on_the_same_host(incidents) -> None:
    """Headline guarantee: one conclusion per (rule_id, host), everywhere."""
    for name, incident in incidents.items():
        seen: set[tuple[str, str]] = set()
        for conclusion in incident.conclusions:
            assert conclusion.hosts, f"{name}: conclusion has no host populated"
            for host in conclusion.hosts:
                key = (conclusion.rule_id, host)
                assert key not in seen, f"{name}: duplicate conclusion {key}"
                seen.add(key)


def test_wevtutil_private_and_multicast_destinations_do_not_beacon(incidents) -> None:
    # Real flood-control case: this dataset's only network destinations are
    # private (10.0.10.x) or multicast/benign-port, so C2 must be silent.
    incident = incidents["wevtutil"]
    assert _rule_counts(incident)["C2-BEACON-01"] == 0
    assert len(incident.conclusions) <= 2


def test_bitsadmin_multicast_and_loopback_do_not_beacon(incidents) -> None:
    incident = incidents["bitsadmin"]
    # 239.255.255.250:1900 is SSDP multicast, 127.0.0.1 / ::1 are loopback.
    assert _rule_counts(incident)["C2-BEACON-01"] == 0
    assert len(incident.conclusions) <= 3


def test_psexec_private_network_does_not_beacon(incidents) -> None:
    incident = incidents["psexec"]
    # Every destination is a 172.18.x RFC1918 address.
    assert _rule_counts(incident)["C2-BEACON-01"] == 0
    assert len(incident.conclusions) <= 2


def test_psh_httplistener_still_detects_log_clear(incidents) -> None:
    incident = incidents["psh_http"]
    assert "LOG-CLEAR-01" in {c.rule_id for c in incident.conclusions}
    assert len(incident.conclusions) <= 2


def test_attack_sample_recalls_every_injected_technique(incidents) -> None:
    """Recall guard: precision work must not drop the synthetic demo chain."""
    rule_ids = {c.rule_id for c in incidents["attack"].conclusions}
    assert {
        "REG-PERSIST-01",
        "PSH-STAGING-01",
        "PERSIST-ESTABLISHED-01",
        "LOG-CLEAR-01",
    } <= rule_ids


def test_benign_sample_yields_zero_conclusions(incidents) -> None:
    assert incidents["benign"].conclusions == []


def test_empire_persistence_is_bounded(incidents) -> None:
    # Documented limitation: this dataset has 0 process_execution events, so
    # the writer-linked REG-PERSIST-01 cannot fire and C2-BEACON-01 (also
    # process-gated) cannot either. Assert a bound rather than a count.
    incident = incidents["persistence"]
    assert len(incident.conclusions) <= 2
