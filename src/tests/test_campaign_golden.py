"""Golden check on the committed APT29 Day 1 demo output.

Reads docs/demo/campaign_result.json (regenerate with `make demo`), so it is
cheap and runs everywhere. Asserts intent, not exact counts.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.correlation import KILL_CHAIN_ORDER

RESULT = Path(__file__).resolve().parents[2] / "docs" / "demo" / "campaign_result.json"

pytestmark = pytest.mark.skipif(
    not RESULT.exists(), reason="run `make data && make demo` to generate"
)


@pytest.fixture(scope="module")
def incident() -> dict:
    return json.loads(RESULT.read_text())


def test_campaign_spans_all_four_hosts(incident: dict) -> None:
    hosts = {h for c in incident["conclusions"] for h in c["hosts"]}
    assert hosts == {"nashua", "newyork", "scranton", "utica"}
    assert incident["severity"] == "high"


def test_persistence_technique_found_once_per_host(incident: dict) -> None:
    keys = [(c["rule_id"], h) for c in incident["conclusions"] for h in c["hosts"]]
    assert len(keys) == len(set(keys))
    assert any(c["technique_id"] == "T1547.001" for c in incident["conclusions"])


def test_conclusions_follow_kill_chain_order(incident: dict) -> None:
    ranks = [
        KILL_CHAIN_ORDER.index(c["tactic"])
        for c in incident["conclusions"]
        if c["tactic"] in KILL_CHAIN_ORDER
    ]
    assert ranks == sorted(ranks)


def test_narrative_shape_and_no_benign_system_key_links(incident: dict) -> None:
    summary = incident["summary"]
    assert summary.startswith("Analyzed ")
    assert "Kill-chain reconstruction across 4 host(s)" in summary
    assert "currentcontrolset\\services" not in summary.lower()
