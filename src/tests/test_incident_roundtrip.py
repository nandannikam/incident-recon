"""Phase 3, Step 7 — an Incident must survive the storage layer unchanged.

The storage layer keeps each Incident as JSON and rebuilds it with Pydantic on
the way out, so these tests check the Pydantic contract end to end: what goes
in is exactly what comes out, including chained evidence, derived fields
(confidence, severity, hosts) and awkward real-world strings.

They talk to ``save_incident`` / ``get_incident`` only. When storage moves to
PostgreSQL, change the ``db`` fixture below to point at the test database; the
tests themselves should not need to change.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app import storage
from app.models import Conclusion, Evidence, Incident, Severity
from app.orchestrator import run_analysis
from app.storage import get_incident, save_incident
from app.synthetic import write_synthetic_csv

MORDOR_DIR = Path(__file__).resolve().parents[1] / "data" / "mordor"
SMALL_MORDOR_DATASETS = [
    "cmd_bitsadmin_download_psh_script",
    "empire_persistence_registry_modification_run_keys",
    "psh_powershell_httplistener",
]


@pytest.fixture()
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
    storage.settings,
    "database_url",
    f"sqlite:///{tmp_path / 'roundtrip.db'}",
)


def _conclusion(**overrides) -> Conclusion:
    values = {
        "conclusion_id": "c-1",
        "rule_id": "REG-PERSIST-01",
        "technique_id": "T1547.001",
        "tactic": "Persistence",
        "description": "d",
        "evidence": [Evidence(event_ids=["f.csv:0", "f.csv:1"], explanation="e")],
    }
    values.update(overrides)
    return Conclusion(**values)


def _attack_incident(tmp_path: Path) -> Incident:
    path = write_synthetic_csv(tmp_path / "attack.csv", 300, seed=1, attack_chains=2)
    return run_analysis(str(path))


def test_analysed_incident_round_trips_through_storage(
    db: None, tmp_path: Path
) -> None:
    incident = _attack_incident(tmp_path)
    assert incident.conclusions, "fixture should produce conclusions"

    save_incident(incident)
    restored = get_incident(incident.id)

    assert restored == incident
    assert restored is not None
    assert restored.model_dump() == incident.model_dump()


def test_chained_parent_conclusion_id_survives(db: None, tmp_path: Path) -> None:
    incident = _attack_incident(tmp_path)
    chained = [c for c in incident.conclusions if c.rule_id == "PERSIST-ESTABLISHED-01"]
    assert chained

    save_incident(incident)
    restored = get_incident(incident.id)

    assert restored is not None
    restored_chained = [
        c for c in restored.conclusions if c.rule_id == "PERSIST-ESTABLISHED-01"
    ]
    assert [
        ev.parent_conclusion_id for c in restored_chained for ev in c.evidence
    ] == [ev.parent_conclusion_id for c in chained for ev in c.evidence]
    assert all(
        ev.parent_conclusion_id for c in restored_chained for ev in c.evidence
    )


def test_derived_fields_survive(db: None) -> None:
    incident = Incident(
        id="derived",
        summary="s",
        conclusions=[
            _conclusion(confidence=0.42, severity=Severity.LOW, hosts=["H1", "H2"]),
            _conclusion(conclusion_id="c-2", rule_id="LOG-CLEAR-01", tactic="Defense Evasion"),
        ],
    )

    save_incident(incident)
    restored = get_incident("derived")

    assert restored is not None
    assert restored.conclusions[0].confidence == 0.42
    assert restored.conclusions[0].severity == Severity.LOW
    assert restored.conclusions[0].hosts == ["H1", "H2"]
    assert restored.conclusions[1].confidence == 0.9  # derived default
    assert restored.severity == Severity.HIGH  # max of the conclusions


def test_none_and_empty_values_survive(db: None) -> None:
    incident = Incident(id="empty", summary="nothing found")

    save_incident(incident)
    restored = get_incident("empty")

    assert restored == incident
    assert restored is not None
    assert restored.conclusions == []
    assert restored.severity == Severity.INFO


def test_unicode_and_control_characters_survive(db: None) -> None:
    # A real APT29 target contains a right-to-left override character.
    tricky = "C:\\ProgramData\\victim\\\u202ecod.3aka3.scr \u2603 \"quoted\" \\ \n tab\t"
    incident = Incident(
        id="unicode",
        summary="s",
        conclusions=[
            _conclusion(
                description=tricky,
                evidence=[Evidence(event_ids=["x:1"], explanation=tricky)],
            )
        ],
    )

    save_incident(incident)
    restored = get_incident("unicode")

    assert restored is not None
    assert restored.conclusions[0].description == tricky
    assert restored.conclusions[0].evidence[0].explanation == tricky


def test_saving_the_same_id_again_replaces_it(db: None) -> None:
    save_incident(Incident(id="same", summary="first"))
    save_incident(Incident(id="same", summary="second"))

    restored = get_incident("same")

    assert restored is not None
    assert restored.summary == "second"


def test_unknown_id_returns_none(db: None) -> None:
    save_incident(Incident(id="exists", summary="s"))

    assert get_incident("does-not-exist") is None


def test_json_mode_dump_is_serialisable_and_validates_back(db: None, tmp_path: Path) -> None:
    incident = _attack_incident(tmp_path)

    as_json = json.dumps(incident.model_dump(mode="json"))

    assert Incident.model_validate_json(as_json) == incident


@pytest.mark.parametrize("dataset_prefix", SMALL_MORDOR_DATASETS)
def test_real_dataset_incidents_round_trip(db: None, dataset_prefix: str) -> None:
    matches = sorted(MORDOR_DIR.glob(f"{dataset_prefix}*.json"))
    if not matches:
        pytest.skip(f"{dataset_prefix} dataset not downloaded")

    incident = run_analysis(str(matches[0]))
    save_incident(incident)

    assert get_incident(incident.id) == incident
