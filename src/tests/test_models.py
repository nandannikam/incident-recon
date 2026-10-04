import pytest
from pydantic import ValidationError

from app.models import (
    DEMO_RULES,
    TIME_WINDOW_MINUTES,
    Conclusion,
    EdgeType,
    Event,
    EventType,
    Evidence,
    Incident,
    Severity,
    max_severity,
)


def test_event_constructs_from_dict():
    raw = {
        "event_id": "attack_sample.csv:0",
        "timestamp": "2024-01-01T10:00:00Z",
        "source": "HOST01",
        "event_type": "process_execution",
        "actor": "USER01",
        "target": "invoice.exe",
        "metadata": {"pid": 2048, "parentpid": 1024},
    }
    event = Event.model_validate(raw)

    assert event.event_id == "attack_sample.csv:0"
    assert event.event_type == EventType.PROCESS_EXECUTION
    assert event.metadata["pid"] == 2048
    assert event.timestamp.tzinfo is not None


def test_event_type_rejects_unknown_value():
    raw = {
        "event_id": "x:0",
        "timestamp": "2024-01-01T10:00:00Z",
        "source": "HOST01",
        "event_type": "totally_not_a_real_type",
        "actor": "USER01",
        "target": "x",
    }
    with pytest.raises(ValidationError):
        Event.model_validate(raw)


def test_incident_round_trip_with_derived_conclusion():
    """Builds a full Incident -> Conclusion -> Evidence tree, including the
    parent_conclusion_id=None case and the set (chained) case, and asserts
    it survives a serialize/deserialize round trip."""

    base_evidence = Evidence(
        event_ids=["a:1", "a:2"],
        explanation="powershell_execution followed by file_download within 5 min.",
        parent_conclusion_id=None,
    )
    base_conclusion = Conclusion(
        conclusion_id="test-conclusion-1",
        rule_id="PSH-STAGING-01",
        technique_id="T1059.001",
        tactic="Execution",
        description="Possible PowerShell staging activity.",
        evidence=[base_evidence],
    )

    chained_evidence = Evidence(
        event_ids=["a:2", "a:5"],
        explanation="Staging conclusion followed by a registry_modification.",
        parent_conclusion_id="PSH-STAGING-01",
    )
    chained_conclusion = Conclusion(
        conclusion_id="test-conclusion-2",
        rule_id="PERSIST-ESTABLISHED-01",
        technique_id="T1547.001",
        tactic="Persistence",
        description="Persistence established after staging.",
        evidence=[chained_evidence],
    )

    incident = Incident(
        id="incident-1",
        summary="2 conclusions found.",
        conclusions=[base_conclusion, chained_conclusion],
    )

    dumped = incident.model_dump_json()
    restored = Incident.model_validate_json(dumped)

    assert restored.conclusions[0].evidence[0].parent_conclusion_id is None
    assert restored.conclusions[1].evidence[0].parent_conclusion_id == "PSH-STAGING-01"
    assert restored.conclusions[1].rule_id == "PERSIST-ESTABLISHED-01"
    assert restored == incident


def test_edge_vocabulary_is_exactly_three_kinds():
    kinds = {e.value for e in EdgeType}
    assert kinds == {"followed_by", "spawned", "same_object"}


def test_time_window_constant_defined_once():
    assert TIME_WINDOW_MINUTES == 5


def test_demo_rules_named_and_one_is_chained():
    rule_ids = {r.rule_id for r in DEMO_RULES}
    assert rule_ids == {"REG-PERSIST-01", "PSH-STAGING-01", "PERSIST-ESTABLISHED-01"}
    chained = [r for r in DEMO_RULES if r.chained]
    assert len(chained) == 1
    assert chained[0].rule_id == "PERSIST-ESTABLISHED-01"


# ---------------------------------------------------------------------------
# Phase 3 Step 2/4 — confidence, severity, hosts
# ---------------------------------------------------------------------------


def _conclusion(**overrides):
    values = {
        "conclusion_id": "c-1",
        "rule_id": "REG-PERSIST-01",
        "technique_id": "T1547.001",
        "tactic": "Persistence",
        "description": "d",
        "evidence": [Evidence(event_ids=["a:1"], explanation="e")],
    }
    values.update(overrides)
    return Conclusion(**values)


def test_confidence_defaults_come_from_the_rule_table():
    assert _conclusion(rule_id="LOG-CLEAR-01").confidence == 0.9
    assert _conclusion(rule_id="C2-BEACON-01").confidence == 0.3
    assert _conclusion(rule_id="SOME-NEW-RULE").confidence == 0.5


def test_explicit_confidence_wins_over_the_default():
    assert _conclusion(rule_id="LOG-CLEAR-01", confidence=0.1).confidence == 0.1


@pytest.mark.parametrize("bad", [-0.01, 1.01, 5])
def test_confidence_outside_zero_to_one_is_rejected(bad):
    with pytest.raises(ValidationError):
        _conclusion(confidence=bad)


def test_confidence_boundaries_are_accepted():
    assert _conclusion(confidence=0.0).confidence == 0.0
    assert _conclusion(confidence=1.0).confidence == 1.0


@pytest.mark.parametrize(
    "tactic, expected",
    [
        ("Persistence", Severity.HIGH),
        ("Execution", Severity.MEDIUM),
        ("Defense Evasion", Severity.HIGH),
        ("Command and Control", Severity.HIGH),
        ("Discovery", Severity.LOW),
        ("Impact", Severity.CRITICAL),
        ("A Tactic Nobody Listed", Severity.MEDIUM),
    ],
)
def test_conclusion_severity_is_derived_from_tactic(tactic, expected):
    assert _conclusion(tactic=tactic).severity == expected


def test_explicit_severity_wins_over_the_derived_one():
    assert _conclusion(severity=Severity.LOW).severity == Severity.LOW


def test_unknown_severity_value_is_rejected():
    with pytest.raises(ValidationError):
        _conclusion(severity="catastrophic")


def test_incident_severity_is_the_maximum_of_its_conclusions():
    incident = Incident(
        id="i",
        summary="s",
        conclusions=[
            _conclusion(conclusion_id="a", tactic="Execution"),  # medium
            _conclusion(conclusion_id="b", tactic="Persistence"),  # high
            _conclusion(conclusion_id="c", tactic="Discovery"),  # low
        ],
    )
    assert incident.severity == Severity.HIGH


def test_incident_without_conclusions_has_info_severity():
    assert Incident(id="i", summary="s").severity == Severity.INFO


def test_max_severity_helper():
    assert max_severity([]) == Severity.INFO
    assert max_severity([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) == (
        Severity.CRITICAL
    )


def test_hosts_default_to_an_empty_list_that_is_not_shared():
    first, second = _conclusion(), _conclusion()
    first.hosts.append("HOST01")
    assert second.hosts == []


def test_incident_stored_before_these_fields_existed_still_loads():
    """Old rows in incidents.db have no confidence/severity/hosts keys."""
    legacy = (
        '{"id": "old", "summary": "s", "conclusions": [{"conclusion_id": "c",'
        ' "rule_id": "LOG-CLEAR-01", "technique_id": "T1070", "tactic":'
        ' "Defense Evasion", "description": "d", "evidence": [{"event_ids":'
        ' ["x:1"], "explanation": "e", "parent_conclusion_id": null}]}]}'
    )
    incident = Incident.model_validate_json(legacy)

    assert incident.conclusions[0].confidence == 0.9
    assert incident.conclusions[0].severity == Severity.HIGH
    assert incident.conclusions[0].hosts == []
    assert incident.severity == Severity.HIGH


def test_new_fields_survive_a_json_round_trip():
    incident = Incident(
        id="i",
        summary="s",
        conclusions=[
            _conclusion(confidence=0.42, severity=Severity.LOW, hosts=["H1", "H2"])
        ],
    )
    restored = Incident.model_validate_json(incident.model_dump_json())

    assert restored == incident
    assert restored.conclusions[0].confidence == 0.42
    assert restored.conclusions[0].hosts == ["H1", "H2"]
