from datetime import datetime, timezone

from app.models import (
    DEMO_RULES,
    Conclusion,
    EdgeType,
    Event,
    EventType,
    Evidence,
    Incident,
    TIME_WINDOW_MINUTES,
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
    try:
        Event.model_validate(raw)
        assert False, "expected a validation error for an unknown event_type"
    except Exception:
        pass


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
