from pathlib import Path
from app.orchestrator import run_analysis


def test_dod_attack_sample_has_conclusions_with_evidence_and_rule_id() -> None:
    incident = run_analysis("data/attack_sample.csv")
    assert len(incident.conclusions) >= 1
    for c in incident.conclusions:
        assert c.rule_id
        assert len(c.evidence) >= 1


def test_negative_benign_sample_has_zero_conclusions() -> None:
    incident = run_analysis("data/benign_sample.csv")
    assert incident.conclusions == []


def test_provenance_all_event_ids_resolve_to_real_events() -> None:
    from app.parser import parse_log

    result = parse_log("data/attack_sample.csv")
    real_ids = {e.event_id for e in result.events}

    incident = run_analysis("data/attack_sample.csv")
    for c in incident.conclusions:
        for ev in c.evidence:
            for eid in ev.event_ids:
                assert eid in real_ids, f"{eid} not in parsed events"


def test_chaining_persist_established_requires_prerequisite() -> None:
    incident = run_analysis("data/attack_sample.csv")

    staging_ids = {c.rule_id for c in incident.conclusions if c.rule_id == "PSH-STAGING-01"}
    established = [c for c in incident.conclusions if c.rule_id == "PERSIST-ESTABLISHED-01"]

    if established:
        assert "PSH-STAGING-01" in staging_ids
        for c in established:
            for ev in c.evidence:
                assert ev.parent_conclusion_id == "PSH-STAGING-01"