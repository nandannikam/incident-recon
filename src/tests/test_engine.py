"""Step 7 tests — Reasoning Engine (forward chaining)."""

from datetime import UTC, datetime
from pathlib import Path

from app.engine import analyze, hash_conclusion
from app.graph import build_graph
from app.models import Conclusion, Event, EventType, Evidence
from app.parser import parse_log
from app.rules.registry import RULES

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


def _graph(name: str):
    events = parse_log(str(DATA_DIR / name)).events
    return build_graph(events)


def _rule_ids(conclusions):
    return [c.rule_id for c in conclusions]


def test_attack_graph_yields_the_three_expected_rules() -> None:
    graph = _graph("attack_sample.csv")
    conclusions = analyze(graph, RULES)

    assert {"REG-PERSIST-01", "PSH-STAGING-01", "PERSIST-ESTABLISHED-01"} <= set(
        _rule_ids(conclusions)
    )


def test_benign_graph_yields_zero_conclusions() -> None:
    graph = _graph("benign_sample.csv")
    assert analyze(graph, RULES) == []


def test_chained_conclusion_carries_parent_conclusion_id() -> None:
    graph = _graph("attack_sample.csv")
    conclusions = analyze(graph, RULES)
    chained = [c for c in conclusions if c.rule_id == "PERSIST-ESTABLISHED-01"]
    assert chained, "PERSIST-ESTABLISHED-01 should fire on the attack graph"
    assert all(
        ev.parent_conclusion_id is not None for c in chained for ev in c.evidence
    )


def test_conclusions_carry_rule_and_evidence() -> None:
    graph = _graph("attack_sample.csv")
    conclusions = analyze(graph, RULES)
    assert conclusions
    for conclusion in conclusions:
        assert conclusion.rule_id
        assert conclusion.technique_id
        assert conclusion.tactic
        assert conclusion.evidence, "every conclusion must have evidence"
        for evidence in conclusion.evidence:
            assert evidence.event_ids, "evidence must reference concrete events"


def test_no_duplicate_conclusions_by_identity() -> None:
    graph = _graph("attack_sample.csv")
    conclusions = analyze(graph, RULES)
    identities = [hash_conclusion(c) for c in conclusions]
    assert len(identities) == len(set(identities))


def test_evidence_ids_resolve_to_real_events() -> None:
    graph = _graph("attack_sample.csv")
    conclusions = analyze(graph, RULES)
    assert conclusions
    for conclusion in conclusions:
        for evidence in conclusion.evidence:
            for event_id in evidence.event_ids:
                assert graph.has_node(event_id), f"{event_id} not in graph"


def test_loop_terminates_on_both_datasets() -> None:
    assert analyze(_graph("attack_sample.csv"), RULES)
    assert analyze(_graph("benign_sample.csv"), RULES) == []


# ---------------------------------------------------------------------------
# Post-loop clustering (Phase 3 Step 2)
# ---------------------------------------------------------------------------


def _event(event_id: str, host: str, confidence: float) -> Event:
    return Event(
        event_id=event_id,
        timestamp=datetime(2024, 1, 1, 10, 0, tzinfo=UTC),
        source=host,
        event_type=EventType.PROCESS_EXECUTION,
        actor="USER01",
        target=event_id,
        # Confidence is smuggled through metadata only so the fake rule below
        # can emit controlled values; real rules set it on the Conclusion.
        metadata={"_host_norm": host.lower(), "confidence": confidence},
    )


def test_same_rule_same_host_collapses_to_highest_confidence() -> None:
    """Three findings on H1 collapse to the 0.5 one with all evidence merged;
    the same rule on H2 stays a separate conclusion."""

    def fake_rule(neighborhood, graph, facts):
        center = neighborhood[0]
        return Conclusion(
            conclusion_id=f"c-{center.event_id}",
            rule_id="REG-PERSIST-01",
            technique_id="T1547.001",
            tactic="Persistence",
            description="fake",
            evidence=[Evidence(event_ids=[center.event_id], explanation="e")],
            confidence=center.metadata["confidence"],
        )

    events = [
        _event("e1", "H1", 0.2),
        _event("e2", "H1", 0.5),
        _event("e3", "H1", 0.4),
        _event("e4", "H2", 0.9),
    ]
    clustered = analyze(build_graph(events), [fake_rule])

    by_key = {(c.rule_id, c.hosts[0] if c.hosts else ""): c for c in clustered}
    assert set(by_key) == {("REG-PERSIST-01", "h1"), ("REG-PERSIST-01", "h2")}

    h1 = by_key[("REG-PERSIST-01", "h1")]
    assert h1.confidence == 0.5, "highest-confidence instance must be kept"
    assert sorted(ev.event_ids[0] for ev in h1.evidence) == ["e1", "e2", "e3"]
    assert h1.hosts == ["h1"]

    assert by_key[("REG-PERSIST-01", "h2")].hosts == ["h2"]
