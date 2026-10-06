"""Phase 3 Step 4 -- kill-chain ordering, narrative, cross-host links."""

from __future__ import annotations

from datetime import datetime, timedelta

import networkx as nx

from app.correlation import (
    build_summary,
    find_cross_host_links,
    order_by_kill_chain,
)
from app.engine import analyze
from app.models import Conclusion, Event, EventType, Evidence

T0 = datetime(2020, 5, 1, 12, 0, 0)


def _event(n: int, host: str, etype: EventType, target: str, minute: int, **meta):
    return Event(
        event_id=f"synthetic.csv:{n}",
        timestamp=T0 + timedelta(minutes=minute),
        source=host,
        event_type=etype,
        actor="alice",
        target=target,
        metadata=dict(meta),
    )


def _graph(events: list[Event], edges: list[tuple[int, int]]) -> nx.DiGraph:
    graph = nx.DiGraph()
    for event in events:
        graph.add_node(event.event_id, event=event)
    for a, b in edges:
        graph.add_edge(f"synthetic.csv:{a}", f"synthetic.csv:{b}")
    return graph


def _two_host_campaign(second_target: str = "c:\\temp\\payload.exe"):
    events = [
        _event(1, "hostA", EventType.POWERSHELL_EXECUTION, "powershell.exe", 0),
        _event(2, "hostA", EventType.FILE_DOWNLOAD, "c:\\temp\\payload.exe", 1),
        _event(3, "hostB", EventType.POWERSHELL_EXECUTION, "powershell.exe", 2),
        _event(4, "hostB", EventType.FILE_DOWNLOAD, second_target, 3),
        _event(5, "hostB", EventType.LOG_DELETION, "Security", 4),
    ]
    return _graph(events, [(1, 2), (3, 4)])


def test_multi_host_campaign_is_ordered_and_linked() -> None:
    graph = _two_host_campaign()
    conclusions = analyze(graph)
    ordered = order_by_kill_chain(conclusions)

    assert [c.tactic for c in ordered] == ["Execution", "Execution", "Defense Evasion"]

    links = find_cross_host_links(graph, ordered)
    assert [(l.kind, l.hosts) for l in links] == [("file", ("hostA", "hostB"))]

    summary = build_summary(5, 0, ordered, links)
    assert summary.index("Execution") < summary.index("Defense Evasion")
    assert "Cross-host link: hostA and hostB share file" in summary
    assert "found 3 conclusions" in summary


def test_different_objects_do_not_link_hosts() -> None:
    graph = _two_host_campaign(second_target="c:\\temp\\other.exe")
    assert find_cross_host_links(graph, analyze(graph)) == []


def test_single_host_never_links() -> None:
    events = [
        _event(1, "hostA", EventType.POWERSHELL_EXECUTION, "powershell.exe", 0),
        _event(2, "hostA", EventType.FILE_DOWNLOAD, "c:\\temp\\payload.exe", 1),
    ]
    graph = _graph(events, [(1, 2)])
    assert find_cross_host_links(graph, analyze(graph)) == []


def _net_conclusion(n: int, host: str, ip: str) -> tuple[Event, Conclusion]:
    event = _event(
        n, host, EventType.NETWORK_CONNECTION, ip, n, DestinationIp=ip
    )
    conclusion = Conclusion(
        conclusion_id=f"c{n}",
        rule_id="C2-BEACON-01",
        technique_id="T1071",
        tactic="Command and Control",
        description="beacon",
        evidence=[Evidence(event_ids=[event.event_id], explanation="x")],
        hosts=[host],
    )
    return event, conclusion


def test_shared_public_ip_links_but_private_ip_does_not() -> None:
    for ip, expected in (("93.184.216.34", 1), ("10.0.0.5", 0)):
        ea, ca = _net_conclusion(1, "hostA", ip)
        eb, cb = _net_conclusion(2, "hostB", ip)
        graph = _graph([ea, eb], [])
        links = find_cross_host_links(graph, [ca, cb])
        assert len(links) == expected
        if expected:
            assert links[0].kind == "ip"


def test_unknown_tactic_sorts_last_and_empty_summary() -> None:
    _, known = _net_conclusion(1, "hostA", "93.184.216.34")
    odd = known.model_copy(update={"conclusion_id": "c9", "tactic": "Mystery"})
    assert order_by_kill_chain([odd, known])[-1].tactic == "Mystery"
    assert "No malicious activity" in build_summary(10, 0, [], [])


def _reg_conclusion(n: int, host: str, key: str) -> tuple[Event, Conclusion]:
    event = _event(n, host, EventType.REGISTRY_MODIFICATION, key, n)
    conclusion = Conclusion(
        conclusion_id=f"r{n}",
        rule_id="REG-PERSIST-01",
        technique_id="T1547.001",
        tactic="Persistence",
        description="persistence",
        evidence=[Evidence(event_ids=[event.event_id], explanation="x")],
        hosts=[host],
    )
    return event, conclusion


def test_registry_link_needs_a_real_autorun_key() -> None:
    cases = (
        ("hklm\\system\\currentcontrolset\\services\\tcpip\\parameters", 0),
        ("hklm\\software\\microsoft\\windows\\currentversion\\run\\evil", 1),
    )
    for key, expected in cases:
        ea, ca = _reg_conclusion(1, "hostA", key)
        eb, cb = _reg_conclusion(2, "hostB", key)
        links = find_cross_host_links(_graph([ea, eb], []), [ca, cb])
        assert len(links) == expected, key
