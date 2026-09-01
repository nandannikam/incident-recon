"""Step 5 tests — Graph Builder."""

from datetime import UTC, datetime
from pathlib import Path

from app.graph import build_graph, edge_kinds
from app.models import EdgeType, Event, EventType

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


def _event(
    event_id: str,
    timestamp: str,
    *,
    event_type: str = "process_execution",
    actor: str = "USER01",
    source: str = "HOST01",
    target: str | None = None,
    metadata: dict | None = None,
) -> Event:
    return Event(
        event_id=event_id,
        timestamp=datetime.fromisoformat(timestamp).astimezone(UTC),
        source=source,
        event_type=EventType(event_type),
        actor=actor,
        # Unique targets by default — a shared one would add same_object edges.
        target=target if target is not None else f"obj-{event_id}",
        metadata=metadata or {},
    )


def test_followed_by_chain_within_window() -> None:
    a = _event("a", "2024-01-01T10:00:00Z")
    b = _event("b", "2024-01-01T10:01:00Z")
    c = _event("c", "2024-01-01T10:02:00Z")

    g = build_graph([a, b, c])

    # All pairs within the window, hence A -> C too.
    assert g.has_edge("a", "b")
    assert g.has_edge("b", "c")
    assert g.has_edge("a", "c")
    assert edge_kinds(g, "a", "b") == {EdgeType.FOLLOWED_BY.value}
    # Directed: no reverse edges.
    assert not g.has_edge("b", "a")
    assert not g.has_edge("c", "a")


def test_followed_by_respects_time_window_boundary() -> None:
    a = _event("a", "2024-01-01T10:00:00Z")
    b = _event("b", "2024-01-01T10:05:00Z")  # exactly 5 min — inclusive boundary
    c = _event("c", "2024-01-01T10:11:00Z")  # 11/6 min out — no edges

    g = build_graph([a, b, c])

    assert g.has_edge("a", "b")
    assert not g.has_edge("a", "c")
    assert not g.has_edge("b", "c")


def test_spawned_edges_from_parentpid() -> None:
    parent = _event(
        "p", "2024-01-01T10:00:00Z", target="parent.exe", metadata={"pid": 2048}
    )
    child = _event(
        "c",
        "2024-01-01T11:00:00Z",  # outside window: spawned edge only
        target="child.exe",
        metadata={"pid": 2100, "parentpid": 2048},
    )
    orphan = _event(
        "o", "2024-01-01T12:00:00Z", target="orphan.exe", metadata={"pid": 9999}
    )

    g = build_graph([parent, child, orphan])

    assert g.has_edge("p", "c")
    assert edge_kinds(g, "p", "c") == {EdgeType.SPAWNED.value}
    # No event has pid 9999, so the orphan gets no edge.
    assert not g.has_edge("o", "p")
    assert not g.has_edge("p", "o")


def test_spawned_matches_across_int_and_str_pid_types() -> None:
    parent = _event("p", "2024-01-01T10:00:00Z", metadata={"pid": 2048})
    child = _event("c", "2024-01-01T11:00:00Z", metadata={"parentpid": "2048"})

    g = build_graph([parent, child])

    assert g.has_edge("p", "c")
    assert edge_kinds(g, "p", "c") == {EdgeType.SPAWNED.value}


def test_same_object_edges_are_bidirectional() -> None:
    a = _event("a", "2024-01-01T10:00:00Z", target="C:\\temp\\invoice.exe")
    b = _event(
        "b", "2024-01-01T11:00:00Z", target="C:\\temp\\invoice.exe"
    )  # far apart: same_object only

    g = build_graph([a, b])

    assert g.has_edge("a", "b")
    assert g.has_edge("b", "a")
    assert edge_kinds(g, "a", "b") == {EdgeType.SAME_OBJECT.value}
    assert edge_kinds(g, "b", "a") == {EdgeType.SAME_OBJECT.value}


def test_isolated_event_has_no_edges() -> None:
    g = build_graph([_event("a", "2024-01-01T10:00:00Z")])

    assert g.number_of_nodes() == 1
    assert g.number_of_edges() == 0
    assert g.degree("a") == 0


def test_no_same_user_or_same_host_edges() -> None:
    """Clique explosion: shared actor/source must not become edges."""
    a = _event("a", "2024-01-01T10:00:00Z", target="file1.txt")
    b = _event("b", "2024-01-01T11:00:00Z", target="file2.txt")
    c = _event("c", "2024-01-01T12:00:00Z", target="file3.txt")

    g = build_graph([a, b, c])

    assert g.number_of_edges() == 0
    assert all(g.degree(n) == 0 for n in g.nodes)


def test_node_attributes_store_the_event_object() -> None:
    a = _event("a", "2024-01-01T10:00:00Z")

    g = build_graph([a])

    assert g.nodes["a"]["event"] is a
    assert g.nodes["a"]["event"].event_id == "a"


def test_unsorted_input_yields_same_followed_by_edges() -> None:
    a = _event("a", "2024-01-01T10:00:00Z")
    b = _event("b", "2024-01-01T10:01:00Z")
    c = _event("c", "2024-01-01T10:02:00Z")

    sorted_g = build_graph([a, b, c])
    unsorted_g = build_graph([c, a, b])

    assert sorted_g.edges() == unsorted_g.edges()


def test_multi_relation_edge_merges_kinds() -> None:
    a = _event("a", "2024-01-01T10:00:00Z", target="185.220.101.1")
    b = _event("b", "2024-01-01T10:02:30Z", target="185.220.101.1")

    g = build_graph([a, b])

    assert g.has_edge("a", "b")
    assert edge_kinds(g, "a", "b") == {
        EdgeType.FOLLOWED_BY.value,
        EdgeType.SAME_OBJECT.value,
    }
    # Reverse: only the symmetric same_object kind.
    assert edge_kinds(g, "b", "a") == {EdgeType.SAME_OBJECT.value}


def test_attack_sample_builds_expected_graph() -> None:
    from app.parser import parse_log

    result = parse_log(str(DATA_DIR / "attack_sample.csv"))
    assert result.skipped == 0

    g = build_graph(result.events)

    assert g.number_of_nodes() == len(result.events)

    def by_pid(pid: int) -> str:
        return next(e.event_id for e in result.events if e.metadata.get("pid") == pid)

    # All events are in-window, so spawned pairs also carry followed_by —
    # assert membership, not equality.
    invoice = by_pid(2048)
    cmd = by_pid(2100)
    psh_2150 = by_pid(2150)
    psh_2200 = by_pid(2200)
    wevtutil = by_pid(2300)
    assert EdgeType.SPAWNED.value in edge_kinds(g, invoice, cmd)
    assert EdgeType.SPAWNED.value in edge_kinds(g, cmd, psh_2150)
    assert EdgeType.SPAWNED.value in edge_kinds(g, psh_2150, psh_2200)
    assert EdgeType.SPAWNED.value in edge_kinds(g, cmd, wevtutil)
    assert (
        edge_kinds(g, wevtutil, cmd) == set()
    )  # wevtutil's parent is cmd, not vice versa

    same_ip_events = [e for e in result.events if e.target == "185.220.101.1"]
    assert len(same_ip_events) == 2
    conn1, conn2 = same_ip_events[0].event_id, same_ip_events[1].event_id
    assert conn1 != conn2
    assert g.has_edge(conn1, conn2)
    assert g.has_edge(conn2, conn1)

    allowed = {e.value for e in EdgeType}
    for u, v in g.edges:
        assert edge_kinds(g, u, v) <= allowed
