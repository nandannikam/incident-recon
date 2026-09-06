"""
Step 5 — Graph Builder.

Events become nodes keyed by ``event_id``; edges per ``models.EdgeType``
(no same_user/same_host edges — see EdgeType docstring).

Gotchas: followed_by links all in-window pairs (inclusive boundary);
same_object is symmetric; multi-kind pairs get a list ``kind`` because
DiGraph can't hold parallel edges — read via ``edge_kinds()``.

KNOWN-ISSUES Phase 2 #3 (edge explosion) fix: both ``followed_by`` (all
in-window pairs) and ``same_object`` (cliques within a target group) are
combinatorial in the group/window size. Measured on real data: 1,052
events -> 1,105,652 edges; 10,377 events -> build_graph did not return
within 60s. Neither edge type actually needs to be a complete graph for
the reasoning engine to work — ``analyze()`` only ever looks at a node's
*local* neighborhood (see engine.py), so capping fan-out per node loses
no detections the engine would otherwise use, while bounding worst-case
edge count to O(nodes * MAX_EDGES_PER_NODE_PER_KIND) instead of O(nodes^2).
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

import networkx as nx

from app.models import TIME_WINDOW_MINUTES, EdgeType, Event

log = logging.getLogger("incident.graph")

TIME_WINDOW = timedelta(minutes=TIME_WINDOW_MINUTES)

# Hard cap on how many followed_by / same_object edges a single event can
# accumulate. Chosen generously above what any of the Phase 1/2 rules need
# (they only ever look one or two hops out), while keeping worst-case graph
# size linear in event count instead of quadratic. Override via
# build_graph(..., max_edges_per_node=...) for datasets known to need more.
DEFAULT_MAX_EDGES_PER_NODE_PER_KIND = 50


def _normalize_pid(value: Any) -> str:
    """Normalize pid/parentpid — real logs mix int, string, and float forms (2048.0)."""
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return str(value).strip()


def _add_edge(graph: nx.DiGraph, u: str, v: str, kind: str) -> None:
    """Add an edge; merge ``kind`` into a list when the pair already has one
    (DiGraph can't hold parallel edges)."""
    if graph.has_edge(u, v):
        existing = graph.edges[u, v].get("kind")
        kinds: list[str] = list(existing) if isinstance(existing, list) else []
        if isinstance(existing, str):
            kinds.append(existing)
        if kind not in kinds:
            kinds.append(kind)
        graph.edges[u, v]["kind"] = kinds
    else:
        graph.add_edge(u, v, kind=kind)


def edge_kinds(graph: nx.DiGraph, u: str, v: str) -> set[str]:
    """All kinds on the u->v edge (empty if none); normalizes merged
    multi-kind edges."""
    if not graph.has_edge(u, v):
        return set()
    kind = graph.edges[u, v].get("kind")
    if isinstance(kind, list):
        return {k for k in kind if isinstance(k, str)}
    if isinstance(kind, str):
        return {kind}
    return set()


def _count_kinds(graph: nx.DiGraph) -> dict[str, int]:
    counts: dict[str, int] = {}
    for _, _, data in graph.edges(data=True):
        kind = data.get("kind")
        kinds = kind if isinstance(kind, list) else [kind]
        for k in kinds:
            if isinstance(k, str):
                counts[k] = counts.get(k, 0) + 1
    return counts


def build_graph(
    events: list[Event],
    max_edges_per_node: int = DEFAULT_MAX_EDGES_PER_NODE_PER_KIND,
) -> nx.DiGraph:
    """Build the event graph; sorts first so any input order yields the same graph.

    ``max_edges_per_node`` bounds fan-out for ``followed_by`` and
    ``same_object`` edges (KNOWN-ISSUES #3): once a node has accumulated
    this many edges of a given kind, no further edges of that kind are
    added FROM that node. This keeps worst-case edge count linear in the
    number of events instead of quadratic, without changing the graph at
    all for datasets small enough to never hit the cap (e.g. the Phase 1
    attack_sample.csv / benign_sample.csv fixtures).
    """
    graph = nx.DiGraph()
    ordered = sorted(events, key=lambda e: e.timestamp)

    for event in ordered:
        graph.add_node(event.event_id, event=event)

    # Sorted input: once the gap exceeds the window, nothing later matches — break is safe.
    # Fan-out cap: stop adding followed_by edges FROM `a` once it has
    # max_edges_per_node of them, but keep scanning (via `continue`, not
    # `break` on the cap) since the time-window break must still apply.
    followed_by_count: dict[str, int] = {}
    for i, a in enumerate(ordered):
        for b in ordered[i + 1 :]:
            if b.timestamp - a.timestamp > TIME_WINDOW:
                break
            if followed_by_count.get(a.event_id, 0) >= max_edges_per_node:
                break  # `a` is saturated; later b's are even further away, still saturated
            _add_edge(graph, a.event_id, b.event_id, EdgeType.FOLLOWED_BY.value)
            followed_by_count[a.event_id] = followed_by_count.get(a.event_id, 0) + 1

    by_pid: dict[str, Event] = {}
    for event in ordered:
        pid = event.metadata.get("pid")
        if pid is not None:
            by_pid[_normalize_pid(pid)] = event
    for event in ordered:
        ppid = event.metadata.get("parentpid")
        if ppid is not None:
            parent = by_pid.get(_normalize_pid(ppid))
            if parent is not None:
                _add_edge(
                    graph, parent.event_id, event.event_id, EdgeType.SPAWNED.value
                )

    # same_object is symmetric — add both directions, capped per node so a
    # single very common target (e.g. a shared temp path) can't create a
    # clique across thousands of events.
    by_target: dict[str, list[Event]] = {}
    for event in ordered:
        by_target.setdefault(event.target, []).append(event)

    same_object_count: dict[str, int] = {}
    for group in by_target.values():
        for i, a in enumerate(group):
            for b in group[i + 1 :]:
                if (
                    same_object_count.get(a.event_id, 0) >= max_edges_per_node
                    or same_object_count.get(b.event_id, 0) >= max_edges_per_node
                ):
                    continue  # skip this pair, but keep checking others in the group
                _add_edge(graph, a.event_id, b.event_id, EdgeType.SAME_OBJECT.value)
                _add_edge(graph, b.event_id, a.event_id, EdgeType.SAME_OBJECT.value)
                same_object_count[a.event_id] = same_object_count.get(a.event_id, 0) + 1
                same_object_count[b.event_id] = same_object_count.get(b.event_id, 0) + 1

    log.info(
        "Built graph: %d nodes, %d edges (%s)",
        graph.number_of_nodes(),
        graph.number_of_edges(),
        ", ".join(f"{k}={n}" for k, n in sorted(_count_kinds(graph).items())),
    )
    return graph
