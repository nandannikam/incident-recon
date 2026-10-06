"""
Step 5 — Graph Builder.

Events become nodes keyed by ``event_id``; edges per ``models.EdgeType``
(no same_user/same_host edges — see EdgeType docstring).

Gotchas: followed_by links all in-window pairs (inclusive boundary);
same_object is symmetric; multi-kind pairs get a list ``kind`` because
DiGraph can't hold parallel edges — read via ``edge_kinds()``.

Phase 3 Step 3 — relevance-ordered capping (replaces the single
``MAX_EDGES_PER_NODE_PER_KIND`` cap from Phase 2's KNOWN-ISSUES #3 fix):

  * ``spawned`` edges are parent/child facts from the log and are ALWAYS
    added in full — they are sparse, high-signal, and dropping one would
    drop the relationship the rules exist to find.
  * ``same_object`` edges link events that share a concrete object (file,
    registry key, IP). They are high-signal, so the budget is generous
    (``DEFAULT_MAX_SAME_OBJECT_PER_NODE``): small/real groups are kept as a
    complete clique, and only a pathologically common target (e.g. the
    synthetic generator reuses seven process-image names for thousands of
    rows) is bounded. Within a bounded group the nearest-in-time edges are
    kept, because every current rule pairs events within the time window.
  * ``followed_by`` edges are the dense, low-signal kind (all in-window
    pairs) and are capped tightly by proximity. Input is timestamp-sorted,
    so the FIRST K successors of an event are its nearest successors;
    capping there keeps the temporally adjacent pairs the rules actually
    pair on and drops only far-away noise inside the window.

The budgets were chosen against the 10,000-event synthetic workload (seed
7) and the seven golden datasets. ``followed_by`` is set to the smallest
value that keeps every golden conclusion identical: the injected chain's
process execution and its network connection are 40s apart with ~13 noise
events between, so the nearest-successor edge only survives at K >= 15.
``same_object`` is left at its previous generous value — golden object
groups never reach it, so they stay complete cliques.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

import networkx as nx

from app.models import TIME_WINDOW_MINUTES, EdgeType, Event

log = logging.getLogger("incident.graph")

TIME_WINDOW = timedelta(minutes=TIME_WINDOW_MINUTES)

# Cap on followed_by edges FROM one event: keep the K nearest successors.
# 15 is the smallest value that still connects the injected chain's process
# execution to its network connection (40s apart, ~13 noise events between)
# on the 10k synthetic workload; it also keeps every golden dataset's
# conclusions identical while cutting the 10k graph from ~620k to ~274k
# edges and graph+reasoning from ~12s to ~3.2s.
DEFAULT_MAX_FOLLOWED_BY_PER_NODE = 15

# Cap on same_object edges per event: left at the Phase 2 value, so the
# high-signal kind is as generous as it ever was. Golden datasets' object
# groups are far below this and stay complete cliques; only a target reused
# by hundreds of events (e.g. the synthetic generator's seven shared
# process-image names) is ordered by proximity and bounded.
DEFAULT_MAX_SAME_OBJECT_PER_NODE = 50

# Backward-compatible alias for the single Phase 2 cap. Kept so any caller
# (and the module's public surface) that imported the old name still works;
# it now bounds same_object, the high-signal kind, matching its spirit.
DEFAULT_MAX_EDGES_PER_NODE_PER_KIND = DEFAULT_MAX_SAME_OBJECT_PER_NODE


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


def _add_followed_by_edges(
    graph: nx.DiGraph, ordered: list[Event], max_followed_by: int
) -> None:
    """Add temporal edges between events within the window, keeping only the
    nearest ``max_followed_by`` successors of each event.

    ``ordered`` is timestamp-sorted, so ``ordered[i+1]`` onward is increasing
    in time: the first K successors are the closest ones. Iterating by index
    (rather than slicing ``ordered[i+1:]``) avoids copying the tail list on
    every outer iteration, which was O(n^2) allocation.
    """
    n = len(ordered)
    followed_by_count: dict[str, int] = {}
    for i in range(n):
        a = ordered[i]
        if followed_by_count.get(a.event_id, 0) >= max_followed_by:
            # Already saturated; the inner loop would break without adding.
            continue
        for j in range(i + 1, n):
            b = ordered[j]
            if b.timestamp - a.timestamp > TIME_WINDOW:
                break
            if followed_by_count.get(a.event_id, 0) >= max_followed_by:
                break  # `a` is saturated; later b's are even further away
            _add_edge(graph, a.event_id, b.event_id, EdgeType.FOLLOWED_BY.value)
            followed_by_count[a.event_id] = followed_by_count.get(a.event_id, 0) + 1


def _add_spawned_edges(graph: nx.DiGraph, ordered: list[Event]) -> None:
    """Add parent -> child edges from pid/parentpid metadata.

    Sparse and definitional, so these are never capped.
    """
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


def _add_same_object_edges(
    graph: nx.DiGraph, ordered: list[Event], max_same_object: int
) -> None:
    """Add symmetric edges between events sharing a target, nearest-in-time
    first within each target group.

    Groups up to ``max_same_object + 1`` events become complete cliques
    (unchanged from the uncapped graph). Larger groups are relevance-ordered:
    each event links to its next ``max_same_object`` successors in the group,
    which for a target group built from timestamp-sorted events are the
    temporally closest sharers — the ones any window-bounded rule can use.
    """
    by_target: dict[str, list[Event]] = {}
    for event in ordered:
        by_target.setdefault(event.target, []).append(event)

    same_object_count: dict[str, int] = {}
    for group in by_target.values():
        size = len(group)
        for i in range(size):
            a = group[i]
            if same_object_count.get(a.event_id, 0) >= max_same_object:
                continue
            for j in range(i + 1, size):
                if same_object_count.get(a.event_id, 0) >= max_same_object:
                    break
                b = group[j]
                if same_object_count.get(b.event_id, 0) >= max_same_object:
                    continue
                _add_edge(graph, a.event_id, b.event_id, EdgeType.SAME_OBJECT.value)
                _add_edge(graph, b.event_id, a.event_id, EdgeType.SAME_OBJECT.value)
                same_object_count[a.event_id] = same_object_count.get(a.event_id, 0) + 1
                same_object_count[b.event_id] = same_object_count.get(b.event_id, 0) + 1


def build_graph(
    events: list[Event],
    max_edges_per_node: int = DEFAULT_MAX_SAME_OBJECT_PER_NODE,
    *,
    max_followed_by: int = DEFAULT_MAX_FOLLOWED_BY_PER_NODE,
) -> nx.DiGraph:
    """Build the event graph; sorts first so any input order yields the same graph.

    ``max_edges_per_node`` bounds ``same_object`` fan-out per event (kept
    under the legacy name for callers that passed the single Phase 2 cap).
    ``max_followed_by`` bounds the dense temporal edges by proximity. Small
    datasets never reach either budget, so their graph is byte-for-byte the
    same as the uncapped one.
    """
    graph = nx.DiGraph()
    ordered = sorted(events, key=lambda e: e.timestamp)

    for event in ordered:
        graph.add_node(event.event_id, event=event)

    _add_followed_by_edges(graph, ordered, max_followed_by)
    _add_spawned_edges(graph, ordered)
    _add_same_object_edges(graph, ordered, max_edges_per_node)

    log.info(
        "Built graph: %d nodes, %d edges (%s)",
        graph.number_of_nodes(),
        graph.number_of_edges(),
        ", ".join(f"{k}={n}" for k, n in sorted(_count_kinds(graph).items())),
    )
    return graph
