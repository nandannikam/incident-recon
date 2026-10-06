"""
Step 7 — Reasoning Engine.

Forward-chaining loop: run every rule against each node's graph-local
neighborhood until fixpoint or MAX_ITERATIONS; dedupe by identity hash so
the loop converges. Matching is per-node neighborhood, NOT rules ×
all-events (roadmap risk table "Matching cost"), with neighborhoods
time-window filtered to curb the near-clique edge explosion
(KNOWN-ISSUES #5).

Phase 3 Step 3 — performance pass. Two things made this O(iterations ×
nodes × neighborhood) expensive on large graphs:

  * ``_neighborhood`` walked NetworkX ``all_neighbors`` (a report view
    with per-access overhead) and was rebuilt for every node on every
    forward-chaining iteration, even though the graph never changes.
  * Neighbors were visited through ``graph.nodes[...]`` report views too.

Now ``_GraphIndex`` is built ONCE per ``analyze()`` call: a plain
``node -> Event`` map, a plain adjacency map (``node -> [neighbor ids]``,
successors then predecessors to match ``all_neighbors``), the
``(event_type, source)`` and ``target`` candidate lookups requested by the
roadmap, and the fully materialized ``node -> [Event]`` neighborhoods.
The loop then reuses those lists, so no NetworkX neighbor traversal
happens per iteration.

The RuleFunc contract is unchanged: rules still receive a plain
``list[Event]`` neighborhood (with the center first) plus the graph and the
accumulated facts. Neighborhoods are a superset of each rule's own
event-type filtering, so detection is unaffected.
"""

from __future__ import annotations

import logging
from datetime import timedelta

import networkx as nx

from app.models import TIME_WINDOW_MINUTES, Conclusion, Event
from app.rules.registry import RULES, RuleFunc

log = logging.getLogger("incident.engine")

MAX_ITERATIONS = 10
TIME_WINDOW = timedelta(minutes=TIME_WINDOW_MINUTES)
_WINDOW_SECONDS = TIME_WINDOW.total_seconds()


class _GraphIndex:
    """Per-graph lookup tables, built once per ``analyze()`` call.

    The plain dictionaries replace NetworkX report views on the hot path;
    ``neighborhoods`` is materialized once and reused across forward-chaining
    iterations. ``by_type_source`` / ``by_target`` are the candidate lookups
    the Step 3 roadmap asks for, available to callers that want to inspect a
    node's candidates without re-walking the graph.
    """

    __slots__ = (
        "adjacency",
        "by_target",
        "by_type_source",
        "neighborhoods",
        "node_events",
    )

    def __init__(self, graph: nx.DiGraph) -> None:
        node_events: dict[str, Event] = {}
        for node_id in graph.nodes:
            event = graph.nodes[node_id].get("event")
            if event is not None:
                node_events[node_id] = event
        self.node_events = node_events

        # all_neighbors on a DiGraph yields successors then predecessors.
        # Append in that order; a pair carrying both directions (e.g. a
        # bidirectional same_object edge) appears twice, then we drop the
        # repeat while keeping the first occurrence so rule selection order
        # is unchanged from the NetworkX version.
        adjacency: dict[str, list[str]] = {node_id: [] for node_id in graph.nodes}
        for u, v in graph.edges:
            adjacency[u].append(v)
            adjacency[v].append(u)
        for node_id, neighbors in adjacency.items():
            if len(neighbors) > 1:
                seen: set[str] = set()
                adjacency[node_id] = [
                    nb for nb in neighbors if not (nb in seen or seen.add(nb))
                ]
        self.adjacency = adjacency

        by_type_source: dict[tuple, list[Event]] = {}
        by_target: dict[str, list[Event]] = {}
        for event in node_events.values():
            by_type_source.setdefault((event.event_type, event.source), []).append(
                event
            )
            by_target.setdefault(event.target, []).append(event)
        self.by_type_source = by_type_source
        self.by_target = by_target

        self.neighborhoods: dict[str, list[Event]] = {
            node_id: self._neighborhood(node_id) for node_id in graph.nodes
        }

    def _neighborhood(self, node_id: str) -> list[Event]:
        """The node's event plus in-window one-hop neighbors (rules filter further)."""
        center = self.node_events.get(node_id)
        if center is None:
            return []
        events = [center]
        center_timestamp = center.timestamp
        append = events.append
        for neighbor_id in self.adjacency.get(node_id, ()):
            event = self.node_events.get(neighbor_id)
            if event is None:
                continue
            if (
                abs((event.timestamp - center_timestamp).total_seconds())
                <= _WINDOW_SECONDS
            ):
                append(event)
        return events


def hash_conclusion(conclusion: Conclusion) -> str:
    """Identity for dedup: rule_id + sorted evidence event_ids + parent_conclusion_id."""
    parts = [conclusion.rule_id]
    for evidence in conclusion.evidence:
        parts.append("|".join(sorted(evidence.event_ids)))
        if evidence.parent_conclusion_id:
            parts.append(evidence.parent_conclusion_id)
    return ":".join(parts)


def _conclusion_hosts(graph: nx.DiGraph, conclusion: Conclusion) -> list[str]:
    """Hosts a conclusion's evidence came from, sorted and unique.

    The host key is the parser's normalized ``_host_norm`` when present
    (Mordor events), otherwise the raw ``source`` (CSV events are not
    normalized).
    """
    hosts: set[str] = set()
    for evidence in conclusion.evidence:
        for event_id in evidence.event_ids:
            if not graph.has_node(event_id):
                continue
            event = graph.nodes[event_id].get("event")
            if event is None:
                continue
            hosts.add(event.metadata.get("_host_norm") or event.source)
    return sorted(hosts)


def _populate_hosts(graph: nx.DiGraph, conclusions: list[Conclusion]) -> None:
    for conclusion in conclusions:
        conclusion.hosts = _conclusion_hosts(graph, conclusion)


def _merge_evidence(kept: Conclusion, other: Conclusion) -> None:
    """Append ``other``'s evidence to ``kept``, dropping duplicates keyed by
    ``(event_ids, parent_conclusion_id)``."""
    seen = {(tuple(e.event_ids), e.parent_conclusion_id) for e in kept.evidence}
    for evidence in other.evidence:
        key = (tuple(evidence.event_ids), evidence.parent_conclusion_id)
        if key in seen:
            continue
        seen.add(key)
        kept.evidence.append(evidence)


def cluster_conclusions(conclusions: list[Conclusion]) -> list[Conclusion]:
    """Collapse same-rule findings on the same host into a single conclusion.

    Group key is ``(rule_id, hosts[0])``; the highest-confidence instance wins
    and ties keep the first seen. Every other instance's evidence is merged
    into the winner (de-duplicated by ``(event_ids, parent_conclusion_id)``)
    and the hosts are unioned. First-seen key order is preserved so the same
    input always yields the same list.
    """
    best: dict[tuple[str, str], Conclusion] = {}
    order: list[tuple[str, str]] = []

    for conclusion in conclusions:
        key = (conclusion.rule_id, conclusion.hosts[0] if conclusion.hosts else "")
        incumbent = best.get(key)
        if incumbent is None:
            best[key] = conclusion
            order.append(key)
            continue
        if (conclusion.confidence or 0.0) > (incumbent.confidence or 0.0):
            _merge_evidence(conclusion, incumbent)
            conclusion.hosts = sorted(set(conclusion.hosts) | set(incumbent.hosts))
            best[key] = conclusion
        else:
            _merge_evidence(incumbent, conclusion)
            incumbent.hosts = sorted(set(incumbent.hosts) | set(conclusion.hosts))

    return [best[key] for key in order]


def analyze(
    graph: nx.DiGraph,
    rules: list[RuleFunc] | None = None,
) -> list[Conclusion]:
    """Forward chain until fixpoint or MAX_ITERATIONS, deduping by identity.

    Each pass hands the accumulated conclusions back as ``facts`` so chained
    rules fire once their prerequisite exists. Clustering happens only after
    the loop terminates, so chained rules still see every un-merged fact.
    """
    if rules is None:
        rules = list(RULES)

    index = _GraphIndex(graph)
    log.info(
        "Indexed %d nodes (%d candidate events).",
        len(index.node_events),
        len(index.by_type_source),
    )

    conclusions: list[Conclusion] = []
    seen_hashes: set[str] = set()

    for iteration in range(1, MAX_ITERATIONS + 1):
        new_conclusions: list[Conclusion] = []

        for node_id in graph.nodes:
            neighborhood = index.neighborhoods[node_id]
            if not neighborhood:
                continue
            for rule in rules:
                result = rule(neighborhood, graph, conclusions)
                if result is None:
                    continue
                identity = hash_conclusion(result)
                if identity in seen_hashes:
                    continue
                seen_hashes.add(identity)
                new_conclusions.append(result)

        if not new_conclusions:
            log.info(
                "Fixpoint reached after %d iteration(s); %d conclusion(s).",
                iteration,
                len(conclusions),
            )
            break

        conclusions.extend(new_conclusions)
        log.info(
            "Iteration %d: +%d new conclusion(s) (%d total).",
            iteration,
            len(new_conclusions),
            len(conclusions),
        )
    else:
        log.warning(
            "MAX_ITERATIONS (%d) reached with %d conclusion(s); stopping.",
            MAX_ITERATIONS,
            len(conclusions),
        )

    _populate_hosts(graph, conclusions)
    clustered = cluster_conclusions(conclusions)
    log.info(
        "Clustered %d conclusion(s) into %d (one per rule/host).",
        len(conclusions),
        len(clustered),
    )
    return clustered
