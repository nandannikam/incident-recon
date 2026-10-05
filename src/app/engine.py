"""
Step 7 — Reasoning Engine.

Forward-chaining loop: run every rule against each node's graph-local
neighborhood until fixpoint or MAX_ITERATIONS; dedupe by identity hash so
the loop converges. Matching is per-node neighborhood, NOT rules ×
all-events (roadmap risk table "Matching cost"), with neighborhoods
time-window filtered to curb the near-clique edge explosion
(KNOWN-ISSUES #5).
"""

from __future__ import annotations

import logging
from datetime import timedelta

import networkx as nx

from app.models import TIME_WINDOW_MINUTES, Conclusion
from app.rules.registry import RULES, RuleFunc

log = logging.getLogger("incident.engine")

MAX_ITERATIONS = 10
TIME_WINDOW = timedelta(minutes=TIME_WINDOW_MINUTES)


def _neighborhood(graph: nx.DiGraph, node_id: str) -> list:
    """The node's event plus in-window one-hop neighbors (rules filter further)."""
    center = graph.nodes[node_id]["event"]
    events = [center]
    for nbr in nx.all_neighbors(graph, node_id):
        if nbr == node_id:
            continue
        event = graph.nodes[nbr].get("event")
        if event is None:
            continue
        if (
            abs((event.timestamp - center.timestamp).total_seconds())
            <= TIME_WINDOW.total_seconds()
        ):
            events.append(event)
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

    conclusions: list[Conclusion] = []
    seen_hashes: set[str] = set()

    for iteration in range(1, MAX_ITERATIONS + 1):
        new_conclusions: list[Conclusion] = []

        for node_id in graph.nodes:
            neighborhood = _neighborhood(graph, node_id)
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
