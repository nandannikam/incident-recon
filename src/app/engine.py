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


def analyze(
    graph: nx.DiGraph,
    rules: list[RuleFunc] | None = None,
) -> list[Conclusion]:
    """Forward chain until fixpoint or MAX_ITERATIONS, deduping by identity.

    Each pass hands the accumulated conclusions back as ``facts`` so chained
    rules fire once their prerequisite exists.
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

    return conclusions
