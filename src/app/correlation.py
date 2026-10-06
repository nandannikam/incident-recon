"""Phase 3 Step 4 -- cross-host correlation and the kill-chain narrative.

Rules stay same-host on purpose (links by time alone re-introduce false
positives). This layer runs AFTER the engine and links conclusions on
different hosts only through a shared concrete object: a public destination
IP, a dropped-file path or hash, or a persistence registry key.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import networkx as nx

from app.models import Conclusion, Event, EventType
from app.rules.registry import _destination_ip_is_public, _is_persistence_registry_key

KILL_CHAIN_ORDER: tuple[str, ...] = (
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)

_MAX_LINKS_IN_SUMMARY = 5
_HASH_RE = re.compile(r"\b(SHA256|SHA1|MD5)=([0-9A-Fa-f]{32,64})\b")


@dataclass(frozen=True)
class CrossHostLink:
    kind: str
    value: str
    hosts: tuple[str, ...]
    conclusion_ids: tuple[str, ...]


def _host_of(event: Event) -> str:
    return str(event.metadata.get("_host_norm") or event.source)


def _event_objects(event: Event) -> set[tuple[str, str]]:
    """Concrete shared objects an event exposes (kind, normalized value)."""
    objects: set[tuple[str, str]] = set()
    if event.event_type == EventType.NETWORK_CONNECTION:
        if _destination_ip_is_public(event):
            raw = (
                event.metadata.get("DestinationIp")
                or event.metadata.get("_ip_norm")
                or event.target
            )
            objects.add(("ip", str(raw).strip()))
    elif event.event_type == EventType.REGISTRY_MODIFICATION:
        if _is_persistence_registry_key(event.target):
            objects.add(("registry key", event.target.strip().lower()))
    elif event.event_type in (EventType.FILE_DOWNLOAD, EventType.FILE_CREATION):
        target = event.target.strip().lower()
        if target and target != "unknown":
            objects.add(("file", target))
        for algo, digest in _HASH_RE.findall(str(event.metadata.get("Hashes") or "")):
            objects.add((f"{algo.lower()} hash", digest.lower()))
    return objects


def find_cross_host_links(
    graph: nx.DiGraph, conclusions: list[Conclusion]
) -> list[CrossHostLink]:
    """Objects that appear in the evidence of conclusions on 2+ hosts."""
    index: dict[tuple[str, str], tuple[set[str], set[str]]] = {}
    for conclusion in conclusions:
        for evidence in conclusion.evidence:
            for event_id in evidence.event_ids:
                if not graph.has_node(event_id):
                    continue
                event = graph.nodes[event_id].get("event")
                if event is None:
                    continue
                host = _host_of(event)
                for obj in _event_objects(event):
                    hosts, ids = index.setdefault(obj, (set(), set()))
                    hosts.add(host)
                    ids.add(conclusion.conclusion_id)
    return [
        CrossHostLink(kind, value, tuple(sorted(hosts)), tuple(sorted(ids)))
        for (kind, value), (hosts, ids) in sorted(index.items())
        if len(hosts) >= 2
    ]


def _rank(tactic: str) -> int:
    try:
        return KILL_CHAIN_ORDER.index(tactic)
    except ValueError:
        return len(KILL_CHAIN_ORDER)


def order_by_kill_chain(conclusions: list[Conclusion]) -> list[Conclusion]:
    """Kill-chain order; ties by higher confidence, then rule id and host."""
    return sorted(
        conclusions,
        key=lambda c: (_rank(c.tactic), -(c.confidence or 0.0), c.rule_id, c.hosts),
    )


def _join(items: list[str] | tuple[str, ...]) -> str:
    items = list(items)
    if len(items) <= 2:
        return " and ".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def build_summary(
    event_count: int,
    skipped: int,
    conclusions: list[Conclusion],
    links: list[CrossHostLink],
) -> str:
    """Counts sentence (kept for compatibility) plus the ordered narrative."""
    base = (
        f"Analyzed {event_count} events "
        f"(skipped {skipped} malformed rows), "
        f"found {len(conclusions)} conclusions."
    )
    if not conclusions:
        return base + " No malicious activity reconstructed from this dataset."

    ordered = order_by_kill_chain(conclusions)
    all_hosts = sorted({h for c in ordered for h in c.hosts})
    parts = [
        base,
        f"Kill-chain reconstruction across {len(all_hosts)} host(s):",
    ]
    for number, c in enumerate(ordered, start=1):
        where = _join(c.hosts) if c.hosts else "unknown host"
        parts.append(
            f"{number}) {c.tactic} ({c.technique_id}) on {where}, "
            f"confidence {(c.confidence or 0.0):.0%}: {c.description}"
        )
    for link in links[:_MAX_LINKS_IN_SUMMARY]:
        parts.append(
            f"Cross-host link: {_join(link.hosts)} share {link.kind} {link.value}."
        )
    if len(links) > _MAX_LINKS_IN_SUMMARY:
        parts.append(f"(+{len(links) - _MAX_LINKS_IN_SUMMARY} more cross-host links)")
    return " ".join(parts)
