"""
Step 6 — Knowledge Base.

Three MITRE ATT&CK rules as plain functions — no DSL (roadmap §Step 6).
Each rule takes (neighborhood, graph, facts) and returns a Conclusion with
concrete evidence event_ids, or None. `facts` holds prior Conclusions from
forward chaining; only the chained rule (PERSIST-ESTABLISHED-01) consumes
them — the signature stays uniform (see KNOWN-ISSUES #4).
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from datetime import timedelta

import networkx as nx

from app.models import (
    TIME_WINDOW_MINUTES,
    Conclusion,
    Event,
    EventType,
    Evidence,
)

log = logging.getLogger("incident.rules")

TIME_WINDOW = timedelta(minutes=TIME_WINDOW_MINUTES)

RuleFunc = Callable[[list[Event], nx.DiGraph, list[Conclusion]], Conclusion | None]


def _within_window(a: Event, b: Event) -> bool:
    return (
        abs((a.timestamp - b.timestamp).total_seconds()) <= TIME_WINDOW.total_seconds()
    )


def _same_host(a: Event, b: Event) -> bool:
    return a.source == b.source


def _prior_conclusions(facts: list[Conclusion], rule_id: str) -> list[Conclusion]:
    return [c for c in facts if c.rule_id == rule_id]


def _events_for_ids(
    conclusion: Conclusion,
    graph: nx.DiGraph,
    neighborhood: list[Event],
) -> list[Event]:
    """Resolve evidence ids to Events (neighborhood first, then graph);
    ids that resolve nowhere are skipped."""
    by_id = {e.event_id: e for e in neighborhood}
    ids = conclusion.evidence[0].event_ids if conclusion.evidence else []
    resolved: list[Event] = []
    for event_id in ids:
        event = by_id.get(event_id)
        if event is None and graph.has_node(event_id):
            event = graph.nodes[event_id].get("event")
        if event is not None:
            resolved.append(event)
    return resolved


def detect_registry_persistence(
    neighborhood: list[Event],
    graph: nx.DiGraph,
    facts: list[Conclusion],  # unused here — uniform rule signature
) -> Conclusion | None:
    """REG-PERSIST-01 (T1547.001): process_execution then registry_modification
    on the same host within the window — the classic autostart-key planting."""
    proc_execs = [
        e for e in neighborhood if e.event_type == EventType.PROCESS_EXECUTION
    ]
    reg_mods = [
        e for e in neighborhood if e.event_type == EventType.REGISTRY_MODIFICATION
    ]
    for proc in proc_execs:
        for reg in reg_mods:
            if (
                _same_host(proc, reg)
                and proc.timestamp <= reg.timestamp
                and _within_window(proc, reg)
            ):
                return Conclusion(
                    conclusion_id=uuid.uuid4().hex,
                    rule_id="REG-PERSIST-01",
                    technique_id="T1547.001",
                    tactic="Persistence",
                    description=(
                        "Possible registry-based persistence established: a process "
                        "execution was followed by a registry modification within the "
                        "time window."
                    ),
                    evidence=[
                        Evidence(
                            event_ids=[proc.event_id, reg.event_id],
                            explanation=(
                                f"Process {proc.actor} executed ({proc.target}), then "
                                f"registry key {reg.target} was modified on {proc.source} "
                                f"within {TIME_WINDOW_MINUTES} minutes."
                            ),
                        )
                    ],
                )
    return None


def detect_powershell_staging(
    neighborhood: list[Event],
    graph: nx.DiGraph,
    facts: list[Conclusion],  # unused here — uniform rule signature
) -> Conclusion | None:
    """PSH-STAGING-01 (T1059.001): powershell_execution then file_download on
    the same host within the window — fetching a payload before execution."""
    psh_execs = [
        e for e in neighborhood if e.event_type == EventType.POWERSHELL_EXECUTION
    ]
    downloads = [e for e in neighborhood if e.event_type == EventType.FILE_DOWNLOAD]
    for psh in psh_execs:
        for download in downloads:
            if (
                _same_host(psh, download)
                and psh.timestamp <= download.timestamp
                and _within_window(psh, download)
            ):
                return Conclusion(
                    conclusion_id=uuid.uuid4().hex,
                    rule_id="PSH-STAGING-01",
                    technique_id="T1059.001",
                    tactic="Execution",
                    description=(
                        "Possible PowerShell staging activity: PowerShell execution "
                        "followed by a file download within the time window."
                    ),
                    evidence=[
                        Evidence(
                            event_ids=[psh.event_id, download.event_id],
                            explanation=(
                                f"PowerShell ({psh.target}) executed on {psh.source}, "
                                f"then downloaded {download.target} within "
                                f"{TIME_WINDOW_MINUTES} minutes."
                            ),
                        )
                    ],
                )
    return None


def detect_persistence_established(
    neighborhood: list[Event],
    graph: nx.DiGraph,
    facts: list[Conclusion],
) -> Conclusion | None:
    """PERSIST-ESTABLISHED-01 (T1547.001) — CHAINED: consumes a prior
    PSH-STAGING-01 conclusion and fires when a registry_modification lands
    within the window of that staging. Evidence = staging ids + registry
    event, with parent_conclusion_id set."""
    reg_mods = [
        e for e in neighborhood if e.event_type == EventType.REGISTRY_MODIFICATION
    ]
    if not reg_mods:
        return None

    for staging in _prior_conclusions(facts, "PSH-STAGING-01"):
        staging_events = _events_for_ids(staging, graph, neighborhood)
        if not staging_events:
            continue
        for reg in reg_mods:
            if any(
                _same_host(s, reg) and _within_window(s, reg) for s in staging_events
            ):
                return Conclusion(
                    conclusion_id=uuid.uuid4().hex,
                    rule_id="PERSIST-ESTABLISHED-01",
                    technique_id="T1547.001",
                    tactic="Persistence",
                    description=(
                        "Persistence established: PowerShell staging was followed by "
                        "a registry modification within the time window."
                    ),
                    evidence=[
                        Evidence(
                            event_ids=list(staging.evidence[0].event_ids)
                            + [reg.event_id],
                            explanation=(
                                f"Staging on {reg.source} was followed by registry key "
                                f"{reg.target} modification within "
                                f"{TIME_WINDOW_MINUTES} minutes, establishing "
                                "persistence."
                            ),
                            parent_conclusion_id=staging.conclusion_id,
                        )
                    ],
                )
    return None


def detect_network_beacon(
    neighborhood: list[Event],
    graph: nx.DiGraph,
    facts: list[Conclusion],  # unused here — uniform rule signature
) -> Conclusion | None:
    """C2-BEACON-01 (T1071): process_execution then network_connection on
    the same host within the window, where the connection's metadata
    reason marks it as C2 activity (not ordinary browsing/sync/video)."""
    proc_execs = [
        e for e in neighborhood if e.event_type == EventType.PROCESS_EXECUTION
    ]
    net_conns = [
        e
        for e in neighborhood
        if e.event_type == EventType.NETWORK_CONNECTION
        and "c2" in str(e.metadata.get("reason", "")).lower()
    ]
    for proc in proc_execs:
        for net in net_conns:
            if (
                _same_host(proc, net)
                and proc.timestamp <= net.timestamp
                and _within_window(proc, net)
            ):
                return Conclusion(
                    conclusion_id=uuid.uuid4().hex,
                    rule_id="C2-BEACON-01",
                    technique_id="T1071",
                    tactic="Command and Control",
                    description=(
                        "Possible C2 beacon: a process execution was followed by an "
                        "outbound network connection flagged as command-and-control "
                        "activity within the time window."
                    ),
                    evidence=[
                        Evidence(
                            event_ids=[proc.event_id, net.event_id],
                            explanation=(
                                f"Process {proc.actor} executed ({proc.target}) on "
                                f"{proc.source}, then connected to {net.target} within "
                                f"{TIME_WINDOW_MINUTES} minutes."
                            ),
                        )
                    ],
                )
    return None


def detect_log_deletion(
    neighborhood: list[Event],
    graph: nx.DiGraph,
    facts: list[Conclusion],  # unused here — uniform rule signature
) -> Conclusion | None:
    """LOG-CLEAR-01 (T1070): a log_deletion event on its own is evidence of
    defense evasion — no pairing needed, a single event is enough."""
    log_dels = [e for e in neighborhood if e.event_type == EventType.LOG_DELETION]
    for entry in log_dels:
        return Conclusion(
            conclusion_id=uuid.uuid4().hex,
            rule_id="LOG-CLEAR-01",
            technique_id="T1070",
            tactic="Defense Evasion",
            description=(
                "Possible defense evasion: security or system logs were cleared, "
                "likely to hide prior activity."
            ),
            evidence=[
                Evidence(
                    event_ids=[entry.event_id],
                    explanation=(
                        f"{entry.actor} cleared logs on {entry.source} "
                        f"({entry.target})."
                    ),
                )
            ],
        )
    return None


RULES: list[RuleFunc] = [
    detect_registry_persistence,
    detect_powershell_staging,
    detect_persistence_established,
    detect_network_beacon,
    detect_log_deletion,
]