"""
Step 6 — Knowledge Base.

Five MITRE ATT&CK rules as plain functions — no DSL (roadmap §Step 6).
Each rule takes (neighborhood, graph, facts) and returns a Conclusion with
concrete evidence event_ids, or None. `facts` holds prior Conclusions from
forward chaining; only the chained rule (PERSIST-ESTABLISHED-01) consumes
them — the signature stays uniform.

KNOWN-ISSUES Phase 2 #4 fixes applied here:

  - detect_network_beacon previously required metadata["reason"] to
    contain "c2" -- a synthetic field that only ever existed in the
    hand-crafted attack_sample.csv. No real Sysmon/Mordor network event
    carries a "reason" field, so this rule fired 0 times on any real
    dataset. It now inspects real Sysmon EventID 3 fields with a
    documented, conservative heuristic: a non-benign destination port AND
    a destination IP that is public (not RFC1918 / loopback / link-local /
    multicast / reserved). This is intentionally conservative -- it is a
    heuristic, not a definitive C2 detector, and is documented as such
    below.

  - detect_registry_persistence previously fired on ANY
    process_execution + registry_modification pair within the window,
    with no check on which registry key was touched. On a real dataset
    (bitsadmin, 89 events) this produced 66 conclusions -- almost every
    process/registry pair in the file, which is noise, not signal. It now
    requires both (a) the registry key to match a known autostart /
    persistence location and (b) the process to be the one that actually
    wrote the key (Sysmon 13 "Image"), when the source records it. The
    synthetic CSV records no writer, so that case falls back to the old
    any-prior-process behaviour at a lower confidence.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import Any

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


def _normalize_image(value: Any) -> str | None:
    """Canonical process-image identity: strip surrounding quotes, lower-case.

    Real sources disagree on quoting and case (``"C:\\Windows\\cmd.exe"`` vs
    ``c:\\windows\\CMD.EXE``); the normalized form is what writer/process
    comparison uses. Empty values give None.
    """
    if value is None:
        return None
    text = str(value).strip()
    while len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1].strip()
    return text.lower() or None


def _image_from_metadata(event: Event) -> str | None:
    for key in ("Image", "NewProcessName", "New Process Name"):
        image = _normalize_image(event.metadata.get(key))
        if image is not None:
            return image
    return None


def _writer_image(reg: Event) -> str | None:
    """The process that wrote a registry key, or None when the source does
    not record it (e.g. the hand-crafted CSV, which carries only a value)."""
    return _image_from_metadata(reg)


def _process_image(proc: Event) -> str | None:
    """The image of a process_execution; falls back to ``target`` because the
    parser sets that to Image/NewProcessName when Sysmon omits one."""
    return _image_from_metadata(proc) or _normalize_image(proc.target)


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


# ---------------------------------------------------------------------------
# REG-PERSIST-01 — autostart-location allowlist (fixes over-firing, #4)
#
# Standard Windows persistence locations for T1547.001 (Registry Run Keys /
# Startup Folder). A registry_modification only counts as *persistence*
# evidence if its target touches one of these -- an arbitrary key write
# (e.g. an app writing its own settings) is not persistence.
# ---------------------------------------------------------------------------
_PERSISTENCE_REGISTRY_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\b",
        r"\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\b",
        r"\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices\b",
        r"\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\b",
        r"\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit\b",
        r"\\System\\CurrentControlSet\\Services\\",
        r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Startup",
    )
)


def _is_persistence_registry_key(target: str) -> bool:
    return any(pattern.search(target) for pattern in _PERSISTENCE_REGISTRY_PATTERNS)


def detect_registry_persistence(
    neighborhood: list[Event],
    graph: nx.DiGraph,
    facts: list[Conclusion],  # unused here — uniform rule signature
) -> Conclusion | None:
    """REG-PERSIST-01 (T1547.001): the process that WRITES an autostart key,
    shortly after it executes, on the same host within the window.

    Two guards keep this honest: the registry target must be a real
    persistence location (KNOWN-ISSUES #4), and when the source records the
    writing process (Sysmon 13 ``Image``), only that process matches. If the
    source records no writer (the synthetic CSV), it falls back to any prior
    process at a lower confidence.
    """
    proc_execs = [
        e for e in neighborhood if e.event_type == EventType.PROCESS_EXECUTION
    ]
    reg_mods = [
        e
        for e in neighborhood
        if e.event_type == EventType.REGISTRY_MODIFICATION
        and _is_persistence_registry_key(e.target)
    ]
    for reg in reg_mods:
        candidates = [
            proc
            for proc in proc_execs
            if _same_host(proc, reg)
            and proc.timestamp <= reg.timestamp
            and _within_window(proc, reg)
        ]
        if not candidates:
            continue

        writer = _writer_image(reg)
        if writer is not None:
            matched = [proc for proc in candidates if _process_image(proc) == writer]
            if not matched:
                continue  # writer recorded but no executing process matches it
            proc = matched[0]
            confidence = 0.6
        else:
            proc = candidates[0]
            confidence = 0.4  # no writer recorded: weaker, fall back to time order

        return Conclusion(
            conclusion_id=uuid.uuid4().hex,
            rule_id="REG-PERSIST-01",
            technique_id="T1547.001",
            tactic="Persistence",
            confidence=confidence,
            description=(
                "Possible registry-based persistence established: a process "
                "execution was followed by a modification to a known "
                "autostart registry location within the time window."
            ),
            evidence=[
                Evidence(
                    event_ids=[proc.event_id, reg.event_id],
                    explanation=(
                        f"Process {proc.actor} executed ({proc.target}), then "
                        f"persistence-relevant registry key {reg.target} was "
                        f"modified on {proc.source} within "
                        f"{TIME_WINDOW_MINUTES} minutes."
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


# ---------------------------------------------------------------------------
# C2-BEACON-01 — real-field heuristic (fixes #4, tightened in Phase 3 Step 2)
#
# Replaces the synthetic metadata["reason"] == "c2" check (which never
# existed in real Sysmon data) with a heuristic over actual Sysmon
# EventID 3 (Network connection) fields:
#
#   - DestinationPort is present and NOT a well-known service port
#     (80/443/53/etc.) -- C2 frameworks frequently use high/non-standard ports.
#   - The destination IP is PUBLIC. Private, loopback, link-local, multicast
#     and reserved destinations are everyday LAN/mDNS/SSDP noise, not command
#     and control, so they no longer fire.
#
# Residual false positives remain by design: a genuinely public host on a
# non-standard port can still be legitimate traffic. This is a heuristic, not
# ground truth, and is documented as such per the roadmap's Step 6 timebox
# guidance ("3-5 rules, one page each"), not a production detection rule.
# ---------------------------------------------------------------------------
_COMMON_BENIGN_PORTS = {
    20,
    21,
    22,
    23,
    25,
    53,
    67,
    68,
    80,
    110,
    123,
    143,
    161,
    389,
    443,
    445,
    465,
    587,
    636,
    993,
    995,
    3306,
    3389,
    5432,
    8080,
    8443,
}


def _destination_ip_is_public(event: Event) -> bool:
    """True only when the destination parses and is a global unicast address.

    Conservative: anything unparseable, or private / loopback / link-local /
    multicast / reserved / unspecified, is not public, so the caller cannot
    confirm C2 and does not fire.

    ``is_global`` alone is not enough on this project's Python: it still
    returns True for multicast ranges such as 239.255.255.250, so
    ``is_multicast`` is checked explicitly.
    """
    raw = (
        event.metadata.get("DestinationIp")
        or event.metadata.get("_ip_norm")
        or event.target
    )
    try:
        address = ipaddress.ip_address(str(raw).strip())
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


def _looks_like_c2_connection(event: Event) -> bool:
    """Heuristic: a network_connection to a PUBLIC destination on a port that
    is present, numeric, and NOT a well-known service port. See module
    docstring."""
    port_raw = event.metadata.get("DestinationPort") or event.metadata.get("dport")
    if port_raw is None:
        return False
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        return False
    if port in _COMMON_BENIGN_PORTS:
        return False
    return _destination_ip_is_public(event)


def detect_network_beacon(
    neighborhood: list[Event],
    graph: nx.DiGraph,
    facts: list[Conclusion],  # unused here — uniform rule signature
) -> Conclusion | None:
    """C2-BEACON-01 (T1071): process_execution then network_connection on
    the same host within the window, where the connection goes to a public
    destination on a non-standard port (see _looks_like_c2_connection).
    """
    proc_execs = [
        e for e in neighborhood if e.event_type == EventType.PROCESS_EXECUTION
    ]
    net_conns = [
        e
        for e in neighborhood
        if e.event_type == EventType.NETWORK_CONNECTION and _looks_like_c2_connection(e)
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
                        "outbound network connection to a public destination on a "
                        "non-standard port within the time window."
                    ),
                    evidence=[
                        Evidence(
                            event_ids=[proc.event_id, net.event_id],
                            explanation=(
                                f"Process {proc.actor} executed ({proc.target}) on "
                                f"{proc.source}, then connected to public "
                                f"{net.target} on a non-standard destination port "
                                f"within {TIME_WINDOW_MINUTES} minutes."
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
