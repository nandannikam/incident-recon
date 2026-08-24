"""
Step 2 — Data Contracts.

Every typed contract the pipeline uses lives here: the input Event, the
7-type event taxonomy, the output Incident/Conclusion/Evidence models, the
provenance ID scheme, the graph edge vocabulary + time window, and the
named (not-yet-implemented) demo rules. Every other module imports its
constants from here rather than redefining them, so there is exactly one
source of truth for things like TIME_WINDOW_MINUTES.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Provenance scheme (documented as a contract, not just implemented in
# parser.py — see roadmap Step 2 checklist item + KNOWN-ISSUES #9/#17):
#
#   event_id = f"{source_file}:{original_row_number}"
#
# `original_row_number` MUST be the row's position in the *source file*,
# assigned once at parse time, BEFORE any chronological sorting happens.
# Sorting must never change an event's ID. This guarantee is what lets every
# Evidence.event_ids entry trace back to a real source line.
# ---------------------------------------------------------------------------

# Default time window used for both `followed_by` graph edges (Step 5) and
# rule matching (Step 6). Defined once, here, so it can never drift between
# the two consumers.
TIME_WINDOW_MINUTES = 5


class EventType(str, Enum):
    PROCESS_EXECUTION = "process_execution"
    FILE_DOWNLOAD = "file_download"
    FILE_CREATION = "file_creation"
    REGISTRY_MODIFICATION = "registry_modification"
    NETWORK_CONNECTION = "network_connection"
    POWERSHELL_EXECUTION = "powershell_execution"
    LOG_DELETION = "log_deletion"


class EdgeType(str, Enum):
    """
    The ONLY graph edge kinds allowed in Phase 1. Kept to exactly three to
    avoid clique explosion (see roadmap risk table). `same_user` / `same_host`
    are deliberately NOT edges — they stay as rule-matchable Event fields
    (`actor`, `source`) that a rule function can compare directly, instead of
    materializing an edge between every event sharing a user or host.
    """

    FOLLOWED_BY = "followed_by"   # temporal adjacency within TIME_WINDOW_MINUTES
    SPAWNED = "spawned"           # parent/child process relationship
    SAME_OBJECT = "same_object"   # shared file / registry key / IP target


class Event(BaseModel):
    event_id: str
    timestamp: datetime
    source: str
    event_type: EventType
    actor: str
    target: str
    metadata: dict = Field(default_factory=dict)


class Evidence(BaseModel):
    event_ids: list[str]
    explanation: str
    parent_conclusion_id: str | None = None  # set when this evidence backs a chained/derived fact


class Conclusion(BaseModel):
    rule_id: str
    technique_id: str  # MITRE ATT&CK technique, e.g. "T1547.001"
    tactic: str         # e.g. "Persistence"
    description: str
    evidence: list[Evidence]


class Incident(BaseModel):
    id: str
    summary: str
    conclusions: list[Conclusion] = Field(default_factory=list)


class DemoRule(BaseModel):
    """A named-but-not-yet-implemented rule, recorded in Step 2 so Step 3's
    sample data and Step 6's implementation have an agreed target."""

    rule_id: str
    intent: str
    chained: bool = False  # True == consumes a prior Conclusion (proves forward chaining)


# The 2-3 demo rules named in Step 2. Full logic is implemented in
# src/app/rules/registry.py (Step 6). PERSIST-ESTABLISHED-01 is the
# two-level chained rule: it is the one that actually proves forward
# chaining works, because it consumes PSH-STAGING-01's conclusion rather
# than only raw events.
DEMO_RULES: list[DemoRule] = [
    DemoRule(
        rule_id="REG-PERSIST-01",
        intent=(
            "Registry persistence: a process_execution followed by a "
            "registry_modification within the time window."
        ),
    ),
    DemoRule(
        rule_id="PSH-STAGING-01",
        intent=(
            "PowerShell staging: a powershell_execution followed by a "
            "file_download within the time window."
        ),
    ),
    DemoRule(
        rule_id="PERSIST-ESTABLISHED-01",
        intent=(
            "Chained: a PSH-STAGING-01 conclusion followed by a "
            "registry_modification within the time window -> "
            "'persistence established'. Consumes a prior Conclusion, not "
            "just raw events."
        ),
        chained=True,
    ),
]
