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

from collections.abc import Iterable
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator

from app.config import settings

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

# Time window used for both `followed_by` graph edges (Step 5) and rule
# matching (Step 6). Defined once, here, so it can never drift between the
# two consumers. The value comes from configuration (TIME_WINDOW_MINUTES env
# var, default 5 -- see app/config.py), read once at import time.
TIME_WINDOW_MINUTES = settings.time_window_minutes


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

    FOLLOWED_BY = "followed_by"  # temporal adjacency within TIME_WINDOW_MINUTES
    SPAWNED = "spawned"  # parent/child process relationship
    SAME_OBJECT = "same_object"  # shared file / registry key / IP target


def _empty_metadata_dict() -> dict[str, Any]:
    """Helper for strictly typed Pydantic dictionary factories."""
    return {}


class Event(BaseModel):
    event_id: str
    timestamp: datetime
    source: str
    event_type: EventType
    actor: str
    target: str
    metadata: dict[str, Any] = Field(default_factory=_empty_metadata_dict)


class Evidence(BaseModel):
    event_ids: list[str]
    explanation: str
    parent_conclusion_id: str | None = (
        None  # set when this evidence backs a chained/derived fact
    )


class Severity(str, Enum):
    """How serious a finding is, lowest to highest. ``INFO`` is only used for
    an Incident that has no conclusions at all."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Severity is derived from the MITRE tactic a conclusion belongs to, so the UI
# can rank findings without every rule having to restate it. Tactics not
# listed here fall back to MEDIUM.
TACTIC_SEVERITY: dict[str, Severity] = {
    "Initial Access": Severity.MEDIUM,
    "Execution": Severity.MEDIUM,
    "Persistence": Severity.HIGH,
    "Privilege Escalation": Severity.HIGH,
    "Defense Evasion": Severity.HIGH,
    "Credential Access": Severity.HIGH,
    "Discovery": Severity.LOW,
    "Lateral Movement": Severity.HIGH,
    "Collection": Severity.MEDIUM,
    "Command and Control": Severity.HIGH,
    "Exfiltration": Severity.CRITICAL,
    "Impact": Severity.CRITICAL,
}
DEFAULT_SEVERITY = Severity.MEDIUM

# Confidence (0-1) used when a rule does not state one explicitly. A rule that
# knows better simply passes ``confidence=...`` and this table is not consulted.
#   LOG-CLEAR-01   : a log-clear event is unambiguous.
#   C2-BEACON-01   : a non-standard-port heuristic -- weak evidence.
#   PERSIST-ESTABLISHED-01 : two chained stages agree, so stronger than one.
RULE_DEFAULT_CONFIDENCE: dict[str, float] = {
    "LOG-CLEAR-01": 0.9,
    "PERSIST-ESTABLISHED-01": 0.8,
    "REG-PERSIST-01": 0.6,
    "PSH-STAGING-01": 0.5,
    "C2-BEACON-01": 0.3,
}
DEFAULT_CONFIDENCE = 0.5


def severity_for_tactic(tactic: str) -> Severity:
    """Severity implied by a MITRE tactic name (unknown tactics -> MEDIUM)."""
    return TACTIC_SEVERITY.get(tactic, DEFAULT_SEVERITY)


def max_severity(severities: Iterable[Severity]) -> Severity:
    """The most serious of ``severities``; ``INFO`` when there are none."""
    highest = Severity.INFO
    for severity in severities:
        if _SEVERITY_RANK[severity] > _SEVERITY_RANK[highest]:
            highest = severity
    return highest


def _empty_str_list() -> list[str]:
    """Helper for strictly typed Pydantic list factories."""
    return []


class Conclusion(BaseModel):
    conclusion_id: str
    rule_id: str
    technique_id: str
    tactic: str
    description: str
    evidence: list[Evidence]
    # Optional on input, always filled after validation: a rule may state its
    # own confidence/severity, otherwise they are derived (see the tables
    # above). Giving them defaults also keeps incidents stored before these
    # fields existed loadable.
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    severity: Severity | None = None
    # Hosts (Event.source values) the evidence came from. The field is part of
    # the contract now; the rules/engine step fills it (defaults to empty).
    hosts: list[str] = Field(default_factory=_empty_str_list)

    @model_validator(mode="after")
    def _fill_derived_fields(self) -> Conclusion:
        if self.confidence is None:
            self.confidence = RULE_DEFAULT_CONFIDENCE.get(
                self.rule_id, DEFAULT_CONFIDENCE
            )
        if self.severity is None:
            self.severity = severity_for_tactic(self.tactic)
        return self


def _empty_conclusion_list() -> list[Conclusion]:
    """Helper for strictly typed Pydantic list factories."""
    return []


class Incident(BaseModel):
    id: str
    summary: str
    conclusions: list[Conclusion] = Field(default_factory=_empty_conclusion_list)
    # The most serious conclusion's severity (INFO when there are none);
    # derived automatically unless given explicitly.
    severity: Severity | None = None

    @model_validator(mode="after")
    def _derive_severity(self) -> Incident:
        if self.severity is None:
            self.severity = max_severity(
                c.severity for c in self.conclusions if c.severity is not None
            )
        return self


class DemoRule(BaseModel):
    """A named-but-not-yet-implemented rule, recorded in Step 2 so Step 3's
    sample data and Step 6's implementation have an agreed target."""

    rule_id: str
    intent: str
    chained: bool = (
        False  # True == consumes a prior Conclusion (proves forward chaining)
    )


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
