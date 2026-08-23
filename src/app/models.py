from pydantic import BaseModel
from enum import Enum
from datetime import datetime

class EventType(str, Enum):
    PROCESS_EXECUTION = "process_execution"
    FILE_DOWNLOAD = "file_download"
    FILE_CREATION = "file_creation"
    REGISTRY_MODIFICATION = "registry_modification"
    NETWORK_CONNECTION = "network_connection"
    POWERSHELL_EXECUTION = "powershell_execution"
    LOG_DELETION = "log_deletion"

class Event(BaseModel):
    event_id: str            # "{source}:{row}" — assigned at parse time
    timestamp: datetime
    source: str              # log source / hostname
    event_type: EventType
    actor: str               # user / process that acted
    target: str              # object acted upon (file, reg key, dest IP...)
    metadata: dict           # everything else (commandline, parentpid, etc.)

class Evidence(BaseModel):
    event_ids: list[str]
    explanation: str
    parent_conclusion_id: str | None = None   # for derived/chained facts

class Conclusion(BaseModel):
    rule_id: str
    technique_id: str        # MITRE ATT&CK technique, e.g. "T1547.001"
    tactic: str              # e.g. "Persistence"
    description: str
    evidence: list[Evidence]

class Incident(BaseModel):
    id: str
    summary: str
    conclusions: list[Conclusion]