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
    event_id: str            
    timestamp: datetime
    source: str              
    event_type: EventType
    actor: str               
    target: str              
    metadata: dict           

class Evidence(BaseModel):
    event_ids: list[str]
    explanation: str
    parent_conclusion_id: str | None = None   

class Conclusion(BaseModel):
    rule_id: str
    technique_id: str        
    tactic: str              
    description: str
    evidence: list[Evidence]

class Incident(BaseModel):
    id: str
    summary: str
    conclusions: list[Conclusion]