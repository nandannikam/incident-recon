from datetime import datetime
from src.app.models import Event, EventType

def test_event_creation():
    event_data = {
        "event_id": "attack_sample.csv:1",
        "timestamp": datetime.now(),
        "source": "HOST01",
        "event_type": EventType.PROCESS_EXECUTION,
        "actor": "USER01",
        "target": "cmd.exe",
        "metadata": {"pid": 1234}
    }
    
    event = Event(**event_data)
    
    assert event.event_id == "attack_sample.csv:1"
    assert event.event_type == "process_execution"
    assert event.metadata["pid"] == 1234