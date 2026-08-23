import pandas as pd
from src.models import Event, EventType
from datetime import datetime
import logging

log = logging.getLogger("incident")

def parse_log(file_path: str) -> list[Event]:
    df = pd.read_csv(file_path)
    df = df.sort_values("timestamp").reset_index(drop=True)
    
    events = []
    skipped = 0
    
    for i, row in df.iterrows():
        try:
            events.append(Event(
                event_id=f"{file_path}:{i}",
                timestamp=datetime.fromisoformat(row["timestamp"]),
                source=row["source"],
                event_type=EventType(row["event_type"]),
                actor=row["actor"],
                target=row["target"],
                metadata=eval(row["metadata"]) if isinstance(row["metadata"], str) else {},
            ))
        except Exception as e:
            skipped += 1
            log.warning(f"Skipping malformed row {i} in {file_path}: {e}")
            
    log.info(f"Parsed {len(events)} events, skipped {skipped}")
    return events