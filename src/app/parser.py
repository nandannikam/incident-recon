import pandas as pd
import ast
import logging
from datetime import datetime
from src.app.models import Event, EventType

log = logging.getLogger("incident")

def parse_log(file_path: str) -> list[Event]:
    try:
        df = pd.read_csv(file_path)
    except Exception as e:
        log.error(f"Failed to read file {file_path}: {e}")
        return []

    # Sort events chronologically if timestamp exists
    if "timestamp" in df.columns:
        df = df.sort_values("timestamp").reset_index(drop=True)
    
    events = []
    skipped = 0
    
    for index, row in df.iterrows():
        try:
            # Safely extract and convert the metadata column
            meta_val = row.get("metadata", "{}")
            if isinstance(meta_val, str):
                try:
                    metadata_dict = ast.literal_eval(meta_val)
                except (ValueError, SyntaxError):
                    metadata_dict = {}
            else:
                metadata_dict = dict(meta_val) if pd.notna(meta_val) else {}

            event = Event(
                event_id=f"{file_path}:{index}",
                timestamp=datetime.fromisoformat(str(row["timestamp"])),
                source=str(row["source"]),
                event_type=EventType(str(row["event_type"])),
                actor=str(row["actor"]),
                target=str(row["target"]),
                metadata=metadata_dict,
            )
            events.append(event)
        except Exception as e:
            skipped += 1
            log.warning(f"Skipping malformed row {index} in {file_path}: {e}")
            
    log.info(f"Parsed {len(events)} events, skipped {skipped} in {file_path}")
    return events