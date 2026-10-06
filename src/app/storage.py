import sqlite3
from app.models import Incident
from app.config import settings


def _conn():
    db_path = settings.database_url.removeprefix("sqlite:///")
    return sqlite3.connect(db_path)

def save_incident(incident: Incident) -> None:
    with _conn() as c:
        c.execute(
            "CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, data TEXT)"
        )
        c.execute(
            "INSERT OR REPLACE INTO incidents VALUES (?, ?)",
            (incident.id, incident.model_dump_json()),
        )


def get_incident(incident_id: str) -> Incident | None:
    with _conn() as c:
        row = c.execute(
            "SELECT data FROM incidents WHERE id=?", (incident_id,)
        ).fetchone()
        return Incident.model_validate_json(row[0]) if row else None