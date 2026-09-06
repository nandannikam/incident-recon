from __future__ import annotations

import ast
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, cast

import pandas as pd

from app.models import Event, EventType

log = logging.getLogger("incident.parser")

REQUIRED_STRING_FIELDS = ("source", "actor", "target", "event_type")


def _empty_str_list() -> list[str]:
    """Helper for strictly typed dataclass factories."""
    return []


@dataclass
class ParseResult:
    """Everything the caller needs to know about a parse run."""

    events: list[Event]
    skipped: int
    total_rows: int
    errors: list[str] = field(default_factory=_empty_str_list)


def _is_missing(value: Any) -> bool:
    if value is None:
        return True
    try:
        if isinstance(value, float) and pd.isna(value):
            return True
    except (TypeError, ValueError):
        pass
    return isinstance(value, str) and value.strip() == ""


def _clean_required_field(value: Any) -> str | None:
    """Return a stripped string, or None if the value is missing/NaN.
    Never produces the literal string 'nan' for an absent field."""
    if _is_missing(value):
        return None
    return str(value).strip()


def _parse_metadata(raw: Any) -> tuple[dict[str, Any], bool]:
    """Returns (metadata_dict, ok). ok=False means the field was present but
    unparseable, which the caller must treat as a malformed row."""
    if isinstance(raw, dict):
        return cast(dict[str, Any], raw), True
    if _is_missing(raw):
        return {}, True  # metadata is optional; absent is fine
    if not isinstance(raw, str):
        return {}, False

    text = raw.strip()
    if text == "":
        return {}, True

    # Prefer JSON (real-world / Mordor data uses JSON null/true/false).
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return cast(dict[str, Any], parsed), True
        return {}, False
    except (json.JSONDecodeError, ValueError):
        pass

    # Fall back to Python-literal syntax (never the unsafe eval()).
    try:
        parsed = ast.literal_eval(text)
        if isinstance(parsed, dict):
            return cast(dict[str, Any], parsed), True
        return {}, False
    except (ValueError, SyntaxError):
        return {}, False


def _normalize_timestamp(raw: Any) -> datetime:
    """Parse to a real datetime and normalize to UTC. Raises on failure so
    the caller can count the row as malformed."""
    if isinstance(raw, datetime):
        dt = raw
    else:
        text = str(raw).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)

    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)  # noqa: UP017
    return dt.astimezone(timezone.utc)  # noqa: UP017


def parse_log(file_path: str) -> ParseResult:
    """Read `file_path` (CSV) and return a ParseResult.

    Raises FileNotFoundError / pandas errors if the file cannot be read at
    all — that is a distinct failure mode from "zero valid rows" and must
    be visible to the caller, not swallowed.
    """
    try:
        df = pd.read_csv(file_path)
    except FileNotFoundError:
        log.error("Log file not found: %s", file_path)
        raise
    except (pd.errors.EmptyDataError, pd.errors.ParserError) as exc:
        log.error("Failed to parse log file %s: %s", file_path, exc)
        raise

    total_rows = len(df)
    events: list[Event] = []
    skipped = 0
    errors: list[str] = []

    # Assign provenance from the ORIGINAL row position, before any sorting.
    for original_index, row in df.iterrows():
        try:
            values = {
                f: _clean_required_field(row.get(f)) for f in REQUIRED_STRING_FIELDS
            }
            missing = [f for f, v in values.items() if v is None]
            if missing:
                raise ValueError(f"missing required field(s): {', '.join(missing)}")

            timestamp_raw = row.get("timestamp")
            if _is_missing(timestamp_raw):
                raise ValueError("missing required field: timestamp")
            timestamp = _normalize_timestamp(timestamp_raw)

            metadata, ok = _parse_metadata(row.get("metadata"))
            if not ok:
                raise ValueError("metadata field present but could not be parsed")

            events.append(
                Event(
                    event_id=f"{file_path}:{original_index}",
                    timestamp=timestamp,
                    source=cast(str, values["source"]),
                    event_type=EventType(cast(str, values["event_type"])),
                    actor=cast(str, values["actor"]),
                    target=cast(str, values["target"]),
                    metadata=metadata,
                )
            )
        except Exception as exc:  # noqa: BLE001 - intentional: bad-row policy skips and counts any malformed row rather than aborting the whole batch
            skipped += 1
            msg = f"row {original_index}: {exc}"
            errors.append(msg)
            log.warning("Skipping malformed row in %s (%s)", file_path, msg)

    # Sort strictly AFTER provenance IDs are assigned, so event_id always
    # points at the original source line regardless of input order.
    events.sort(key=lambda e: e.timestamp)

    log.info(
        "Parsed %d events, skipped %d of %d rows from %s",
        len(events),
        skipped,
        total_rows,
        file_path,
    )
    return ParseResult(
        events=events, skipped=skipped, total_rows=total_rows, errors=errors
    )
