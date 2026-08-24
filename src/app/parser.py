"""
Step 4 — Log Parser.

Reads a CSV log file and produces validated `Event` objects, chronologically
sorted, with stable provenance IDs and an explicit bad-row policy.

Design notes (see KNOWN-ISSUES.md for the defects this replaces):
  * Provenance IDs are assigned from the row's position in the *source
    file*, captured before any sorting happens (issue #17). Sorting for
    downstream time-window logic happens strictly after ID assignment.
  * A read failure (missing/corrupt file) raises, it is never silently
    swallowed into an empty result (issue #15).
  * The skip count is returned to the caller via `ParseResult`, not just
    logged (issue #16).
  * Timestamps are parsed to real `datetime` objects and normalized to UTC
    before sorting/comparison, so naive and aware timestamps never collide
    (issue #18).
  * A metadata field that fails to parse makes the row malformed (skipped +
    counted) rather than being silently replaced with `{}` (issue #19).
  * Missing/NaN required fields are treated as malformed rows, not coerced
    into the literal string "nan" (issue #20).
  * Metadata is parsed as JSON first (Mordor/real-world data), falling back
    to a Python-literal parse (`ast.literal_eval`, never the unsafe
    `eval()`) for the sample CSVs (issue #21).
"""

from __future__ import annotations

import ast
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, cast

import pandas as pd

from app.models import Event, EventType

log = logging.getLogger("incident.parser")

REQUIRED_STRING_FIELDS = ("source", "actor", "target", "event_type")


@dataclass
class ParseResult:
    """Everything the caller needs to know about a parse run."""

    events: list[Event]
    skipped: int
    total_rows: int
    errors: list[str] = field(default_factory=list)


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


def _parse_metadata(raw: Any) -> tuple[dict, bool]:
    """Returns (metadata_dict, ok). ok=False means the field was present but
    unparseable, which the caller must treat as a malformed row."""
    if isinstance(raw, dict):
        return raw, True
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
        return (parsed if isinstance(parsed, dict) else {}), isinstance(parsed, dict)
    except (json.JSONDecodeError, ValueError):
        pass

    # Fall back to Python-literal syntax (never the unsafe eval()).
    try:
        parsed = ast.literal_eval(text)
        return (parsed if isinstance(parsed, dict) else {}), isinstance(parsed, dict)
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
        return dt.replace(tzinfo=datetime.UTC)
    return dt.astimezone(datetime.UTC)


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
            values = {f: _clean_required_field(row.get(f)) for f in REQUIRED_STRING_FIELDS}
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
        except Exception as exc:  # noqa: BLE001 - deliberately broad: any bad row is skipped
            skipped += 1
            msg = f"row {original_index}: {exc}"
            errors.append(msg)
            log.warning("Skipping malformed row in %s (%s)", file_path, msg)

    # Sort strictly AFTER provenance IDs are assigned, so event_id always
    # points at the original source line regardless of input order.
    events.sort(key=lambda e: e.timestamp)

    log.info(
        "Parsed %d events, skipped %d of %d rows from %s",
        len(events), skipped, total_rows, file_path,
    )
    return ParseResult(events=events, skipped=skipped, total_rows=total_rows, errors=errors)