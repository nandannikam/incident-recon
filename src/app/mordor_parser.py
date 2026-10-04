"""
Real-log parser: Mordor / OTRF Security-Datasets NDJSON -> validated Event objects.

Phase 2, Step 1 (fixes Gap G1 from phase_2_roadmap.md).

Mordor datasets are newline-delimited JSON. Each line is one raw Windows /
Sysmon event. Verified fields across the dataset family:
    SourceName, ProviderGuid, Level, Keywords, Channel, Hostname,
    TimeCreated, @timestamp, EventID, Message, Task

The `Message` field is NOT structured JSON — it is a human-readable,
multi-line "Key: Value" blob (standard Sysmon format), e.g.:

    Process Create:
    RuleName: -
    UtcTime: 2020-09-15 03:29:44.169
    ProcessGuid: {...}
    ProcessId: 3060
    Image: C:\\Windows\\System32\\cmd.exe
    CommandLine: cmd.exe /c whoami

This module extracts that blob into a dict and merges it with the raw event
fields into Event.metadata, so nothing is lost for downstream rule evidence.

Phase 3 Step 5 (real campaign data, e.g. APT29 Day 1) changes:

* Actor/target are looked up in the parsed Message blob AND in the event's own
  top-level fields (Mordor/nxlog flattens many fields to the top level, e.g.
  ``NewProcessName``, ``ScriptBlockText``). Windows 4688 and 4104 events keep
  those values only at the top level, so before this change all of them ended
  up with target ``UNKNOWN`` -- and since the graph links events that share a
  target, every one of them would have been joined into a single false cluster.
  Values parsed from the Message blob still win when both exist.
* The raw ``Message`` text is no longer copied into ``Event.metadata`` by
  default (it duplicates the fields parsed from it and roughly doubles the
  memory of a 400 MB campaign). Pass ``keep_raw_message=True`` to keep it.
  The original line is always recoverable from the event_id.
* Progress is logged every ``_PROGRESS_EVERY`` lines for long files.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.models import Event, EventType
from app.parser import ParseResult

log = logging.getLogger("incident.mordor_parser")

# Log a progress line every this many non-blank lines (large campaign files).
_PROGRESS_EVERY = 100_000

# ---------------------------------------------------------------------------
# EventID -> EventType mapping (Sysmon + Windows Event Log)
# ---------------------------------------------------------------------------

_EVENT_ID_MAP: dict[int, EventType] = {
    1: EventType.PROCESS_EXECUTION,  # Sysmon: Process Create
    3: EventType.NETWORK_CONNECTION,  # Sysmon: Network connection
    11: EventType.FILE_CREATION,  # Sysmon: File Create (refined below)
    12: EventType.REGISTRY_MODIFICATION,  # Sysmon: Registry object added/deleted
    13: EventType.REGISTRY_MODIFICATION,  # Sysmon: Registry value set
    14: EventType.REGISTRY_MODIFICATION,  # Sysmon: Registry object renamed
    4104: EventType.POWERSHELL_EXECUTION,  # Windows: PowerShell ScriptBlock
    1102: EventType.LOG_DELETION,  # Windows: The audit log was cleared
    4688: EventType.PROCESS_EXECUTION,  # Windows: A new process has been created
}

# EventID 11 (Sysmon File Create) is reclassified to FILE_DOWNLOAD when the
# creating process or target path indicates a network-fetch tool. This is a
# heuristic, applied only for EventID 11.
_DOWNLOAD_TOOL_HINTS = (
    "bitsadmin",
    "certutil",
    "curl",
    "wget",
    "invoke-webrequest",
    "iwr ",
    "start-bitstransfer",
)

# TimeCreated in Mordor data appears in a few different shapes across
# dataset versions. Try each, in order, until one parses.
_TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
)


class MordorParseError(ValueError):
    """Raised for a single malformed line; caught internally and counted."""


def _parse_sysmon_message(message: str) -> dict[str, str]:
    """
    Parse a Sysmon-style multi-line 'Key: Value' Message blob into a dict.

    The first line (e.g. "Process Create:") has no ':' followed by a value
    on the same conceptual pair, or is a header with no value -- skip lines
    that don't contain a ': ' key/value separator with a non-empty key.
    """
    fields: dict[str, str] = {}
    if not message:
        return fields

    for raw_line in message.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        # Skip header lines like "Process Create:" (empty value) and any
        # line where the "key" is actually just prose with no real value.
        if not key or not value:
            continue
        fields[key] = value

    return fields


def _normalize_timestamp(raw: Any) -> datetime:
    """
    Normalize a Mordor timestamp field (str, from TimeCreated or @timestamp,
    or occasionally an epoch-like value) into a timezone-aware UTC datetime.

    Raises MordorParseError if no known format matches.
    """
    if raw is None:
        raise MordorParseError("missing timestamp")

    if isinstance(raw, (int, float)):
        # Some Mordor exports carry epoch milliseconds.
        seconds = raw / 1000.0 if raw > 10_000_000_000 else raw
        return datetime.fromtimestamp(seconds, tz=UTC)

    text = str(raw).strip()
    if not text:
        raise MordorParseError("empty timestamp")

    # Try native ISO parsing first (handles "...+00:00" style offsets).
    try:
        iso_text = text[:-1] + "+00:00" if text.endswith("Z") else text
        dt = datetime.fromisoformat(iso_text)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        pass

    for fmt in _TIMESTAMP_FORMATS:
        try:
            # strptime() always returns a naive datetime (it has no %z in our
            # formats), so we immediately attach UTC in the same expression
            # rather than returning a naive value at any point.
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue

    raise MordorParseError(f"unrecognized timestamp format: {text!r}")


def _event_type_from_event_id(event_id: int, msg_fields: dict[str, Any]) -> EventType:
    """
    Map a Windows/Sysmon EventID to our EventType taxonomy.

    EventID 11 (File Create) is disambiguated into FILE_DOWNLOAD when the
    Image (creating process) or CommandLine references a known download
    tool; otherwise it stays FILE_CREATION.

    Raises MordorParseError for any EventID we don't have a mapping for,
    so the caller can count it as a skipped row rather than guessing.
    """
    if event_id not in _EVENT_ID_MAP:
        raise MordorParseError(f"unmapped EventID: {event_id}")

    base_type = _EVENT_ID_MAP[event_id]

    if event_id == 11:
        haystack = " ".join(
            str(msg_fields.get(k, ""))
            for k in ("Image", "CommandLine", "TargetFilename")
        ).lower()
        if any(hint in haystack for hint in _DOWNLOAD_TOOL_HINTS):
            return EventType.FILE_DOWNLOAD

    return base_type


def _first_value(fields: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    """First non-empty value among ``keys`` as a stripped string, else None.

    Values from top-level JSON fields can be ints/bools, but Event.actor and
    Event.target must be strings, so everything is coerced here.
    """
    for key in keys:
        value = fields.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _extract_actor(raw: dict[str, Any], fields: dict[str, Any]) -> str:
    """
    Best-effort extraction of the 'actor' (who/what performed the action).
    ``fields`` is the merged lookup table (top-level fields overlaid with the
    parsed Message blob). Falls back through several common Sysmon/Windows
    fields, then to the hostname, so `actor` is never empty.
    """
    actor = _first_value(fields, ("User", "SubjectUserName", "ParentImage", "ProcessId"))
    if actor:
        return actor

    return _first_value(raw, ("Hostname", "SourceName")) or "UNKNOWN"


_TARGET_PRIORITY_BY_TYPE: dict[EventType, tuple[str, ...]] = {
    EventType.NETWORK_CONNECTION: ("DestinationIp", "DestinationHostname"),
    EventType.REGISTRY_MODIFICATION: ("TargetObject",),
    EventType.FILE_CREATION: ("TargetFilename", "Image"),
    EventType.FILE_DOWNLOAD: ("TargetFilename", "Image"),
    # Multi-part script blocks ("Creating Scriptblock text (1 of 7)") have no
    # ScriptBlockText field: fall back to the block's id (shared by every part
    # of the same script), then to the script file path.
    EventType.POWERSHELL_EXECUTION: ("ScriptBlockText", "ScriptBlock ID", "Path"),
    EventType.LOG_DELETION: ("Channel", "Image"),
    EventType.PROCESS_EXECUTION: ("Image", "NewProcessName"),
}

_TARGET_FALLBACK_KEYS = (
    "Image",
    "TargetFilename",
    "TargetObject",
    "DestinationIp",
    "DestinationHostname",
    "ScriptBlockText",
    "NewProcessName",
)


def _extract_target(event_type: EventType, fields: dict[str, Any]) -> str:
    """
    Best-effort extraction of the 'target' (object acted upon). The relevant
    field depends on the event type, so we look up a type-specific priority
    order rather than one global order (a network event's Image is the
    process that opened the socket, not the target -- the destination IP
    is the target).
    """
    target = _first_value(fields, _TARGET_PRIORITY_BY_TYPE.get(event_type, ()))
    if target:
        return target

    # Fallback: try every known field regardless of type.
    return _first_value(fields, _TARGET_FALLBACK_KEYS) or "UNKNOWN"


def parse_mordor_line(
    line: str,
    line_no: int,
    file_label: str,
    *,
    keep_raw_message: bool = False,
) -> Event:
    """
    Parse a single NDJSON line into a validated Event.

    Raises MordorParseError (or lets json.JSONDecodeError / pydantic's
    ValidationError propagate) on any malformed input; the caller in
    parse_mordor() is responsible for catching and counting these.
    """
    raw: dict[str, Any] = json.loads(line)

    if "EventID" not in raw:
        raise MordorParseError("missing EventID field")

    try:
        event_id = int(raw["EventID"])
    except (TypeError, ValueError) as exc:
        raise MordorParseError(f"non-integer EventID: {raw.get('EventID')!r}") from exc

    msg_fields = _parse_sysmon_message(str(raw.get("Message", "")))

    # One lookup table for actor/target extraction: the event's own top-level
    # fields, overlaid with what was parsed out of the Message blob (the blob
    # wins on conflict, as it always did). The raw Message text itself is left
    # out -- see the module docstring.
    fields: dict[str, Any] = {k: v for k, v in raw.items() if k != "Message"}
    fields.update(msg_fields)
    event_type = _event_type_from_event_id(event_id, fields)

    timestamp_raw = raw.get("TimeCreated") or raw.get("@timestamp")
    timestamp = _normalize_timestamp(timestamp_raw)

    source = str(raw.get("Hostname") or raw.get("SourceName") or "UNKNOWN_HOST")

    metadata: dict[str, Any] = dict(fields)
    if keep_raw_message and "Message" in raw:
        metadata["Message"] = raw["Message"]
    metadata["_event_id"] = event_id  # keep the numeric EventID for rules/debugging

    return Event(
        event_id=f"{file_label}:{line_no}",
        timestamp=timestamp,
        source=source,
        event_type=event_type,
        actor=_extract_actor(raw, fields),
        target=_extract_target(event_type, fields),
        metadata=metadata,
    )


def parse_mordor(file_path: str | Path, *, keep_raw_message: bool = False) -> ParseResult:
    """
    Parse a Mordor NDJSON file into a ParseResult (events + diagnostics).

    Bad-row policy (matches the Phase 1 CSV parser): malformed lines are
    skipped and counted, never silently dropped without a trace. The
    returned `errors` list carries a bounded, human-readable reason per
    skipped line so failures are debuggable without re-parsing.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Mordor dataset not found: {path}")

    file_label = path.name
    events: list[Event] = []
    skipped = 0
    errors: list[str] = []
    total_rows = 0

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, raw_line in enumerate(f):
            stripped = raw_line.strip()
            if not stripped:
                continue  # blank lines don't count as rows at all
            total_rows += 1
            try:
                event = parse_mordor_line(
                    stripped, line_no, file_label, keep_raw_message=keep_raw_message
                )
                events.append(event)
            except Exception as exc:  # noqa: BLE001 - intentional: any bad row is skip+count
                skipped += 1
                if len(errors) < 200:  # cap memory use on pathological files
                    errors.append(f"line {line_no}: {type(exc).__name__}: {exc}")
            if total_rows % _PROGRESS_EVERY == 0:
                log.info(
                    "parse_mordor(%s): %d lines read, %d events kept so far",
                    file_label,
                    total_rows,
                    len(events),
                )

    events.sort(key=lambda e: e.timestamp)

    log.info(
        "parse_mordor(%s): %d parsed, %d skipped, %d total",
        file_label,
        len(events),
        skipped,
        total_rows,
    )

    return ParseResult(
        events=events, total_rows=total_rows, skipped=skipped, errors=errors
    )
