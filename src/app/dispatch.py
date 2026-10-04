"""
Format dispatch for log parsing.

Fixes KNOWN-ISSUES Phase 2 #1 (real-log parser never wired into the
pipeline), #8 (spawned edges never fire on real data because Mordor
metadata uses ``ProcessId``/``ParentProcessId`` while graph.py reads
lowercase ``pid``/``parentpid``), and #9 (a mislabeled file -- e.g. a CSV
renamed to `.json` -- was routed to parse_mordor purely on extension,
silently producing a 0-event "successful" result instead of a clear
error).

`run_analysis` (orchestrator.py) previously called `parse_log` directly
and unconditionally, so any non-CSV upload (every real Mordor dataset is
NDJSON, usually saved with a `.json` extension) crashed inside
`pd.read_csv` with a `ParserError`. `parse_any_log` is the single
entry point that decides which parser to use and returns a `ParseResult`
either way, so callers (orchestrator, and eventually the API layer) never
need to know the file format up front.

Detection order (#9 fix: content is now ALWAYS checked, extension alone
is never sufficient to route to the Mordor parser):
    1. `.csv` extension -> parse_log directly (CSV has no reliable content
       signature to sniff against; a malformed CSV still produces a clear
       pandas error from parse_log itself, so this is safe to trust).
    2. Any other extension (`.json`, `.ndjson`, unknown, or missing) ->
       sniff the first non-blank line. A parseable JSON object routes to
       parse_mordor. Anything else raises UnknownLogFormatError
       immediately, rather than being silently misrouted.

Phase 3 Step 4: after parsing, `parse_any_log` also adds canonical host / IP /
hash keys (``_host_norm``, ``_ip_norm``, ``_hashes``) to every event's
metadata via `app.normalize`, for cross-host correlation.

This keeps `parser.py` and `mordor_parser.py` untouched (both already
correct in isolation) and keeps `graph.py` untouched (it is not this
module's file to own) by normalizing the pid/parentpid keys here, at the
parser/graph boundary, immediately after parsing.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from app.mordor_parser import parse_mordor
from app.normalize import normalize_events
from app.parser import ParseResult, parse_log

log = logging.getLogger("incident.dispatch")

_CSV_EXTENSIONS = {".csv"}

# graph.py reads these lowercase keys off Event.metadata to build SPAWNED
# edges. mordor_parser.py (correctly, since it preserves raw Sysmon field
# names for evidence/debugging) stores the capitalized Sysmon originals
# instead. We add the lowercase aliases here without removing the
# originals, so graph.py needs no changes and existing evidence fields
# stay intact for anyone inspecting metadata directly.
_PID_ALIASES: tuple[tuple[str, str], ...] = (
    ("ProcessId", "pid"),
    ("ParentProcessId", "parentpid"),
)


class UnknownLogFormatError(ValueError):
    """Raised when the file's format cannot be determined or read at all,
    OR (fixes #9) when a file's extension claims a format its content
    does not actually match -- e.g. a CSV renamed to `.json`."""


def _first_non_blank_line(file_path: Path) -> str | None:
    """Return the first non-blank line of the file, or None if the file
    is empty/all-blank or unreadable."""
    try:
        with file_path.open("r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.strip()
                if line:
                    return line
    except OSError:
        return None
    return None


def _sniff_is_mordor_ndjson(file_path: Path) -> bool:
    """True if the first non-blank line parses as a JSON object. An empty
    file or a read failure returns False (not Mordor), letting the caller
    produce a specific, actionable error rather than a generic one."""
    line = _first_non_blank_line(file_path)
    if line is None:
        return False
    try:
        return isinstance(json.loads(line), dict)
    except (json.JSONDecodeError, ValueError):
        return False


def _normalize_pid_aliases(result: ParseResult) -> ParseResult:
    """Add lowercase pid/parentpid aliases to each event's metadata,
    in place, when the capitalized Sysmon originals are present and the
    lowercase key isn't already set by the source parser itself."""
    for event in result.events:
        for source_key, alias_key in _PID_ALIASES:
            if alias_key in event.metadata:
                continue  # never overwrite an already-present lowercase key
            value = event.metadata.get(source_key)
            if value is not None:
                event.metadata[alias_key] = value
    return result


def detect_format(file_path: str | Path) -> str:
    """Return "csv" or "mordor" for the given path.

    Raises UnknownLogFormatError if:
      - the file doesn't exist,
      - the file is empty / unreadable, or
      - (fixes #9) the file's content doesn't actually look like NDJSON
        for any non-.csv path -- e.g. a CSV renamed to `.json` is
        rejected here instead of silently producing a 0-event Mordor
        parse.

    Extension is used only to decide "trust it as CSV" vs. "verify its
    content" -- it is never, by itself, sufficient to route to the
    Mordor parser. This is deliberate: #9 was exactly a case of
    extension-only routing producing a confidently wrong answer.
    """
    path = Path(file_path)
    if not path.exists():
        raise UnknownLogFormatError(f"file not found: {path}")

    suffix = path.suffix.lower()
    if suffix in _CSV_EXTENSIONS:
        return "csv"

    # Every other extension (.json, .ndjson, unknown, missing) must prove
    # its content is actually NDJSON before being routed to parse_mordor.
    if _sniff_is_mordor_ndjson(path):
        return "mordor"

    first_line = _first_non_blank_line(path)
    if first_line is None:
        raise UnknownLogFormatError(
            f"cannot determine format for {path}: file is empty or unreadable"
        )

    raise UnknownLogFormatError(
        f"cannot determine format for {path}: extension is '{suffix or '(none)'}' "
        "but the content is not valid NDJSON (first line did not parse as a "
        "JSON object). If this is a CSV file, rename it with a .csv extension."
    )


def parse_any_log(file_path: str | Path) -> ParseResult:
    """Single entry point for the pipeline: detect the format and parse
    with the matching parser, returning a normalized ParseResult so
    callers never need format-specific logic."""
    path = Path(file_path)
    fmt = detect_format(path)
    log.info("Detected format '%s' for %s", fmt, path)

    if fmt == "mordor":
        result = _normalize_pid_aliases(parse_mordor(path))
    else:
        result = parse_log(str(path))

    # Canonical host / IP / hash forms for cross-host correlation (Phase 3
    # Step 4). Adds underscore-prefixed metadata keys only; see normalize.py.
    normalize_events(result.events)
    return result
