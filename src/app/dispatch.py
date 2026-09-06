"""
Format dispatch for log parsing.

Fixes KNOWN-ISSUES Phase 2 #1 (real-log parser never wired into the
pipeline) and #8 (spawned edges never fire on real data because Mordor
metadata uses ``ProcessId``/``ParentProcessId`` while graph.py reads
lowercase ``pid``/``parentpid``).

`run_analysis` (orchestrator.py) previously called `parse_log` directly
and unconditionally, so any non-CSV upload (every real Mordor dataset is
NDJSON, usually saved with a `.json` extension) crashed inside
`pd.read_csv` with a `ParserError`. `parse_any_log` is the single
entry point that decides which parser to use and returns a `ParseResult`
either way, so callers (orchestrator, and eventually the API layer) never
need to know the file format up front.

Detection order:
    1. Explicit extension: `.csv` -> parse_log, `.ndjson`/`.json` -> parse_mordor.
    2. Unknown/missing extension -> sniff the first non-blank line: valid
       JSON object => Mordor NDJSON, otherwise assume CSV.

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
from app.parser import ParseResult, parse_log

log = logging.getLogger("incident.dispatch")

_CSV_EXTENSIONS = {".csv"}
_MORDOR_EXTENSIONS = {".ndjson", ".json"}

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
    """Raised when the file's format cannot be determined or read at all."""


def _sniff_is_mordor_ndjson(file_path: Path) -> bool:
    """Peek at the first non-blank line; a parseable JSON object means
    Mordor NDJSON. Any failure (including an empty file) means "not
    detected as Mordor" rather than raising, so the caller can fall back
    to the CSV path and get a normal parse error there if it's neither."""
    try:
        with file_path.open("r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    return isinstance(json.loads(line), dict)
                except (json.JSONDecodeError, ValueError):
                    return False
    except OSError:
        return False
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
    """Return "csv" or "mordor" for the given path. Raises
    UnknownLogFormatError if the file doesn't exist or its format can't
    be determined by extension or content sniffing."""
    path = Path(file_path)
    if not path.exists():
        raise UnknownLogFormatError(f"file not found: {path}")

    suffix = path.suffix.lower()
    if suffix in _CSV_EXTENSIONS:
        return "csv"
    if suffix in _MORDOR_EXTENSIONS:
        return "mordor"

    if _sniff_is_mordor_ndjson(path):
        return "mordor"

    # Default to csv for unknown extensions with non-JSON content; parse_log
    # will raise a clear pandas error if that guess is wrong, which is more
    # actionable than a silent misdetection here.
    return "csv"


def parse_any_log(file_path: str | Path) -> ParseResult:
    """Single entry point for the pipeline: detect the format and parse
    with the matching parser, returning a normalized ParseResult so
    callers never need format-specific logic."""
    path = Path(file_path)
    fmt = detect_format(path)
    log.info("Detected format '%s' for %s", fmt, path)

    if fmt == "mordor":
        result = parse_mordor(path)
        return _normalize_pid_aliases(result)

    return parse_log(str(path))
