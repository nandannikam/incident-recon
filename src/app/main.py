"""
FastAPI thin wrapper (Step 10 / Phase 2 Step 4).

Phase 3 Step 6: CORS origins and the upload size limit now come from
``app.config.settings`` (env vars / .env) instead of being hardcoded.

KNOWN-ISSUES Phase 2 fixes applied here:

  #2: POST /upload only accepted .csv/.ndjson, so every real Mordor dataset
      (which ends in .json) was rejected with a 400 before ever reaching
      the parser. /analyze had no extension check at all, so a .json
      upload was accepted there and then crashed inside run_analysis
      (see dispatch.py / orchestrator.py for the underlying #1 fix this
      depends on). Both endpoints now accept .csv, .ndjson, AND .json.

  #5: /analyze returned only the Incident, with no visibility into how
      many rows were skipped or why -- even though ParseResult (from
      parser.py / mordor_parser.py) already carries that information.
      /analyze now returns an AnalyzeResponse wrapping both the Incident
      and parse diagnostics (skipped count, total rows, a capped list of
      error strings), instead of silently discarding them.
  #9: detect_format previously routed to parse_mordor purely on a .json/
      .ndjson extension, with no content check -- so a mislabeled file
      (e.g. a CSV renamed to .json) silently produced a 0-event
      "successful" Incident instead of an error. dispatch.py now verifies
      content for every non-.csv file; that raises UnknownLogFormatError,
      which /analyze and /upload now catch here and turn into a clear
      422 response instead of an unhandled 500.
"""

from __future__ import annotations

import tempfile
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.config import settings
from app.dispatch import UnknownLogFormatError
from app.models import Incident
from app.orchestrator import run_analysis_with_diagnostics
from app.storage import get_incident, save_incident

app = FastAPI(title="Cybersecurity Incident Reconstruction API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# .json is included alongside .ndjson because every real Mordor/OTRF
# dataset ships with a .json extension despite being newline-delimited
# JSON, not a single JSON document (see dispatch.py's content-sniffing
# fallback for files where the extension is ambiguous or wrong).
ACCEPTED_EXTENSIONS = (".csv", ".ndjson", ".json")

# Bound how many individual parse-error strings are echoed back to a
# client; ParseResult.errors can be long on a very messy file and there is
# no reason to ship thousands of lines of diagnostics over HTTP.
MAX_DIAGNOSTIC_ERRORS = 50


class ParseDiagnostics(BaseModel):
    """Parse-time diagnostics for a single /analyze run (fixes #5)."""

    total_rows: int
    skipped: int
    errors: list[str]


class AnalyzeResponse(BaseModel):
    """Wraps the Incident together with parse diagnostics, so a caller can
    see *why* an Incident has fewer events than the source file without
    re-parsing it themselves."""

    incident: Incident
    diagnostics: ParseDiagnostics


def _human_size(num_bytes: int) -> str:
    """'50 MB' for whole megabytes, otherwise a plain byte count."""
    megabyte = 1024 * 1024
    if num_bytes >= megabyte and num_bytes % megabyte == 0:
        return f"{num_bytes // megabyte} MB"
    return f"{num_bytes} bytes"


def _check_size(contents: bytes) -> None:
    """Reject uploads over the configured limit (MAX_UPLOAD_BYTES), read at
    request time so a changed setting needs no code edit."""
    if len(contents) > settings.max_upload_bytes:
        raise HTTPException(
            413, f"File too large (max {_human_size(settings.max_upload_bytes)})"
        )


def _require_filename(filename: str | None) -> str:
    """Narrow UploadFile.filename (str | None) to str, or raise. FastAPI
    allows a filename-less upload; we don't accept one, and this also
    satisfies static type checkers that _save_upload receives a real str
    instead of str | None."""
    if not filename:
        raise HTTPException(400, "Uploaded file must have a filename")
    return filename


def _validate_extension(filename: str) -> None:
    if not filename.lower().endswith(ACCEPTED_EXTENSIONS):
        accepted = ", ".join(ACCEPTED_EXTENSIONS)
        raise HTTPException(400, f"Only {accepted} files are accepted")


def _save_upload(filename: str, contents: bytes) -> str:
    """Write uploaded bytes to a collision-proof temp path and return it.

    Uses tempfile.gettempdir() instead of a hardcoded "/tmp/..." path.
    "/tmp" doesn't exist on Windows by default, so the old hardcoded path
    raised FileNotFoundError on every upload when the server ran on
    Windows (open() cannot create missing parent directories).
    tempfile.gettempdir() resolves to the correct OS temp directory
    (e.g. C:\\Users\\<user>\\AppData\\Local\\Temp on Windows, /tmp on
    Linux/Mac) so this works the same way regardless of platform.
    """
    temp_dir = Path(tempfile.gettempdir())
    path = temp_dir / f"{uuid.uuid4().hex}_{filename}"
    with open(path, "wb") as f:
        f.write(contents)
    return str(path)


@app.post("/upload")
async def upload_endpoint(file: UploadFile = File(...)):
    filename = _require_filename(file.filename)
    _validate_extension(filename)

    contents = await file.read()
    _check_size(contents)

    file_id = uuid.uuid4().hex
    path = _save_upload(filename, contents)

    return {"file_id": file_id, "path": path}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_endpoint(file: UploadFile = File(...)):
    filename = _require_filename(file.filename)
    _validate_extension(filename)

    contents = await file.read()
    _check_size(contents)

    path = _save_upload(filename, contents)

    try:
        incident, result = run_analysis_with_diagnostics(path)
    except UnknownLogFormatError as exc:
        raise HTTPException(422, f"Could not determine file format: {exc}") from exc

    save_incident(incident)

    return AnalyzeResponse(
        incident=incident,
        diagnostics=ParseDiagnostics(
            total_rows=result.total_rows,
            skipped=result.skipped,
            errors=result.errors[:MAX_DIAGNOSTIC_ERRORS],
        ),
    )


@app.get("/incident/{incident_id}", response_model=Incident)
def get_incident_endpoint(incident_id: str):
    incident = get_incident(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident
