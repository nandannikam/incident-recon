"""Step 1 (Phase 3) — lock the HTTP contract.

Phase 2 changed ``POST /analyze`` from returning a bare ``Incident`` to
returning ``{"incident": ..., "diagnostics": ...}`` and the frontend broke
silently, because nothing asserted the response shape. These tests make that
class of change fail loudly.

The shared fixture ``contracts/analyze_response.json`` (repo root) is the
single description of the response shape. This file checks the backend
against it; the frontend tests (Phase 3 Step 13) import the very same file.
If you change the API shape, update the fixture in the same commit.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from app.main import AnalyzeResponse

# tests/ -> src/ -> repo root
CONTRACT_PATH = (
    Path(__file__).resolve().parents[2] / "contracts" / "analyze_response.json"
)

# Smallest CSV that makes REG-PERSIST-01 fire: a process, then a write to a
# real autostart key on the same host inside the 5-minute window.
ATTACK_CSV = (
    "timestamp,source,event_type,actor,target,metadata\n"
    '2024-01-01T10:00:00Z,HOST01,process_execution,USER01,invoice.exe,"{""pid"": 2048}"\n'
    "2024-01-01T10:01:00Z,HOST01,registry_modification,USER01,"
    r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\Updater"
    ',"{}"\n'
)


def _sysmon_line(event_id: int, time_created: str, message: str) -> str:
    return json.dumps(
        {
            "SourceName": "Microsoft-Windows-Sysmon",
            "Hostname": "HOST01.lab.local",
            "TimeCreated": time_created,
            "EventID": event_id,
            "Message": message,
        }
    )


# Same attack, expressed as Mordor/Sysmon NDJSON (saved with a .json
# extension, exactly like every real Mordor dataset).
ATTACK_NDJSON = (
    _sysmon_line(
        1,
        "2020-09-15 03:29:44.169",
        "Process Create:\nProcessId: 3060\nImage: C:\\Windows\\System32\\cmd.exe\n"
        "User: LAB\\user01\n",
    )
    + "\n"
    + _sysmon_line(
        13,
        "2020-09-15 03:30:14.169",
        "Registry value set:\n"
        "TargetObject: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater\n"
        "User: LAB\\user01\n",
    )
    + "\n"
)


def _key_paths(node: Any, prefix: str = "") -> set[str]:
    """Every dotted key path in a JSON document. Lists are walked through
    their first element (``a[].b``); values and list lengths are ignored, so
    only the *shape* is compared."""
    paths: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            paths.add(child)
            paths |= _key_paths(value, child)
    elif isinstance(node, list) and node:
        paths |= _key_paths(node[0], f"{prefix}[]")
    return paths


def _load_contract() -> dict[str, Any]:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def _post_analyze(client: TestClient, filename: str, content: str, mime: str):
    return client.post(
        "/analyze", files={"file": (filename, content.encode("utf-8"), mime)}
    )


# ---------------------------------------------------------------------------
# The shared fixture itself
# ---------------------------------------------------------------------------


def test_shared_contract_fixture_is_a_valid_analyze_response() -> None:
    """If this fails, the fixture drifted from the backend's own models."""
    AnalyzeResponse.model_validate(_load_contract())


# ---------------------------------------------------------------------------
# POST /analyze response shape
# ---------------------------------------------------------------------------


def test_analyze_returns_wrapped_response(client: TestClient) -> None:
    res = _post_analyze(client, "attack.csv", ATTACK_CSV, "text/csv")

    assert res.status_code == 200
    body = res.json()
    assert set(body) == {"incident", "diagnostics"}, (
        "response shape changed — update contracts/analyze_response.json and api.ts"
    )
    assert "conclusions" in body["incident"]
    assert "total_rows" in body["diagnostics"]


def test_analyze_response_matches_shared_contract(client: TestClient) -> None:
    res = _post_analyze(client, "attack.csv", ATTACK_CSV, "text/csv")
    assert res.status_code == 200
    body = res.json()
    assert body["incident"]["conclusions"], "fixture needs at least one conclusion"

    assert _key_paths(body) == _key_paths(_load_contract()), (
        "live /analyze response and contracts/analyze_response.json disagree "
        "on field names — update the fixture (and the frontend types)"
    )


def test_analyze_conclusions_carry_evidence_and_rule_id(client: TestClient) -> None:
    body = _post_analyze(client, "attack.csv", ATTACK_CSV, "text/csv").json()

    rule_ids = {c["rule_id"] for c in body["incident"]["conclusions"]}
    assert "REG-PERSIST-01" in rule_ids
    for conclusion in body["incident"]["conclusions"]:
        assert conclusion["rule_id"]
        assert conclusion["evidence"]
        assert conclusion["evidence"][0]["event_ids"]


def test_analyze_diagnostics_report_row_counts(client: TestClient) -> None:
    body = _post_analyze(client, "attack.csv", ATTACK_CSV, "text/csv").json()

    assert body["diagnostics"] == {"total_rows": 2, "skipped": 0, "errors": []}


def test_analyze_accepts_mordor_ndjson_with_json_extension(
    client: TestClient,
) -> None:
    """Real Mordor datasets are NDJSON saved as .json — must go through the
    same endpoint and produce the same response shape."""
    res = _post_analyze(client, "mordor_sample.json", ATTACK_NDJSON, "application/json")

    assert res.status_code == 200
    body = res.json()
    assert set(body) == {"incident", "diagnostics"}
    assert body["diagnostics"]["total_rows"] == 2
    assert "REG-PERSIST-01" in {c["rule_id"] for c in body["incident"]["conclusions"]}


# ---------------------------------------------------------------------------
# GET /incident/{id}
# ---------------------------------------------------------------------------


def test_get_incident_returns_the_bare_incident(client: TestClient) -> None:
    analyzed = _post_analyze(client, "attack.csv", ATTACK_CSV, "text/csv").json()
    incident_id = analyzed["incident"]["id"]

    res = client.get(f"/incident/{incident_id}")

    assert res.status_code == 200
    # GET returns the Incident itself — NOT the {incident, diagnostics} wrapper.
    assert set(res.json()) == set(analyzed["incident"])
    assert res.json() == analyzed["incident"]


# ---------------------------------------------------------------------------
# Rejected input
# ---------------------------------------------------------------------------


def test_csv_renamed_to_json_is_rejected_with_422(client: TestClient) -> None:
    """KNOWN-ISSUES #9: a CSV saved as .json must produce a clear error, not
    a 200 with zero events."""
    res = _post_analyze(client, "attack_sample.json", ATTACK_CSV, "application/json")

    assert res.status_code == 422
    assert "Could not determine file format" in res.json()["detail"]


def test_unsupported_extension_is_rejected_with_400(client: TestClient) -> None:
    res = _post_analyze(client, "notes.txt", "hello", "text/plain")

    assert res.status_code == 400


def test_upload_endpoint_returns_file_id_and_path(client: TestClient) -> None:
    res = client.post(
        "/upload", files={"file": ("attack.csv", ATTACK_CSV.encode(), "text/csv")}
    )

    assert res.status_code == 200
    assert set(res.json()) == {"file_id", "path"}
