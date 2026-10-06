"""Phase 3, Step 3 — request-level background analysis guard.

Small uploads stay on the synchronous ``{incident, diagnostics}`` path.
Above ``BACKGROUND_ANALYSIS_THRESHOLD`` parsed events, ``POST /analyze``
returns 202 with a job id and runs graph + reasoning on a FastAPI
BackgroundTask; ``GET /jobs/{id}`` reports its status.

TestClient runs background tasks before ``client.post`` returns, so these
tests stay deterministic without polling.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import _JOBS

# Two events that make REG-PERSIST-01 fire (process -> autostart registry key).
SMALL_CSV = (
    "timestamp,source,event_type,actor,target,metadata\n"
    '2024-01-01T10:00:00Z,HOST01,process_execution,USER01,invoice.exe,"{""pid"": 2048}"\n'
    "2024-01-01T10:01:00Z,HOST01,registry_modification,USER01,"
    r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\Updater"
    ',"{}"\n'
)


@pytest.fixture(autouse=True)
def _clear_jobs() -> Iterator[None]:
    _JOBS.clear()
    yield
    _JOBS.clear()


def _post_analyze(client: TestClient):
    return client.post(
        "/analyze", files={"file": ("attack.csv", SMALL_CSV.encode(), "text/csv")}
    )


def test_small_file_stays_synchronous(client: TestClient) -> None:
    res = _post_analyze(client)

    assert res.status_code == 200
    body = res.json()
    assert set(body) == {"incident", "diagnostics"}
    assert body["diagnostics"]["total_rows"] == 2


def test_large_file_returns_202_and_completes(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "background_analysis_threshold", 1)

    res = _post_analyze(client)

    assert res.status_code == 202
    body = res.json()
    assert body["status"] == "pending"
    job_id = body["job_id"]
    assert job_id

    job = client.get(f"/jobs/{job_id}")
    assert job.status_code == 200
    payload = job.json()
    assert payload["status"] == "completed"
    assert payload["diagnostics"]["total_rows"] == 2
    assert payload["incident"] is not None
    assert "REG-PERSIST-01" in {
        c["rule_id"] for c in payload["incident"]["conclusions"]
    }


def test_completed_job_incident_is_persisted(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "background_analysis_threshold", 1)

    job_id = _post_analyze(client).json()["job_id"]
    incident_id = client.get(f"/jobs/{job_id}").json()["incident"]["id"]

    res = client.get(f"/incident/{incident_id}")

    assert res.status_code == 200
    assert res.json()["id"] == incident_id


def test_mislabeled_file_still_gets_422_before_scheduling(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Parse happens before the threshold check, so a CSV renamed .json must
    # still fail with 422 even when the background path would be taken.
    monkeypatch.setattr(settings, "background_analysis_threshold", 1)

    res = client.post(
        "/analyze",
        files={"file": ("attack.json", SMALL_CSV.encode(), "application/json")},
    )

    assert res.status_code == 422
    assert "Could not determine file format" in res.json()["detail"]


def test_unknown_job_id_returns_404(client: TestClient) -> None:
    assert client.get("/jobs/does-not-exist").status_code == 404
