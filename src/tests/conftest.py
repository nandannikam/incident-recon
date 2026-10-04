"""Shared pytest fixtures.

`client` gives every API test its own throw-away SQLite file, so tests never
write to (or read from) a developer's real ``incidents.db``.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import storage
from app.main import app


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "test_incidents.db"))
    with TestClient(app) as test_client:
        yield test_client
