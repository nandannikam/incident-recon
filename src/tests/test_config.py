"""Phase 3, Step 6 — configuration management tests."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings, settings

SRC_DIR = Path(__file__).resolve().parents[1]

# Exactly the variables Settings reads. Removed from the environment in
# `clean_env` so a developer's shell can never change a test result.
_SETTING_VARS = (
    "ENVIRONMENT",
    "CORS_ORIGINS",
    "MAX_UPLOAD_BYTES",
    "TIME_WINDOW_MINUTES",
    "DATABASE_URL",
    "API_KEY",
    "LOG_LEVEL",
)

SMALL_CSV = (
    b"timestamp,source,event_type,actor,target,metadata\n"
    b"2024-01-01T10:00:00Z,HOST01,process_execution,USER01,a.exe,{}\n"
)


@pytest.fixture()
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in _SETTING_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def _fresh(**overrides: object) -> Settings:
    """A Settings that ignores any real .env file."""
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Defaults and overrides
# ---------------------------------------------------------------------------


def test_defaults_match_the_previously_hardcoded_values(
    clean_env: pytest.MonkeyPatch,
) -> None:
    s = _fresh()

    assert s.environment == "development"
    assert s.max_upload_bytes == 50 * 1024 * 1024
    assert s.time_window_minutes == 5
    assert s.database_url == "sqlite:///./incidents.db"
    assert s.log_level == "INFO"
    assert s.api_key is None
    assert s.cors_origin_list == ["http://localhost:5173", "http://127.0.0.1:5173"]


def test_environment_variable_overrides_a_setting(
    clean_env: pytest.MonkeyPatch,
) -> None:
    clean_env.setenv("MAX_UPLOAD_BYTES", "10")
    clean_env.setenv("TIME_WINDOW_MINUTES", "9")
    clean_env.setenv("LOG_LEVEL", "debug")

    s = _fresh()

    assert s.max_upload_bytes == 10
    assert s.time_window_minutes == 9
    assert s.log_level == "DEBUG"  # normalised to upper case


def test_dotenv_file_is_read_and_unknown_keys_are_ignored(
    clean_env: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "MAX_UPLOAD_BYTES=123\nVITE_API_BASE_URL=http://localhost:8000\n",
        encoding="utf-8",
    )

    s = Settings(_env_file=env_file)  # type: ignore[call-arg]

    assert s.max_upload_bytes == 123


def test_cors_origins_are_split_trimmed_and_slash_stripped(
    clean_env: pytest.MonkeyPatch,
) -> None:
    clean_env.setenv("CORS_ORIGINS", " http://a.example/ ,http://b.example ,, ")

    assert _fresh().cors_origin_list == ["http://a.example", "http://b.example"]


# ---------------------------------------------------------------------------
# Validation (fail fast on bad configuration)
# ---------------------------------------------------------------------------


def test_wildcard_cors_origin_is_rejected() -> None:
    with pytest.raises(ValidationError, match="explicit origins"):
        _fresh(cors_origins="*")


@pytest.mark.parametrize("bad_level", ["LOUD", "", "notset"])
def test_unknown_log_level_is_rejected(bad_level: str) -> None:
    with pytest.raises(ValidationError, match="log level"):
        _fresh(log_level=bad_level)


@pytest.mark.parametrize(
    "field, value",
    [("max_upload_bytes", 0), ("max_upload_bytes", -1), ("time_window_minutes", 0)],
)
def test_non_positive_limits_are_rejected(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        _fresh(**{field: value})


def test_database_url_without_scheme_is_rejected() -> None:
    with pytest.raises(ValidationError, match="DATABASE_URL"):
        _fresh(database_url="incidents.db")


def test_production_requires_an_api_key() -> None:
    with pytest.raises(ValidationError, match="API_KEY"):
        _fresh(environment="production", api_key=None)
    with pytest.raises(ValidationError, match="API_KEY"):
        _fresh(environment="production", api_key="   ")

    assert _fresh(environment="production", api_key="s3cret").api_key == "s3cret"


def test_development_does_not_require_an_api_key() -> None:
    assert _fresh(environment="development", api_key=None).api_key is None


# ---------------------------------------------------------------------------
# The settings really drive behaviour (no code edit needed)
# ---------------------------------------------------------------------------


def test_smaller_upload_limit_changes_api_behaviour(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = {"file": ("small.csv", SMALL_CSV, "text/csv")}
    assert client.post("/analyze", files=files).status_code == 200

    monkeypatch.setattr(settings, "max_upload_bytes", 10)
    res = client.post("/analyze", files=files)

    assert res.status_code == 413
    assert "File too large" in res.json()["detail"]
    assert "10 bytes" in res.json()["detail"]


def test_upload_endpoint_also_enforces_the_limit(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "max_upload_bytes", 1)

    res = client.post(
        "/upload", files={"file": ("a.csv", SMALL_CSV, "text/csv")}
    )

    assert res.status_code == 413


def test_time_window_env_var_reaches_the_models_module(tmp_path: Path) -> None:
    """TIME_WINDOW_MINUTES is read once at import, so verify it in a fresh
    interpreter: changing the environment must change the value with no code
    edit."""
    env = {**os.environ, "TIME_WINDOW_MINUTES": "7", "PYTHONPATH": str(SRC_DIR)}
    env.pop("API_KEY", None)
    env["ENVIRONMENT"] = "development"

    out = subprocess.run(
        [sys.executable, "-c", "from app.models import TIME_WINDOW_MINUTES as t; print(t)"],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        check=True,
    )

    assert out.stdout.strip() == "7"


def test_invalid_environment_stops_startup_with_a_clear_error(tmp_path: Path) -> None:
    env = {**os.environ, "ENVIRONMENT": "production", "PYTHONPATH": str(SRC_DIR)}
    env.pop("API_KEY", None)

    out = subprocess.run(
        [sys.executable, "-c", "import app"],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
    )

    assert out.returncode != 0
    assert "API_KEY must be set" in out.stderr
