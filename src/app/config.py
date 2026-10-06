"""
Phase 3, Step 6 — Configuration management.

One source of truth for the environment-specific values. Values are read
(in priority order) from: explicit constructor arguments, real environment
variables, then a ``.env`` file in the working directory, then the defaults
below. Variable names are the upper-case field names (``MAX_UPLOAD_BYTES``,
``CORS_ORIGINS`` ...); see ``.env.example`` at the repository root.

This module must not import anything else from ``app`` -- ``app.models`` and
``app.__init__`` both import it, so any back-import would be circular.

Fail-fast rule: a bad value (non-positive upload limit, ``*`` as a CORS origin,
unknown log level, production without an API key ...) raises a pydantic
``ValidationError`` when the ``app`` package is first imported, so a
misconfigured deployment refuses to start instead of misbehaving later.

``database_url`` and ``api_key`` are declared here so the whole configuration
lives in one place; they are consumed by the PostgreSQL step (Step 7) and the
API-hardening step (Step 8) respectively.
"""

from __future__ import annotations

import logging
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """The tunable values of the backend, validated once at start-up."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        # A shared .env may also hold frontend values (VITE_API_BASE_URL ...);
        # unknown keys are ignored rather than rejected.
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "development"

    # Comma-separated list. A plain string (not list[str]) on purpose: the
    # natural way to write it in a .env file or a Docker env var is
    # "http://a.com,http://b.com", which pydantic-settings would otherwise
    # try (and fail) to decode as JSON.
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    max_upload_bytes: int = Field(default=50 * 1024 * 1024, gt=0)
    upload_dir: str | None = None
    time_window_minutes: int = Field(default=5, ge=1)

    # Above this many parsed events, POST /analyze runs graph + reasoning as
    # a FastAPI BackgroundTask and returns 202 with a job id instead of
    # blocking the request (see main.py). Kept configurable so tests can force
    # the background path with a small upload.
    background_analysis_threshold: int = Field(default=5000, ge=1)

    database_url: str = "sqlite:///./incidents.db"
    api_key: str | None = None

    log_level: str = "INFO"

    @field_validator("log_level")
    @classmethod
    def _check_log_level(cls, value: str) -> str:
        level = value.strip().upper()
        if level not in logging.getLevelNamesMapping() or level == "NOTSET":
            raise ValueError(
                f"unknown log level {value!r}; use DEBUG, INFO, WARNING, ERROR or CRITICAL"
            )
        return level

    @field_validator("cors_origins")
    @classmethod
    def _check_cors_origins(cls, value: str) -> str:
        origins = [o.strip() for o in value.split(",") if o.strip()]
        if "*" in origins:
            # The API sends credentials; browsers reject "*" together with them.
            raise ValueError(
                "CORS_ORIGINS must list explicit origins, not '*' "
                "(wildcard origins are invalid with credentials)"
            )
        return value

    @field_validator("database_url")
    @classmethod
    def _check_database_url(cls, value: str) -> str:
        if "://" not in value.strip():
            raise ValueError(
                "DATABASE_URL must look like 'sqlite:///./incidents.db' "
                "or 'postgresql://user:pass@host/db'"
            )
        return value.strip()

    @model_validator(mode="after")
    def _require_secrets_in_production(self) -> Settings:
        if self.environment == "production" and not (self.api_key or "").strip():
            raise ValueError("API_KEY must be set when ENVIRONMENT=production")
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        """CORS origins with whitespace and trailing slashes removed (a
        trailing slash makes the browser's Origin comparison fail)."""
        return [
            o.strip().rstrip("/") for o in self.cors_origins.split(",") if o.strip()
        ]


settings = Settings()
