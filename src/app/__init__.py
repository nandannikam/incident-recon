"""
Central place to configure logging exactly once, before any submodule logs.

Every entrypoint imports the `app` package before doing anything else
(the CLI does via `python -m app.orchestrator`, FastAPI does via
`uvicorn app.main:app`, pytest does via its normal test collection import),
so configuring logging here guarantees it runs first and is never duplicated.
"""

import logging

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def _configure_logging() -> None:
    root = logging.getLogger()
    if getattr(root, "_incident_configured", False):
        return  # idempotent: safe if `app` gets imported more than once

    root.setLevel(logging.INFO)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter(_LOG_FORMAT))

    file_handler = logging.FileHandler("app.log", encoding="utf-8")
    file_handler.setFormatter(logging.Formatter(_LOG_FORMAT))

    root.addHandler(stream_handler)
    root.addHandler(file_handler)
    setattr(root, "_incident_configured", True)  # noqa: B010


_configure_logging()
