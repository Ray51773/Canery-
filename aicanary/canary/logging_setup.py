"""Central logging.

Every component logs through the one logger configured here so that a single
file is the audit trail for canary creation, planting, S3-hit ingestion and
probe runs. The alerting path must never fail silently, so alert-related call
sites log at WARNING/ERROR and re-raise where a caller needs to know.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

_LOGGER_NAME = "canary"
_CONFIGURED = False


def setup_logging(log_path: str | Path = "canary.log", level: str = "INFO") -> logging.Logger:
    """Configure and return the shared ``canary`` logger.

    Logs go to both stderr (so CLI runs are visible) and a rotating-friendly
    append-only file (the central audit trail). Calling this more than once is
    safe and does not duplicate handlers.
    """
    global _CONFIGURED
    logger = logging.getLogger(_LOGGER_NAME)

    if _CONFIGURED:
        return logger

    numeric_level = getattr(logging, str(level).upper(), logging.INFO)
    logger.setLevel(numeric_level)

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s.%(module)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)

    try:
        path = Path(log_path)
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)
    except OSError as exc:  # pragma: no cover - filesystem edge case
        # Losing the file sink must not take down the process, but it must be
        # loud: the central audit trail is a security control.
        logger.warning("Could not open log file %s: %s (stderr logging only)", log_path, exc)

    logger.propagate = False
    _CONFIGURED = True
    return logger


def get_logger() -> logging.Logger:
    """Return the shared logger, configuring a default if needed."""
    if not _CONFIGURED:
        return setup_logging()
    return logging.getLogger(_LOGGER_NAME)
