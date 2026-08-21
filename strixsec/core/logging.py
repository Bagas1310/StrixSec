"""
Structured Logging Subsystem for StrixSec.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter for automated log ingestion & auditing."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "extra") and isinstance(record.extra, dict):  # type: ignore[attr-defined]
            log_entry["extra"] = record.extra  # type: ignore[attr-defined]
        return json.dumps(log_entry)


def setup_logger(
    name: str = "strixsec",
    level: str = "INFO",
    json_format: bool = False,
) -> logging.Logger:
    """Configure and return a structured logger for StrixSec modules.

    Args:
        name: Logger name.
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        json_format: If True, output structured JSON records to stderr.
    """
    logger = logging.getLogger(name)
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    # Avoid duplicate handlers
    if logger.handlers:
        return logger

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(numeric_level)

    if json_format:
        handler.setFormatter(JSONFormatter())
    else:
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)

    logger.addHandler(handler)
    logger.propagate = False
    return logger


# Default application logger instance
logger = setup_logger()
