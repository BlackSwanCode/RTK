"""Structured JSON logging for RTK.

All modules MUST use this logger. Plain ``print()`` is forbidden.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class JSONFormatter(logging.Formatter):
    """Render log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        # Merge any extra fields attached to the record
        for key in ("module", "target", "scope", "http_status", "url"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        return json.dumps(payload, default=str)


def configure(level: int = logging.INFO) -> logging.Logger:
    """Configure and return the root ``rtk`` logger."""
    logger = logging.getLogger("rtk")
    if logger.handlers:
        return logger
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JSONFormatter())
    logger.setLevel(level)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the ``rtk`` namespace."""
    configure()
    return logging.getLogger(f"rtk.{name}")
