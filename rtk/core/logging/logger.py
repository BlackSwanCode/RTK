"""Structured JSON logging with automatic PII/secret masking."""
from __future__ import annotations

import hashlib
import json
import logging
import re
import sys
from datetime import datetime, timezone
from typing import Any

AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
GCP_KEY_RE = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
GENERIC_TOKEN_RE = re.compile(r"(?i)\b(?:token|key|secret|password)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{16,})['\"]?")


def _mask_secrets(text: str) -> str:
    def replacer(match: re.Match) -> str:
        return f"HASH:{hashlib.sha256(match.group(0).encode('utf-8')).hexdigest()[:16]}"
    text = AWS_KEY_RE.sub(replacer, text)
    text = GCP_KEY_RE.sub(replacer, text)
    text = GENERIC_TOKEN_RE.sub(replacer, text)
    return text


class SecureJSONFormatter(logging.Formatter):
    REQUIRED_FIELDS = {"timestamp_utc", "module", "session_id", "actor", "action", "target", "request_summary", "response_summary", "correlation_id"}

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp_utc": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": _mask_secrets(record.getMessage()),
        }

        for field in self.REQUIRED_FIELDS:
            val = getattr(record, field, None)
            payload[field] = _mask_secrets(str(val)) if val is not None else "unknown"

        for key, value in record.__dict__.items():
            if key not in {"msg", "levelname", "name", "created", "exc_info"} and key not in self.REQUIRED_FIELDS:
                payload[key] = _mask_secrets(str(value))

        if record.exc_info:
            payload["exc"] = _mask_secrets(self.formatException(record.exc_info))

        return json.dumps(payload, default=str)


def configure(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("rtk")
    if logger.handlers:
        return logger
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(SecureJSONFormatter())
    logger.setLevel(level)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def get_logger(name: str) -> logging.Logger:
    configure()
    return logging.getLogger(f"rtk.{name}")
