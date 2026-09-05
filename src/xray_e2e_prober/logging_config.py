"""JSON logging whose formatter applies the same redaction as public APIs."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from .security import redact_text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": redact_text(record.getMessage()),
        }
        for key in ("event", "instance_id", "source_id", "check_id", "reason"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = redact_text(value, max_length=128)
        if record.exc_info:
            payload["exception"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())

