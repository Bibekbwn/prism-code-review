"""
Structured logging for PRISM.

Uses Python's standard logging with structured format.
For production, install: pip install structlog
"""

import logging
import sys
import json
from datetime import datetime


def setup_logging(level: str = "INFO", json_format: bool = False) -> logging.Logger:
    """Configure structured logging for PRISM."""
    logger = logging.getLogger("prism")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers
    logger.handlers.clear()

    handler = logging.StreamHandler(sys.stderr)

    if json_format:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))

    logger.addHandler(handler)
    logger.propagate = False
    return logger


class JsonFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


logger = setup_logging()