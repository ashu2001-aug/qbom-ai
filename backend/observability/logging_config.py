"""
observability/logging_config.py — Structured JSON logging for production.

In development:  coloured human-readable output
In production:   JSON lines (stdout → Azure Monitor / ELK / Loki)

Usage in main.py:
    from observability.logging_config import configure_logging
    configure_logging()
"""
from __future__ import annotations

import json
import logging
import os
import sys
import traceback
from datetime import datetime, timezone
from typing import Any


class JsonFormatter(logging.Formatter):
    """
    Formats log records as JSON lines.
    Every line is a valid JSON object — friendly to log aggregators.
    """
    SERVICE = "qbom-ai-backend"
    VERSION = "1.0.0"

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        payload: dict[str, Any] = {
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "level":       record.levelname,
            "logger":      record.name,
            "message":     record.getMessage(),
            "service":     self.SERVICE,
            "version":     self.VERSION,
            "environment": os.getenv("ENVIRONMENT", "development"),
        }

        # Include exception info if present
        if record.exc_info:
            payload["exception"] = {
                "type":       record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message":    str(record.exc_info[1]),
                "stacktrace": traceback.format_exception(*record.exc_info),
            }

        # Include any extra fields attached to the log record
        for key, value in record.__dict__.items():
            if key not in (
                "args", "asctime", "created", "exc_info", "exc_text", "filename",
                "funcName", "id", "levelname", "levelno", "lineno", "module",
                "msecs", "message", "msg", "name", "pathname", "process",
                "processName", "relativeCreated", "stack_info", "thread", "threadName",
            ):
                payload[key] = value

        return json.dumps(payload, default=str)


class DevFormatter(logging.Formatter):
    """Coloured human-readable formatter for local development."""

    COLOURS = {
        "DEBUG":    "\033[36m",   # cyan
        "INFO":     "\033[32m",   # green
        "WARNING":  "\033[33m",   # yellow
        "ERROR":    "\033[31m",   # red
        "CRITICAL": "\033[35m",   # magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        colour = self.COLOURS.get(record.levelname, "")
        ts     = datetime.now().strftime("%H:%M:%S")
        prefix = f"{colour}[{record.levelname[0]}]{self.RESET}"
        name   = f"\033[2m{record.name}\033[0m"
        return f"{ts} {prefix} {name}  {record.getMessage()}"


def configure_logging(level: str = "INFO") -> None:
    """
    Configure root logger and key library loggers.
    Call once at application startup — before the first log message.
    """
    environment = os.getenv("ENVIRONMENT", "development")
    is_prod     = environment == "production"

    formatter = JsonFormatter() if is_prod else DevFormatter()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    # Root logger
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()
    root.addHandler(handler)

    # Quieten noisy third-party loggers
    for noisy in ("httpx", "httpcore", "openai", "pinecone", "urllib3", "botocore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    # LangChain can be very verbose in dev — keep at WARNING unless debugging
    for lc in ("langchain", "langchain_core", "langgraph"):
        logging.getLogger(lc).setLevel(
            logging.DEBUG if os.getenv("LANGCHAIN_VERBOSE") else logging.WARNING
        )

    logging.getLogger("qbom").info(
        "Logging configured",
        extra={"environment": environment, "level": level, "format": "json" if is_prod else "dev"}
    )
