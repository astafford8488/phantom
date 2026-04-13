"""Structured logging for PHANTOM."""

from __future__ import annotations

import logging
import sys
from typing import Any


class StructuredFormatter(logging.Formatter):
    """Formatter that appends key=value pairs to log messages."""

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = getattr(record, "_structured", {})
        if extras:
            pairs = " ".join(f"{k}={v}" for k, v in extras.items())
            return f"{base} | {pairs}"
        return base


class StructuredLogger:
    """Logger wrapper that supports structured key-value logging."""

    def __init__(self, name: str) -> None:
        self._logger = logging.getLogger(f"phantom.{name}")
        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(
                StructuredFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            )
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.INFO)

    def _log(self, level: int, msg: str, **kwargs: Any) -> None:
        extra = {"_structured": kwargs}
        self._logger.log(level, msg, extra=extra)

    def info(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.INFO, msg, **kwargs)

    def warning(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.WARNING, msg, **kwargs)

    def error(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.ERROR, msg, **kwargs)

    def debug(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.DEBUG, msg, **kwargs)


def get_logger(name: str) -> StructuredLogger:
    """Get a structured logger instance."""
    return StructuredLogger(name)
