"""Structured logging with correlation ID support for end-to-end tracing.

All agent logs include the correlation_id for tracing requests through
the entire agent stack.

JSON output
-----------
``configure_json_logging()`` installs a JSON formatter on the root logger.
Call once at application startup (e.g. in ``orchestrator.api.main()``).
Set ``KGCS_LOG_FORMAT=text`` to keep plain-text output during local development.

Structured fields emitted per JSON record: ``ts``, ``level``, ``logger``,
``msg``, ``correlation_id``, ``agent``, ``intent``, ``latency_ms``, ``status``.
None-valued keys are omitted to keep lines compact.
"""

import contextlib
import json
import logging
import os
import time
from typing import Any, Optional


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object.

    Well-known extra keys supplied via ``extra=`` or ``AgentLogger`` kwargs
    are promoted to top-level fields.  Unknown extra keys are silently dropped.
    """

    _WELL_KNOWN = ("correlation_id", "agent", "intent", "latency_ms", "status")

    def format(self, record: logging.LogRecord) -> str:
        doc: dict = {
            "ts":     self.formatTime(record, self.datefmt),
            "level":  record.levelname,
            "logger": record.name,
            "msg":    record.getMessage(),
        }
        for key in self._WELL_KNOWN:
            val = getattr(record, key, None)
            if val is not None:
                doc[key] = val
        return json.dumps(doc)


# ---------------------------------------------------------------------------
# Application-level configuration helper
# ---------------------------------------------------------------------------

def configure_json_logging(level: int = logging.INFO) -> None:
    """Install the JSON formatter on the root logger's StreamHandler.

    Call once at application startup.  When ``KGCS_LOG_FORMAT=text`` is set
    the standard ``logging.basicConfig`` is used instead (better for local dev).

    Args:
        level: Root logger level (default: INFO).
    """
    if os.getenv("KGCS_LOG_FORMAT", "json").lower() == "text":
        logging.basicConfig(
            level=level,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        return

    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(handler)


# ---------------------------------------------------------------------------
# Agent logger
# ---------------------------------------------------------------------------

class AgentLogger:
    """Logger that injects correlation_id into all log messages.

    Each log entry includes [correlation_id] prefix for easy filtering and
    tracing across agent boundaries.  When JSON logging is active the
    correlation_id is also emitted as a structured field.

    Use :meth:`timed` to measure and log the wall-clock duration of a block::

        with self.logger.timed("agent_execute", intent=intent):
            result = agent.execute(request)
    """

    def __init__(self, name: str, correlation_id: str, level: int = logging.NOTSET):
        """Initialize logger with correlation ID.

        Args:
            name: Logger name (typically module name, e.g., "agents.systems")
            correlation_id: Request correlation ID (UUID string)
            level: Logging level (default: INFO)
        """
        self.logger = logging.getLogger(name)
        self.correlation_id = correlation_id
        # Inherit the effective level from test or app logging configuration by default.
        self.logger.setLevel(level)

    def info(self, msg: str, **kwargs) -> None:
        """Log info message with correlation ID."""
        self.logger.info(
            f"[{self.correlation_id}] {msg}",
            extra={"correlation_id": self.correlation_id, **kwargs}
        )

    def debug(self, msg: str, **kwargs) -> None:
        """Log debug message with correlation ID."""
        self.logger.debug(
            f"[{self.correlation_id}] {msg}",
            extra={"correlation_id": self.correlation_id, **kwargs}
        )

    def warning(self, msg: str, **kwargs) -> None:
        """Log warning message with correlation ID."""
        self.logger.warning(
            f"[{self.correlation_id}] {msg}",
            extra={"correlation_id": self.correlation_id, **kwargs}
        )

    def error(
        self,
        msg: str,
        exc: Optional[Exception] = None,
        **kwargs
    ) -> None:
        """Log error message with correlation ID.

        Args:
            msg: Error message
            exc: Optional exception object (will include stack trace)
            **kwargs: Additional context to include in log
        """
        if exc:
            self.logger.error(
                f"[{self.correlation_id}] {msg}",
                exc_info=exc,
                extra={"correlation_id": self.correlation_id, **kwargs}
            )
        else:
            self.logger.error(
                f"[{self.correlation_id}] {msg}",
                extra={"correlation_id": self.correlation_id, **kwargs}
            )

    def critical(
        self,
        msg: str,
        exc: Optional[Exception] = None,
        **kwargs
    ) -> None:
        """Log critical message with correlation ID."""
        if exc:
            self.logger.critical(
                f"[{self.correlation_id}] {msg}",
                exc_info=exc,
                extra={"correlation_id": self.correlation_id, **kwargs}
            )
        else:
            self.logger.critical(
                f"[{self.correlation_id}] {msg}",
                extra={"correlation_id": self.correlation_id, **kwargs}
            )

    @contextlib.contextmanager
    def timed(self, label: str, **kwargs: Any):
        """Context manager that measures wall-clock duration and logs it.

        Emits an INFO record after the block exits with ``latency_ms`` set
        to the elapsed time in milliseconds.

        Example::

            with self.logger.timed("agent_execute", intent="vuln_lookup"):
                result = agent.execute(request)

        Args:
            label: Log message label (e.g., "agent_execute")
            **kwargs: Additional structured fields forwarded to the log record
        """
        t0 = time.perf_counter()
        try:
            yield
        finally:
            latency_ms = round((time.perf_counter() - t0) * 1000, 1)
            self.info(label, latency_ms=latency_ms, **kwargs)
