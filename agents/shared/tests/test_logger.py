"""Unit tests for agents.shared.logger — JsonFormatter and configure_json_logging."""

import json
import logging

import pytest

from agents.shared.logger import AgentLogger, JsonFormatter, configure_json_logging


def _make_record(msg: str = "hello", name: str = "test.logger", level: int = logging.INFO, **extra):
    """Build a minimal LogRecord with optional extra attributes."""
    record = logging.LogRecord(
        name=name,
        level=level,
        pathname="",
        lineno=0,
        msg=msg,
        args=(),
        exc_info=None,
    )
    for key, val in extra.items():
        setattr(record, key, val)
    return record


class TestJsonFormatter:
    """Tests for JsonFormatter.format()."""

    def test_standard_fields_always_present(self):
        """ts, level, logger, and msg must appear in every record."""
        formatter = JsonFormatter()
        record = _make_record("test message")
        result = json.loads(formatter.format(record))

        assert "ts" in result
        assert result["level"] == "INFO"
        assert result["logger"] == "test.logger"
        assert result["msg"] == "test message"

    def test_none_valued_well_known_fields_are_stripped(self):
        """Optional fields not set on the record should not appear in output."""
        formatter = JsonFormatter()
        record = _make_record("bare record")
        result = json.loads(formatter.format(record))

        assert "correlation_id" not in result
        assert "agent" not in result
        assert "intent" not in result
        assert "latency_ms" not in result
        assert "status" not in result

    def test_extra_well_known_fields_are_included(self):
        """latency_ms, status, intent, agent, correlation_id flow through when set."""
        formatter = JsonFormatter()
        record = _make_record(
            "structured",
            correlation_id="corr-123",
            agent="systems",
            intent="vuln_lookup",
            latency_ms=42.5,
            status=200,
        )
        result = json.loads(formatter.format(record))

        assert result["correlation_id"] == "corr-123"
        assert result["agent"] == "systems"
        assert result["intent"] == "vuln_lookup"
        assert result["latency_ms"] == 42.5
        assert result["status"] == 200

    def test_output_is_valid_json_for_error_record(self):
        """ERROR-level records must still produce valid, parseable JSON."""
        formatter = JsonFormatter()
        record = _make_record("something broke", level=logging.ERROR, correlation_id="c-err")
        raw = formatter.format(record)
        result = json.loads(raw)

        assert result["level"] == "ERROR"
        assert result["correlation_id"] == "c-err"


class TestConfigureJsonLogging:
    """Tests for configure_json_logging()."""

    def test_installs_json_formatter_on_root_logger(self):
        """configure_json_logging() must install a StreamHandler with JsonFormatter."""
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        original_level = root.level
        try:
            configure_json_logging(level=logging.WARNING)
            assert len(root.handlers) == 1
            handler = root.handlers[0]
            assert isinstance(handler, logging.StreamHandler)
            assert isinstance(handler.formatter, JsonFormatter)
            assert root.level == logging.WARNING
        finally:
            root.handlers.clear()
            root.handlers.extend(original_handlers)
            root.setLevel(original_level)

    def test_text_fallback_does_not_install_json_formatter(self, monkeypatch):
        """KGCS_LOG_FORMAT=text must not install a JsonFormatter."""
        monkeypatch.setenv("KGCS_LOG_FORMAT", "text")
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        original_level = root.level
        try:
            configure_json_logging()
            # basicConfig was called; ensure no JsonFormatter is active
            for handler in root.handlers:
                assert not isinstance(handler.formatter, JsonFormatter), (
                    "JsonFormatter must not be installed when KGCS_LOG_FORMAT=text"
                )
        finally:
            root.handlers.clear()
            root.handlers.extend(original_handlers)
            root.setLevel(original_level)


class TestAgentLoggerTimed:
    """Tests for AgentLogger.timed() context manager."""

    def test_timed_logs_latency_ms(self, caplog):
        """timed() must emit an INFO record that includes a latency_ms field."""
        logger = AgentLogger("test.timed", "corr-timed-001")
        with caplog.at_level(logging.DEBUG, logger="test.timed"):
            with logger.timed("my_operation"):
                pass  # instant; latency_ms will be ~0

        records = [r for r in caplog.records if r.name == "test.timed"]
        assert records, "Expected at least one log record from timed()"
        last = records[-1]
        assert hasattr(last, "latency_ms"), "timed() must set latency_ms on the log record"
        assert isinstance(last.latency_ms, float)
        assert last.latency_ms >= 0.0

    def test_timed_propagates_extra_kwargs(self, caplog):
        """Extra kwargs passed to timed() are forwarded to the log record."""
        logger = AgentLogger("test.timed.kwargs", "corr-kw-001")
        with caplog.at_level(logging.DEBUG, logger="test.timed.kwargs"):
            with logger.timed("step", intent="attack_path"):
                pass

        records = [r for r in caplog.records if r.name == "test.timed.kwargs"]
        assert records
        last = records[-1]
        assert getattr(last, "intent", None) == "attack_path"
