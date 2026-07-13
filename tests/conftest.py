"""Root-level pytest configuration and shared fixtures for the KGCS test suite.

Fixtures defined here are available to all tests in the ``tests/`` directory
tree without explicit import.
"""

import logging

import pytest

from agents.shared.logger import JsonFormatter


@pytest.fixture
def correlation_id() -> str:
    """A stable correlation ID for use in tests that need one."""
    return "test-corr-00000000-0000-0000-0000-000000000001"


@pytest.fixture
def json_caplog(caplog):
    """A ``caplog`` variant that enables DEBUG-level capture.

    Use this fixture when you want to assert that specific log records were
    emitted at any level.  The ``JsonFormatter`` is NOT installed here because
    ``caplog`` captures ``LogRecord`` objects directly — call
    ``JsonFormatter().format(record)`` in the test if you need the JSON string.

    Example::

        def test_something(json_caplog):
            with json_caplog.at_level(logging.INFO, logger="kgcs.api"):
                do_something()
            assert any(r.levelname == "INFO" for r in json_caplog.records)
    """
    with caplog.at_level(logging.DEBUG):
        yield caplog
