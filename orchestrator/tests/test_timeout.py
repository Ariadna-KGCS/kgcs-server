"""Tests for P5.3 failure handling — timeouts and retries.

Covers:
- API /query returns HTTP 504 when OrchestratorTimeoutError is raised
- API /ask returns HTTP 504 when OrchestratorTimeoutError is raised
- executor._execute_single_intent raises OrchestratorTimeoutError when deadline is exceeded
- executor.execute() propagates OrchestratorTimeoutError uncaught (not swallowed as 500)
- Neo4jClient.query() raises TimeoutError when driver reports a timeout
- Neo4jClient.query() retries on transient Neo4j errors and succeeds on second attempt
"""

import asyncio
import time
from unittest.mock import MagicMock, Mock, patch

import pytest
from aiohttp.test_utils import TestClient, TestServer

from orchestrator.api import create_app
from orchestrator.errors import OrchestratorTimeoutError
from orchestrator.executor import MasterOrchestrator


# ---------------------------------------------------------------------------
# Helpers shared across API tests
# ---------------------------------------------------------------------------

def run_async(coro):
    return asyncio.run(coro)


async def _create_client(app):
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    return client


class _DummyValidator:
    def validate_request(self, payload):
        pass


class _TimeoutOrchestrator:
    """Orchestrator stub that always raises OrchestratorTimeoutError."""

    def __init__(self, correlation_id=None):
        self.correlation_id = correlation_id

    def execute(self, request):
        raise OrchestratorTimeoutError("deadline exceeded in stub")


# ---------------------------------------------------------------------------
# API timeout tests
# ---------------------------------------------------------------------------

class TestApiTimeoutHandling:
    """API layer returns HTTP 504 when the pipeline times out."""

    def test_query_returns_504_on_timeout(self):
        """POST /query must return 504 when OrchestratorTimeoutError is raised."""

        async def scenario():
            app = create_app(
                orchestrator_factory=_TimeoutOrchestrator,
                schema_validator_factory=_DummyValidator,
                readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
            )
            client = await _create_client(app)
            try:
                resp = await client.post(
                    "/query",
                    json={
                        "version": "1.0",
                        "correlation_id": "test-timeout-001",
                        "agent": "systems",
                        "intent": "vuln_lookup",
                        "payload": {"cveId": "CVE-2021-44228"},
                    },
                )
                assert resp.status == 504, f"Expected 504 but got {resp.status}"
                body = await resp.json()
                assert body.get("errors") or body.get("status") == "error"
            finally:
                await client.close()

        run_async(scenario())

    def test_ask_returns_504_on_timeout(self):
        """POST /ask must return 504 when OrchestratorTimeoutError propagates."""

        async def scenario():
            # Patch LLMAdapter.process so it raises OrchestratorTimeoutError
            # without needing a real orchestrator or Neo4j connection.
            with patch("orchestrator.api.LLMAdapter") as MockAdapter:
                mock_instance = MockAdapter.return_value
                mock_instance.process.side_effect = OrchestratorTimeoutError(
                    "pipeline deadline exceeded"
                )

                app = create_app(
                    orchestrator_factory=_TimeoutOrchestrator,
                    schema_validator_factory=_DummyValidator,
                    readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
                )
                client = await _create_client(app)
                try:
                    resp = await client.post(
                        "/ask",
                        json={"prompt": "What vulnerabilities affect log4j?"},
                    )
                    assert resp.status == 504, f"Expected 504 but got {resp.status}"
                    body = await resp.json()
                    assert body.get("errors") or body.get("status") == "error"
                finally:
                    await client.close()

        run_async(scenario())


# ---------------------------------------------------------------------------
# Executor timeout tests
# ---------------------------------------------------------------------------

class TestExecutorTimeoutHandling:
    """Executor raises / propagates OrchestratorTimeoutError correctly."""

    def _make_orchestrator(self):
        """Return a MasterOrchestrator with all agents mocked out."""
        with patch("orchestrator.executor.SystemsAgent"), \
             patch("orchestrator.executor.OffensiveAgent"), \
             patch("orchestrator.executor.DefensiveAgent"):
            return MasterOrchestrator(correlation_id="test-exec-timeout")

    def test_single_intent_raises_on_expired_deadline(self):
        """_execute_single_intent raises OrchestratorTimeoutError when deadline is in the past."""
        orch = self._make_orchestrator()

        # Provide a mock agent that would succeed, but deadline is already past.
        mock_agent = Mock()
        mock_agent.execute.return_value = {"status": "ok"}
        orch.agents["systems"] = mock_agent

        expired_deadline = time.perf_counter() - 1.0  # 1 second in the past

        with pytest.raises(OrchestratorTimeoutError):
            orch._execute_single_intent("vuln_lookup", {"payload": {}, "intent": "vuln_lookup"}, expired_deadline)

    def test_execute_propagates_timeout_uncaught(self):
        """execute() must propagate OrchestratorTimeoutError — it must not be swallowed as a 500."""
        with patch("orchestrator.executor.SystemsAgent"), \
             patch("orchestrator.executor.OffensiveAgent"), \
             patch("orchestrator.executor.DefensiveAgent"), \
             patch("orchestrator.executor._ORCHESTRATOR_TIMEOUT_S", -1.0):
            # Setting the timeout to -1 s means the deadline is already in the past
            # by the time execute() starts.
            orch = MasterOrchestrator(correlation_id="test-propagate-timeout")
            # Give the 'systems' agent slot a callable mock so routing succeeds.
            orch.agents["systems"] = Mock()
            orch.agents["systems"].execute.return_value = {"status": "ok"}

            with pytest.raises(OrchestratorTimeoutError):
                orch.execute({
                    "version": "1.0",
                    "correlation_id": "test-propagate-timeout",
                    "agent": "systems",
                    "intent": "vuln_lookup",
                    "payload": {"cveId": "CVE-2021-44228"},
                })

    def test_agent_timeout_error_propagates_as_orchestrator_timeout(self):
        """TimeoutError from an agent execution is re-raised as OrchestratorTimeoutError."""
        orch = self._make_orchestrator()

        mock_agent = Mock()
        mock_agent.execute.side_effect = TimeoutError("neo4j timed out")
        orch.agents["systems"] = mock_agent

        # Deadline is far in the future so the deadline check does not fire first.
        future_deadline = time.perf_counter() + 30.0

        with pytest.raises(OrchestratorTimeoutError):
            orch._execute_single_intent("vuln_lookup", {"payload": {}, "intent": "vuln_lookup"}, future_deadline)


# ---------------------------------------------------------------------------
# Neo4j client timeout and retry tests
# ---------------------------------------------------------------------------

class TestNeo4jClientFailureHandling:
    """Neo4j client raises TimeoutError and retries transient errors."""

    def _make_client(self):
        """Build a Neo4jClient with a mock driver (no real Neo4j needed)."""
        from agents.shared.neo4j_client import Neo4jClient

        with patch("agents.shared.neo4j_client.GraphDatabase") as MockGDB:
            MockGDB.driver.return_value = MagicMock()
            client = Neo4jClient(
                uri="bolt://localhost:7687",
                user="neo4j",
                password="test",
            )
            # Replace the driver with the mock so we can configure session behavior.
            client.driver = MockGDB.driver.return_value
        return client

    def test_raises_timeout_error_when_driver_reports_timeout(self):
        """query() raises TimeoutError when the Neo4j driver raises an exception
        whose string representation contains 'timeout'.
        """
        client = self._make_client()

        mock_session = MagicMock()
        mock_session.__enter__ = Mock(return_value=mock_session)
        mock_session.__exit__ = Mock(return_value=False)
        mock_session.run.side_effect = Exception("Query execution timeout exceeded")
        client.driver.session.return_value = mock_session

        with pytest.raises(TimeoutError):
            client.query("MATCH (n) RETURN n", {})

    def test_retries_on_transient_error_and_succeeds(self):
        """query() retries on ServiceUnavailable-like transient errors and returns
        the result on the second attempt.
        """
        from agents.shared.neo4j_client import _RETRYABLE_EXC

        if not _RETRYABLE_EXC:
            pytest.skip("neo4j package not installed; can't test with real exception types")

        client = self._make_client()

        call_count = 0

        def _session_factory(**kwargs):
            nonlocal call_count
            mock_session = MagicMock()
            mock_session.__enter__ = Mock(return_value=mock_session)
            mock_session.__exit__ = Mock(return_value=False)

            if call_count == 0:
                call_count += 1
                mock_session.run.side_effect = _RETRYABLE_EXC[0]("service unavailable")
            else:
                mock_record = MagicMock()
                mock_record.data.return_value = {"n": 1}
                mock_session.run.return_value = [mock_record]
            return mock_session

        client.driver.session.side_effect = _session_factory

        # Patch time.sleep to avoid actual waiting in tests.
        with patch("agents.shared.neo4j_client.time.sleep"):
            results = client.query("MATCH (n) RETURN n LIMIT 1", {})

        assert results == [{"n": 1}]
