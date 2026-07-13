"""Test Master Orchestrator executor

Verifies:
- Request routing and validation
- Single-intent request handling
- Mixed-intent request orchestration
- Correlation ID propagation
- Error handling
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from orchestrator.executor import MasterOrchestrator


class TestMasterOrchestratorInit:
    """Test MasterOrchestrator initialization"""

    def test_init_with_correlation_id(self):
        """Test initialization with provided correlation_id"""
        with patch('orchestrator.executor.SystemsAgent'), \
             patch('orchestrator.executor.OffensiveAgent'), \
             patch('orchestrator.executor.DefensiveAgent'):
            correlation_id = "test-123"
            orchestrator = MasterOrchestrator(correlation_id=correlation_id)
            assert orchestrator.correlation_id == correlation_id

    def test_init_generates_correlation_id(self):
        """Test initialization generates correlation_id if not provided"""
        with patch('orchestrator.executor.SystemsAgent'), \
             patch('orchestrator.executor.OffensiveAgent'), \
             patch('orchestrator.executor.DefensiveAgent'):
            orchestrator = MasterOrchestrator()
            assert orchestrator.correlation_id is not None
            assert len(orchestrator.correlation_id) > 0

    def test_init_creates_logger(self):
        """Test initialization creates logger with correlation_id"""
        with patch('orchestrator.executor.SystemsAgent'), \
             patch('orchestrator.executor.OffensiveAgent'), \
             patch('orchestrator.executor.DefensiveAgent'):
            orchestrator = MasterOrchestrator(correlation_id="test-123")
            assert orchestrator.logger is not None
            assert orchestrator.logger.correlation_id == "test-123"

    def test_init_creates_all_agents(self):
        """Test initialization creates all 3 agents"""
        with patch('orchestrator.executor.SystemsAgent') as MockSystems, \
             patch('orchestrator.executor.OffensiveAgent') as MockOffensive, \
             patch('orchestrator.executor.DefensiveAgent') as MockDefensive:
            orchestrator = MasterOrchestrator()
            assert orchestrator.systems_agent is not None
            assert orchestrator.offensive_agent is not None
            assert orchestrator.defensive_agent is not None
            assert len(orchestrator.agents) == 3


class TestSingleIntentExecution:
    """Test single-intent request execution"""

    def test_execute_vuln_lookup_routes_to_systems(self):
        """Test vuln_lookup intent routes to Systems Agent"""
        with patch('orchestrator.executor.SystemsAgent') as MockSystems, \
             patch('orchestrator.executor.OffensiveAgent'), \
             patch('orchestrator.executor.DefensiveAgent'):
            mock_agent = Mock()
            mock_agent.execute.return_value = {
                "version": "1.0",
                "correlation_id": "test-123",
                "status": "ok",
                "data": {},
                "provenance": [],
                "confidence": {"value": 0.9, "basis": "TEST"},
                "errors": []
            }
            MockSystems.return_value = mock_agent

            orchestrator = MasterOrchestrator(correlation_id="test-123")
            orchestrator.systems_agent = mock_agent

            request = {
                "version": "1.0",
                "correlation_id": "test-123",
                "intent": "vuln_lookup",
                "payload": {"cveId": "CVE-2021-44228"}
            }

            with patch.object(orchestrator.schema_validator, 'validate_response'):
                response = orchestrator.execute(request)

            assert response["status"] == "ok"
            mock_agent.execute.assert_called_once()

    def test_execute_attack_path_routes_to_offensive(self):
        """Test attack_path intent routes to Offensive Agent"""
        with patch('orchestrator.executor.SystemsAgent'), \
             patch('orchestrator.executor.OffensiveAgent') as MockOffensive, \
             patch('orchestrator.executor.DefensiveAgent'):
            mock_agent = Mock()
            mock_agent.execute.return_value = {
                "version": "1.0",
                "correlation_id": "test-123",
                "status": "ok",
                "data": {},
                "provenance": [],
                "confidence": {"value": 0.9, "basis": "TEST"},
                "errors": []
            }
            MockOffensive.return_value = mock_agent

            orchestrator = MasterOrchestrator(correlation_id="test-123")
            orchestrator.offensive_agent = mock_agent

            request = {
                "version": "1.0",
                "correlation_id": "test-123",
                "intent": "attack_path",
                "payload": {"cweId": "CWE-79"}
            }

            with patch.object(orchestrator.schema_validator, 'validate_response'):
                response = orchestrator.execute(request)

            assert response["status"] == "ok"
            mock_agent.execute.assert_called_once()

    def test_execute_coverage_map_routes_to_defensive(self):
        """Test coverage_map intent routes to Defensive Agent"""
        with patch('orchestrator.executor.SystemsAgent'), \
             patch('orchestrator.executor.OffensiveAgent'), \
             patch('orchestrator.executor.DefensiveAgent') as MockDefensive:
            mock_agent = Mock()
            mock_agent.execute.return_value = {
                "version": "1.0",
                "correlation_id": "test-123",
                "status": "ok",
                "data": {},
                "provenance": [],
                "confidence": {"value": 0.9, "basis": "TEST"},
                "errors": []
            }
            MockDefensive.return_value = mock_agent

            orchestrator = MasterOrchestrator(correlation_id="test-123")
            orchestrator.defensive_agent = mock_agent

            request = {
                "version": "1.0",
                "correlation_id": "test-123",
                "intent": "coverage_map",
                "payload": {"attackId": "T1059"}
            }

            with patch.object(orchestrator.schema_validator, 'validate_response'):
                response = orchestrator.execute(request)

            assert response["status"] == "ok"
            mock_agent.execute.assert_called_once()

    def test_execute_single_intent_preserves_response(self):
        """Test single-intent execution returns agent response unchanged"""
        with patch('orchestrator.executor.SystemsAgent') as MockSystems, \
             patch('orchestrator.executor.OffensiveAgent'), \
             patch('orchestrator.executor.DefensiveAgent'):
            expected_response = {
                "version": "1.0",
                "correlation_id": "test-123",
                "status": "ok",
                "data": {"vulnerabilities": [{"cveId": "CVE-2021-44228"}]},
                "provenance": [{"source": "NVD", "ids": ["CVE-2021-44228"], "timestamp": "2024-01-01T00:00:00Z"}],
                "confidence": {"value": 1.0, "basis": "COMPLETE_CHAIN"},
                "errors": []
            }
            mock_agent = Mock()
            mock_agent.execute.return_value = expected_response
            MockSystems.return_value = mock_agent

            orchestrator = MasterOrchestrator(correlation_id="test-123")
            orchestrator.systems_agent = mock_agent

            request = {
                "version": "1.0",
                "correlation_id": "test-123",
                "intent": "vuln_lookup",
                "payload": {"cveId": "CVE-2021-44228"}
            }

            with patch.object(orchestrator.schema_validator, 'validate_response'):
                response = orchestrator.execute(request)

            assert response == expected_response


class TestMixedIntentExecution:
    """Test mixed-intent request execution"""

    def test_execute_mixed_intent_runs_all_agents_in_sequence(self):
        """Test mixed intent executes all 3 agents in sequence"""
        with patch('orchestrator.executor.SystemsAgent') as MockSystems, \
             patch('orchestrator.executor.OffensiveAgent') as MockOffensive, \
             patch('orchestrator.executor.DefensiveAgent') as MockDefensive:

            systems_response = {
                "status": "ok",
                "data": {"vulnerabilities": [{"cveId": "CVE-2021-44228"}]},
                "provenance": [{"source": "NVD", "ids": ["CVE-2021-44228"], "timestamp": "2024-01-01T00:00:00Z"}],
                "confidence": {"value": 1.0, "basis": "COMPLETE_CHAIN"}
            }
            offensive_response = {
                "status": "ok",
                "data": {"techniques": [{"id": "T1059"}]},
                "provenance": [{"source": "MITRE ATT&CK", "ids": ["T1059"], "timestamp": "2024-01-01T00:00:00Z"}],
                "confidence": {"value": 0.9, "basis": "COMPLETE_CHAIN"}
            }
            defensive_response = {
                "status": "ok",
                "data": {"mitigations": [{"d3fendId": "D3-PA"}]},
                "provenance": [{"source": "MITRE D3FEND", "ids": ["D3-PA"], "timestamp": "2024-01-01T00:00:00Z"}],
                "confidence": {"value": 0.8, "basis": "COVERAGE_MAP"}
            }

            systems_agent = Mock()
            systems_agent.execute.return_value = systems_response
            offensive_agent = Mock()
            offensive_agent.execute.return_value = offensive_response
            defensive_agent = Mock()
            defensive_agent.execute.return_value = defensive_response

            MockSystems.return_value = systems_agent
            MockOffensive.return_value = offensive_agent
            MockDefensive.return_value = defensive_agent

            orchestrator = MasterOrchestrator(correlation_id="test-123")
            orchestrator.systems_agent = systems_agent
            orchestrator.offensive_agent = offensive_agent
            orchestrator.defensive_agent = defensive_agent

            request = {
                "version": "1.0",
                "correlation_id": "test-123",
                "intent": "mixed",
                "payload": {"cveId": "CVE-2021-44228"}
            }

            response = orchestrator.execute(request)

            # All agents should be called
            systems_agent.execute.assert_called_once()
            offensive_agent.execute.assert_called_once()
            defensive_agent.execute.assert_called_once()

    def test_execute_mixed_intent_stops_on_agent_error(self):
        """Test mixed intent stops when agent fails"""
        with patch('orchestrator.executor.SystemsAgent') as MockSystems, \
             patch('orchestrator.executor.OffensiveAgent') as MockOffensive, \
             patch('orchestrator.executor.DefensiveAgent') as MockDefensive:

            systems_response = {"status": "error", "errors": ["Query failed"]}

            systems_agent = Mock()
            systems_agent.execute.return_value = systems_response
            offensive_agent = Mock()
            defensive_agent = Mock()

            MockSystems.return_value = systems_agent
            MockOffensive.return_value = offensive_agent
            MockDefensive.return_value = defensive_agent

            orchestrator = MasterOrchestrator(correlation_id="test-123")
            orchestrator.systems_agent = systems_agent
            orchestrator.offensive_agent = offensive_agent
            orchestrator.defensive_agent = defensive_agent

            request = {
                "version": "1.0",
                "correlation_id": "test-123",
                "intent": "mixed",
                "payload": {"cveId": "CVE-2021-44228"}
            }

            response = orchestrator.execute(request)

            # Systems agent called
            systems_agent.execute.assert_called_once()
            # Offensive agent should NOT be called
            offensive_agent.execute.assert_not_called()

    def test_execute_mixed_intent_derives_cwe_for_offensive(self):
        """Test mixed intent derives cweId from Systems response for Offensive Agent."""
        with patch('orchestrator.executor.SystemsAgent') as MockSystems, \
             patch('orchestrator.executor.OffensiveAgent') as MockOffensive, \
             patch('orchestrator.executor.DefensiveAgent') as MockDefensive:

            systems_response = {
                "status": "ok",
                "data": {
                    "vulnerabilities": [
                        {"cveId": "CVE-2021-44228", "weakness": {"cweId": "CWE-79"}}
                    ]
                },
                "provenance": [],
                "confidence": {"value": 1.0, "basis": "COMPLETE_CHAIN"}
            }
            offensive_response = {
                "status": "ok",
                "data": {"techniques": [{"id": "T1059"}], "attack_paths": [{"technique_id": "T1059"}]},
                "provenance": [],
                "confidence": {"value": 0.9, "basis": "COMPLETE_CHAIN"}
            }
            defensive_response = {
                "status": "ok",
                "data": {"mitigations": []},
                "provenance": [],
                "confidence": {"value": 0.8, "basis": "COVERAGE_MAP"}
            }

            systems_agent = Mock()
            systems_agent.execute.return_value = systems_response
            offensive_agent = Mock()
            offensive_agent.execute.return_value = offensive_response
            defensive_agent = Mock()
            defensive_agent.execute.return_value = defensive_response

            MockSystems.return_value = systems_agent
            MockOffensive.return_value = offensive_agent
            MockDefensive.return_value = defensive_agent

            orchestrator = MasterOrchestrator(correlation_id="test-123")
            orchestrator.systems_agent = systems_agent
            orchestrator.offensive_agent = offensive_agent
            orchestrator.defensive_agent = defensive_agent
            orchestrator.agents["systems"] = systems_agent
            orchestrator.agents["offensive"] = offensive_agent
            orchestrator.agents["defensive"] = defensive_agent

            request = {
                "version": "1.0",
                "correlation_id": "test-123",
                "intent": "mixed",
                "payload": {"cveId": "CVE-2021-44228"}
            }

            orchestrator.execute(request)

            offensive_request = offensive_agent.execute.call_args[0][0]
            assert offensive_request["payload"] == {"cweId": "CWE-79"}

    def test_execute_mixed_intent_derives_attack_id_for_defensive(self):
        """Test mixed intent derives attackId from Offensive response for Defensive Agent."""
        with patch('orchestrator.executor.SystemsAgent') as MockSystems, \
             patch('orchestrator.executor.OffensiveAgent') as MockOffensive, \
             patch('orchestrator.executor.DefensiveAgent') as MockDefensive:

            systems_response = {
                "status": "ok",
                "data": {
                    "vulnerabilities": [
                        {"cveId": "CVE-2021-44228", "weakness": {"cweId": "CWE-79"}}
                    ]
                },
                "provenance": [],
                "confidence": {"value": 1.0, "basis": "COMPLETE_CHAIN"}
            }
            offensive_response = {
                "status": "ok",
                "data": {
                    "techniques": [{"id": "T1059"}],
                    "attack_paths": [{"technique_id": "T1059"}]
                },
                "provenance": [],
                "confidence": {"value": 0.9, "basis": "COMPLETE_CHAIN"}
            }
            defensive_response = {
                "status": "ok",
                "data": {"mitigations": []},
                "provenance": [],
                "confidence": {"value": 0.8, "basis": "COVERAGE_MAP"}
            }

            systems_agent = Mock()
            systems_agent.execute.return_value = systems_response
            offensive_agent = Mock()
            offensive_agent.execute.return_value = offensive_response
            defensive_agent = Mock()
            defensive_agent.execute.return_value = defensive_response

            MockSystems.return_value = systems_agent
            MockOffensive.return_value = offensive_agent
            MockDefensive.return_value = defensive_agent

            orchestrator = MasterOrchestrator(correlation_id="test-123")
            orchestrator.systems_agent = systems_agent
            orchestrator.offensive_agent = offensive_agent
            orchestrator.defensive_agent = defensive_agent
            orchestrator.agents["systems"] = systems_agent
            orchestrator.agents["offensive"] = offensive_agent
            orchestrator.agents["defensive"] = defensive_agent

            request = {
                "version": "1.0",
                "correlation_id": "test-123",
                "intent": "mixed",
                "payload": {"cveId": "CVE-2021-44228"}
            }

            orchestrator.execute(request)

            defensive_request = defensive_agent.execute.call_args[0][0]
            assert defensive_request["payload"] == {"attackId": "T1059"}

    def test_build_mixed_payload_prefers_match_criteria_id(self):
        """Test mixed vuln_lookup step preserves explicit matchCriteriaId input."""
        with patch('orchestrator.executor.SystemsAgent'), \
             patch('orchestrator.executor.OffensiveAgent'), \
             patch('orchestrator.executor.DefensiveAgent'):
            orchestrator = MasterOrchestrator(correlation_id="test-123")
            payload = orchestrator._build_mixed_payload(
                "vuln_lookup",
                {"matchCriteriaId": "8a5c4e5b-3d6f-4a7e-9b8c-2d3e4f5a6b7c", "cpeName": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
                [],
            )
            assert payload == {"matchCriteriaId": "8a5c4e5b-3d6f-4a7e-9b8c-2d3e4f5a6b7c"}

    def test_build_mixed_payload_uses_cpe_name_before_legacy_alias(self):
        """Test mixed vuln_lookup step preserves explicit cpeName input."""
        with patch('orchestrator.executor.SystemsAgent'), \
             patch('orchestrator.executor.OffensiveAgent'), \
             patch('orchestrator.executor.DefensiveAgent'):
            orchestrator = MasterOrchestrator(correlation_id="test-123")
            payload = orchestrator._build_mixed_payload(
                "vuln_lookup",
                {"cpeName": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", "cpe": "legacy-value"},
                [],
            )
            assert payload == {"cpeName": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}


class TestErrorHandling:
    """Test error handling"""

    def test_execute_invalid_intent_returns_error(self):
        """Test invalid intent returns error response"""
        with patch('orchestrator.executor.SystemsAgent'), \
             patch('orchestrator.executor.OffensiveAgent'), \
             patch('orchestrator.executor.DefensiveAgent'):
            orchestrator = MasterOrchestrator(correlation_id="test-123")

            request = {
                "version": "1.0",
                "correlation_id": "test-123",
                "intent": "invalid_intent",
                "payload": {}
            }

            response = orchestrator.execute(request)

            assert response["status"] == "error"
            assert len(response["errors"]) > 0

    def test_execute_missing_payload_field_returns_error(self):
        """Test missing required payload field returns error"""
        with patch('orchestrator.executor.SystemsAgent'), \
             patch('orchestrator.executor.OffensiveAgent'), \
             patch('orchestrator.executor.DefensiveAgent'):
            orchestrator = MasterOrchestrator(correlation_id="test-123")

            request = {
                "version": "1.0",
                "correlation_id": "test-123",
                "intent": "coverage_map",
                "payload": {}  # Missing attackId
            }

            response = orchestrator.execute(request)

            assert response["status"] == "error"
            assert len(response["errors"]) > 0

    def test_execute_updates_correlation_id_from_request(self):
        """Test execute() updates correlation_id from request"""
        with patch('orchestrator.executor.SystemsAgent') as MockSystems, \
             patch('orchestrator.executor.OffensiveAgent'), \
             patch('orchestrator.executor.DefensiveAgent'):
            mock_agent = Mock()
            mock_agent.execute.return_value = {
                "version": "1.0",
                "correlation_id": "new-correlation-id",
                "status": "ok",
                "data": {},
                "provenance": [],
                "confidence": {"value": 0.9, "basis": "TEST"},
                "errors": []
            }
            MockSystems.return_value = mock_agent

            orchestrator = MasterOrchestrator(correlation_id="old-id")
            orchestrator.systems_agent = mock_agent

            request = {
                "version": "1.0",
                "correlation_id": "new-correlation-id",
                "intent": "vuln_lookup",
                "payload": {"cveId": "CVE-2021-44228"}
            }

            with patch.object(orchestrator.schema_validator, 'validate_response'):
                orchestrator.execute(request)

            # Logger should be updated with new correlation_id
            assert orchestrator.correlation_id == "new-correlation-id"

    def test_execute_passes_correlation_id_to_agents(self):
        """Test execute() passes correlation_id to agent requests"""
        with patch('orchestrator.executor.SystemsAgent') as MockSystems, \
             patch('orchestrator.executor.OffensiveAgent'), \
             patch('orchestrator.executor.DefensiveAgent'):
            mock_agent = Mock()
            mock_agent.execute.return_value = {
                "version": "1.0",
                "correlation_id": "test-123",
                "status": "ok",
                "data": {},
                "provenance": [],
                "confidence": {"value": 0.9, "basis": "TEST"},
                "errors": []
            }
            MockSystems.return_value = mock_agent

            orchestrator = MasterOrchestrator(correlation_id="test-123")
            orchestrator.systems_agent = mock_agent

            request = {
                "version": "1.0",
                "correlation_id": "test-123",
                "intent": "vuln_lookup",
                "payload": {"cveId": "CVE-2021-44228"}
            }

            with patch.object(orchestrator.schema_validator, 'validate_response'):
                orchestrator.execute(request)

            # Verify the request passed to agent includes correlation_id
            call_args = mock_agent.execute.call_args
            agent_request = call_args[0][0]
            assert agent_request["correlation_id"] == "test-123"
