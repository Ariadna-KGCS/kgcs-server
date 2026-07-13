"""End-to-end integration tests for Master Orchestrator

Tests complete orchestration flows with mocked agents to verify:
- Full vuln_lookup flow
- Full attack_path flow
- Full coverage_map flow
- Mixed-intent orchestration
- Error scenarios
- Provenance aggregation
"""

import pytest
from unittest.mock import Mock, patch
from orchestrator.executor import MasterOrchestrator


class TestVulnLookupFlow:
    """Test complete vuln_lookup orchestration flow"""

    def test_full_vuln_lookup_flow_cve(self):
        """Test complete vuln_lookup flow with CVE input"""
        with patch('orchestrator.executor.SystemsAgent') as MockSystems, \
             patch('orchestrator.executor.OffensiveAgent'), \
             patch('orchestrator.executor.DefensiveAgent'):

            mock_agent = Mock()
            mock_agent.execute.return_value = {
                "version": "1.0",
                "correlation_id": "test-123",
                "status": "ok",
                "data": {
                    "vulnerabilities": [
                        {
                            "cveId": "CVE-2021-44228",
                            "scores": [{"version": "3.1", "baseScore": 10.0}],
                            "weakness": {"cweId": "CWE-502"}
                        }
                    ]
                },
                "provenance": [
                    {"source": "NVD", "ids": ["CVE-2021-44228"], "timestamp": "2024-01-01T00:00:00Z"}
                ],
                "confidence": {"value": 1.0, "basis": "COMPLETE_CHAIN", "signals": {"rows": 1}, "degradation": []},
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
            assert response["correlation_id"] == "test-123"
            assert len(response["data"]["vulnerabilities"]) == 1
            assert response["data"]["vulnerabilities"][0]["cveId"] == "CVE-2021-44228"
            assert response["confidence"]["value"] == 1.0

    def test_full_vuln_lookup_flow_cpe_name(self):
        """Test complete vuln_lookup flow with canonical cpeName input"""
        with patch('orchestrator.executor.SystemsAgent') as MockSystems, \
             patch('orchestrator.executor.OffensiveAgent'), \
             patch('orchestrator.executor.DefensiveAgent'):

            mock_agent = Mock()
            mock_agent.execute.return_value = {
                "version": "1.0",
                "correlation_id": "test-456",
                "status": "ok",
                "data": {
                    "vulnerabilities": [
                        {"cveId": "CVE-2021-44228", "scores": [{"version": "3.1", "baseScore": 10.0}]}
                    ],
                    "platforms": [
                        {"matchCriteriaId": "criteria-001", "uri": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"}
                    ]
                },
                "provenance": [
                    {"source": "NVD", "ids": ["CVE-2021-44228"], "timestamp": "2024-01-01T00:00:00Z"}
                ],
                "confidence": {"value": 0.95, "basis": "COMPLETE_CHAIN", "signals": {"rows": 1}, "degradation": []},
                "errors": []
            }
            MockSystems.return_value = mock_agent

            orchestrator = MasterOrchestrator(correlation_id="test-456")
            orchestrator.systems_agent = mock_agent

            request = {
                "version": "1.0",
                "correlation_id": "test-456",
                "intent": "vuln_lookup",
                "payload": {"cpeName": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"}
            }

            with patch.object(orchestrator.schema_validator, 'validate_response'):
                response = orchestrator.execute(request)

            assert response["status"] == "ok"
            assert "vulnerabilities" in response["data"]
            assert "platforms" in response["data"]


class TestAttackPathFlow:
    """Test complete attack_path orchestration flow"""

    def test_full_attack_path_flow(self):
        """Test complete attack_path flow"""
        with patch('orchestrator.executor.SystemsAgent'), \
             patch('orchestrator.executor.OffensiveAgent') as MockOffensive, \
             patch('orchestrator.executor.DefensiveAgent'):

            mock_agent = Mock()
            mock_agent.execute.return_value = {
                "version": "1.0",
                "correlation_id": "test-789",
                "status": "ok",
                "data": {
                    "techniques": [
                        {
                            "id": "T1059",
                            "name": "Command and Scripting Interpreter",
                            "tactics": ["Execution"],
                            "capec": ["CAPEC-88"],
                            "subtechniques": ["T1059.001"]
                        }
                    ],
                    "attack_paths": [
                        {
                            "weakness_id": "CWE-502",
                            "pattern_id": "CAPEC-88",
                            "technique_id": "T1059"
                        }
                    ]
                },
                "provenance": [
                    {"source": "MITRE CAPEC", "ids": ["CAPEC-88"], "timestamp": "2024-01-01T00:00:00Z"},
                    {"source": "MITRE ATT&CK", "ids": ["T1059"], "timestamp": "2024-01-01T00:00:00Z"}
                ],
                "confidence": {"value": 1.0, "basis": "COMPLETE_CHAIN", "signals": {"rows": 1, "hops": 3}, "degradation": []},
                "errors": []
            }
            MockOffensive.return_value = mock_agent

            orchestrator = MasterOrchestrator(correlation_id="test-789")
            orchestrator.offensive_agent = mock_agent

            request = {
                "version": "1.0",
                "correlation_id": "test-789",
                "intent": "attack_path",
                "payload": {"cweId": "CWE-502"}
            }

            with patch.object(orchestrator.schema_validator, 'validate_response'):
                response = orchestrator.execute(request)

            assert response["status"] == "ok"
            assert len(response["data"]["techniques"]) == 1
            assert response["data"]["techniques"][0]["id"] == "T1059"
            assert len(response["data"]["attack_paths"]) == 1
            assert len(response["provenance"]) == 2  # CAPEC + ATT&CK


class TestCoverageMapFlow:
    """Test complete coverage_map orchestration flow"""

    def test_full_coverage_map_flow(self):
        """Test complete coverage_map flow"""
        with patch('orchestrator.executor.SystemsAgent'), \
             patch('orchestrator.executor.OffensiveAgent'), \
             patch('orchestrator.executor.DefensiveAgent') as MockDefensive:

            mock_agent = Mock()
            mock_agent.execute.return_value = {
                "version": "1.0",
                "correlation_id": "test-abc",
                "status": "ok",
                "data": {
                    "mitigations": [{"d3fendId": "D3-PA", "name": "Process Analysis"}],
                    "detections": [{"analyticId": "CAR-2020-04-001", "title": "Shells", "coverageLevel": "High"}],
                    "deceptions": [{"techniqueId": "DTE0001", "name": "Admin User Account"}],
                    "engagements": [{"activityId": "EAC0002", "name": "Application Diversity"}],
                    "summary": {
                        "total_mitigations": 1,
                        "total_detections": 1,
                        "total_deceptions": 1,
                        "total_engagements": 1,
                        "has_coverage": True
                    }
                },
                "provenance": [
                    {"source": "MITRE D3FEND", "ids": ["D3-PA"], "timestamp": "2024-01-01T00:00:00Z"},
                    {"source": "MITRE CAR", "ids": ["CAR-2020-04-001"], "timestamp": "2024-01-01T00:00:00Z"},
                    {"source": "MITRE SHIELD", "ids": ["DTE0001"], "timestamp": "2024-01-01T00:00:00Z"},
                    {"source": "MITRE ENGAGE", "ids": ["EAC0002"], "timestamp": "2024-01-01T00:00:00Z"}
                ],
                "confidence": {"value": 1.0, "basis": "COVERAGE_MAP", "signals": {"rows": 1}, "degradation": []},
                "errors": []
            }
            MockDefensive.return_value = mock_agent

            orchestrator = MasterOrchestrator(correlation_id="test-abc")
            orchestrator.defensive_agent = mock_agent

            request = {
                "version": "1.0",
                "correlation_id": "test-abc",
                "intent": "coverage_map",
                "payload": {"attackId": "T1059"}
            }

            with patch.object(orchestrator.schema_validator, 'validate_response'):
                response = orchestrator.execute(request)

            assert response["status"] == "ok"
            assert response["data"]["summary"]["has_coverage"] == True
            assert len(response["provenance"]) == 4  # All 4 frameworks


class TestMixedIntentFlow:
    """Test complete mixed-intent orchestration flow"""

    def test_full_mixed_intent_orchestration(self):
        """Test complete mixed-intent flow with all 3 agents"""
        with patch('orchestrator.executor.SystemsAgent') as MockSystems, \
             patch('orchestrator.executor.OffensiveAgent') as MockOffensive, \
             patch('orchestrator.executor.DefensiveAgent') as MockDefensive:

            systems_response = {
                "version": "1.0",
                "correlation_id": "mixed-123",
                "status": "ok",
                "data": {
                    "vulnerabilities": [{"cveId": "CVE-2021-44228", "scores": [{"version": "3.1", "baseScore": 10.0}]}]
                },
                "provenance": [
                    {"source": "NVD", "ids": ["CVE-2021-44228"], "timestamp": "2024-01-01T00:00:00Z"}
                ],
                "confidence": {"value": 1.0, "basis": "COMPLETE_CHAIN", "signals": {"rows": 1}, "degradation": []},
                "errors": []
            }

            offensive_response = {
                "version": "1.0",
                "correlation_id": "mixed-123",
                "status": "ok",
                "data": {
                    "techniques": [{"id": "T1059", "tactics": ["Execution"], "capec": ["CAPEC-88"]}],
                    "attack_paths": [{"weakness_id": "CWE-502", "pattern_id": "CAPEC-88", "technique_id": "T1059"}]
                },
                "provenance": [
                    {"source": "MITRE CAPEC", "ids": ["CAPEC-88"], "timestamp": "2024-01-01T00:00:00Z"},
                    {"source": "MITRE ATT&CK", "ids": ["T1059"], "timestamp": "2024-01-01T00:00:00Z"}
                ],
                "confidence": {"value": 0.9, "basis": "COMPLETE_CHAIN", "signals": {"rows": 1}, "degradation": []},
                "errors": []
            }

            defensive_response = {
                "version": "1.0",
                "correlation_id": "mixed-123",
                "status": "ok",
                "data": {
                    "mitigations": [{"d3fendId": "D3-PA"}],
                    "detections": [{"analyticId": "CAR-2020-04-001"}],
                    "deceptions": [],
                    "engagements": [],
                    "summary": {"total_mitigations": 1, "total_detections": 1, "has_coverage": True}
                },
                "provenance": [
                    {"source": "MITRE D3FEND", "ids": ["D3-PA"], "timestamp": "2024-01-01T00:00:00Z"},
                    {"source": "MITRE CAR", "ids": ["CAR-2020-04-001"], "timestamp": "2024-01-01T00:00:00Z"}
                ],
                "confidence": {"value": 0.8, "basis": "COVERAGE_MAP", "signals": {"rows": 1}, "degradation": []},
                "errors": []
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

            orchestrator = MasterOrchestrator(correlation_id="mixed-123")
            orchestrator.systems_agent = systems_agent
            orchestrator.offensive_agent = offensive_agent
            orchestrator.defensive_agent = defensive_agent

            request = {
                "version": "1.0",
                "correlation_id": "mixed-123",
                "intent": "mixed",
                "payload": {"cveId": "CVE-2021-44228"}
            }

            response = orchestrator.execute(request)

            # Verify all agents were called
            systems_agent.execute.assert_called_once()
            offensive_agent.execute.assert_called_once()
            defensive_agent.execute.assert_called_once()

            # Verify aggregation
            assert response["status"] == "ok"
            assert response["correlation_id"] == "mixed-123"

    def test_mixed_intent_provenance_aggregation(self):
        """Test that mixed-intent aggregates provenance from all agents"""
        with patch('orchestrator.executor.SystemsAgent') as MockSystems, \
             patch('orchestrator.executor.OffensiveAgent') as MockOffensive, \
             patch('orchestrator.executor.DefensiveAgent') as MockDefensive:

            systems_agent = Mock()
            systems_agent.execute.return_value = {
                "status": "ok",
                "correlation_id": "agg-123",
                "data": {},
                "provenance": [{"source": "NVD", "ids": ["CVE-2021-44228"], "timestamp": "2024-01-01T00:00:00Z"}],
                "confidence": {"value": 1.0, "basis": "COMPLETE_CHAIN", "signals": {"rows": 1}, "degradation": []},
                "errors": []
            }
            offensive_agent = Mock()
            offensive_agent.execute.return_value = {
                "status": "ok",
                "correlation_id": "agg-123",
                "data": {},
                "provenance": [
                    {"source": "MITRE CAPEC", "ids": ["CAPEC-88"], "timestamp": "2024-01-01T00:00:00Z"},
                    {"source": "MITRE ATT&CK", "ids": ["T1059"], "timestamp": "2024-01-01T00:00:00Z"}
                ],
                "confidence": {"value": 0.9, "basis": "COMPLETE_CHAIN", "signals": {"rows": 1}, "degradation": []},
                "errors": []
            }
            defensive_agent = Mock()
            defensive_agent.execute.return_value = {
                "status": "ok",
                "correlation_id": "agg-123",
                "data": {},
                "provenance": [{"source": "MITRE D3FEND", "ids": ["D3-PA"], "timestamp": "2024-01-01T00:00:00Z"}],
                "confidence": {"value": 0.8, "basis": "COVERAGE_MAP", "signals": {"rows": 1}, "degradation": []},
                "errors": []
            }

            MockSystems.return_value = systems_agent
            MockOffensive.return_value = offensive_agent
            MockDefensive.return_value = defensive_agent

            orchestrator = MasterOrchestrator(correlation_id="agg-123")
            orchestrator.systems_agent = systems_agent
            orchestrator.offensive_agent = offensive_agent
            orchestrator.defensive_agent = defensive_agent

            request = {
                "version": "1.0",
                "correlation_id": "agg-123",
                "intent": "mixed",
                "payload": {"cveId": "CVE-2021-44228"}
            }

            response = orchestrator.execute(request)

            # Verify provenance aggregation (should include all 4 sources)
            assert response["status"] == "ok"
            provenance_sources = {p["source"] for p in response["provenance"]}
            assert "NVD" in provenance_sources
            assert "MITRE CAPEC" in provenance_sources
            assert "MITRE ATT&CK" in provenance_sources
            assert "MITRE D3FEND" in provenance_sources


class TestErrorScenarios:
    """Test error scenarios"""

    def test_agent_execution_error_returns_error_response(self):
        """Test agent execution error returns error response"""
        with patch('orchestrator.executor.SystemsAgent') as MockSystems, \
             patch('orchestrator.executor.OffensiveAgent'), \
             patch('orchestrator.executor.DefensiveAgent'):
            mock_agent = Mock()
            mock_agent.execute.side_effect = Exception("Connection failed")
            MockSystems.return_value = mock_agent

            orchestrator = MasterOrchestrator(correlation_id="error-123")
            orchestrator.systems_agent = mock_agent

            request = {
                "version": "1.0",
                "correlation_id": "error-123",
                "intent": "vuln_lookup",
                "payload": {"cveId": "CVE-2021-44228"}
            }

            response = orchestrator.execute(request)

            assert response["status"] == "error"
            assert len(response["errors"]) > 0

    def test_mixed_intent_partial_failure_aggregates_results(self):
        """Test mixed intent with partial failure aggregates available results"""
        with patch('orchestrator.executor.SystemsAgent') as MockSystems, \
             patch('orchestrator.executor.OffensiveAgent') as MockOffensive, \
             patch('orchestrator.executor.DefensiveAgent') as MockDefensive:

            systems_response = {
                "status": "ok",
                "correlation_id": "partial-123",
                "data": {"vulnerabilities": []},
                "provenance": [],
                "confidence": {"value": 0.0, "basis": "NO_MATCH", "signals": {}, "degradation": []},
                "errors": []
            }
            offensive_response = {
                "status": "error",
                "correlation_id": "partial-123",
                "data": {},
                "provenance": [],
                "confidence": {"value": 0.0, "basis": "NO_MATCH", "signals": {}, "degradation": []},
                "errors": ["Query timeout"]
            }

            systems_agent = Mock()
            systems_agent.execute.return_value = systems_response
            offensive_agent = Mock()
            offensive_agent.execute.return_value = offensive_response
            defensive_agent = Mock()

            MockSystems.return_value = systems_agent
            MockOffensive.return_value = offensive_agent
            MockDefensive.return_value = defensive_agent

            orchestrator = MasterOrchestrator(correlation_id="partial-123")
            orchestrator.systems_agent = systems_agent
            orchestrator.offensive_agent = offensive_agent
            orchestrator.defensive_agent = defensive_agent

            request = {
                "version": "1.0",
                "correlation_id": "partial-123",
                "intent": "mixed",
                "payload": {"cveId": "CVE-2021-44228"}
            }

            response = orchestrator.execute(request)

            # Should return error status when any agent fails
            assert response["status"] == "error"
            # Offensive agent should NOT be called since Systems succeeded but we stop on error
            defensive_agent.execute.assert_not_called()
