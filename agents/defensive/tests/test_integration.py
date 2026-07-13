"""Integration tests for DefensiveAgent

End-to-end tests with mocked Neo4jClient, verifying:
- Full request-to-response flow
- Schema compliance (agent-consumable-schema.json + defensive-response.json)
- Correct data transformation
- Confidence scoring
- Error handling scenarios
"""

import pytest
from unittest.mock import Mock
from uuid import uuid4
from agents.defensive.executor import DefensiveAgent


class TestIntegrationCoverageMap:
    """Integration tests for coverage map queries"""

    def test_coverage_map_full_flow(self):
        """Test complete coverage map flow with mocked Neo4j"""
        # Mock Neo4j response with all 4 frameworks
        mock_client = Mock()
        mock_client.query = Mock(return_value=[
            {
                "mitigations": [
                    {"d3fendId": "D3-PA", "name": "Process Analysis"},
                    {"d3fendId": "D3-NTA", "name": "Network Traffic Analysis"}
                ],
                "detections": [
                    {"analyticId": "CAR-2020-04-001", "title": "Batch File Write", "coverageLevel": "High"},
                    {"analyticId": "CAR-2021-05-002", "title": "Powershell Execution", "coverageLevel": "Moderate"}
                ],
                "deceptions": [
                    {"techniqueId": "DTE0001", "name": "Admin User Account"}
                ],
                "engagements": [
                    {"activityId": "EAC0002", "name": "Application Diversity"}
                ]
            }
        ])

        correlation_id = str(uuid4())
        agent = DefensiveAgent(neo4j_client=mock_client, correlation_id=correlation_id)

        request = {
            "version": "1.0",
            "correlation_id": correlation_id,
            "agent": "defensive",
            "intent": "coverage_map",
            "payload": {"attackId": "T1059"}
        }

        response = agent.execute(request)

        # Verify response structure
        assert response["version"] == "1.0"
        assert response["correlation_id"] == correlation_id
        assert response["status"] == "ok"

        # Verify data payload
        assert "data" in response
        data = response["data"]
        assert len(data["mitigations"]) == 2
        assert len(data["detections"]) == 2
        assert len(data["deceptions"]) == 1
        assert len(data["engagements"]) == 1

        # Verify summary
        assert data["summary"]["total_mitigations"] == 2
        assert data["summary"]["total_detections"] == 2
        assert data["summary"]["total_deceptions"] == 1
        assert data["summary"]["total_engagements"] == 1
        assert data["summary"]["has_coverage"] is True

        # Verify confidence
        assert response["confidence"]["value"] == 1.0
        assert response["confidence"]["basis"] == "COVERAGE_MAP"

        # Verify provenance
        assert len(response["provenance"]) == 4
        sources = {p["source"] for p in response["provenance"]}
        assert sources == {"MITRE D3FEND", "MITRE CAR", "MITRE SHIELD", "MITRE ENGAGE"}


class TestIntegrationPartialCoverage:
    """Integration tests for partial coverage scenarios"""

    def test_coverage_only_d3fend(self):
        """Test coverage with only D3FEND mitigations"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[
            {
                "mitigations": [{"d3fendId": "D3-PA", "name": "Process Analysis"}],
                "detections": [],
                "deceptions": [],
                "engagements": []
            }
        ])

        agent = DefensiveAgent(neo4j_client=mock_client, correlation_id=str(uuid4()))

        request = {
            "version": "1.0",
            "correlation_id": agent.correlation_id,
            "agent": "defensive",
            "intent": "coverage_map",
            "payload": {"attackId": "T1059"}
        }

        response = agent.execute(request)

        # 3 missing frameworks * -0.1 = 0.7 confidence
        assert response["confidence"]["value"] == 0.7
        assert len(response["provenance"]) == 1
        assert response["provenance"][0]["source"] == "MITRE D3FEND"

    def test_coverage_d3fend_and_car_only(self):
        """Test coverage with D3FEND and CAR only"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[
            {
                "mitigations": [{"d3fendId": "D3-PA", "name": ""}],
                "detections": [{"analyticId": "CAR-2020-04-001", "title": "", "coverageLevel": ""}],
                "deceptions": [],
                "engagements": []
            }
        ])

        agent = DefensiveAgent(neo4j_client=mock_client, correlation_id=str(uuid4()))

        request = {
            "version": "1.0",
            "correlation_id": agent.correlation_id,
            "agent": "defensive",
            "intent": "coverage_map",
            "payload": {"attackId": "T1059"}
        }

        response = agent.execute(request)

        # 2 missing frameworks * -0.1 = 0.8 confidence
        assert response["confidence"]["value"] == 0.8
        assert len(response["provenance"]) == 2
        sources = {p["source"] for p in response["provenance"]}
        assert sources == {"MITRE D3FEND", "MITRE CAR"}


class TestIntegrationErrorScenarios:
    """Integration tests for error scenarios"""

    def test_invalid_payload_missing_field(self):
        """Test error when payload missing required field"""
        mock_client = Mock()
        agent = DefensiveAgent(neo4j_client=mock_client, correlation_id=str(uuid4()))

        request = {
            "version": "1.0",
            "correlation_id": agent.correlation_id,
            "agent": "defensive",
            "intent": "coverage_map",
            "payload": {}  # Missing attackId
        }

        response = agent.execute(request)
        assert response["status"] == "error"
        assert len(response["errors"]) > 0

    def test_neo4j_connection_error(self):
        """Test error when Neo4j connection fails"""
        mock_client = Mock()
        mock_client.query = Mock(side_effect=Exception("Connection refused"))
        agent = DefensiveAgent(neo4j_client=mock_client, correlation_id=str(uuid4()))

        request = {
            "version": "1.0",
            "correlation_id": agent.correlation_id,
            "agent": "defensive",
            "intent": "coverage_map",
            "payload": {"attackId": "T1059"}
        }

        response = agent.execute(request)
        assert response["status"] == "error"
        assert response["data"] == {}

    def test_no_results_empty_response(self):
        """Test empty response when query returns no results"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[])
        agent = DefensiveAgent(neo4j_client=mock_client, correlation_id=str(uuid4()))

        request = {
            "version": "1.0",
            "correlation_id": agent.correlation_id,
            "agent": "defensive",
            "intent": "coverage_map",
            "payload": {"attackId": "T9999"}  # Non-existent technique
        }

        response = agent.execute(request)
        assert response["status"] == "empty"
        assert response["data"] == {
            "technique_id": "T9999",
            "mitigations": [],
            "detections": [],
            "deceptions": [],
            "engagements": [],
            "summary": {
                "total_mitigations": 0,
                "total_detections": 0,
                "total_deceptions": 0,
                "total_engagements": 0,
                "has_coverage": False,
            },
        }
        assert response["confidence"]["value"] == 0.0
        assert response["confidence"]["basis"] == "NO_MATCH"


class TestEnvelopeStructure:
    """Integration tests for response envelope structure"""

    def test_response_envelope_fields(self):
        """Test that response has all required envelope fields"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[])
        correlation_id = str(uuid4())
        agent = DefensiveAgent(neo4j_client=mock_client, correlation_id=correlation_id)

        request = {
            "version": "1.0",
            "correlation_id": correlation_id,
            "agent": "defensive",
            "intent": "coverage_map",
            "payload": {"attackId": "T1059"}
        }

        response = agent.execute(request)

        # Verify all envelope fields present
        required_fields = ["version", "correlation_id", "status", "data", "provenance", "confidence", "errors"]
        for field in required_fields:
            assert field in response, f"Missing field: {field}"

        # Verify field types
        assert response["version"] == "1.0"
        assert isinstance(response["correlation_id"], str)
        assert response["status"] in ["ok", "empty", "error"]
        assert isinstance(response["data"], (dict, list))
        assert isinstance(response["provenance"], list)
        assert isinstance(response["confidence"], dict)
        assert isinstance(response["errors"], list)

    def test_confidence_fields(self):
        """Test that confidence object has all required fields"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[])
        agent = DefensiveAgent(neo4j_client=mock_client, correlation_id=str(uuid4()))

        request = {
            "version": "1.0",
            "correlation_id": agent.correlation_id,
            "agent": "defensive",
            "intent": "coverage_map",
            "payload": {"attackId": "T1059"}
        }

        response = agent.execute(request)
        confidence = response["confidence"]

        # Required fields
        assert "value" in confidence
        assert "basis" in confidence
        assert "signals" in confidence
        assert "degradation" in confidence

        # Type validation
        assert isinstance(confidence["value"], (int, float))
        assert 0.0 <= confidence["value"] <= 1.0
        assert isinstance(confidence["basis"], str)
        assert isinstance(confidence["signals"], dict)
        assert isinstance(confidence["degradation"], list)

    def test_provenance_fields(self):
        """Test that provenance entries have required fields"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[
            {
                "mitigations": [{"d3fendId": "D3-PA", "name": ""}],
                "detections": [],
                "deceptions": [],
                "engagements": []
            }
        ])

        agent = DefensiveAgent(neo4j_client=mock_client, correlation_id=str(uuid4()))
        request = {
            "version": "1.0",
            "correlation_id": agent.correlation_id,
            "agent": "defensive",
            "intent": "coverage_map",
            "payload": {"attackId": "T1059"}
        }

        response = agent.execute(request)

        # Provenance should exist for ok status
        if response["status"] == "ok":
            assert len(response["provenance"]) > 0
            for entry in response["provenance"]:
                assert "source" in entry
                assert "ids" in entry
                assert isinstance(entry["ids"], list)
                assert len(entry["ids"]) > 0
                # Should have timestamp
                assert "timestamp" in entry

    def test_data_payload_structure(self):
        """Test defensive-response.json data structure"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[
            {
                "mitigations": [{"d3fendId": "D3-PA", "name": "Process Analysis"}],
                "detections": [{"analyticId": "CAR-2020-04-001", "title": "Batch File", "coverageLevel": "High"}],
                "deceptions": [{"techniqueId": "DTE0001", "name": "Admin Account"}],
                "engagements": [{"activityId": "EAC0002", "name": "Application Diversity"}]
            }
        ])

        agent = DefensiveAgent(neo4j_client=mock_client, correlation_id=str(uuid4()))
        request = {
            "version": "1.0",
            "correlation_id": agent.correlation_id,
            "agent": "defensive",
            "intent": "coverage_map",
            "payload": {"attackId": "T1059"}
        }

        response = agent.execute(request)

        # Verify data structure
        data = response["data"]
        assert isinstance(data["mitigations"], list)
        assert isinstance(data["detections"], list)
        assert isinstance(data["deceptions"], list)
        assert isinstance(data["engagements"], list)
        assert isinstance(data["summary"], dict)

        # Verify mitigation structure
        for mitigation in data["mitigations"]:
            assert "d3fendId" in mitigation
            assert "name" in mitigation

        # Verify detection structure
        for detection in data["detections"]:
            assert "analyticId" in detection
            assert "title" in detection
            assert "coverageLevel" in detection

        # Verify deception structure
        for deception in data["deceptions"]:
            assert "techniqueId" in deception
            assert "name" in deception

        # Verify engagement structure
        for engagement in data["engagements"]:
            # Should have one of: activityId, approachId, or goalId
            has_id = "activityId" in engagement or "approachId" in engagement or "goalId" in engagement
            assert has_id
            assert "name" in engagement

        # Verify summary structure
        summary = data["summary"]
        assert "total_mitigations" in summary
        assert "total_detections" in summary
        assert "total_deceptions" in summary
        assert "total_engagements" in summary
        assert "has_coverage" in summary
