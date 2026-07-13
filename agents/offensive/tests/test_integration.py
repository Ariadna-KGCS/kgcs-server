"""Integration tests for OffensiveAgent

End-to-end tests with mocked Neo4jClient, verifying:
- Full request-to-response flow
- Schema compliance (agent-consumable-schema.json + offensive-response.json)
- Correct data transformation
- Confidence scoring
- Error handling scenarios
"""

import pytest
from unittest.mock import Mock
from uuid import uuid4
from agents.offensive.executor import OffensiveAgent


class TestIntegrationWeaknessLookup:
    """Integration tests for weakness lookup (T_OFF_01)"""

    def test_weakness_lookup_full_flow(self):
        """Test complete weakness lookup flow with mocked Neo4j"""
        # Mock Neo4j response: CWE-79 affected by 3 techniques
        mock_client = Mock()
        mock_client.query = Mock(return_value=[
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": {
                    "attackId": "T1059",
                    "name": "Command and Scripting Interpreter"
                },
                "tac": {"name": "Execution"},
                "st": None
            },
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": {
                    "attackId": "T1059",
                    "name": "Command and Scripting Interpreter"
                },
                "tac": {"name": "Execution"},
                "st": {"attackId": "T1059.001"}
            },
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-242"},
                "t": {
                    "attackId": "T1059",
                    "name": "Command and Scripting Interpreter"
                },
                "tac": None,
                "st": {"attackId": "T1059.002"}
            }
        ])

        correlation_id = str(uuid4())
        agent = OffensiveAgent(neo4j_client=mock_client, correlation_id=correlation_id)

        request = {
            "version": "1.0",
            "correlation_id": correlation_id,
            "agent": "offensive",
            "intent": "attack_path",
            "payload": {
                "cweId": "CWE-79"
            }
        }

        response = agent.execute(request)

        # Verify response structure
        assert response["version"] == "1.0"
        assert response["correlation_id"] == correlation_id
        assert response["status"] == "ok"

        # Verify data payload
        assert "data" in response
        assert "techniques" in response["data"]
        assert "attack_paths" in response["data"]
        assert len(response["data"]["techniques"]) == 1  # T1059 deduplicated

        technique = response["data"]["techniques"][0]
        assert technique["id"] == "T1059"
        assert len(technique["capec"]) == 2  # CAPEC-88 and CAPEC-242 aggregated
        assert "Execution" in technique["tactics"]
        assert len(technique["subtechniques"]) == 2  # T1059.001 and T1059.002

        # Verify provenance
        assert len(response["provenance"]) == 2  # CAPEC and ATT&CK
        sources = {p["source"] for p in response["provenance"]}
        assert sources == {"MITRE CAPEC", "MITRE ATT&CK"}

        # Verify confidence
        assert "confidence" in response
        assert response["confidence"]["value"] >= 0.0

        # Verify attack_paths
        assert len(response["data"]["attack_paths"]) == 2  # Deduplicated causal chains


class TestIntegrationError:
    """Integration tests for error scenarios"""

    def test_invalid_payload_missing_field(self):
        """Test error when payload missing required field"""
        mock_client = Mock()
        agent = OffensiveAgent(neo4j_client=mock_client, correlation_id=str(uuid4()))

        request = {
            "version": "1.0",
            "correlation_id": agent.correlation_id,
            "agent": "offensive",
            "intent": "attack_path",
            "payload": {}  # Missing cweId
        }

        response = agent.execute(request)
        assert response["status"] == "error"
        assert len(response["errors"]) > 0

    def test_neo4j_connection_error(self):
        """Test error when Neo4j connection fails"""
        mock_client = Mock()
        mock_client.query = Mock(side_effect=Exception("Connection refused"))
        agent = OffensiveAgent(neo4j_client=mock_client, correlation_id=str(uuid4()))

        request = {
            "version": "1.0",
            "correlation_id": agent.correlation_id,
            "agent": "offensive",
            "intent": "attack_path",
            "payload": {
                "cweId": "CWE-79"
            }
        }

        response = agent.execute(request)
        assert response["status"] == "error"
        assert response["data"] == {}

    def test_no_results_empty_response(self):
        """Test empty response when query returns no results"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[])
        agent = OffensiveAgent(neo4j_client=mock_client, correlation_id=str(uuid4()))

        request = {
            "version": "1.0",
            "correlation_id": agent.correlation_id,
            "agent": "offensive",
            "intent": "attack_path",
            "payload": {
                "cweId": "CWE-9999"  # Doesn't exist
            }
        }

        response = agent.execute(request)
        assert response["status"] == "empty"
        assert response["data"] == {"techniques": [], "attack_paths": []}
        assert response["confidence"]["value"] == 0.0
        assert response["confidence"]["basis"] == "NO_MATCH"


class TestEnvelopeStructure:
    """Integration tests for response envelope structure"""

    def test_response_envelope_fields(self):
        """Test that response has all required envelope fields"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[
            {
                "w": {"cweId": "CWE-79"},
                "ap": None,
                "t": None,
                "tac": None,
                "st": None
            }
        ])

        correlation_id = str(uuid4())
        agent = OffensiveAgent(neo4j_client=mock_client, correlation_id=correlation_id)

        request = {
            "version": "1.0",
            "correlation_id": correlation_id,
            "agent": "offensive",
            "intent": "attack_path",
            "payload": {"cweId": "CWE-79"}
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
        mock_client.query = Mock(return_value=[
            {
                "w": {"cweId": "CWE-79"},
                "ap": None,
                "t": None,
                "tac": None,
                "st": None
            }
        ])

        agent = OffensiveAgent(neo4j_client=mock_client, correlation_id=str(uuid4()))
        request = {
            "version": "1.0",
            "correlation_id": agent.correlation_id,
            "agent": "offensive",
            "intent": "attack_path",
            "payload": {"cweId": "CWE-79"}
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
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": {"attackId": "T1059"},
                "tac": None,
                "st": None
            }
        ])

        agent = OffensiveAgent(neo4j_client=mock_client, correlation_id=str(uuid4()))
        request = {
            "version": "1.0",
            "correlation_id": agent.correlation_id,
            "agent": "offensive",
            "intent": "attack_path",
            "payload": {"cweId": "CWE-79"}
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
        """Test offensive-response.json data structure"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": {
                    "attackId": "T1059",
                    "name": "Command and Scripting Interpreter"
                },
                "tac": {"name": "Execution"},
                "st": None
            }
        ])

        agent = OffensiveAgent(neo4j_client=mock_client, correlation_id=str(uuid4()))
        request = {
            "version": "1.0",
            "correlation_id": agent.correlation_id,
            "agent": "offensive",
            "intent": "attack_path",
            "payload": {"cweId": "CWE-79"}
        }

        response = agent.execute(request)

        # Verify data structure
        data = response["data"]
        assert isinstance(data["techniques"], list)
        assert isinstance(data["attack_paths"], list)

        # Verify technique structure
        for technique in data["techniques"]:
            assert "id" in technique
            assert "name" in technique
            assert "tactics" in technique
            assert "capec" in technique
            assert "subtechniques" in technique
            assert isinstance(technique["tactics"], list)
            assert isinstance(technique["capec"], list)
            assert isinstance(technique["subtechniques"], list)

        # Verify attack_path structure
        for path in data["attack_paths"]:
            assert "weakness_id" in path
            assert "attack_pattern_id" in path
            assert "technique_id" in path
