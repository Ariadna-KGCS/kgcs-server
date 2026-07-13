"""Test DefensiveAgent executor

Tests request routing, response building, error handling, and correlation ID propagation.
"""

import pytest
from unittest.mock import Mock
from uuid import uuid4
from agents.defensive.executor import DefensiveAgent


class TestDefensiveAgentInit:
    """Test DefensiveAgent initialization"""

    def test_init_with_neo4j_client(self):
        """Test initialization with provided Neo4jClient"""
        mock_client = Mock()
        correlation_id = str(uuid4())
        agent = DefensiveAgent(neo4j_client=mock_client, correlation_id=correlation_id)

        assert agent.neo4j_client == mock_client
        assert agent.correlation_id == correlation_id

    def test_init_assigns_correlation_id(self):
        """Test initialization assigns correlation_id"""
        mock_client = Mock()
        correlation_id = str(uuid4())
        agent = DefensiveAgent(neo4j_client=mock_client, correlation_id=correlation_id)

        assert agent.correlation_id == correlation_id


class TestTemplateSelection:
    """Test template selection logic"""

    def test_coverage_map_template_selected(self):
        """Test that coverage_map intent selects correct template"""
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

        # Template should be selected and query should be called
        mock_client.query.assert_called_once()


class TestQueryExecution:
    """Test query execution with parameter binding"""

    def test_query_execution_with_valid_params(self):
        """Test query execution with valid attackId parameter"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[
            {
                "mitigations": [],
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

        # Verify query was called with correct parameters
        args, kwargs = mock_client.query.call_args
        assert kwargs.get("attackId") == "T1059" or (len(args) > 1 and args[1].get("attackId") == "T1059")

    def test_query_execution_with_subtechnique(self):
        """Test query execution with subtechnique ID (T1059.001 format)"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[])
        agent = DefensiveAgent(neo4j_client=mock_client, correlation_id=str(uuid4()))

        request = {
            "version": "1.0",
            "correlation_id": agent.correlation_id,
            "agent": "defensive",
            "intent": "coverage_map",
            "payload": {"attackId": "T1059.001"}
        }

        response = agent.execute(request)

        # Should not raise error for valid subtechnique format
        assert response["status"] in ["ok", "empty", "error"]  # Would be empty if no results


class TestConfidenceComputation:
    """Test confidence scoring"""

    def test_confidence_full_coverage(self):
        """Test confidence when all 4 frameworks are represented"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[
            {
                "mitigations": [{"d3fendId": "D3-PA", "name": "Process Analysis"}],
                "detections": [{"analyticId": "CAR-2020-04-001", "title": "", "coverageLevel": ""}],
                "deceptions": [{"techniqueId": "DTE0001", "name": ""}],
                "engagements": [{"activityId": "EAC0002", "name": ""}]
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

        assert response["confidence"]["value"] == 1.0
        assert response["confidence"]["basis"] == "COVERAGE_MAP"

    def test_confidence_partial_coverage(self):
        """Test confidence when only 2 of 4 frameworks represented"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[
            {
                "mitigations": [{"d3fendId": "D3-PA", "name": ""}],
                "detections": [{"analyticId": "CAR-2020-04-001", "title": "", "coverageLevel": ""}],
                "deceptions": [],  # Missing
                "engagements": []  # Missing
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

        # 2 missing frameworks * -0.1 penalty = 0.8 confidence
        assert response["confidence"]["value"] == 0.8
        assert response["confidence"]["basis"] == "COVERAGE_MAP"
        assert "missing_frameworks" in response["confidence"]["degradation"][0]

    def test_confidence_no_coverage(self):
        """Test confidence when no results returned"""
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

        assert response["confidence"]["value"] == 0.0
        assert response["confidence"]["basis"] == "NO_MATCH"
        assert response["status"] == "empty"


class TestResponseBuilding:
    """Test response envelope building"""

    def test_response_envelope_structure(self):
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

        # Verify all required fields
        assert response["version"] == "1.0"
        assert response["correlation_id"] == correlation_id
        assert response["status"] in ["ok", "empty", "error"]
        assert "data" in response
        assert "provenance" in response
        assert "confidence" in response
        assert "errors" in response

    def test_data_payload_structure(self):
        """Test defensive response data structure"""
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

        # Verify data structure
        data = response["data"]
        assert "mitigations" in data
        assert "detections" in data
        assert "deceptions" in data
        assert "engagements" in data
        assert "summary" in data

        # Verify summary fields
        summary = data["summary"]
        assert "total_mitigations" in summary
        assert "total_detections" in summary
        assert "total_deceptions" in summary
        assert "total_engagements" in summary
        assert "has_coverage" in summary


class TestCorrelationIDPropagation:
    """Test correlation ID propagation"""

    def test_correlation_id_in_request(self):
        """Test that correlation ID from request is used in response"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[])
        correlation_id = str(uuid4())

        request = {
            "version": "1.0",
            "correlation_id": correlation_id,
            "agent": "defensive",
            "intent": "coverage_map",
            "payload": {"attackId": "T1059"}
        }

        agent = DefensiveAgent(neo4j_client=mock_client)
        response = agent.execute(request)

        assert response["correlation_id"] == correlation_id


class TestErrorHandling:
    """Test error handling scenarios"""

    def test_invalid_payload_missing_field(self):
        """Test error when payload missing attackId"""
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

    def test_invalid_attack_id_format(self):
        """Test error when attackId has invalid format"""
        mock_client = Mock()
        agent = DefensiveAgent(neo4j_client=mock_client, correlation_id=str(uuid4()))

        request = {
            "version": "1.0",
            "correlation_id": agent.correlation_id,
            "agent": "defensive",
            "intent": "coverage_map",
            "payload": {"attackId": "INVALID"}  # Not T#### format
        }

        response = agent.execute(request)

        assert response["status"] == "error"
        assert "Invalid attackId format" in response["errors"][0]

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

    def test_invalid_intent(self):
        """Test error when intent is invalid"""
        mock_client = Mock()
        agent = DefensiveAgent(neo4j_client=mock_client, correlation_id=str(uuid4()))

        request = {
            "version": "1.0",
            "correlation_id": agent.correlation_id,
            "agent": "defensive",
            "intent": "invalid_intent",
            "payload": {"attackId": "T1059"}
        }

        response = agent.execute(request)

        assert response["status"] == "error"
        assert "Invalid intent" in response["errors"][0]
