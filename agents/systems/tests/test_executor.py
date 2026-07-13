"""Test SystemsAgent executor (main entry point)

Verifies that:
- Request validation (cpe or cveId required)
- Template selection (cpe vs cveId)
- Query execution with parameter binding
- Response envelope structure
- Error handling and correlation ID propagation
- Schema validation before return
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from uuid import uuid4
from agents.systems.executor import SystemsAgent
from agents.systems.errors import ValidationError, QueryExecutionError


class TestSystemsAgentInit:
    """Test SystemsAgent initialization"""

    def test_init_with_neo4j_client(self):
        """Test initialization with custom Neo4jClient"""
        mock_client = Mock()
        agent = SystemsAgent(neo4j_client=mock_client, correlation_id="test-uuid")
        assert agent.neo4j_client == mock_client
        assert agent.correlation_id == "test-uuid"

    def test_init_with_defaults(self):
        """Test initialization with default Neo4jClient"""
        with patch("agents.systems.executor.Neo4jClient") as mock_neo4j_class:
            agent = SystemsAgent()
            mock_neo4j_class.assert_called_once()


class TestTemplateSelection:
    """Test _select_template() method"""

    def test_select_template_match_criteria_id(self):
        """Test that matchCriteriaId payload selects matchCriteriaId template"""
        mock_client = Mock()
        agent = SystemsAgent(neo4j_client=mock_client)
        payload = {"matchCriteriaId": "8a5c4e5b-3d6f-4a7e-9b8c-2d3e4f5a6b7c"}
        template_key = agent._select_template(payload)
        assert template_key == "matchCriteriaId"

    def test_select_template_cpe_name(self):
        """Test that cpeName payload selects cpeName template"""
        mock_client = Mock()
        agent = SystemsAgent(neo4j_client=mock_client)
        payload = {"cpeName": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}
        template_key = agent._select_template(payload)
        assert template_key == "cpeName"

    def test_select_template_legacy_cpe(self):
        """Test that legacy cpe payload remains supported"""
        mock_client = Mock()
        agent = SystemsAgent(neo4j_client=mock_client)
        payload = {"cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}
        template_key = agent._select_template(payload)
        assert template_key == "cpe"

    def test_select_template_cveId(self):
        """Test that cveId payload selects cveId template"""
        mock_client = Mock()
        agent = SystemsAgent(neo4j_client=mock_client)
        payload = {"cveId": "CVE-2021-44228"}
        template_key = agent._select_template(payload)
        assert template_key == "cveId"

    def test_select_template_missing_both(self):
        """Test that missing all supported lookup fields raises ValidationError"""
        mock_client = Mock()
        agent = SystemsAgent(neo4j_client=mock_client)
        payload = {"other_field": "value"}
        with pytest.raises(ValidationError, match="matchCriteriaId.*cpeName.*cpe.*cveId"):
            agent._select_template(payload)

    def test_select_template_empty_payload(self):
        """Test that empty payload raises ValidationError"""
        mock_client = Mock()
        agent = SystemsAgent(neo4j_client=mock_client)
        with pytest.raises(ValidationError):
            agent._select_template({})


class TestQueryExecution:
    """Test _execute_query() method"""

    def test_execute_query_match_criteria_id(self):
        """Test query execution with explicit matchCriteriaId parameter"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[
            {"v": {"cveId": "CVE-2021-44228"}, "w": None, "scores": []}
        ])
        agent = SystemsAgent(neo4j_client=mock_client)
        payload = {"matchCriteriaId": "8a5c4e5b-3d6f-4a7e-9b8c-2d3e4f5a6b7c"}
        records = agent._execute_query("matchCriteriaId", payload)
        assert len(records) == 1
        mock_client.query.assert_called_once()
        args, kwargs = mock_client.query.call_args
        assert "$matchCriteriaId" in args[0]
        assert args[1] == {"matchCriteriaId": "8a5c4e5b-3d6f-4a7e-9b8c-2d3e4f5a6b7c"}

    def test_execute_query_cpe_name(self):
        """Test query execution with explicit canonical cpeName parameter"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[
            {"v": {"cveId": "CVE-2021-44228"}, "w": None, "scores": []}
        ])
        agent = SystemsAgent(neo4j_client=mock_client)
        payload = {"cpeName": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}
        records = agent._execute_query("cpeName", payload)
        assert len(records) == 1
        mock_client.query.assert_called_once()
        args, kwargs = mock_client.query.call_args
        assert "$cpeName" in args[0]
        assert args[1] == {"cpeName": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}

    def test_execute_query_legacy_cpe_name_alias(self):
        """Test legacy cpe payload routes canonical CPE strings to cpeName lookup"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[
            {"v": {"cveId": "CVE-2021-44228"}, "w": None, "scores": []}
        ])
        agent = SystemsAgent(neo4j_client=mock_client)
        payload = {"cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}
        records = agent._execute_query("cpe", payload)
        assert len(records) == 1
        args, kwargs = mock_client.query.call_args
        assert "$cpeName" in args[0]
        assert args[1] == {"cpeName": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}

    def test_execute_query_legacy_cpe_match_criteria_alias(self):
        """Test legacy cpe payload routes non-CPE strings to matchCriteriaId lookup"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[
            {"v": {"cveId": "CVE-2021-44228"}, "w": None, "scores": []}
        ])
        agent = SystemsAgent(neo4j_client=mock_client)
        payload = {"cpe": "8a5c4e5b-3d6f-4a7e-9b8c-2d3e4f5a6b7c"}
        records = agent._execute_query("cpe", payload)
        assert len(records) == 1
        args, kwargs = mock_client.query.call_args
        assert "$matchCriteriaId" in args[0]
        assert args[1] == {"matchCriteriaId": "8a5c4e5b-3d6f-4a7e-9b8c-2d3e4f5a6b7c"}

    def test_execute_query_missing_param(self):
        """Test query execution fails when required parameter missing"""
        mock_client = Mock()
        agent = SystemsAgent(neo4j_client=mock_client)
        payload = {}  # Missing cveId
        with pytest.raises(ValidationError, match="Missing required parameter"):
            agent._execute_query("cveId", payload)

    def test_execute_query_too_many_rows(self):
        """Test query execution fails when result exceeds MAX_RESULT_ROWS"""
        mock_client = Mock()
        # Mock returns more than max allowed
        mock_client.query = Mock(return_value=[{"v": {}}] * 10001)
        agent = SystemsAgent(neo4j_client=mock_client)
        payload = {"cveId": "CVE-2021-44228"}
        with pytest.raises(QueryExecutionError, match="too many rows"):
            agent._execute_query("cveId", payload)

    def test_execute_query_neo4j_error(self):
        """Test query execution handles Neo4j client errors"""
        mock_client = Mock()
        mock_client.query = Mock(side_effect=Exception("Connection timeout"))
        agent = SystemsAgent(neo4j_client=mock_client)
        payload = {"cveId": "CVE-2021-44228"}
        with pytest.raises(QueryExecutionError, match="Query execution failed"):
            agent._execute_query("cveId", payload)


class TestConfidenceComputation:
    """Test _compute_confidence() method"""

    def test_compute_confidence_complete_chain_cpe(self):
        """Test confidence scoring with complete chain for criteria lookup"""
        mock_client = Mock()
        agent = SystemsAgent(neo4j_client=mock_client)
        confidence = agent._compute_confidence("matchCriteriaId", row_count=5)
        assert confidence["value"] > 0.0  # Should have some confidence with results
        assert "basis" in confidence  # Should have a basis

    def test_compute_confidence_complete_chain_cveId(self):
        """Test confidence scoring with complete chain for CVE lookup"""
        mock_client = Mock()
        agent = SystemsAgent(neo4j_client=mock_client)
        confidence = agent._compute_confidence("cveId", row_count=2)
        assert confidence["value"] > 0.0
        assert "basis" in confidence

    def test_compute_confidence_no_results(self):
        """Test confidence scoring with zero results"""
        mock_client = Mock()
        agent = SystemsAgent(neo4j_client=mock_client)
        confidence = agent._compute_confidence("cveId", row_count=0)
        assert confidence["value"] == 0.0
        assert confidence["basis"] == "NO_MATCH"

    def test_compute_confidence_signals(self):
        """Test that confidence includes signals dict"""
        mock_client = Mock()
        agent = SystemsAgent(neo4j_client=mock_client)
        confidence = agent._compute_confidence("cveId", row_count=2)
        assert "signals" in confidence
        assert "degradation" in confidence


class TestResponseBuilding:
    """Test response envelope building"""

    def test_execute_empty_results(self):
        """Test that empty query results return empty response"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[])
        agent = SystemsAgent(neo4j_client=mock_client, correlation_id="test-uuid")
        request = {
            "correlation_id": "test-uuid",
            "payload": {"cveId": "CVE-9999-9999"}
        }
        with patch.object(agent.schema_validator, "validate_response"):
            response = agent.execute(request)
        assert response["status"] == "empty"
        assert response["data"] == {"vulnerabilities": []}
        assert response["correlation_id"] == "test-uuid"

    def test_execute_ok_response(self):
        """Test that successful query returns ok response"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[
            {"v": {"cveId": "CVE-2021-44228"}, "w": None, "scores": []}
        ])
        agent = SystemsAgent(neo4j_client=mock_client, correlation_id="test-uuid")
        request = {
            "correlation_id": "test-uuid",
            "payload": {"cveId": "CVE-2021-44228"}
        }
        with patch.object(agent.schema_validator, "validate_response"):
            response = agent.execute(request)
        assert response["status"] == "ok"
        assert response["version"] == "1.0"
        assert response["correlation_id"] == "test-uuid"
        assert "data" in response
        assert "provenance" in response
        assert "confidence" in response

    def test_execute_error_missing_payload_field(self):
        """Test that missing payload field returns error response"""
        mock_client = Mock()
        agent = SystemsAgent(neo4j_client=mock_client, correlation_id="test-uuid")
        request = {
            "correlation_id": "test-uuid",
            "payload": {}  # Missing cpe or cveId
        }
        with patch.object(agent.schema_validator, "validate_response", side_effect=ValueError):
            response = agent.execute(request)
        assert response["status"] == "error"
        assert len(response["errors"]) > 0


class TestCorrelationIDPropagation:
    """Test correlation ID propagation through request"""

    def test_execute_updates_correlation_id(self):
        """Test that execute() updates internal correlation_id from request"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[])
        agent = SystemsAgent(neo4j_client=mock_client, correlation_id="initial-uuid")
        request = {
            "correlation_id": "request-uuid",
            "payload": {"cveId": "CVE-2021-44228"}
        }
        with patch.object(agent.schema_validator, "validate_response"):
            response = agent.execute(request)
        assert agent.correlation_id == "request-uuid"
        assert response["correlation_id"] == "request-uuid"

    def test_execute_preserves_correlation_id_in_logs(self):
        """Test that logger receives updated correlation_id"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[])
        agent = SystemsAgent(neo4j_client=mock_client, correlation_id="initial-uuid")
        request = {
            "correlation_id": "request-uuid",
            "payload": {"cveId": "CVE-2021-44228"}
        }
        with patch.object(agent.schema_validator, "validate_response"):
            response = agent.execute(request)
        assert agent.logger.correlation_id == "request-uuid"


class TestErrorHandling:
    """Test error handling in execute() method"""

    def test_execute_validation_error_returns_error_response(self):
        """Test that ValidationError returns error response"""
        mock_client = Mock()
        agent = SystemsAgent(neo4j_client=mock_client, correlation_id="test-uuid")
        request = {
            "correlation_id": "test-uuid",
            "payload": {}  # Invalid payload
        }
        response = agent.execute(request)
        assert response["status"] == "error"
        assert response["errors"]

    def test_execute_query_error_returns_error_response(self):
        """Test that QueryExecutionError returns error response"""
        mock_client = Mock()
        mock_client.query = Mock(side_effect=Exception("Query timeout"))
        agent = SystemsAgent(neo4j_client=mock_client, correlation_id="test-uuid")
        request = {
            "correlation_id": "test-uuid",
            "payload": {"cveId": "CVE-2021-44228"}
        }
        response = agent.execute(request)
        assert response["status"] == "error"
        assert "Query execution failed" in response["errors"]

    def test_execute_unexpected_error_returns_error_response(self):
        """Test that unexpected errors return error response"""
        mock_client = Mock()
        agent = SystemsAgent(neo4j_client=mock_client, correlation_id="test-uuid")
        request = {
            "correlation_id": "test-uuid",
            "payload": {"cveId": "CVE-2021-44228"}
        }
        with patch.object(agent, "_select_template", side_effect=RuntimeError("Unexpected error")):
            response = agent.execute(request)
        assert response["status"] == "error"


class TestSchemaValidation:
    """Test schema validation integration"""

    def test_execute_validates_response(self):
        """Test that execute() validates response before returning"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[
            {"v": {"cveId": "CVE-2021-44228"}, "w": None, "scores": []}
        ])
        agent = SystemsAgent(neo4j_client=mock_client, correlation_id="test-uuid")
        request = {
            "correlation_id": "test-uuid",
            "payload": {"cveId": "CVE-2021-44228"}
        }
        with patch.object(agent.schema_validator, "validate_response") as mock_validate:
            response = agent.execute(request)
            mock_validate.assert_called_once()
            args = mock_validate.call_args[0]
            assert args[0] == "systems"  # Agent type
            assert "status" in args[1]  # Response envelope

    def test_execute_validation_error_caught(self):
        """Test that schema validation errors are caught"""
        mock_client = Mock()
        mock_client.query = Mock(return_value=[
            {"v": {"cveId": "CVE-2021-44228"}, "w": None, "scores": []}
        ])
        agent = SystemsAgent(neo4j_client=mock_client, correlation_id="test-uuid")
        request = {
            "correlation_id": "test-uuid",
            "payload": {"cveId": "CVE-2021-44228"}
        }
        with patch.object(agent.schema_validator, "validate_response", side_effect=ValueError("Schema invalid")):
            response = agent.execute(request)
        assert response["status"] == "error"
        assert len(response["errors"]) > 0
