"""Defensive Agent executor

Main entry point for Defensive Agent microservice.
Handles request routing, template selection, query execution, and response building.
"""

import re
from typing import Any, Dict, Optional
from uuid import uuid4

from agents.shared.confidence_scorer import ConfidenceScorer
from agents.shared.logger import AgentLogger
from agents.shared.neo4j_client import Neo4jClient
from agents.shared.response_builder import ResponseBuilder
from agents.shared.schema_validator import SchemaValidator

from .constants import (
    EXPECTED_HOPS,
    MISSING_FRAMEWORK_PENALTY,
    QUERY_TIMEOUT_SECONDS,
    MAX_RESULT_ROWS,
    STALE_DATA_PENALTY,
    STALE_DATA_THRESHOLD_DAYS,
    TECHNIQUE_PATTERN,
    VALID_INTENTS,
    VALID_PAYLOAD_FIELDS
)
from .cypher_templates import TEMPLATES, validate_template
from .errors import QueryExecutionError, TemplateError, ValidationError
from .transformers import DefensiveTransformer


class DefensiveAgent:
    """Defensive Agent microservice for ATT&CK technique coverage maps.

    Executes read-only queries against Neo4j to retrieve D3FEND mitigations,
    CAR detections, SHIELD deceptions, and ENGAGE engagement concepts for
    a given ATT&CK technique.
    """

    def __init__(self, neo4j_client: Optional[Neo4jClient] = None, correlation_id: Optional[str] = None):
        """Initialize DefensiveAgent.

        Args:
            neo4j_client: Neo4jClient instance (optional; if None, creates new instance)
            correlation_id: Request correlation ID for logging (optional; generated if not provided)
        """
        self.neo4j_client = neo4j_client or Neo4jClient()
        self.correlation_id = correlation_id or str(uuid4())
        self.logger = AgentLogger("agents.defensive", self.correlation_id)
        self.confidence_scorer = ConfidenceScorer()
        self.response_builder = ResponseBuilder()
        self.schema_validator = SchemaValidator()
        self.transformer = DefensiveTransformer()

    def execute(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Defensive Agent request.

        Flow:
        1. Update correlation_id from request
        2. Extract and validate payload (expect attackId)
        3. Select template by intent
        4. Execute Cypher query with parameter binding
        5. Transform Neo4j records to coverage response
        6. Extract provenance (4 frameworks: D3FEND, CAR, SHIELD, ENGAGE)
        7. Compute confidence score
        8. Build response envelope
        9. Validate against schema
        10. Return response (ok/empty/error status)

        Args:
            request: Full request envelope with version, correlation_id, agent, intent, payload

        Returns:
            Response envelope dict with version, correlation_id, status, data, provenance, confidence
        """
        try:
            # Update correlation ID from request
            self.correlation_id = request.get("correlation_id", self.correlation_id)
            self.logger = AgentLogger("agents.defensive", self.correlation_id)

            self.logger.info("execute() start")

            # Extract and validate payload
            payload = request.get("payload", {})
            intent = request.get("intent")

            self.logger.info(f"intent={intent}, payload_keys={list(payload.keys())}")

            # Validate intent
            if intent not in VALID_INTENTS:
                raise ValidationError(f"Invalid intent: {intent}. Expected one of {VALID_INTENTS}")

            # Validate payload has required field
            if "attackId" not in payload:
                raise ValidationError("Missing required payload field: attackId")

            attackId = payload["attackId"]

            # Validate attackId pattern (T1059 or T1059.001 format)
            if not re.match(TECHNIQUE_PATTERN, attackId):
                raise ValidationError(
                    f"Invalid attackId format: {attackId}. Expected pattern: T\\d{{4}}(\\.\\d{{3}})?"
                )

            # Select and validate template
            template_meta = TEMPLATES.get("coverage_map")
            if not template_meta:
                raise TemplateError("Template 'coverage_map' not found")

            template = template_meta["template"]
            self.logger.info("Template T_DEF_01 selected")

            # Execute query
            records = self._execute_query(template, {"attackId": attackId})
            self.logger.info(f"Query returned {len(records)} records")

            # Handle no results
            if not records:
                self.logger.info("No coverage found for technique")
                confidence = self.confidence_scorer.compute(
                    row_count=0,
                    hop_count=0,
                    hops_expected=EXPECTED_HOPS.get("coverage_map", 1),
                    shape_validated=False
                )
                response = {
                    "version": self.response_builder.SCHEMA_VERSION,
                    "correlation_id": self.correlation_id,
                    "status": "empty",
                    "data": {
                        "technique_id": attackId,
                        "mitigations": [],
                        "detections": [],
                        "deceptions": [],
                        "engagements": [],
                        "summary": {
                            "total_mitigations": 0,
                            "total_detections": 0,
                            "total_deceptions": 0,
                            "total_engagements": 0,
                            "has_coverage": False
                        }
                    },
                    "provenance": [],
                    "confidence": confidence,
                    "errors": []
                }
                self.schema_validator.validate_response("defensive", response)
                return response

            # Transform results
            data = self.transformer.transform_coverage_results(records)
            self.logger.info(
                f"Transformed: {data['summary']['total_mitigations']} mitigations, "
                f"{data['summary']['total_detections']} detections, "
                f"{data['summary']['total_deceptions']} deceptions, "
                f"{data['summary']['total_engagements']} engagements"
            )

            # Extract provenance
            provenance = self.transformer.extract_provenance(records)
            self.logger.info(f"Provenance: {len(provenance)} sources")

            # Compute confidence
            # For Defensive Agent: count how many frameworks are represented
            framework_count = len(provenance)  # Can be 1-4 (D3FEND, CAR, SHIELD, ENGAGE)
            frameworks_expected = 4  # We expect all 4 frameworks
            missing_frameworks = frameworks_expected - framework_count
            confidence_penalty = missing_frameworks * MISSING_FRAMEWORK_PENALTY

            # Start at 1.0 if we have any coverage, apply penalties
            confidence_value = 1.0 if len(records) > 0 else 0.0
            confidence_value -= confidence_penalty
            confidence_value = max(0.0, min(1.0, confidence_value))  # Clamp to [0.0, 1.0]

            confidence = {
                "value": confidence_value,
                "basis": "COVERAGE_MAP" if len(records) > 0 else "NO_MATCH",
                "signals": {
                    "rows": len(records),
                    "hops": EXPECTED_HOPS.get("coverage_map", 1)
                },
                "degradation": []
            }

            if confidence_penalty > 0:
                confidence["degradation"].append(
                    f"missing_frameworks ({missing_frameworks}/{frameworks_expected})"
                )

            self.logger.info(f"Confidence: {confidence['value']:.2f} ({confidence['basis']})")

            # Build response
            response = self.response_builder.ok(
                data=data,
                provenance=provenance,
                confidence=confidence,
                correlation_id=self.correlation_id
            )

            # Validate response
            self.schema_validator.validate_response("defensive", response)
            self.logger.info("Response schema validation passed")

            self.logger.info("execute() success")
            return response

        except ValidationError as e:
            self.logger.error(f"Validation error: {str(e)}", exc=e)
            return self.response_builder.error(
                errors=[f"ValidationError: {str(e)}"],
                correlation_id=self.correlation_id
            )

        except QueryExecutionError as e:
            self.logger.error(f"Query execution error: {str(e)}", exc=e)
            return self.response_builder.error(
                errors=[f"QueryExecutionError: {str(e)}"],
                correlation_id=self.correlation_id
            )

        except Exception as e:
            self.logger.error(f"Unexpected error: {str(e)}", exc=e)
            return self.response_builder.error(
                errors=["Internal service error"],
                correlation_id=self.correlation_id
            )

    def _execute_query(self, template: str, params: Dict[str, Any]) -> list:
        """Execute Cypher query against Neo4j.

        Args:
            template: Cypher template string
            params: Parameters to bind in query

        Returns:
            List of result dicts from Neo4j

        Raises:
            QueryExecutionError: If query fails
        """
        try:
            self.logger.info(f"Executing query with params: {list(params.keys())}")
            results = self.neo4j_client.query(template, params)
            return results

        except Exception as e:
            raise QueryExecutionError(f"Neo4j query failed: {str(e)}")
