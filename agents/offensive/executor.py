"""Offensive Agent executor: Main entry point for agent microservice

Implements attack_path intent with request routing and response building.
"""

from typing import Dict, Any, Optional

from agents.shared.neo4j_client import Neo4jClient
from agents.shared.confidence_scorer import ConfidenceScorer
from agents.shared.response_builder import ResponseBuilder
from agents.shared.schema_validator import SchemaValidator
from agents.shared.logger import AgentLogger

from .cypher_templates import TEMPLATES
from .transformers import OffensiveTransformer
from .constants import EXPECTED_HOPS, QUERY_TIMEOUT_SECONDS, MAX_RESULT_ROWS
from .errors import ValidationError, QueryExecutionError


class OffensiveAgent:
    """
    Offensive Agent: Read-only microservice for Weakness ↔ AttackPattern ↔ Technique queries

    Implements attack_path intent via weakness-to-techniques pathway:
    - By CWE (cweId) → all ATT&CK techniques that exploit/demonstrate that weakness

    Constructor:
        neo4j_client: Optional Neo4jClient (default: create from env vars)
        correlation_id: Optional UUID for request tracking
    """

    def __init__(
        self,
        neo4j_client: Optional[Neo4jClient] = None,
        correlation_id: Optional[str] = None
    ):
        """Initialize Offensive Agent with shared utilities.

        Args:
            neo4j_client: Optional Neo4jClient instance (default: create from env)
            correlation_id: Optional UUID (default: generated from request)
        """
        self.neo4j_client = neo4j_client or Neo4jClient()
        self.correlation_id = correlation_id
        self.logger = AgentLogger("agents.offensive", correlation_id or "unknown")
        self.confidence_scorer = ConfidenceScorer()
        self.response_builder = ResponseBuilder()
        self.schema_validator = SchemaValidator()
        self.transformer = OffensiveTransformer()

    def execute(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute an attack_path request.

        Request contract (validated by orchestrator before calling):
        {
            "version": "1.0",
            "correlation_id": "<uuid>",
            "agent": "offensive",
            "intent": "attack_path",
            "payload": {
                "cweId": "CWE-79"
            },
            "constraints": {
                "max_hops": 4,
                "allow_extensions": false
            }
        }

        Returns:
            Full response envelope dict matching agent-consumable-schema.json
        """
        try:
            # Update correlation_id from request
            if request.get("correlation_id"):
                self.correlation_id = request["correlation_id"]
                self.logger.correlation_id = self.correlation_id

            self.logger.info("Processing attack_path request")

            # Route by payload field (only one route: weakness)
            payload = request.get("payload", {})
            template_key = self._select_template(payload)
            self.logger.debug(f"Selected template: {template_key}")

            # Execute query
            records = self._execute_query(template_key, payload)
            self.logger.debug(f"Query returned {len(records)} records")

            # Handle empty results
            if not records:
                return self._build_empty_response()

            # Transform results
            response_data = self._transform_results(template_key, records)
            provenance = self.transformer.extract_provenance(records)
            confidence = self._compute_confidence(template_key, len(records))

            # Build response envelope
            response = self.response_builder.ok(
                data=response_data,
                provenance=provenance,
                confidence=confidence,
                correlation_id=self.correlation_id
            )

            # Validate envelope
            self.schema_validator.validate_response("offensive", response)
            self.logger.info("Response validated successfully")

            return response

        except ValidationError as e:
            self.logger.error(f"Validation error: {e}")
            return self.response_builder.error(
                errors=[str(e)],
                correlation_id=self.correlation_id
            )
        except QueryExecutionError as e:
            self.logger.error(f"Query execution error: {e}")
            return self.response_builder.error(
                errors=["Query execution failed"],
                correlation_id=self.correlation_id
            )
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}", exc=e)
            return self.response_builder.error(
                errors=["Internal service error"],
                correlation_id=self.correlation_id
            )

    def _select_template(self, payload: Dict[str, Any]) -> str:
        """
        Route to correct template based on payload fields.

        Args:
            payload: Request payload

        Returns:
            Template key ("weakness")

        Raises:
            ValidationError: If payload has neither cweId
        """
        if "cweId" in payload:
            return "weakness"
        else:
            raise ValidationError("Payload must contain 'cweId'")

    def _execute_query(self, template_key: str, payload: Dict[str, Any]) -> list:
        """
        Execute parameterized Cypher query.

        Args:
            template_key: "weakness"
            payload: Request payload with parameter values (key: "cweId")

        Returns:
            List of Neo4j record dicts

        Raises:
            ValidationError: If parameter is missing
            QueryExecutionError: If query fails or times out
        """
        template_meta = TEMPLATES[template_key]
        cypher = template_meta["template"]
        neo4j_param = template_meta["params"][0]  # e.g., "cweId"

        # Get value from payload using the ACTUAL payload field name ("cweId")
        # NOT the routing key ("weakness")
        param_value = payload.get("cweId")

        if not param_value:
            raise ValidationError(f"Missing required parameter: cweId")

        # Build params dict for Neo4j query using the actual parameter name
        params = {neo4j_param: param_value}

        try:
            records = self.neo4j_client.query(cypher, params)

            if len(records) > MAX_RESULT_ROWS:
                raise QueryExecutionError(f"Query returned too many rows: {len(records)}")

            return records
        except Exception as e:
            raise QueryExecutionError(f"Query execution failed: {str(e)}") from e

    def _transform_results(self, template_key: str, records: list) -> Dict[str, Any]:
        """Transform Neo4j records into offensive-response.json structure."""
        if template_key == "weakness":
            return self.transformer.transform_weakness_results(records)
        else:
            raise ValidationError(f"Unknown template key: {template_key}")

    def _compute_confidence(self, template_key: str, row_count: int) -> Dict[str, Any]:
        """
        Compute confidence score using shared ConfidenceScorer.

        Args:
            template_key: "weakness"
            row_count: Number of records returned from query

        Returns:
            Confidence dict {value, basis, signals, degradation}
        """
        expected_hops = EXPECTED_HOPS[template_key]

        # Heuristic: assume complete chain if query succeeded with results
        actual_hops = expected_hops if row_count > 0 else 0

        confidence = self.confidence_scorer.compute(
            row_count=row_count,
            hop_count=actual_hops,
            hops_expected=expected_hops,
            shape_validated=False,  # Offensive Agent doesn't run SHACL (yet)
            freshness_days=self._extract_freshness_days()  # Not available from query
        )

        return confidence

    def _extract_freshness_days(self) -> Optional[float]:
        """Extract data age from current timestamp (not available without query context)."""
        # For now, assume fresh data (MITRE data loaded recently)
        # TODO: Extract from Neo4j query results if available
        return None

    def _build_empty_response(self) -> Dict[str, Any]:
        """Build a response for zero-result queries."""
        confidence = self.confidence_scorer.compute(
            row_count=0,
            hop_count=0,
            hops_expected=2,  # Default minimum
            shape_validated=False,
            freshness_days=None
        )
        response = {
            "version": self.response_builder.SCHEMA_VERSION,
            "correlation_id": self.correlation_id,
            "status": "empty",
            "data": {"techniques": [], "attack_paths": []},
            "provenance": [],
            "confidence": confidence,
            "errors": []
        }
        self.schema_validator.validate_response("offensive", response)
        return response
