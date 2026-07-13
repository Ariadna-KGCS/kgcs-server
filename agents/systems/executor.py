"""Systems Agent executor: Main entry point for agent microservice

Implements vuln_lookup intent with request routing and response building.
"""

from typing import Dict, Any, Optional
from datetime import datetime

from agents.shared.neo4j_client import Neo4jClient
from agents.shared.confidence_scorer import ConfidenceScorer
from agents.shared.response_builder import ResponseBuilder
from agents.shared.schema_validator import SchemaValidator
from agents.shared.logger import AgentLogger

from .cypher_templates import TEMPLATES
from .transformers import SystemsTransformer
from .constants import EXPECTED_HOPS, QUERY_TIMEOUT_SECONDS, MAX_RESULT_ROWS
from .errors import ValidationError, QueryExecutionError


class SystemsAgent:
    """
    Systems Agent: Read-only microservice for Platform/PlatformConfiguration ↔ Vulnerability queries

    Implements vuln_lookup intent via three pathways:
    1. By matchCriteriaId → all CVEs affecting that platform configuration
    2. By canonical cpeName → resolve Platform, then CVEs affecting matching configurations
    3. By CVE ID → CVE details, root cause (Weakness), and CVSS scores

    Constructor:
        neo4j_client: Optional Neo4jClient (default: create from env vars)
        correlation_id: Optional UUID for request tracking
    """

    def __init__(
        self,
        neo4j_client: Optional[Neo4jClient] = None,
        correlation_id: Optional[str] = None
    ):
        """Initialize Systems Agent with shared utilities.

        Args:
            neo4j_client: Optional Neo4jClient instance (default: create from env)
            correlation_id: Optional UUID (default: generated from request)
        """
        self.neo4j_client = neo4j_client or Neo4jClient()
        self.correlation_id = correlation_id
        self.logger = AgentLogger("agents.systems", correlation_id or "unknown")
        self.confidence_scorer = ConfidenceScorer()
        self.response_builder = ResponseBuilder()
        self.schema_validator = SchemaValidator()
        self.transformer = SystemsTransformer()

    def execute(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a vuln_lookup request.

        Request contract (validated by orchestrator before calling):
        {
            "version": "1.0",
            "correlation_id": "<uuid>",
            "agent": "systems",
            "intent": "vuln_lookup",
            "payload": {
                "matchCriteriaId": "<criteria uuid>" OR
                "cpeName": "<canonical CPE 2.3 string>" OR
                "cpe": "<legacy alias: criteria uuid or CPE 2.3 string>" OR
                "cveId": "CVE-2021-44228"
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

            self.logger.info("Processing vuln_lookup request")

            # Route by payload field
            payload = request.get("payload", {})
            template_key = self._select_template(payload)
            self.logger.debug(f"Selected template: {template_key}")

            # Execute query
            records = self._execute_query(template_key, payload)
            self.logger.debug(f"Query returned {len(records)} records")

            # Handle empty results
            if not records:
                return self._build_empty_response(template_key)

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
            self.schema_validator.validate_response("systems", response)
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
            Template key ("matchCriteriaId", "cpeName", "cpe", or "cveId")

        Raises:
            ValidationError: If payload has neither matchCriteriaId/cpeName/cpe nor cveId
        """
        if "matchCriteriaId" in payload:
            return "matchCriteriaId"
        elif "cpeName" in payload:
            return "cpeName"
        elif "cpe" in payload:
            return "cpe"
        elif "cveId" in payload:
            return "cveId"
        else:
            raise ValidationError(
                "Payload must contain 'matchCriteriaId', 'cpeName', 'cpe', or 'cveId'"
            )

    def _execute_query(self, template_key: str, payload: Dict[str, Any]) -> list:
        """
        Execute parameterized Cypher query.

        Args:
            template_key: Lookup routing key
            payload: Request payload with parameter values

        Returns:
            List of Neo4j record dicts

        Raises:
            ValidationError: If parameter is missing
            QueryExecutionError: If query fails or times out
        """
        template_meta = TEMPLATES[template_key]
        cypher = template_meta["template"]
        neo4j_param = template_meta["params"][0]  # e.g., "matchCriteriaId" or "cveId"

        # Get value from payload using the routing key (not the Neo4j param name)
        param_value = payload.get(template_key)
        if template_key == "cpe" and param_value:
            # Compatibility alias: infer whether legacy payload.cpe is a canonical
            # CPE name or a PlatformConfiguration matchCriteriaId.
            if str(param_value).lower().startswith("cpe:2.3:"):
                cypher = TEMPLATES["cpeName"]["template"]
                neo4j_param = "cpeName"
            else:
                neo4j_param = "matchCriteriaId"

        if not param_value:
            raise ValidationError(f"Missing required parameter: {template_key}")

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
        """Transform Neo4j records into systems-response.json structure."""
        if template_key in {"matchCriteriaId", "cpeName", "cpe"}:
            return self.transformer.transform_cpe_results(records)
        elif template_key == "cveId":
            return self.transformer.transform_cve_results(records)
        else:
            raise ValidationError(f"Unknown template key: {template_key}")

    def _compute_confidence(self, template_key: str, row_count: int) -> Dict[str, Any]:
        """
        Compute confidence score using shared ConfidenceScorer.

        Args:
            template_key: "cpe" or "cveId"
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
            shape_validated=False,  # Systems Agent doesn't run SHACL (yet)
            freshness_days=self._extract_freshness_days()  # Not available from query
        )

        return confidence

    def _extract_freshness_days(self) -> Optional[float]:
        """Extract data age from current timestamp (not available without query context)."""
        # For now, assume fresh data (systems loaded recently)
        # TODO: Extract from Neo4j query results if available
        return None

    def _build_empty_response(self, template_key: str) -> Dict[str, Any]:
        """Build a response for zero-result queries."""
        confidence = self.confidence_scorer.compute(
            row_count=0,
            hop_count=0,
            hops_expected=2,  # Default minimum
            shape_validated=False,
            freshness_days=None
        )
        data: Dict[str, Any] = {"vulnerabilities": []}

        response = {
            "version": self.response_builder.SCHEMA_VERSION,
            "correlation_id": self.correlation_id,
            "status": "empty",
            "data": data,
            "provenance": [],
            "confidence": confidence,
            "errors": []
        }
        self.schema_validator.validate_response("systems", response)
        return response
