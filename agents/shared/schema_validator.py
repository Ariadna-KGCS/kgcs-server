"""JSON Schema validation for request/response contracts

Loads all 5 schemas from spec/contracts/ and provides validation methods.
"""

import json
import os
from typing import Dict, Any
from jsonschema import Draft7Validator, SchemaError, ValidationError
import logging


logger = logging.getLogger(__name__)


class SchemaValidator:
    """Validates KGCS agent requests and responses against JSON Schema Draft-07 contracts.

    Schemas must exist at:
    - spec/contracts/agent-consumable-schema.json
    - spec/contracts/request-schema.json
    - spec/contracts/systems-response.json
    - spec/contracts/offensive-response.json
    - spec/contracts/defensive-response.json
    """

    SCHEMAS_DIR = "spec/contracts"

    def __init__(self, schemas_dir: str = SCHEMAS_DIR):
        """Initialize validator by loading all 5 schemas.

        Args:
            schemas_dir: Path to schemas directory relative to project root

        Raises:
            FileNotFoundError: If any schema file is missing
            SchemaError: If any schema is invalid Draft-07
        """
        self.schemas_dir = schemas_dir

        # Load all 5 schemas and validate them against Draft-07 spec
        self.envelope_schema = self._load_and_validate_schema("agent-consumable-schema.json")
        self.request_schema = self._load_and_validate_schema("request-schema.json")
        self.systems_schema = self._load_and_validate_schema("systems-response.json")
        self.offensive_schema = self._load_and_validate_schema("offensive-response.json")
        self.defensive_schema = self._load_and_validate_schema("defensive-response.json")

        logger.info(f"SchemaValidator initialized with schemas from {schemas_dir}")

    def _load_and_validate_schema(self, filename: str) -> Dict[str, Any]:
        """Load a JSON schema file and validate it against Draft-07.

        Args:
            filename: Name of the schema file

        Returns:
            Loaded schema dict

        Raises:
            FileNotFoundError: If schema file doesn't exist
            SchemaError: If schema is invalid
        """
        path = os.path.join(self.schemas_dir, filename)

        if not os.path.exists(path):
            raise FileNotFoundError(f"Schema file not found: {path}")

        with open(path, 'r') as f:
            schema = json.load(f)

        # Validate schema structure itself
        try:
            Draft7Validator.check_schema(schema)
        except SchemaError as e:
            raise SchemaError(f"{filename} is not a valid JSON Schema Draft-07: {e.message}") from e

        logger.debug(f"Loaded schema: {filename}")
        return schema

    def validate_request(self, payload: Dict[str, Any]) -> None:
        """Validate a request against request-schema.json.

        Args:
            payload: Request payload dict

        Raises:
            ValueError: If validation fails
        """
        errors = list(Draft7Validator(self.request_schema).iter_errors(payload))
        if errors:
            error_msg = errors[0].message
            raise ValueError(f"Request validation failed: {error_msg}")

    def validate_response(self, agent_type: str, payload: Dict[str, Any]) -> None:
        """Validate a response envelope + agent-specific data payload.

        Args:
            agent_type: Agent type ("systems", "offensive", "defensive")
            payload: Full response envelope dict

        Raises:
            ValueError: If envelope or data validation fails
        """

        # First: validate response envelope structure
        envelope_errors = list(Draft7Validator(self.envelope_schema).iter_errors(payload))
        if envelope_errors:
            error_msg = envelope_errors[0].message
            raise ValueError(f"Response envelope validation failed: {error_msg}")

        # Second: validate agent-specific data payload
        agent_type_lower = agent_type.lower()
        if agent_type_lower == "systems":
            data_schema = self.systems_schema
        elif agent_type_lower == "offensive":
            data_schema = self.offensive_schema
        elif agent_type_lower == "defensive":
            data_schema = self.defensive_schema
        else:
            raise ValueError(f"Unknown agent_type: {agent_type}")

        data_payload = payload.get("data", {})
        data_errors = list(Draft7Validator(data_schema).iter_errors(data_payload))
        if data_errors:
            error_msg = data_errors[0].message
            raise ValueError(f"{agent_type} data validation failed: {error_msg}")

    def validate_response_envelope_only(self, payload: Dict[str, Any]) -> None:
        """Validate response envelope structure only (without agent-specific data check).

        Used for validation before agent-specific types are known.

        Args:
            payload: Response envelope dict

        Raises:
            ValueError: If envelope validation fails
        """
        errors = list(Draft7Validator(self.envelope_schema).iter_errors(payload))
        if errors:
            error_msg = errors[0].message
            raise ValueError(f"Response envelope validation failed: {error_msg}")

    @staticmethod
    def get_validation_error_details(validator, instance) -> Dict[str, Any]:
        """Get detailed validation error information for debugging.

        Args:
            validator: Draft7Validator instance
            instance: Instance being validated

        Returns:
            Dict with error details
        """
        errors = list(validator.iter_errors(instance))
        if not errors:
            return {"valid": True, "errors": []}

        error_details = []
        for error in errors:
            error_details.append({
                "path": list(error.absolute_path),
                "message": error.message,
                "validator": error.validator,
                "validator_value": error.validator_value
            })

        return {
            "valid": False,
            "error_count": len(errors),
            "errors": error_details
        }
