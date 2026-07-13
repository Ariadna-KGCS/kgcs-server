"""Request routing logic for Master Orchestrator

Maps intents to agents and validates request payloads.
"""

from typing import Any, Dict, Tuple

from .constants import INTENT_TO_AGENT, INTENT_PAYLOAD_FIELDS, VALID_INTENTS
from .errors import RoutingError, ValidationError


class RequestRouter:
    """Routes requests to appropriate agents based on intent"""

    @staticmethod
    def validate_intent(intent: str) -> None:
        """Validate that intent is supported.

        Args:
            intent: Request intent string

        Raises:
            ValidationError: If intent is not in VALID_INTENTS
        """
        if intent not in VALID_INTENTS:
            raise ValidationError(
                f"Invalid intent: {intent}. Expected one of {VALID_INTENTS}"
            )

    @staticmethod
    def validate_payload(intent: str, payload: Dict[str, Any]) -> None:
        """Validate payload has required fields for intent.

        Args:
            intent: Request intent
            payload: Request payload dict

        Raises:
            ValidationError: If payload missing required fields
        """
        required_fields = INTENT_PAYLOAD_FIELDS.get(intent, set())

        # For intents that require "at least one of" multiple fields
        if intent in ["vuln_lookup", "attack_path", "mixed"]:
            field_found = any(field in payload for field in required_fields)
            if not field_found:
                raise ValidationError(
                    f"Payload missing required field for {intent}. "
                    f"Expected at least one of {required_fields}"
                )
        # For intents that require specific field
        elif intent == "coverage_map":
            if "attackId" not in payload:
                raise ValidationError(
                    f"Payload missing required field for {intent}: attackId"
                )

    @staticmethod
    def route_intent(intent: str) -> str:
        """Route single-intent request to appropriate agent.

        For "mixed" intent, use route_mixed_intent() instead.

        Args:
            intent: Request intent

        Returns:
            Agent name (systems, offensive, defensive)

        Raises:
            RoutingError: If intent cannot be routed
        """
        if intent == "mixed":
            raise RoutingError("Use route_mixed_intent() for 'mixed' intent requests")

        agent = INTENT_TO_AGENT.get(intent)
        if not agent:
            raise RoutingError(f"No agent found for intent: {intent}")

        return agent

    @staticmethod
    def route_mixed_intent() -> list:
        """Route multi-agent 'mixed' intent request.

        Returns:
            List of (agent, intent) tuples in execution order
        """
        from .constants import MIXED_INTENT_SEQUENCE
        return MIXED_INTENT_SEQUENCE
