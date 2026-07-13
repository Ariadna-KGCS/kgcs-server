"""Response envelope builder for agent responses.

Constructs valid agent response envelopes that conform to agent-consumable-schema.json
"""

from typing import Dict, List, Any, Optional
from uuid import UUID
from datetime import datetime, timezone
import logging


logger = logging.getLogger(__name__)


class ResponseBuilder:
    """Constructs KGCS agent response envelopes.

    Handles all 3 status types: ok, empty, error
    """

    SCHEMA_VERSION = "1.0"

    def ok(
        self,
        data: Dict[str, Any] | List[Any],
        provenance: List[Dict[str, Any]],
        confidence: Dict[str, Any],
        correlation_id: str,
        errors: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Build a successful response envelope (status=ok).

        Args:
            data: Agent-specific payload (dict or list)
            provenance: List of provenance entries [{source, ids, timestamp}, ...]
            confidence: Confidence dict {value, basis, signals, degradation}
            correlation_id: Request correlation ID (UUID string)
            errors: Optional error messages (usually empty for ok status)

        Returns:
            Complete response envelope dict
        """
        return {
            "version": self.SCHEMA_VERSION,
            "correlation_id": correlation_id,
            "status": "ok",
            "data": data,
            "provenance": provenance,
            "confidence": confidence,
            "errors": errors or []
        }

    def empty(
        self,
        confidence: Dict[str, Any],
        correlation_id: str
    ) -> Dict[str, Any]:
        """Build an empty response envelope (status=empty, no results but valid).

        Used when query executes successfully but returns no results.

        Args:
            confidence: Confidence dict {value, basis, signals, degradation}
            correlation_id: Request correlation ID (UUID string)

        Returns:
            Complete response envelope dict
        """
        return {
            "version": self.SCHEMA_VERSION,
            "correlation_id": correlation_id,
            "status": "empty",
            "data": {},
            "provenance": [],
            "confidence": confidence,
            "errors": []
        }

    def error(
        self,
        errors: List[str],
        correlation_id: str,
        confidence: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Build an error response envelope (status=error).

        Used when query fails or encounters validation errors.

        Args:
            errors: List of error messages
            correlation_id: Request correlation ID (UUID string)
            confidence: Optional confidence dict (defaults to 0.0 NO_MATCH)

        Returns:
            Complete response envelope dict
        """
        # Default confidence for errors
        if confidence is None:
            confidence = {
                "value": 0.0,
                "basis": "NO_MATCH",
                "signals": {},
                "degradation": ["query_failed"]
            }

        return {
            "version": self.SCHEMA_VERSION,
            "correlation_id": correlation_id,
            "status": "error",
            "data": {},
            "provenance": [],
            "confidence": confidence,
            "errors": errors
        }

    @staticmethod
    def ensure_provenance_entry(source: str, ids: List[str]) -> Dict[str, Any]:
        """Construct a single provenance entry.

        Args:
            source: Source system name (e.g., "NVD", "MITRE", "CAPEC")
            ids: List of identifiers from source (e.g., ["CVE-2021-44228"])

        Returns:
            Provenance entry dict
        """
        return {
            "source": source,
            "ids": ids,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        }

    @staticmethod
    def ensure_confidence_signal(
        value: float,
        basis: str,
        signals: Optional[Dict[str, Any]] = None,
        degradation: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Construct a confidence signal dict.

        Args:
            value: Confidence value [0.0, 1.0]
            basis: Basis enum (COMPLETE_CHAIN, PARTIAL_CHAIN, etc.)
            signals: Optional signals dict {rows, hops, shape_validated, freshness_days}
            degradation: Optional list of degradation reasons

        Returns:
            Confidence signal dict
        """
        return {
            "value": value,
            "basis": basis,
            "signals": signals or {},
            "degradation": degradation or []
        }
