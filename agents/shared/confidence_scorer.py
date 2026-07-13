"""Confidence scoring model for agent responses

Algorithm from docs/05-agents/confidence-model/spec.md
"""

from typing import Optional, List, Dict, Any
import logging


logger = logging.getLogger(__name__)


class ConfidenceScorer:
    """Computes confidence scores for agent query results.

    Confidence scoring follows the canonical algorithm from the specification:
    1. Start at 1.0 if all conditions met (rows > 0, SHACL validated, full causal chain traversed)
    2. Degrade by 0.2 per missing hop in the causal chain
    3. Degrade by 0.1 if data is stale (> 365 days old)
    4. Clamp final value to [0.0, 1.0]
    5. Assign basis enum based on which conditions were met
    6. Include signals dict for transparency
    7. Include degradation array with reasons
    """

    # Degradation reasons
    STALE_DATA = "stale_data"
    PARTIAL_CHAIN = "partial_chain"
    NO_RESULTS = "no_results"
    VALIDATION_FAILED = "validation_failed"

    def compute(
        self,
        row_count: int,
        hop_count: int,
        hops_expected: int,
        shape_validated: bool,
        freshness_days: Optional[float] = None
    ) -> Dict[str, Any]:
        """Compute confidence score for query results.

        Args:
            row_count: Number of result rows returned
            hop_count: Number of hops actually traversed in the graph
            hops_expected: Expected number of hops for a complete causal chain
            shape_validated: Whether SHACL shape validation passed
            freshness_days: Age of the data in days (optional)

        Returns:
            Dict with keys:
            - value: float [0.0, 1.0]
            - basis: str (enum: COMPLETE_CHAIN, PARTIAL_CHAIN, SINGLE_HOP, NO_MATCH, VALIDATED_BY_SHACL, COVERAGE_MAP)
            - signals: dict with rows, hops, shape_validated, freshness_days
            - degradation: list of degradation reasons
        """

        confidence_value = 1.0
        basis = "COMPLETE_CHAIN"
        degradation: List[str] = []

        # Case 1: No results - confidence is 0
        if row_count == 0:
            confidence_value = 0.0
            basis = "NO_MATCH"
            degradation.append(self.NO_RESULTS)

        else:
            # Case 2: Check for missing hops (causal chain incompleteness)
            missing_hops = hops_expected - hop_count
            if missing_hops > 0:
                confidence_value -= (0.2 * missing_hops)
                basis = "PARTIAL_CHAIN"
                degradation.append(self.PARTIAL_CHAIN)
            elif not shape_validated:
                # Case 3: Single hop or unvalidated data
                basis = "SINGLE_HOP"
                degradation.append(self.VALIDATION_FAILED)

            # Case 4: Check for stale data
            if freshness_days is not None and freshness_days > 365:
                confidence_value -= 0.1
                degradation.append(self.STALE_DATA)

        # Clamp to valid range
        confidence_value = max(0.0, min(1.0, confidence_value))

        # Build signals dict
        signals = {
            "rows": row_count,
            "hops": hop_count,
            "shape_validated": shape_validated,
        }
        if freshness_days is not None:
            signals["freshness_days"] = freshness_days

        return {
            "value": round(confidence_value, 2),  # Round to 2 decimals
            "basis": basis,
            "signals": signals,
            "degradation": degradation
        }

    @staticmethod
    def high_confidence_threshold() -> float:
        """Return threshold for 'high confidence' results (>= 0.75)"""
        return 0.75

    @staticmethod
    def low_confidence_threshold() -> float:
        """Return threshold for 'low confidence' results (< 0.5)"""
        return 0.5
