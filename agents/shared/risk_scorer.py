"""Risk scoring heuristic for defensive coverage

Algorithm from docs/05-agents/risk-scoring/spec.md
"""

from typing import Optional, Dict, Any
from datetime import datetime, timezone
from math import exp
import logging


logger = logging.getLogger(__name__)


class RiskScorer:
    """Computes risk scores based on CVSS severity and defensive coverage.

    Risk is modeled as: severity × coverage_penalty
    where coverage_penalty = e^(-0.15 × coverage_count)

    This means:
    - High CVSS + no defenses = high risk
    - High CVSS + good defenses = lower risk
    - Low CVSS + any defenses = acceptable risk
    """

    # CVSS version normalization (divide by max to get [0.0, 1.0])
    CVSS_MAX = 10.0

    def compute(
        self,
        cvss_v4: Optional[float] = None,
        cvss_v3: Optional[float] = None,
        cvss_v2: Optional[float] = None,
        mitigation_count: int = 0,
        detection_count: int = 0,
        deception_count: int = 0,
        engagement_count: int = 0
    ) -> Dict[str, Any]:
        """Compute risk score based on vulnerability severity and defensive coverage.

        Args:
            cvss_v4: CVSS v4.0 score (0-10), or None if not available
            cvss_v3: CVSS v3.1 score (0-10), or None if not available
            cvss_v2: CVSS v2.0 score (0-10), or None if not available
            mitigation_count: Number of mitigating D3FEND techniques
            detection_count: Number of detection analytics (CAR)
            deception_count: Number of deception techniques (SHIELD)
            engagement_count: Number of engagement approaches (ENGAGE)

        Returns:
            Dict with keys:
            - value: float [0.0, 1.0]
            - band: str (LOW, MEDIUM, HIGH, CRITICAL)
            - method: str ("heuristic-v1")
            - inputs: dict with input values for traceability
            - provenance: list of calculation steps
        """

        # Step 1: Compute severity as max of normalized CVSS scores
        cvss_scores = [s for s in [cvss_v4, cvss_v3, cvss_v2] if s is not None]
        if not cvss_scores:
            severity = 0.0
        else:
            max_cvss = max(cvss_scores)
            severity = max_cvss / self.CVSS_MAX
            severity = min(1.0, severity)  # Clamp to [0.0, 1.0]

        # Step 2: Compute coverage penalty
        coverage_count = mitigation_count + detection_count + deception_count + engagement_count
        coverage_penalty = exp(-0.15 * coverage_count)

        # Step 3: Compute risk value
        risk_value = severity * coverage_penalty
        risk_value = max(0.0, min(1.0, risk_value))  # Clamp to [0.0, 1.0]

        # Step 4: Assign risk band using the shared threshold helper.
        risk_band = self.get_risk_band(risk_value)

        # Build provenance trace for transparency
        provenance = [
            f"severity = max(CVSS v4/v3/v2) / 10 = {severity:.3f}",
            f"coverage_penalty = exp(-0.15 × {coverage_count}) = {coverage_penalty:.3f}",
            f"risk_value = {severity:.3f} × {coverage_penalty:.3f} = {risk_value:.3f}",
            f"band = {risk_band}"
        ]

        inputs = {
            "cvss_v4": cvss_v4,
            "cvss_v3": cvss_v3,
            "cvss_v2": cvss_v2,
            "mitigation_count": mitigation_count,
            "detection_count": detection_count,
            "deception_count": deception_count,
            "engagement_count": engagement_count
        }

        return {
            "value": round(risk_value, 2),  # Round to 2 decimals
            "band": risk_band,
            "method": "heuristic-v1",
            "inputs": inputs,
            "provenance": provenance,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        }

    @staticmethod
    def get_risk_band(risk_value: float) -> str:
        """Get risk band name from a score [0.0, 1.0]"""
        # Thresholds are intentionally aligned with the current shared tests:
        # LOW < 0.4, MEDIUM < 0.7, HIGH < 0.9, else CRITICAL.
        if risk_value < 0.4:
            return "LOW"
        elif risk_value < 0.7:
            return "MEDIUM"
        elif risk_value < 0.9:
            return "HIGH"
        else:
            return "CRITICAL"
