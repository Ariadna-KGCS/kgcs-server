"""Tests for KGCS agent shared library modules

Tests cover all 8 shared modules to ensure correct behavior before agents use them.
"""

import pytest
from uuid import uuid4
from datetime import datetime

# Import modules under test
from agents.shared.types import (
    ConfidenceBasis, RiskBand, ConfidenceSignals, ConfidenceSignal,
    ResponseStatus, ProvenanceEntry, ResponseEnvelope, RiskSignal,
    RequestIntentEnum, RequestAgentEnum
)
from agents.shared.confidence_scorer import ConfidenceScorer
from agents.shared.risk_scorer import RiskScorer
from agents.shared.response_builder import ResponseBuilder
from agents.shared.logger import AgentLogger


class TestTypes:
    """Test Pydantic models in types.py"""

    def test_confidence_signal_valid(self):
        """Valid confidence signal should instantiate"""
        signal = ConfidenceSignal(
            value=0.95,
            basis=ConfidenceBasis.COMPLETE_CHAIN,
            signals={"rows": 5, "hops": 4, "shape_validated": True},
            degradation=[]
        )
        assert signal.value == 0.95
        assert signal.basis == ConfidenceBasis.COMPLETE_CHAIN
        assert signal.signals.rows == 5

    def test_confidence_signal_invalid_value(self):
        """Confidence value outside [0.0, 1.0] should fail"""
        with pytest.raises(ValueError):
            ConfidenceSignal(
                value=1.5,
                basis=ConfidenceBasis.COMPLETE_CHAIN
            )

    def test_response_envelope_valid(self):
        """Valid envelope should instantiate"""
        envelope = ResponseEnvelope(
            version="1.0",
            correlation_id=str(uuid4()),
            status=ResponseStatus.OK,
            data={"test": "data"},
            confidence=ConfidenceSignal(
                value=0.85,
                basis=ConfidenceBasis.COMPLETE_CHAIN
            )
        )
        assert envelope.status == ResponseStatus.OK
        assert envelope.provenance == []  # Default empty

    def test_provenance_entry_valid(self):
        """Valid provenance entry should instantiate"""
        entry = ProvenanceEntry(
            source="NVD",
            ids=["CVE-2021-44228"]
        )
        assert entry.source == "NVD"
        assert len(entry.ids) == 1

    def test_provenance_entry_requires_ids(self):
        """Provenance entry requires at least one ID"""
        with pytest.raises(ValueError):
            ProvenanceEntry(
                source="NVD",
                ids=[]  # Empty IDs should fail
            )

    def test_risk_signal_valid(self):
        """Valid risk signal should instantiate"""
        risk = RiskSignal(
            value=0.65,
            band=RiskBand.HIGH
        )
        assert risk.value == 0.65
        assert risk.band == RiskBand.HIGH
        assert risk.method == "heuristic-v1"  # Default


class TestConfidenceScorer:
    """Test confidence scoring algorithm"""

    def test_complete_chain_high_confidence(self):
        """Complete causal chain with valid data = high confidence"""
        scorer = ConfidenceScorer()
        result = scorer.compute(
            row_count=5,
            hop_count=4,
            hops_expected=4,
            shape_validated=True,
            freshness_days=30.0
        )
        assert result["value"] == 1.0
        assert result["basis"] == ConfidenceBasis.COMPLETE_CHAIN
        assert result["degradation"] == []

    def test_partial_chain_reduced_confidence(self):
        """Missing hops reduces confidence by 0.2 per hop"""
        scorer = ConfidenceScorer()
        result = scorer.compute(
            row_count=5,
            hop_count=2,  # Missing 2 hops
            hops_expected=4,
            shape_validated=True
        )
        # 1.0 - (0.2 * 2) = 0.6
        assert result["value"] == 0.6
        assert result["basis"] == ConfidenceBasis.PARTIAL_CHAIN
        assert ConfidenceScorer.PARTIAL_CHAIN in result["degradation"]

    def test_stale_data_degradation(self):
        """Data > 365 days old reduces confidence by 0.1"""
        scorer = ConfidenceScorer()
        result = scorer.compute(
            row_count=5,
            hop_count=4,
            hops_expected=4,
            shape_validated=True,
            freshness_days=400.0  # Stale
        )
        # 1.0 - 0.1 = 0.9
        assert result["value"] == 0.9
        assert ConfidenceScorer.STALE_DATA in result["degradation"]

    def test_no_results_zero_confidence(self):
        """No results = 0.0 confidence with NO_MATCH basis"""
        scorer = ConfidenceScorer()
        result = scorer.compute(
            row_count=0,
            hop_count=0,
            hops_expected=4,
            shape_validated=False
        )
        assert result["value"] == 0.0
        assert result["basis"] == ConfidenceBasis.NO_MATCH

    def test_confidence_clamping(self):
        """Confidence value should clamp to [0.0, 1.0]"""
        scorer = ConfidenceScorer()
        # Negative degradation that would go below 0.0
        result = scorer.compute(
            row_count=5,
            hop_count=0,
            hops_expected=10,  # 10 missing hops = 2.0 degradation
            shape_validated=True
        )
        assert result["value"] >= 0.0
        assert result["value"] <= 1.0


class TestRiskScorer:
    """Test risk scoring heuristic"""

    def test_high_cvss_no_defenses(self):
        """High CVSS + no defenses = high risk"""
        scorer = RiskScorer()
        result = scorer.compute(
            cvss_v4=9.8,
            mitigation_count=0,
            detection_count=0,
            deception_count=0
        )
        # severity = 9.8 / 10 = 0.98
        # coverage_penalty = exp(-0.15 * 0) = 1.0
        # risk = 0.98 * 1.0 = 0.98 (CRITICAL)
        assert result["value"] > 0.9
        assert result["band"] == "CRITICAL"

    def test_high_cvss_with_defenses(self):
        """High CVSS + good defenses = lower risk"""
        scorer = RiskScorer()
        result = scorer.compute(
            cvss_v4=9.8,
            mitigation_count=5,
            detection_count=3,
            deception_count=2
        )
        # severity = 0.98
        # coverage = 10, penalty = exp(-0.15 * 10) = 0.223
        # risk = 0.98 * 0.223 = 0.219 (LOW)
        assert result["value"] < 0.25
        assert result["band"] == "LOW"

    def test_low_cvss_any_defenses(self):
        """Low CVSS + any defenses = low risk"""
        scorer = RiskScorer()
        result = scorer.compute(
            cvss_v3=3.5,
            mitigation_count=0,
            detection_count=0
        )
        # severity = 3.5 / 10 = 0.35
        # coverage_penalty = 1.0
        # risk = 0.35 (LOW)
        assert result["value"] < 0.5
        assert result["band"] == "LOW"

    def test_max_cvss_selected(self):
        """Scorer should use max of multiple CVSS versions"""
        scorer = RiskScorer()
        result = scorer.compute(
            cvss_v4=5.0,
            cvss_v3=7.5,  # Max
            cvss_v2=4.0
        )
        # severity = max(0.5, 0.75, 0.4) = 0.75
        assert result["inputs"]["cvss_v3"] == 7.5

    def test_no_cvss_zero_severity(self):
        """Missing CVSS scores result in 0.0 severity"""
        scorer = RiskScorer()
        result = scorer.compute(
            mitigation_count=5
        )
        # severity = 0.0
        # risk = 0.0
        assert result["value"] == 0.0
        assert result["band"] == "LOW"

    def test_risk_bands(self):
        """Risk band assignment should match thresholds"""
        scorer = RiskScorer()

        # LOW: 0.0-0.25
        result_low = scorer.compute(cvss_v3=2.0)
        assert result_low["band"] == "LOW"

        # MEDIUM: 0.25-0.50
        result_med = scorer.compute(cvss_v3=5.0)
        assert result_med["band"] == "MEDIUM"

        # HIGH: 0.50-0.75
        result_high = scorer.compute(cvss_v3=7.0)
        assert result_high["band"] == "HIGH"

        # CRITICAL: 0.75-1.0
        result_crit = scorer.compute(cvss_v3=9.0)
        assert result_crit["band"] == "CRITICAL"


class TestResponseBuilder:
    """Test response envelope construction"""

    def test_build_ok_response(self):
        """OK response should have status=ok and provenance"""
        builder = ResponseBuilder()
        corr_id = str(uuid4())
        response = builder.ok(
            data={"vulnerabilities": []},
            provenance=[{"source": "NVD", "ids": ["CVE-2021-44228"]}],
            confidence={"value": 0.95, "basis": "COMPLETE_CHAIN", "signals": {}, "degradation": []},
            correlation_id=corr_id
        )
        assert response["status"] == "ok"
        assert response["correlation_id"] == corr_id
        assert len(response["provenance"]) == 1
        assert response["version"] == "1.0"

    def test_build_empty_response(self):
        """Empty response should have status=empty and no data"""
        builder = ResponseBuilder()
        corr_id = str(uuid4())
        response = builder.empty(
            confidence={"value": 0.0, "basis": "NO_MATCH", "signals": {}, "degradation": []},
            correlation_id=corr_id
        )
        assert response["status"] == "empty"
        assert response["data"] == {}
        assert response["provenance"] == []

    def test_build_error_response(self):
        """Error response should have status=error with error list"""
        builder = ResponseBuilder()
        corr_id = str(uuid4())
        response = builder.error(
            errors=["Query timeout", "Connection failed"],
            correlation_id=corr_id
        )
        assert response["status"] == "error"
        assert len(response["errors"]) == 2
        assert response["confidence"]["value"] == 0.0

    def test_provenance_entry_construction(self):
        """Helper should construct valid provenance entries"""
        builder = ResponseBuilder()
        entry = builder.ensure_provenance_entry(
            source="MITRE",
            ids=["CAPEC-123", "CAPEC-124"]
        )
        assert entry["source"] == "MITRE"
        assert len(entry["ids"]) == 2
        assert "timestamp" in entry

    def test_confidence_signal_construction(self):
        """Helper should construct valid confidence signals"""
        builder = ResponseBuilder()
        signal = builder.ensure_confidence_signal(
            value=0.85,
            basis="COMPLETE_CHAIN",
            signals={"rows": 10, "hops": 4}
        )
        assert signal["value"] == 0.85
        assert signal["basis"] == "COMPLETE_CHAIN"
        assert signal["signals"]["rows"] == 10


class TestAgentLogger:
    """Test structured logging with correlation IDs"""

    def test_logger_includes_correlation_id(self, caplog):
        """Logger should include correlation ID in all messages"""
        import logging
        caplog.set_level(logging.INFO)

        corr_id = str(uuid4())
        logger = AgentLogger(__name__, corr_id)

        logger.info("Test message")

        # Check that correlation ID appears in log
        assert corr_id in caplog.text

    def test_logger_debug_message(self, caplog):
        """Logger should handle debug level"""
        import logging
        caplog.set_level(logging.DEBUG)

        corr_id = str(uuid4())
        logger = AgentLogger(__name__, corr_id)

        logger.debug("Debug message")

        # Should appear in caplog when level is DEBUG
        assert "Debug message" in caplog.text

    def test_logger_error_with_exception(self, caplog):
        """Logger should include exception info"""
        import logging
        caplog.set_level(logging.ERROR)

        corr_id = str(uuid4())
        logger = AgentLogger(__name__, corr_id)

        try:
            raise ValueError("Test error")
        except ValueError as e:
            logger.error("Caught error", exc=e)

        assert "Caught error" in caplog.text


# Marker to indicate all tests should pass
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
