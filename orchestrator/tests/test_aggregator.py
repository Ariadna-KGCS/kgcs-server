"""Test response aggregation for Master Orchestrator"""

import pytest
from orchestrator.aggregator import ResponseAggregator


class TestProvenanceMerging:
    """Test provenance merging"""

    def test_merge_single_source(self):
        """Test merging provenance from single source"""
        responses = [
            {
                "status": "ok",
                "provenance": [
                    {"source": "NVD", "ids": ["CVE-2021-44228"], "timestamp": "2026-01-01T00:00:00Z"}
                ]
            }
        ]

        provenance = ResponseAggregator.merge_provenance(responses)

        assert len(provenance) == 1
        assert provenance[0]["source"] == "NVD"
        assert "CVE-2021-44228" in provenance[0]["ids"]

    def test_merge_multiple_sources(self):
        """Test merging provenance from multiple sources"""
        responses = [
            {
                "status": "ok",
                "provenance": [
                    {"source": "NVD", "ids": ["CVE-2021-44228"], "timestamp": "2026-01-01T00:00:00Z"}
                ]
            },
            {
                "status": "ok",
                "provenance": [
                    {"source": "MITRE CAPEC", "ids": ["CAPEC-88"], "timestamp": "2026-01-01T00:00:00Z"}
                ]
            }
        ]

        provenance = ResponseAggregator.merge_provenance(responses)

        assert len(provenance) == 2
        sources = {p["source"] for p in provenance}
        assert sources == {"NVD", "MITRE CAPEC"}

    def test_merge_deduplicates_by_source_and_id(self):
        """Test that merging deduplicates by source and ID"""
        responses = [
            {
                "status": "ok",
                "provenance": [
                    {"source": "NVD", "ids": ["CVE-2021-44228", "CVE-2021-12345"], "timestamp": "2026-01-01T00:00:00Z"}
                ]
            },
            {
                "status": "ok",
                "provenance": [
                    {"source": "NVD", "ids": ["CVE-2021-44228"], "timestamp": "2026-01-01T00:00:00Z"}
                ]
            }
        ]

        provenance = ResponseAggregator.merge_provenance(responses)

        assert len(provenance) == 1
        assert len(provenance[0]["ids"]) == 2  # Deduplicated

    def test_merge_skips_error_responses(self):
        """Test that error responses are skipped"""
        responses = [
            {
                "status": "error",
                "provenance": [{"source": "NVD", "ids": ["CVE-2021"], "timestamp": "2026-01-01T00:00:00Z"}]
            },
            {
                "status": "ok",
                "provenance": [{"source": "MITRE", "ids": ["T1059"], "timestamp": "2026-01-01T00:00:00Z"}]
            }
        ]

        provenance = ResponseAggregator.merge_provenance(responses)

        assert len(provenance) == 1
        assert provenance[0]["source"] == "MITRE"


class TestConfidenceMerging:
    """Test confidence merging"""

    def test_merge_single_confidence(self):
        """Test merging single confidence value"""
        responses = [
            {
                "status": "ok",
                "confidence": {
                    "value": 0.95,
                    "basis": "COMPLETE_CHAIN",
                    "signals": {"rows": 5}
                }
            }
        ]

        confidence = ResponseAggregator.merge_confidence(responses)

        assert confidence["value"] == 0.95
        assert "MULTI" not in confidence["basis"]

    def test_merge_multiple_confidences_average(self):
        """Test averaging multiple confidence values"""
        responses = [
            {
                "status": "ok",
                "confidence": {
                    "value": 1.0,
                    "basis": "COMPLETE_CHAIN",
                    "signals": {"rows": 5}
                }
            },
            {
                "status": "ok",
                "confidence": {
                    "value": 0.8,
                    "basis": "PARTIAL_CHAIN",
                    "signals": {"rows": 3}
                }
            }
        ]

        confidence = ResponseAggregator.merge_confidence(responses)

        assert confidence["value"] == 0.9  # Average of 1.0 and 0.8
        assert "MULTI" in confidence["basis"]

    def test_merge_with_no_results(self):
        """Test merging when no results returned"""
        responses = [
            {
                "status": "empty",
                "confidence": {
                    "value": 0.0,
                    "basis": "NO_MATCH"
                }
            }
        ]

        confidence = ResponseAggregator.merge_confidence(responses)

        assert confidence["value"] == 0.0
        assert confidence["basis"] == "NO_MATCH"

    def test_clamp_confidence_to_bounds(self):
        """Test that confidence is clamped to [0.0, 1.0]"""
        responses = [
            {
                "status": "ok",
                "confidence": {"value": 1.5, "basis": "TEST", "signals": {}}
            }
        ]

        confidence = ResponseAggregator.merge_confidence(responses)

        assert 0.0 <= confidence["value"] <= 1.0


class TestResponseAggregation:
    """Test full response aggregation"""

    def test_aggregate_multi_agent_ok_status(self):
        """Test that aggregated response has ok status when all agents succeed"""
        responses = [
            {
                "version": "1.0",
                "correlation_id": "test-123",
                "status": "ok",
                "data": {"vulnerabilities": []},
                "provenance": [{"source": "NVD", "ids": [], "timestamp": "2026-01-01T00:00:00Z"}],
                "confidence": {"value": 1.0, "basis": "TEST", "signals": {}},
                "errors": []
            },
            {
                "version": "1.0",
                "correlation_id": "test-123",
                "status": "ok",
                "data": {"techniques": []},
                "provenance": [{"source": "MITRE ATT&CK", "ids": [], "timestamp": "2026-01-01T00:00:00Z"}],
                "confidence": {"value": 0.9, "basis": "TEST", "signals": {}},
                "errors": []
            }
        ]

        aggregated = ResponseAggregator.aggregate_multi_agent_responses(responses)

        assert aggregated["status"] == "ok"
        assert aggregated["correlation_id"] == "test-123"
        assert aggregated["version"] == "1.0"

    def test_aggregate_has_all_envelope_fields(self):
        """Test that aggregated response has all envelope fields"""
        responses = [
            {
                "version": "1.0",
                "correlation_id": "test-123",
                "status": "ok",
                "data": {},
                "provenance": [],
                "confidence": {"value": 0.0, "basis": "NO_MATCH", "signals": {}, "degradation": []},
                "errors": []
            }
        ]

        aggregated = ResponseAggregator.aggregate_multi_agent_responses(responses)

        required_fields = ["version", "correlation_id", "status", "data", "provenance", "confidence", "errors"]
        for field in required_fields:
            assert field in aggregated
