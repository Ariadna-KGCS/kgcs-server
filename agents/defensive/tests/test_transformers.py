"""Test transformation logic for Defensive Agent

Verifies Neo4j record transformation and provenance extraction.
"""

import pytest
from agents.defensive.transformers import DefensiveTransformer


class TestCoverageResultsTransformation:
    """Test transform_coverage_results() method"""

    def test_full_coverage_all_frameworks(self):
        """Test full coverage with all 4 frameworks present"""
        records = [
            {
                "mitigations": [
                    {"d3fendId": "D3-PA", "name": "Process Analysis"},
                    {"d3fendId": "D3-NTA", "name": "Network Traffic Analysis"}
                ],
                "detections": [
                    {"analyticId": "CAR-2020-04-001", "title": "Batch File", "coverageLevel": "High"}
                ],
                "deceptions": [
                    {"techniqueId": "DTE0001", "name": "Admin User Account"}
                ],
                "engagements": [
                    {"activityId": "EAC0002", "name": "Application Diversity"}
                ]
            }
        ]

        result = DefensiveTransformer.transform_coverage_results(records)

        assert len(result["mitigations"]) == 2
        assert len(result["detections"]) == 1
        assert len(result["deceptions"]) == 1
        assert len(result["engagements"]) == 1
        assert result["summary"]["has_coverage"] is True
        assert result["summary"]["total_mitigations"] == 2

    def test_partial_coverage_some_frameworks(self):
        """Test partial coverage with only some frameworks"""
        records = [
            {
                "mitigations": [{"d3fendId": "D3-PA", "name": "Process Analysis"}],
                "detections": [],
                "deceptions": [],
                "engagements": []
            }
        ]

        result = DefensiveTransformer.transform_coverage_results(records)

        assert len(result["mitigations"]) == 1
        assert len(result["detections"]) == 0
        assert len(result["deceptions"]) == 0
        assert len(result["engagements"]) == 0
        assert result["summary"]["has_coverage"] is True

    def test_no_coverage(self):
        """Test with no coverage results"""
        records = [
            {
                "mitigations": [],
                "detections": [],
                "deceptions": [],
                "engagements": []
            }
        ]

        result = DefensiveTransformer.transform_coverage_results(records)

        assert len(result["mitigations"]) == 0
        assert len(result["detections"]) == 0
        assert len(result["deceptions"]) == 0
        assert len(result["engagements"]) == 0
        assert result["summary"]["has_coverage"] is False

    def test_empty_records(self):
        """Test with empty records list"""
        records = []

        result = DefensiveTransformer.transform_coverage_results(records)

        assert result["summary"]["total_mitigations"] == 0
        assert result["summary"]["total_detections"] == 0
        assert result["summary"]["total_deceptions"] == 0
        assert result["summary"]["total_engagements"] == 0
        assert result["summary"]["has_coverage"] is False

    def test_deduplication_by_id(self):
        """Test that IDs are deduplicated"""
        records = [
            {
                "mitigations": [
                    {"d3fendId": "D3-PA", "name": "Process Analysis"},
                    {"d3fendId": "D3-PA", "name": "Process Analysis"}  # Duplicate
                ],
                "detections": [],
                "deceptions": [],
                "engagements": []
            }
        ]

        result = DefensiveTransformer.transform_coverage_results(records)

        assert len(result["mitigations"]) == 1  # Only 1 unique
        assert result["summary"]["total_mitigations"] == 1

    def test_engagement_types_activity_id(self):
        """Test engagement with activityId type"""
        records = [
            {
                "mitigations": [],
                "detections": [],
                "deceptions": [],
                "engagements": [
                    {"activityId": "EAC0002", "name": "Application Diversity"}
                ]
            }
        ]

        result = DefensiveTransformer.transform_coverage_results(records)

        assert len(result["engagements"]) == 1
        assert result["engagements"][0]["activityId"] == "EAC0002"
        assert "approachId" not in result["engagements"][0]
        assert "goalId" not in result["engagements"][0]

    def test_engagement_types_approach_id(self):
        """Test engagement with approachId type"""
        records = [
            {
                "mitigations": [],
                "detections": [],
                "deceptions": [],
                "engagements": [
                    {"approachId": "SAP0001", "name": "Strategic Approach"}
                ]
            }
        ]

        result = DefensiveTransformer.transform_coverage_results(records)

        assert len(result["engagements"]) == 1
        assert result["engagements"][0]["approachId"] == "SAP0001"
        assert "activityId" not in result["engagements"][0]

    def test_engagement_types_goal_id(self):
        """Test engagement with goalId type"""
        records = [
            {
                "mitigations": [],
                "detections": [],
                "deceptions": [],
                "engagements": [
                    {"goalId": "SGO0001", "name": "Strategic Goal"}
                ]
            }
        ]

        result = DefensiveTransformer.transform_coverage_results(records)

        assert len(result["engagements"]) == 1
        assert result["engagements"][0]["goalId"] == "SGO0001"

    def test_null_safety_optional_fields(self):
        """Test null-safety when optional fields are None"""
        records = [
            {
                "mitigations": [None],
                "detections": [None],
                "deceptions": [None],
                "engagements": [None]
            }
        ]

        result = DefensiveTransformer.transform_coverage_results(records)

        assert len(result["mitigations"]) == 0
        assert len(result["detections"]) == 0
        assert len(result["deceptions"]) == 0
        assert len(result["engagements"]) == 0


class TestProvenanceExtraction:
    """Test extract_provenance() method"""

    def test_provenance_all_sources(self):
        """Test provenance extraction with all 4 sources"""
        records = [
            {
                "mitigations": [{"d3fendId": "D3-PA"}],
                "detections": [{"analyticId": "CAR-2020-04-001"}],
                "deceptions": [{"techniqueId": "DTE0001"}],
                "engagements": [{"activityId": "EAC0002"}]
            }
        ]

        provenance = DefensiveTransformer.extract_provenance(records)

        assert len(provenance) == 4
        sources = {p["source"] for p in provenance}
        assert sources == {"MITRE D3FEND", "MITRE CAR", "MITRE SHIELD", "MITRE ENGAGE"}

    def test_provenance_single_source(self):
        """Test provenance extraction with only one source"""
        records = [
            {
                "mitigations": [{"d3fendId": "D3-PA"}],
                "detections": [],
                "deceptions": [],
                "engagements": []
            }
        ]

        provenance = DefensiveTransformer.extract_provenance(records)

        assert len(provenance) == 1
        assert provenance[0]["source"] == "MITRE D3FEND"
        assert provenance[0]["ids"] == ["D3-PA"]

    def test_provenance_deduplication(self):
        """Test that provenance IDs are deduplicated"""
        records = [
            {
                "mitigations": [
                    {"d3fendId": "D3-PA"},
                    {"d3fendId": "D3-PA"}  # Duplicate
                ],
                "detections": [],
                "deceptions": [],
                "engagements": []
            }
        ]

        provenance = DefensiveTransformer.extract_provenance(records)

        assert len(provenance) == 1
        assert provenance[0]["ids"] == ["D3-PA"]  # Only 1 unique

    def test_provenance_sorting(self):
        """Test that provenance IDs are sorted"""
        records = [
            {
                "mitigations": [
                    {"d3fendId": "D3-ZZ"},
                    {"d3fendId": "D3-AA"},
                    {"d3fendId": "D3-MM"}
                ],
                "detections": [],
                "deceptions": [],
                "engagements": []
            }
        ]

        provenance = DefensiveTransformer.extract_provenance(records)

        assert provenance[0]["ids"] == ["D3-AA", "D3-MM", "D3-ZZ"]

    def test_provenance_timestamp_present(self):
        """Test that timestamp is present in provenance"""
        records = [
            {
                "mitigations": [{"d3fendId": "D3-PA"}],
                "detections": [],
                "deceptions": [],
                "engagements": []
            }
        ]

        provenance = DefensiveTransformer.extract_provenance(records)

        assert "timestamp" in provenance[0]
        assert provenance[0]["timestamp"].endswith("Z")  # ISO-8601 UTC format

    def test_provenance_empty_records(self):
        """Test provenance extraction with empty records"""
        records = []

        provenance = DefensiveTransformer.extract_provenance(records)

        assert len(provenance) == 0
