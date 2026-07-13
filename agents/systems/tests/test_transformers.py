"""Test data transformation from Neo4j records to systems-response.json

Verifies that:
- CPE results are correctly transformed with platforms
- CVE results are correctly transformed without platforms
- Deduplication works for cveId, scoreId, and matchCriteriaId
- Null/missing weakness fields are handled correctly
- Provenance extraction works with timestamp parsing
"""

import pytest
from datetime import datetime
from agents.systems.transformers import SystemsTransformer


class TestTransformerCPEResults:
    """Test transform_cpe_results() method"""

    def test_empty_records(self):
        """Test that empty records return empty vulnerabilities"""
        result = SystemsTransformer.transform_cpe_results([])
        assert result == {"vulnerabilities": []}

    def test_single_cve_single_platform(self):
        """Test transformation of single CVE with single platform"""
        records = [
            {
                "v": {
                    "cveId": "CVE-2021-44228",
                    "published": "2021-12-10",
                    "lastModified": "2024-01-01",
                    "source": "NVD"
                },
                "w": {
                    "cweId": "CWE-79",
                    "abstraction": "Base",
                    "name": "Improper Neutralization of Input During Web Page Generation"
                },
                "scores": [
                    {
                        "scoreId": "CVE-2021-44228-v3.1",
                        "version": "3.1",
                        "baseScore": 9.8
                    }
                ],
                "pc": {
                    "matchCriteriaId": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                    "cpeUri": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                    "configStatus": "VULNERABLE"
                },
                "p": {
                    "cpeUri": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                    "cpeNameId": "cpe-name-001",
                    "vendor": "apache",
                    "product": "log4j",
                    "version": "2.14.1"
                },
                "applicabilityRows": [
                    {
                        "vc": {
                            "vcId": "CVE-2021-44228::CFG::1",
                            "operator": "OR",
                            "negate": False
                        },
                        "vcn": {
                            "vcnId": "CVE-2021-44228::CFG::1::NODE::1",
                            "operator": "OR",
                            "negate": False
                        },
                        "mc": {
                            "vulnerable": True,
                            "matchIndex": 1
                        },
                        "pc_match": {
                            "matchCriteriaId": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                            "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                            "configStatus": "VULNERABLE"
                        },
                        "p_match": {
                            "cpeUri": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                            "cpeNameId": "cpe-name-001"
                        }
                    }
                ]
            }
        ]
        result = SystemsTransformer.transform_cpe_results(records)
        assert len(result["vulnerabilities"]) == 1
        vuln = result["vulnerabilities"][0]
        assert vuln["cveId"] == "CVE-2021-44228"
        assert vuln["weakness"]["cweId"] == "CWE-79"
        assert len(vuln["scores"]) == 1
        assert vuln["scores"][0]["baseScore"] == 9.8
        assert len(vuln["platforms"]) == 1
        assert vuln["platforms"][0]["matchCriteriaId"] == "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
        assert len(vuln["resolvedPlatforms"]) == 1
        assert vuln["resolvedPlatforms"][0]["cpeUri"] == "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
        assert len(vuln["applicability"]["configurations"]) == 1
        criterion = vuln["applicability"]["configurations"][0]["nodes"][0]["criteria"][0]
        assert criterion["matchCriteriaId"] == "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
        assert criterion["resolvedPlatforms"][0]["cpeUri"] == "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"

    def test_deduplication_multiple_scores(self):
        """Test deduplication of multiple CVSS versions for same CVE"""
        records = [
            {
                "v": {"cveId": "CVE-2021-44228", "published": "2021-12-10", "lastModified": "2024-01-01"},
                "w": None,
                "scores": [{"scoreId": "CVE-2021-44228-v3.1", "version": "3.1", "baseScore": 9.8}],
                "pc": None,
                "p": None
            },
            {
                "v": {"cveId": "CVE-2021-44228", "published": "2021-12-10", "lastModified": "2024-01-01"},
                "w": None,
                "scores": [{"scoreId": "CVE-2021-44228-v3.1", "version": "3.1", "baseScore": 9.8}],  # Duplicate
                "pc": None,
                "p": None
            },
            {
                "v": {"cveId": "CVE-2021-44228", "published": "2021-12-10", "lastModified": "2024-01-01"},
                "w": None,
                "scores": [{"scoreId": "CVE-2021-44228-v2.0", "version": "2.0", "baseScore": 9.3}],
                "pc": None,
                "p": None
            }
        ]
        result = SystemsTransformer.transform_cpe_results(records)
        assert len(result["vulnerabilities"]) == 1
        vuln = result["vulnerabilities"][0]
        # Should have 2 unique scores (by scoreId), not 3
        assert len(vuln["scores"]) == 2
        score_ids = [s["scoreId"] for s in vuln["scores"]]
        assert "CVE-2021-44228-v3.1" in score_ids
        assert "CVE-2021-44228-v2.0" in score_ids

    def test_deduplication_multiple_platforms(self):
        """Test deduplication of multiple platforms for same CVE"""
        records = [
            {
                "v": {"cveId": "CVE-2021-44228", "published": "2021-12-10", "lastModified": "2024-01-01"},
                "w": None,
                "scores": [],
                "pc": {
                    "matchCriteriaId": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                    "cpeUri": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                    "configStatus": "VULNERABLE"
                },
                "p": None
            },
            {
                "v": {"cveId": "CVE-2021-44228", "published": "2021-12-10", "lastModified": "2024-01-01"},
                "w": None,
                "scores": [],
                "pc": {
                    "matchCriteriaId": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",  # Duplicate
                    "cpeUri": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                    "configStatus": "VULNERABLE"
                },
                "p": None
            },
            {
                "v": {"cveId": "CVE-2021-44228", "published": "2021-12-10", "lastModified": "2024-01-01"},
                "w": None,
                "scores": [],
                "pc": {
                    "matchCriteriaId": "cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*",
                    "cpeUri": "cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*",
                    "configStatus": "UNKNOWN"
                },
                "p": None
            }
        ]
        result = SystemsTransformer.transform_cpe_results(records)
        assert len(result["vulnerabilities"]) == 1
        vuln = result["vulnerabilities"][0]
        # Should have 2 unique platforms (by matchCriteriaId), not 3
        assert len(vuln["platforms"]) == 2

    def test_null_weakness_handling(self):
        """Test that missing weakness is omitted from the serialized output"""
        records = [
            {
                "v": {"cveId": "CVE-2021-44228", "published": "2021-12-10", "lastModified": "2024-01-01"},
                "w": None,  # No weakness
                "scores": [],
                "pc": None,
                "p": None
            }
        ]
        result = SystemsTransformer.transform_cpe_results(records)
        vuln = result["vulnerabilities"][0]
        assert "weakness" not in vuln

    def test_applicability_grouping_deduplicates_platforms(self):
        """Test grouped applicability output is deduplicated across repeated rows."""
        records = [
            {
                "v": {"cveId": "CVE-2023-1380", "published": "2023-01-01", "lastModified": "2024-01-01"},
                "w": None,
                "scores": [],
                "pc": None,
                "p": None,
                "applicabilityRows": [{
                    "vc": {"vcId": "CVE-2023-1380::CFG::1", "operator": "AND", "negate": False},
                    "vcn": {"vcnId": "CVE-2023-1380::CFG::1::NODE::1", "operator": "OR", "negate": False},
                    "mc": {"vulnerable": True, "matchIndex": 1},
                    "pc_match": {
                        "matchCriteriaId": "criteria-001",
                        "criteria": "cpe:2.3:o:tp-link:archer_ax21_firmware:*:*:*:*:*:*:*:*",
                        "configStatus": "VULNERABLE"
                    },
                    "p_match": {"cpeUri": "cpe:2.3:o:tp-link:archer_ax21_firmware:1.1.4:*:*:*:*:*:*:*", "cpeNameId": "cpe-1"},
                }],
            },
            {
                "v": {"cveId": "CVE-2023-1380", "published": "2023-01-01", "lastModified": "2024-01-01"},
                "w": None,
                "scores": [],
                "pc": None,
                "p": None,
                "applicabilityRows": [{
                    "vc": {"vcId": "CVE-2023-1380::CFG::1", "operator": "AND", "negate": False},
                    "vcn": {"vcnId": "CVE-2023-1380::CFG::1::NODE::1", "operator": "OR", "negate": False},
                    "mc": {"vulnerable": True, "matchIndex": 1},
                    "pc_match": {
                        "matchCriteriaId": "criteria-001",
                        "criteria": "cpe:2.3:o:tp-link:archer_ax21_firmware:*:*:*:*:*:*:*:*",
                        "configStatus": "VULNERABLE"
                    },
                    "p_match": {"cpeUri": "cpe:2.3:o:tp-link:archer_ax21_firmware:1.1.4:*:*:*:*:*:*:*", "cpeNameId": "cpe-1"},
                }],
            },
        ]
        result = SystemsTransformer.transform_cve_results(records)
        vuln = result["vulnerabilities"][0]
        assert len(vuln["resolvedPlatforms"]) == 1
        assert len(vuln["applicability"]["configurations"]) == 1
        assert len(vuln["applicability"]["configurations"][0]["nodes"]) == 1
        assert len(vuln["applicability"]["configurations"][0]["nodes"][0]["criteria"]) == 1

    def test_missing_cve_id_skipped(self):
        """Test that records without cveId are skipped"""
        records = [
            {
                "v": {"cveId": "CVE-2021-44228", "published": "2021-12-10", "lastModified": "2024-01-01"},
                "w": None,
                "scores": [],
                "pc": None,
                "p": None
            },
            {
                "v": {"published": "2021-12-10"},  # Missing cveId
                "w": None,
                "scores": [],
                "pc": None,
                "p": None
            }
        ]
        result = SystemsTransformer.transform_cpe_results(records)
        assert len(result["vulnerabilities"]) == 1


class TestTransformerCVEResults:
    """Test transform_cve_results() method"""

    def test_empty_records(self):
        """Test that empty records return empty vulnerabilities"""
        result = SystemsTransformer.transform_cve_results([])
        assert result == {"vulnerabilities": []}

    def test_single_cve_no_platforms_field(self):
        """Test that CVE results do NOT include compatibility platforms field"""
        records = [
            {
                "v": {
                    "cveId": "CVE-2021-44228",
                    "published": "2021-12-10",
                    "lastModified": "2024-01-01",
                    "source": "NVD"
                },
                "w": {
                    "cweId": "CWE-79",
                    "abstraction": "Base",
                    "name": "Improper Neutralization"
                },
                "scores": [
                    {
                        "scoreId": "CVE-2021-44228-v3.1",
                        "version": "3.1",
                        "baseScore": 9.8
                    }
                ],
                "applicabilityRows": []
            }
        ]
        result = SystemsTransformer.transform_cve_results(records)
        assert len(result["vulnerabilities"]) == 1
        vuln = result["vulnerabilities"][0]
        assert "cveId" in vuln
        assert "weakness" in vuln
        assert "scores" in vuln
        assert "platforms" not in vuln  # Should NOT be present

    def test_multiple_cves(self):
        """Test transformation of multiple distinct CVEs"""
        records = [
            {
                "v": {"cveId": "CVE-2021-44228", "published": "2021-12-10", "lastModified": "2024-01-01"},
                "w": {"cweId": "CWE-79", "abstraction": "Base", "name": "XSS"},
                "scores": [{"scoreId": "CVE-2021-44228-v3.1", "version": "3.1", "baseScore": 9.8}]
            },
            {
                "v": {"cveId": "CVE-2021-3129", "published": "2021-01-11", "lastModified": "2024-01-02"},
                "w": {"cweId": "CWE-94", "abstraction": "Base", "name": "Improper Code Generation"},
                "scores": [{"scoreId": "CVE-2021-3129-v3.1", "version": "3.1", "baseScore": 9.8}]
            }
        ]
        result = SystemsTransformer.transform_cve_results(records)
        assert len(result["vulnerabilities"]) == 2
        cve_ids = [v["cveId"] for v in result["vulnerabilities"]]
        assert "CVE-2021-44228" in cve_ids
        assert "CVE-2021-3129" in cve_ids


class TestProvenance:
    """Test extract_provenance() method"""

    def test_empty_records(self):
        """Test that empty records return empty provenance"""
        result = SystemsTransformer.extract_provenance([])
        assert result == []

    def test_single_cve_provenance(self):
        """Test provenance extraction for single CVE"""
        records = [
            {
                "v": {
                    "cveId": "CVE-2021-44228",
                    "lastModified": "2024-01-01T00:00:00Z"
                },
                "w": None,
                "s": None
            }
        ]
        result = SystemsTransformer.extract_provenance(records)
        assert len(result) == 1
        provenance = result[0]
        assert provenance["source"] == "NVD"
        assert "CVE-2021-44228" in provenance["ids"]
        assert provenance["timestamp"] is not None

    def test_multiple_cves_deduplication(self):
        """Test that multiple CVEs are deduplicated in provenance"""
        records = [
            {"v": {"cveId": "CVE-2021-44228", "lastModified": "2024-01-01T00:00:00Z"}, "w": None, "s": None},
            {"v": {"cveId": "CVE-2021-44228", "lastModified": "2024-01-01T00:00:00Z"}, "w": None, "s": None},  # Duplicate
            {"v": {"cveId": "CVE-2021-3129", "lastModified": "2024-01-02T00:00:00Z"}, "w": None, "s": None}
        ]
        result = SystemsTransformer.extract_provenance(records)
        assert len(result) == 1
        assert len(result[0]["ids"]) == 2
        assert set(result[0]["ids"]) == {"CVE-2021-3129", "CVE-2021-44228"}  # Should be sorted

    def test_provenance_timestamp_parsing(self):
        """Test that ISO 8601 timestamps are parsed correctly"""
        records = [
            {
                "v": {
                    "cveId": "CVE-2021-44228",
                    "lastModified": "2024-01-15T12:34:56Z"
                },
                "w": None,
                "s": None
            }
        ]
        result = SystemsTransformer.extract_provenance(records)
        provenance = result[0]
        assert provenance["timestamp"] is not None
        # Should be parseable as ISO 8601
        parsed = datetime.fromisoformat(provenance["timestamp"].replace("Z", "+00:00"))
        assert parsed.year == 2024
        assert parsed.month == 1
        assert parsed.day == 15

    def test_provenance_no_cveids(self):
        """Test that records without cveIds return empty provenance"""
        records = [
            {"v": {"weakness": "CWE-79"}, "w": None, "s": None}  # No cveId
        ]
        result = SystemsTransformer.extract_provenance(records)
        assert result == []

    def test_provenance_invalid_timestamps_ignored(self):
        """Test that invalid timestamps are gracefully skipped"""
        records = [
            {
                "v": {
                    "cveId": "CVE-2021-44228",
                    "lastModified": "INVALID_DATE"
                },
                "w": None,
                "s": None
            }
        ]
        result = SystemsTransformer.extract_provenance(records)
        assert len(result) == 1
        assert result[0]["source"] == "NVD"
        assert "CVE-2021-44228" in result[0]["ids"]
        # Timestamp should be None if no valid timestamps found
        assert result[0]["timestamp"] is None

    def test_provenance_ids_sorted(self):
        """Test that CVE IDs in provenance are sorted"""
        records = [
            {"v": {"cveId": "CVE-2021-3129", "lastModified": "2024-01-01T00:00:00Z"}, "w": None, "s": None},
            {"v": {"cveId": "CVE-2021-44228", "lastModified": "2024-01-01T00:00:00Z"}, "w": None, "s": None},
            {"v": {"cveId": "CVE-2020-1234", "lastModified": "2024-01-01T00:00:00Z"}, "w": None, "s": None}
        ]
        result = SystemsTransformer.extract_provenance(records)
        ids = result[0]["ids"]
        assert ids == sorted(ids)
