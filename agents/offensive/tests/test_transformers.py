"""Test OffensiveTransformer

Verifies:
- Deduplication by technique_id (attackId)
- CAPEC aggregation from AttackPattern nodes
- Tactic aggregation from Tactic nodes
- Subtechnique tracking
- Attack path construction
- Provenance extraction (MITRE CAPEC vs MITRE ATT&CK)
- Null-safety (optional Tactic/SubTechnique)
"""

import pytest
from agents.offensive.transformers import OffensiveTransformer


class TestWeaknessResultsTransformation:
    """Test transform_weakness_results() method"""

    def test_basic_transformation(self):
        """Test basic transformation of weakness query results"""
        records = [
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": {"attackId": "T1059", "name": "Command and Scripting Interpreter"},
                "tac": {"name": "Execution"},
                "st": None
            }
        ]
        result = OffensiveTransformer.transform_weakness_results(records)

        assert "techniques" in result
        assert "attack_paths" in result
        assert len(result["techniques"]) == 1
        assert result["techniques"][0]["id"] == "T1059"
        assert "Execution" in result["techniques"][0]["tactics"]

    def test_deduplication_by_technique_id(self):
        """Test that techniques are deduplicated by attackId"""
        records = [
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": {"attackId": "T1059", "name": "Command and Scripting Interpreter"},
                "tac": {"name": "Execution"},
                "st": None
            },
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-242"},
                "t": {"attackId": "T1059", "name": "Command and Scripting Interpreter"},
                "tac": {"name": "Execution"},
                "st": None
            }
        ]
        result = OffensiveTransformer.transform_weakness_results(records)

        # Should have only 1 technique (T1059) due to deduplication
        assert len(result["techniques"]) == 1
        # But 2 CAPEC IDs aggregated
        assert len(result["techniques"][0]["capec"]) == 2
        assert "CAPEC-88" in result["techniques"][0]["capec"]
        assert "CAPEC-242" in result["techniques"][0]["capec"]

    def test_capec_aggregation(self):
        """Test CAPEC ID aggregation from AttackPattern nodes"""
        records = [
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": {"attackId": "T1059", "name": "Command Interpreter"},
                "tac": None,
                "st": None
            },
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-242"},
                "t": {"attackId": "T1059", "name": "Command Interpreter"},
                "tac": None,
                "st": None
            }
        ]
        result = OffensiveTransformer.transform_weakness_results(records)

        capec_list = result["techniques"][0]["capec"]
        assert len(capec_list) == 2
        assert set(capec_list) == {"CAPEC-88", "CAPEC-242"}

    def test_tactic_aggregation(self):
        """Test tactic aggregation from Tactic nodes"""
        records = [
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": {"attackId": "T1059", "name": "Command Interpreter"},
                "tac": {"name": "Execution"},
                "st": None
            },
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": {"attackId": "T1059", "name": "Command Interpreter"},
                "tac": {"name": "Execution"},  # Duplicate should be filtered
                "st": None
            }
        ]
        result = OffensiveTransformer.transform_weakness_results(records)

        tactics = result["techniques"][0]["tactics"]
        assert len(tactics) == 1
        assert "Execution" in tactics

    def test_subtechnique_tracking(self):
        """Test subtechnique tracking from SubTechnique nodes"""
        records = [
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": {"attackId": "T1059", "name": "Command Interpreter"},
                "tac": None,
                "st": {"attackId": "T1059.001"}
            },
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": {"attackId": "T1059", "name": "Command Interpreter"},
                "tac": None,
                "st": {"attackId": "T1059.002"}
            }
        ]
        result = OffensiveTransformer.transform_weakness_results(records)

        subtechniques = result["techniques"][0]["subtechniques"]
        assert len(subtechniques) == 2
        assert set(subtechniques) == {"T1059.001", "T1059.002"}

    def test_attack_path_construction(self):
        """Test attack path construction (weakness → pattern → technique)"""
        records = [
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": {"attackId": "T1059", "name": "Command Interpreter"},
                "tac": None,
                "st": None
            }
        ]
        result = OffensiveTransformer.transform_weakness_results(records)

        paths = result["attack_paths"]
        assert len(paths) == 1
        assert paths[0]["weakness_id"] == "CWE-79"
        assert paths[0]["attack_pattern_id"] == "CAPEC-88"
        assert paths[0]["technique_id"] == "T1059"
        assert paths[0]["mapping_type"] == "direct"

    def test_inherited_attack_path_construction(self):
        """Test inherited CAPEC parent mapping is labeled explicitly."""
        records = [
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-85"},
                "mapped_ap": {"capecId": "CAPEC-580"},
                "t": {"attackId": "T1082", "name": "System Information Discovery"},
                "tac": {"name": "Discovery"},
                "st": None,
                "hierarchyDepth": 1,
            }
        ]
        result = OffensiveTransformer.transform_weakness_results(records)

        paths = result["attack_paths"]
        assert len(paths) == 1
        assert paths[0]["attack_pattern_id"] == "CAPEC-85"
        assert paths[0]["mapped_attack_pattern_id"] == "CAPEC-580"
        assert paths[0]["technique_id"] == "T1082"
        assert paths[0]["mapping_type"] == "inherited_via_parent_capec"
        assert paths[0]["hierarchy_depth"] == 1

    def test_null_safety_optional_tactic(self):
        """Test null-safety when Tactic node is None"""
        records = [
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": {"attackId": "T1059", "name": "Command Interpreter"},
                "tac": None,  # No tactic
                "st": None
            }
        ]
        result = OffensiveTransformer.transform_weakness_results(records)

        # Should not crash and should have empty tactics list
        assert len(result["techniques"]) == 1
        assert result["techniques"][0]["tactics"] == []

    def test_null_safety_optional_subtechnique(self):
        """Test null-safety when SubTechnique node is None"""
        records = [
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": {"attackId": "T1059", "name": "Command Interpreter"},
                "tac": None,
                "st": None  # No subtechnique
            }
        ]
        result = OffensiveTransformer.transform_weakness_results(records)

        # Should not crash and should have empty subtechniques list
        assert len(result["techniques"]) == 1
        assert result["techniques"][0]["subtechniques"] == []

    def test_multiple_techniques(self):
        """Test transformation with multiple techniques"""
        records = [
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": {"attackId": "T1059", "name": "Command Interpreter"},
                "tac": {"name": "Execution"},
                "st": None
            },
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-242"},
                "t": {"attackId": "T1202", "name": "Indirect Command Execution"},
                "tac": {"name": "Execution"},
                "st": None
            }
        ]
        result = OffensiveTransformer.transform_weakness_results(records)

        assert len(result["techniques"]) == 2
        technique_ids = [t["id"] for t in result["techniques"]]
        assert set(technique_ids) == {"T1059", "T1202"}


class TestProvenanceExtraction:
    """Test extract_provenance() method"""

    def test_extract_capec_provenance(self):
        """Test MITRE CAPEC provenance extraction"""
        records = [
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": None,
                "tac": None,
                "st": None
            }
        ]
        provenance = OffensiveTransformer.extract_provenance(records)

        capec_sources = [p for p in provenance if p["source"] == "MITRE CAPEC"]
        assert len(capec_sources) == 1
        assert "CAPEC-88" in capec_sources[0]["ids"]

    def test_extract_attack_provenance(self):
        """Test MITRE ATT&CK provenance extraction"""
        records = [
            {
                "w": {"cweId": "CWE-79"},
                "ap": None,
                "t": {"attackId": "T1059"},
                "tac": None,
                "st": None
            }
        ]
        provenance = OffensiveTransformer.extract_provenance(records)

        attack_sources = [p for p in provenance if p["source"] == "MITRE ATT&CK"]
        assert len(attack_sources) == 1
        assert "T1059" in attack_sources[0]["ids"]

    def test_extract_dual_provenance(self):
        """Test dual provenance (CAPEC + ATT&CK)"""
        records = [
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": {"attackId": "T1059"},
                "tac": None,
                "st": None
            }
        ]
        provenance = OffensiveTransformer.extract_provenance(records)

        assert len(provenance) == 2
        sources = {p["source"] for p in provenance}
        assert sources == {"MITRE CAPEC", "MITRE ATT&CK"}

    def test_deduplicate_ids_in_provenance(self):
        """Test that duplicate IDs are deduplicated in provenance"""
        records = [
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": {"attackId": "T1059"},
                "tac": None,
                "st": None
            },
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},  # Duplicate
                "t": {"attackId": "T1059"},  # Duplicate
                "tac": None,
                "st": None
            }
        ]
        provenance = OffensiveTransformer.extract_provenance(records)

        capec_sources = [p for p in provenance if p["source"] == "MITRE CAPEC"]
        attack_sources = [p for p in provenance if p["source"] == "MITRE ATT&CK"]

        assert len(capec_sources[0]["ids"]) == 1
        assert len(attack_sources[0]["ids"]) == 1

    def test_provenance_timestamp(self):
        """Test that provenance includes ISO-8601 timestamp"""
        records = [
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": None,
                "tac": None,
                "st": None
            }
        ]
        provenance = OffensiveTransformer.extract_provenance(records)

        assert len(provenance) > 0
        assert all("timestamp" in p for p in provenance)
        # Should end with Z for UTC
        assert all(p["timestamp"].endswith("Z") for p in provenance)

    def test_no_provenance_for_empty_records(self):
        """Test that empty records return empty provenance"""
        records = []
        provenance = OffensiveTransformer.extract_provenance(records)

        assert provenance == []

    def test_provenance_sorted_ids(self):
        """Test that provenance IDs are sorted"""
        records = [
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-242"},
                "t": {"attackId": "T1202"},
                "tac": None,
                "st": None
            },
            {
                "w": {"cweId": "CWE-79"},
                "ap": {"capecId": "CAPEC-88"},
                "t": {"attackId": "T1059"},
                "tac": None,
                "st": None
            }
        ]
        provenance = OffensiveTransformer.extract_provenance(records)

        capec_sources = [p for p in provenance if p["source"] == "MITRE CAPEC"]
        attack_sources = [p for p in provenance if p["source"] == "MITRE ATT&CK"]

        # Check that IDs are sorted
        assert capec_sources[0]["ids"] == sorted(capec_sources[0]["ids"])
        assert attack_sources[0]["ids"] == sorted(attack_sources[0]["ids"])
