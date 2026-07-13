"""Regression tests for EntityExtractor.

Covers
------
1. ``extract()`` returns correct payload for each intent.
2. Entity-specific helpers correctly parse CVE, CWE, ATT&CK, CPE, matchCriteriaId.
3. No identifiers invented — empty dict returned when none are present.
4. Extraction is case-insensitive where the spec allows and normalised on return.
"""

import pytest

from ai.entity_extractor import EntityExtractor, MultipleEntitiesError


class TestEntityExtractorExtract:
    """Tests for EntityExtractor.extract()."""

    def setup_method(self) -> None:
        self.extractor = EntityExtractor()

    # ---- vuln_lookup -------------------------------------------------------

    def test_vuln_lookup_cve(self) -> None:
        result = self.extractor.extract(
            "What do you know about CVE-2021-44228?", "vuln_lookup"
        )
        assert result == {"cveId": "CVE-2021-44228"}

    def test_vuln_lookup_cpe(self) -> None:
        result = self.extractor.extract(
            "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:* vulnerabilities",
            "vuln_lookup",
        )
        assert "cpeName" in result
        assert result["cpeName"].startswith("cpe:2.3:")

    def test_vuln_lookup_cpe_preferred_over_cve(self) -> None:
        """When both CPE and CVE are present, cveId takes priority for vuln_lookup."""
        result = self.extractor.extract(
            "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:* affects CVE-2021-44228",
            "vuln_lookup",
        )
        assert "cveId" in result
        assert result["cveId"] == "CVE-2021-44228"
        assert "cpeName" not in result

    def test_vuln_lookup_match_criteria_id_priority(self) -> None:
        """matchCriteriaId has highest priority for vuln_lookup."""
        result = self.extractor.extract(
            "matchCriteriaId 7c3aede1-1c0c-4bd1-a949-d43cac5b8c9b",
            "vuln_lookup",
        )
        assert result == {"matchCriteriaId": "7c3aede1-1c0c-4bd1-a949-d43cac5b8c9b"}

    def test_vuln_lookup_no_entity(self) -> None:
        result = self.extractor.extract(
            "Tell me about vulnerabilities in general.", "vuln_lookup"
        )
        assert result == {}

    # ---- attack_path -------------------------------------------------------

    def test_attack_path_cwe(self) -> None:
        result = self.extractor.extract(
            "Show attack paths for CWE-502.", "attack_path"
        )
        assert result == {"cweId": "CWE-502"}

    def test_attack_path_cve_fallback(self) -> None:
        """cveId is used when no CWE is present for attack_path."""
        result = self.extractor.extract(
            "Attack path for CVE-2021-44228", "attack_path"
        )
        assert result == {"cveId": "CVE-2021-44228"}

    def test_attack_path_cwe_preferred_over_cve(self) -> None:
        result = self.extractor.extract(
            "Exploit chain for CVE-2021-44228 (CWE-502)", "attack_path"
        )
        assert result == {"cweId": "CWE-502"}

    def test_attack_path_no_entity(self) -> None:
        result = self.extractor.extract(
            "Tell me about attack patterns.", "attack_path"
        )
        assert result == {}

    # ---- coverage_map ------------------------------------------------------

    def test_coverage_map_attack_id(self) -> None:
        result = self.extractor.extract(
            "What defenses cover T1059.001?", "coverage_map"
        )
        assert result == {"attackId": "T1059.001"}

    def test_coverage_map_base_technique(self) -> None:
        result = self.extractor.extract(
            "Mitigations for T1059", "coverage_map"
        )
        assert result == {"attackId": "T1059"}

    def test_coverage_map_no_attack_id(self) -> None:
        result = self.extractor.extract(
            "What are the best mitigations?", "coverage_map"
        )
        assert result == {}

    # ---- mixed -------------------------------------------------------------

    def test_mixed_uses_cve(self) -> None:
        result = self.extractor.extract(
            "Full analysis starting from CVE-2021-44228", "mixed"
        )
        assert result == {"cveId": "CVE-2021-44228"}

    def test_mixed_uses_cpe(self) -> None:
        result = self.extractor.extract(
            "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:* full analysis",
            "mixed",
        )
        assert "cpeName" in result


class TestEntityExtractorHelpers:
    """Tests for the private per-entity helper methods."""

    def setup_method(self) -> None:
        self.extractor = EntityExtractor()

    # ---- _extract_cve ------------------------------------------------------

    def test_cve_standard(self) -> None:
        assert self.extractor._extract_cve("CVE-2021-44228 is critical.") == "CVE-2021-44228"

    def test_cve_lowercase_normalised(self) -> None:
        assert self.extractor._extract_cve("affected by cve-2021-44228") == "CVE-2021-44228"

    def test_cve_five_digit_sequence(self) -> None:
        assert self.extractor._extract_cve("CVE-2014-12345") == "CVE-2014-12345"

    def test_cve_none_when_absent(self) -> None:
        assert self.extractor._extract_cve("no identifier here") is None

    def test_cve_none_for_partial(self) -> None:
        # CVE-YYYY-NNN is too short (< 4 sequence digits)
        assert self.extractor._extract_cve("CVE-2021-123") is None

    # ---- _extract_cwe ------------------------------------------------------

    def test_cwe_standard(self) -> None:
        assert self.extractor._extract_cwe("exploits CWE-502") == "CWE-502"

    def test_cwe_lowercase(self) -> None:
        assert self.extractor._extract_cwe("cwe-89 SQL injection") == "CWE-89"

    def test_cwe_multi_digit(self) -> None:
        assert self.extractor._extract_cwe("CWE-1000 root node") == "CWE-1000"

    def test_cwe_none_when_absent(self) -> None:
        assert self.extractor._extract_cwe("no weakness mentioned") is None

    # ---- _extract_attack_id ------------------------------------------------

    def test_attack_id_base(self) -> None:
        assert self.extractor._extract_attack_id("technique T1059") == "T1059"

    def test_attack_id_subtechnique(self) -> None:
        assert self.extractor._extract_attack_id("sub-technique T1059.001") == "T1059.001"

    def test_attack_id_none_short(self) -> None:
        # T123 is only 3 digits — not a valid ATT&CK ID
        assert self.extractor._extract_attack_id("T123 is not valid") is None

    def test_attack_id_none_when_absent(self) -> None:
        assert self.extractor._extract_attack_id("no technique here") is None

    def test_attack_id_lowercase_not_matched(self) -> None:
        # ATT&CK IDs must start with uppercase T
        assert self.extractor._extract_attack_id("t1059 should not match") is None

    # ---- _extract_cpe ------------------------------------------------------

    def test_cpe_full_uri(self) -> None:
        cpe = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
        assert self.extractor._extract_cpe(f"Affected: {cpe}") == cpe

    def test_cpe_none_when_absent(self) -> None:
        assert self.extractor._extract_cpe("no CPE here") is None

    def test_cpe_strips_trailing_punctuation(self) -> None:
        cpe = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
        result = self.extractor._extract_cpe(f"using {cpe}.")
        assert result == cpe

    # ---- _extract_match_criteria_id ----------------------------------------

    def test_match_criteria_uuid(self) -> None:
        uuid = "7c3aede1-1c0c-4bd1-a949-d43cac5b8c9b"
        assert self.extractor._extract_match_criteria_id(f"id: {uuid}") == uuid

    def test_match_criteria_none_when_absent(self) -> None:
        assert self.extractor._extract_match_criteria_id("no uuid here") is None


# ---------------------------------------------------------------------------
# Multi-entity detection
# ---------------------------------------------------------------------------

class TestEntityExtractorMultipleEntities:
    """Tests for MultipleEntitiesError when more than one identifier of the
    same type appears in the prompt."""

    def setup_method(self) -> None:
        self.extractor = EntityExtractor()

    # ---- helpers -----------------------------------------------------------

    def test_two_cves_raises(self) -> None:
        with pytest.raises(MultipleEntitiesError, match="Multiple CVE identifiers"):
            self.extractor._extract_cve(
                "Compare CVE-2021-44228 and CVE-2023-1234"
            )

    def test_two_cwes_raises(self) -> None:
        with pytest.raises(MultipleEntitiesError, match="Multiple CWE identifiers"):
            self.extractor._extract_cwe(
                "Both CWE-79 and CWE-89 are injection weaknesses"
            )

    def test_two_attack_ids_raises(self) -> None:
        with pytest.raises(MultipleEntitiesError, match="Multiple ATT&CK technique identifiers"):
            self.extractor._extract_attack_id(
                "Techniques T1059 and T1078 are commonly chained"
            )

    def test_two_match_criteria_uuids_raises(self) -> None:
        with pytest.raises(MultipleEntitiesError, match="Multiple matchCriteriaId"):
            self.extractor._extract_match_criteria_id(
                "criteria 7c3aede1-1c0c-4bd1-a949-d43cac5b8c9b "
                "and 00000000-0000-0000-0000-000000000001"
            )

    # ---- error message includes the found identifiers ----------------------

    def test_error_message_contains_both_cves(self) -> None:
        with pytest.raises(MultipleEntitiesError) as exc_info:
            self.extractor._extract_cve(
                "Compare CVE-2021-44228 and CVE-2023-1234"
            )
        msg = str(exc_info.value)
        assert "CVE-2021-44228" in msg
        assert "CVE-2023-1234" in msg

    # ---- extract() propagates the error ------------------------------------

    def test_extract_propagates_multiple_cve_error(self) -> None:
        """extract() must propagate MultipleEntitiesError up to the adapter."""
        with pytest.raises(MultipleEntitiesError):
            self.extractor.extract(
                "Compare CVE-2021-44228 and CVE-2023-1234", "vuln_lookup"
            )

    # ---- single entity still works (no regression) -------------------------

    def test_single_cve_not_affected(self) -> None:
        assert self.extractor._extract_cve("CVE-2021-44228") == "CVE-2021-44228"

    def test_single_cwe_not_affected(self) -> None:
        assert self.extractor._extract_cwe("CWE-79") == "CWE-79"
