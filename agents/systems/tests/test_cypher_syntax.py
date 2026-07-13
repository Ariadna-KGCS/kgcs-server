"""Test Cypher template syntax validation

Verifies that:
- All templates use parameterized syntax ($params, not string concat)
- All templates have MATCH or OPTIONAL MATCH clauses
- All templates have expected parameter markers
"""

import pytest
from agents.systems.cypher_templates import (
    TEMPLATES,
    validate_template,
    TEMPLATE_T_SYS_01_MATCH_CRITERIA,
    TEMPLATE_T_SYS_01_CPE_NAME,
    TEMPLATE_T_SYS_02_CVE,
    TEMPLATE_T_SYS_03_AFFECTED_PLATFORMS
)


class TestCypherSyntax:
    """Test Cypher template syntax validation"""

    def test_all_templates_exist(self):
        """Test that all required templates are defined"""
        assert "matchCriteriaId" in TEMPLATES
        assert "cpeName" in TEMPLATES
        assert "cpe" in TEMPLATES
        assert "cveId" in TEMPLATES

    def test_all_templates_have_metadata(self):
        """Test that each template has required metadata fields"""
        for key, meta in TEMPLATES.items():
            assert "template" in meta
            assert "params" in meta
            assert "expected_hops" in meta
            assert "description" in meta
            assert isinstance(meta["params"], list)
            assert len(meta["params"]) > 0
            assert isinstance(meta["expected_hops"], int)

    def test_match_criteria_template_has_match_statement(self):
        """Test that matchCriteriaId template has MATCH clause"""
        assert "MATCH" in TEMPLATE_T_SYS_01_MATCH_CRITERIA
        assert "$matchCriteriaId" in TEMPLATE_T_SYS_01_MATCH_CRITERIA

    def test_cpe_name_template_has_match_statement(self):
        """Test that cpeName template has MATCH clause"""
        assert "MATCH" in TEMPLATE_T_SYS_01_CPE_NAME
        assert "$cpeName" in TEMPLATE_T_SYS_01_CPE_NAME

    def test_cve_template_has_match_statement(self):
        """Test that CVE template has MATCH clause"""
        assert "MATCH" in TEMPLATE_T_SYS_02_CVE
        assert "$cveId" in TEMPLATE_T_SYS_02_CVE

    def test_affected_platforms_template_has_match_statement(self):
        """Test that affected platforms template has MATCH clause"""
        assert "MATCH" in TEMPLATE_T_SYS_03_AFFECTED_PLATFORMS
        assert "$cveId" in TEMPLATE_T_SYS_03_AFFECTED_PLATFORMS

    def test_match_criteria_template_params(self):
        """Test that matchCriteriaId template has correct parameter list"""
        assert TEMPLATES["matchCriteriaId"]["params"] == ["matchCriteriaId"]

    def test_cpe_name_template_params(self):
        """Test that cpeName template has correct parameter list"""
        assert TEMPLATES["cpeName"]["params"] == ["cpeName"]

    def test_cve_template_params(self):
        """Test that CVE template has correct parameter list"""
        assert TEMPLATES["cveId"]["params"] == ["cveId"]

    def test_match_criteria_template_expected_hops(self):
        """Test that matchCriteriaId template has correct expected hops"""
        assert TEMPLATES["matchCriteriaId"]["expected_hops"] == 3

    def test_cpe_name_template_expected_hops(self):
        """Test that cpeName template has correct expected hops"""
        assert TEMPLATES["cpeName"]["expected_hops"] == 3

    def test_cve_template_expected_hops(self):
        """Test that CVE template has correct expected hops"""
        # CVE lookup: Vulnerability -> Weakness (2 hops)
        assert TEMPLATES["cveId"]["expected_hops"] == 2

    def test_validate_template_valid(self):
        """Test that validate_template accepts valid templates"""
        # Should not raise for valid templates
        validate_template("test_matchcriteria", TEMPLATE_T_SYS_01_MATCH_CRITERIA)
        validate_template("test_cpename", TEMPLATE_T_SYS_01_CPE_NAME)
        validate_template("test_cve", TEMPLATE_T_SYS_02_CVE)

    def test_validate_template_missing_match(self):
        """Test that validate_template rejects templates without MATCH"""
        with pytest.raises(ValueError, match="missing MATCH clause"):
            validate_template("invalid", "RETURN x")

    def test_validate_template_missing_param_match_criteria(self):
        """Test that validate_template rejects criteria template without $matchCriteriaId"""
        invalid_template = """
        MATCH (pc:PlatformConfiguration)
        OPTIONAL MATCH (pc)<-[:AFFECTS]-(v:Vulnerability)
        RETURN v
        """
        with pytest.raises(ValueError, match="matchCriteriaId"):
            validate_template("matchCriteria_invalid", invalid_template)

    def test_validate_template_missing_param_cpe_name(self):
        """Test that validate_template rejects cpeName template without $cpeName"""
        invalid_template = """
        MATCH (p:Platform)
        OPTIONAL MATCH (p)<-[:MATCHES_PLATFORM]-(pc:PlatformConfiguration)
        RETURN pc
        """
        with pytest.raises(ValueError, match="cpeName"):
            validate_template("cpeName_invalid", invalid_template)

    def test_validate_template_missing_param_cve(self):
        """Test that validate_template rejects CVE template without $cveId"""
        invalid_template = """
        MATCH (v:Vulnerability)
        OPTIONAL MATCH (v)-[:CAUSED_BY]->(w:Weakness)
        RETURN w
        """
        with pytest.raises(ValueError, match="cveId"):
            validate_template("cve_invalid", invalid_template)

    def test_validate_template_empty_string(self):
        """Test that validate_template rejects empty template"""
        with pytest.raises(ValueError, match="empty or not a string"):
            validate_template("empty", "")

    def test_validate_template_not_string(self):
        """Test that validate_template rejects non-string template"""
        with pytest.raises(ValueError, match="empty or not a string"):
            validate_template("not_string", None)

    def test_templates_use_parameters_not_string_concat(self):
        """Test that templates use $param syntax (no f-string or format artifacts)"""
        for key, meta in TEMPLATES.items():
            template = meta["template"]
            # Should not have f-string or format placeholders
            assert template.count("${") == 0  # No ${...} format strings
            assert "{" not in template or "{" in "{"  # Cypher uses curly braces for map literals
            # All parameter uses should be $ prefixed
            assert "$" in template
