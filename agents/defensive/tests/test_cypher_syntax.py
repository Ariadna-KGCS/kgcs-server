"""Test Cypher template validation for Defensive Agent

Verifies:
- Template validation at module load time
- Parameter presence validation
- MATCH clause validation
- No string-concat artifact validation
"""

import pytest
from agents.defensive.cypher_templates import validate_template


class TestTemplateValidation:
    """Test validate_template() function"""

    def test_valid_template(self):
        """Test that valid template passes validation"""
        template = "MATCH (t:Technique {attackId: $attackId}) RETURN t"
        params = ["attackId"]
        # Should not raise
        validate_template("test_template", template, params)

    def test_missing_match_clause(self):
        """Test that template without MATCH clause raises error"""
        template = "RETURN something"
        with pytest.raises(ValueError, match="missing MATCH clause"):
            validate_template("test_template", template)

    def test_optional_match_clause(self):
        """Test that template with OPTIONAL MATCH passes"""
        template = "OPTIONAL MATCH (t:Technique {attackId: $attackId}) RETURN t"
        # Should not raise
        validate_template("test_template", template)

    def test_empty_template(self):
        """Test that empty template raises error"""
        with pytest.raises(ValueError, match="empty or not a string"):
            validate_template("test_template", "")

    def test_none_template(self):
        """Test that None template raises error"""
        with pytest.raises(ValueError, match="empty or not a string"):
            validate_template("test_template", None)

    def test_missing_attackId_parameter(self):
        """Test that template missing $attackId parameter raises error"""
        template = "MATCH (t:Technique) RETURN t"
        with pytest.raises(ValueError, match="missing \\$attackId"):
            validate_template("coverage_template", template, ["attackId"])

    def test_correct_parameter_binding(self):
        """Test that correct parameter binding passes validation"""
        template = "MATCH (t:Technique {attackId: $attackId}) RETURN t"
        params = ["attackId"]
        # Should not raise
        validate_template("coverage_template", template, params)

    def test_complex_template_with_optional_matches(self):
        """Test complex template with multiple OPTIONAL MATCH clauses"""
        template = """
        MATCH (t:Technique {attackId: $attackId})
        OPTIONAL MATCH (t)-[:MITIGATED_BY]->(d:DefensiveTechnique)
        OPTIONAL MATCH (t)-[:DETECTED_BY]->(c:DetectionAnalytic)
        OPTIONAL MATCH (t)-[:COUNTERED_BY]->(s:DeceptionTechnique)
        OPTIONAL MATCH (e:EngagementConcept)-[:DISRUPTS]->(t)
        RETURN t, collect(d) AS mitigations, collect(c) AS detections, collect(s) AS deceptions, collect(e) AS engagements
        """
        params = ["attackId"]
        # Should not raise
        validate_template("T_DEF_01", template, params)

    def test_no_string_concatenation_artifacts(self):
        """Test that string concat artifacts (bare values) would fail"""
        # This template has T1059 hardcoded, not as a parameter
        template = "MATCH (t:Technique {attackId: 'T1059'}) RETURN t"
        params = ["attackId"]
        # This should raise because $attackId is missing
        with pytest.raises(ValueError, match="missing \\$attackId"):
            validate_template("test_template", template, params)
