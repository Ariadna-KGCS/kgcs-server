"""Test Cypher template validation for Offensive Agent

Verifies:
- Template validation at module load time
- Parameter presence validation
- MATCH clause validation
- No string-concat artifact validation
"""

import pytest
from agents.offensive.cypher_templates import validate_template


class TestTemplateValidation:
    """Test validate_template() function"""

    def test_valid_template(self):
        """Test that valid template passes validation"""
        template = "MATCH (w:Weakness {cweId: $cweId}) RETURN w"
        params = ["cweId"]
        # Should not raise
        validate_template("test_template", template, params)

    def test_missing_match_clause(self):
        """Test that template without MATCH clause raises error"""
        template = "RETURN something"
        with pytest.raises(ValueError, match="missing MATCH clause"):
            validate_template("test_template", template)

    def test_optional_match_clause(self):
        """Test that template with OPTIONAL MATCH passes"""
        template = "OPTIONAL MATCH (w:Weakness {cweId: $cweId}) RETURN w"
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

    def test_missing_cweId_parameter(self):
        """Test that template missing $cweId parameter raises error"""
        template = "MATCH (w:Weakness) RETURN w"
        with pytest.raises(ValueError, match="missing \\$cweId"):
            validate_template("weakness_template", template, ["cweId"])

    def test_weakness_key_requires_cweId(self):
        """Test that weakness-named template requires $cweId parameter"""
        template = "MATCH (w:Weakness {someId: $someId}) RETURN w"
        with pytest.raises(ValueError, match="missing \\$cweId"):
            validate_template("weakness_template", template)

    def test_correct_parameter_binding(self):
        """Test that correct parameter binding passes validation"""
        template = "MATCH (w:Weakness {cweId: $cweId}) RETURN w"
        params = ["cweId"]
        # Should not raise
        validate_template("weakness_template", template, params)

    def test_multiple_parameters(self):
        """Test validation with multiple parameters"""
        template = "MATCH (w:Weakness {cweId: $cweId}) WHERE w.id = $id RETURN w"
        params = ["cweId", "id"]
        # Should not raise
        validate_template("test_template", template, params)

    def test_missing_one_of_multiple_parameters(self):
        """Test that missing one of multiple parameters raises error"""
        template = "MATCH (w:Weakness {cweId: $cweId}) RETURN w"
        params = ["cweId", "id"]  # Second param is missing
        with pytest.raises(ValueError, match="missing \\$id"):
            validate_template("test_template", template, params)

    def test_no_string_concatenation_artifacts(self):
        """Test that string concat artifacts (like bare values) would fail"""
        # This template has CWE-79 as a bare string, not a parameter
        template = "MATCH (w:Weakness {cweId: 'CWE-79'}) RETURN w"
        params = ["cweId"]
        # This should raise because $cweId is missing
        with pytest.raises(ValueError, match="missing \\$cweId"):
            validate_template("test_template", template, params)

    def test_complex_template_with_optional_matches(self):
        """Test complex template with multiple OPTIONAL MATCH clauses"""
        template = """
        MATCH (w:Weakness {cweId: $cweId})
          -[:DEMONSTRATED_BY]->(ap:AttackPattern)
          -[:IMPLEMENTS]->(t:Technique)
        OPTIONAL MATCH (t)-[:PART_OF]->(tac:Tactic)
        OPTIONAL MATCH (t)<-[:SUBTECHNIQUE_OF]-(st:SubTechnique)
        RETURN w, ap, t, tac, st
        ORDER BY t.attackId
        """
        params = ["cweId"]
        # Should not raise
        validate_template("T_OFF_01_WEAKNESS", template, params)
