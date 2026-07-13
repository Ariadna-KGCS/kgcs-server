"""Test routing logic for Master Orchestrator"""

import pytest
from orchestrator.router import RequestRouter
from orchestrator.errors import ValidationError, RoutingError


class TestIntentValidation:
    """Test intent validation"""

    def test_valid_intents(self):
        """Test that valid intents pass validation"""
        valid_intents = ["vuln_lookup", "attack_path", "coverage_map", "mixed"]
        for intent in valid_intents:
            RequestRouter.validate_intent(intent)  # Should not raise

    def test_invalid_intent(self):
        """Test that invalid intent raises ValidationError"""
        with pytest.raises(ValidationError, match="Invalid intent"):
            RequestRouter.validate_intent("invalid_intent")


class TestPayloadValidation:
    """Test payload validation"""

    def test_vuln_lookup_match_criteria_id(self):
        """Test vuln_lookup with explicit matchCriteriaId payload"""
        payload = {"matchCriteriaId": "8a5c4e5b-3d6f-4a7e-9b8c-2d3e4f5a6b7c"}
        RequestRouter.validate_payload("vuln_lookup", payload)  # Should not raise

    def test_vuln_lookup_cpe_name(self):
        """Test vuln_lookup with explicit cpeName payload"""
        payload = {"cpeName": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}
        RequestRouter.validate_payload("vuln_lookup", payload)  # Should not raise

    def test_vuln_lookup_legacy_cpe(self):
        """Test vuln_lookup with legacy cpe compatibility payload"""
        payload = {"cpe": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}
        RequestRouter.validate_payload("vuln_lookup", payload)  # Should not raise

    def test_vuln_lookup_cveId(self):
        """Test vuln_lookup with CVE payload"""
        payload = {"cveId": "CVE-2021-44228"}
        RequestRouter.validate_payload("vuln_lookup", payload)  # Should not raise

    def test_vuln_lookup_missing_field(self):
        """Test vuln_lookup with missing payload"""
        with pytest.raises(ValidationError, match="missing required field"):
            RequestRouter.validate_payload("vuln_lookup", {})

    def test_attack_path_cweId(self):
        """Test attack_path with CWE payload"""
        payload = {"cweId": "CWE-79"}
        RequestRouter.validate_payload("attack_path", payload)  # Should not raise

    def test_coverage_map_attackId(self):
        """Test coverage_map with attackId payload"""
        payload = {"attackId": "T1059"}
        RequestRouter.validate_payload("coverage_map", payload)  # Should not raise

    def test_coverage_map_missing_attackId(self):
        """Test coverage_map without attackId raises error"""
        with pytest.raises(ValidationError, match="missing required field"):
            RequestRouter.validate_payload("coverage_map", {"cveId": "CVE-2021"})


class TestIntentRouting:
    """Test intent routing"""

    def test_route_vuln_lookup(self):
        """Test that vuln_lookup routes to systems agent"""
        agent = RequestRouter.route_intent("vuln_lookup")
        assert agent == "systems"

    def test_route_attack_path(self):
        """Test that attack_path routes to offensive agent"""
        agent = RequestRouter.route_intent("attack_path")
        assert agent == "offensive"

    def test_route_coverage_map(self):
        """Test that coverage_map routes to defensive agent"""
        agent = RequestRouter.route_intent("coverage_map")
        assert agent == "defensive"

    def test_route_mixed_raises_error(self):
        """Test that mixed intent routing raises error"""
        with pytest.raises(RoutingError, match="Use route_mixed_intent"):
            RequestRouter.route_intent("mixed")

    def test_route_mixed_intent(self):
        """Test mixed intent routing returns sequence"""
        sequence = RequestRouter.route_mixed_intent()
        assert len(sequence) == 3  # systems, offensive, defensive
        assert sequence[0][0] == "systems"
        assert sequence[1][0] == "offensive"
        assert sequence[2][0] == "defensive"
