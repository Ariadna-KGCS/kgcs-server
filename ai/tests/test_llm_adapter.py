"""Tests for LLMAdapter — process_prompt() and pipeline integration.

Covers
------
1. ``process_prompt()`` returns an orchestrator-compatible request dict.
2. Correct intent and payload routing for each of the four intents.
3. ``UnsupportedQueryError`` propagated when intent cannot be resolved.
4. ``EntityNotFoundError`` raised when prompt has intent but no entity.
5. Request envelope shape matches orchestrator expectations.
"""

import pytest

from ai.llm_adapter import LLMAdapter, EntityNotFoundError
from ai.intent_classifier import UnsupportedQueryError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_adapter() -> LLMAdapter:
    """Return an LLMAdapter without an orchestrator (process_prompt only)."""
    return LLMAdapter()


# ---------------------------------------------------------------------------
# process_prompt — request building
# ---------------------------------------------------------------------------

class TestProcessPromptShape:
    """The returned dict must be a valid orchestrator request envelope."""

    def setup_method(self) -> None:
        self.adapter = make_adapter()

    def _assert_envelope(self, result: dict, expected_intent: str) -> None:
        assert result["version"] == "1.0"
        assert result["agent"] == "master"
        assert result["intent"] == expected_intent
        assert isinstance(result["payload"], dict)
        assert len(result["payload"]) > 0
        assert "correlation_id" in result

    def test_vuln_lookup_cve(self) -> None:
        result = self.adapter.process_prompt(
            "What vulnerabilities are in CVE-2021-44228?"
        )
        self._assert_envelope(result, "vuln_lookup")
        assert result["payload"] == {"cveId": "CVE-2021-44228"}

    def test_vuln_lookup_cpe(self) -> None:
        result = self.adapter.process_prompt(
            "Vulnerabilities for cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
        )
        self._assert_envelope(result, "vuln_lookup")
        assert "cpeName" in result["payload"]

    def test_attack_path_cwe(self) -> None:
        result = self.adapter.process_prompt(
            "What attack paths exploit CWE-502?"
        )
        self._assert_envelope(result, "attack_path")
        assert result["payload"] == {"cweId": "CWE-502"}

    def test_attack_path_cve(self) -> None:
        result = self.adapter.process_prompt(
            "Show attack paths for CVE-2021-44228"
        )
        self._assert_envelope(result, "attack_path")
        assert result["payload"] == {"cveId": "CVE-2021-44228"}

    def test_coverage_map_attack_id(self) -> None:
        result = self.adapter.process_prompt("What defenses cover T1059?")
        self._assert_envelope(result, "coverage_map")
        assert result["payload"] == {"attackId": "T1059"}

    def test_coverage_map_subtechnique(self) -> None:
        result = self.adapter.process_prompt("Mitigations for T1059.001")
        self._assert_envelope(result, "coverage_map")
        assert result["payload"] == {"attackId": "T1059.001"}

    def test_mixed_uses_cve(self) -> None:
        result = self.adapter.process_prompt(
            "Full analysis of CVE-2021-44228"
        )
        self._assert_envelope(result, "mixed")
        assert result["payload"] == {"cveId": "CVE-2021-44228"}


# ---------------------------------------------------------------------------
# process_prompt — error cases
# ---------------------------------------------------------------------------

class TestProcessPromptErrors:
    """Error conditions must produce the correct exception."""

    def setup_method(self) -> None:
        self.adapter = make_adapter()

    def test_unsupported_query_raises(self) -> None:
        with pytest.raises(UnsupportedQueryError):
            self.adapter.process_prompt("What is the capital of France?")

    def test_entity_not_found_for_coverage_map(self) -> None:
        """A coverage_map intent prompt with no ATT&CK ID must raise EntityNotFoundError."""
        with pytest.raises(EntityNotFoundError):
            self.adapter.process_prompt("What defenses exist for phishing?")

    def test_entity_not_found_for_vuln_lookup(self) -> None:
        with pytest.raises(EntityNotFoundError):
            self.adapter.process_prompt("List all vulnerabilities.")

    def test_entity_not_found_for_attack_path(self) -> None:
        with pytest.raises(EntityNotFoundError):
            self.adapter.process_prompt("Show me some attack patterns please.")


# ---------------------------------------------------------------------------
# Sample prompt → structured request outputs
# ---------------------------------------------------------------------------

class TestPromptToRequest:
    """End-to-end tracing of real-world prompts to expected request envelopes."""

    CASES = [
        (
            "What vulnerabilities are associated with CVE-2021-44228?",
            {"version": "1.0", "agent": "master", "intent": "vuln_lookup",
             "payload": {"cveId": "CVE-2021-44228"}},
        ),
        (
            "What attack techniques exploit CWE-502?",
            {"version": "1.0", "agent": "master", "intent": "attack_path",
             "payload": {"cweId": "CWE-502"}},
        ),
        (
            "What defenses cover T1059.001?",
            {"version": "1.0", "agent": "master", "intent": "coverage_map",
             "payload": {"attackId": "T1059.001"}},
        ),
        (
            "Full analysis of CVE-2021-44228",
            {"version": "1.0", "agent": "master", "intent": "mixed",
             "payload": {"cveId": "CVE-2021-44228"}},
        ),
    ]

    def test_all_sample_prompts(self) -> None:
        adapter = make_adapter()
        for prompt, expected in self.CASES:
            result = adapter.process_prompt(prompt)
            assert result["version"] == expected["version"], prompt
            assert result["agent"] == expected["agent"], prompt
            assert result["intent"] == expected["intent"], prompt
            assert result["payload"] == expected["payload"], (
                f"Prompt: {prompt!r}\nExpected payload: {expected['payload']}\n"
                f"Got: {result['payload']}"
            )


# ---------------------------------------------------------------------------
# Payload field validation tests
# ---------------------------------------------------------------------------

class TestPayloadValidation:
    """Tests for payload field validation against INTENT_PAYLOAD_FIELDS."""

    def test_valid_vuln_lookup_payload(self) -> None:
        """Valid payload fields for vuln_lookup should pass validation."""
        adapter = make_adapter()
        # This should not raise
        result = adapter.process_prompt("What is CVE-2021-44228?")
        assert result["intent"] == "vuln_lookup"
        assert "cveId" in result["payload"]

    def test_valid_attack_path_payload(self) -> None:
        """Valid payload fields for attack_path should pass validation."""
        adapter = make_adapter()
        # This should not raise
        result = adapter.process_prompt("What attack techniques exploit CWE-502?")
        assert result["intent"] == "attack_path"
        assert "cweId" in result["payload"]

    def test_valid_coverage_map_payload(self) -> None:
        """Valid payload fields for coverage_map should pass validation."""
        adapter = make_adapter()
        # This should not raise
        result = adapter.process_prompt("What defenses cover T1059.001?")
        assert result["intent"] == "coverage_map"
        assert "attackId" in result["payload"]

    def test_invalid_payload_field_raises_error(self) -> None:
        """Invalid payload field for intent should raise ValueError."""
        from ai.llm_adapter import LLMAdapter

        adapter = make_adapter()
        # Manually construct invalid payload to test validation
        with pytest.raises(ValueError, match="invalid fields"):
            adapter._validate_payload_fields(
                "vuln_lookup",
                {"invalidField": "value", "cveId": "CVE-2021-44228"}
            )

    def test_no_valid_fields_raises_error(self) -> None:
        """Payload with no valid fields for intent should raise ValueError."""
        from ai.llm_adapter import LLMAdapter

        adapter = make_adapter()
        # Payload with fields that don't match the intent
        with pytest.raises(ValueError, match="must contain at least one of"):
            adapter._validate_payload_fields(
                "coverage_map",
                {"cveId": "CVE-2021-44228"}  # cveId not valid for coverage_map
            )

    def test_empty_payload_intersection(self) -> None:
        """Payload with empty intersection should raise ValueError."""
        from ai.llm_adapter import LLMAdapter

        adapter = make_adapter()
        with pytest.raises(ValueError, match="must contain at least one of"):
            adapter._validate_payload_fields(
                "attack_path",
                {"attackId": "T1059.001"}  # attackId not valid for attack_path
            )

