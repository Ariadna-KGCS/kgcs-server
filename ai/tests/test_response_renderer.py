"""Tests for ResponseRenderer.

Covers
------
1. render() routing by status (error, empty, ok).
2. Provenance and confidence sections always present in ok responses.
3. Low-confidence responses prepend a warning but still include results.
4. Intent-specific rendering for all four KGCS intents.
5. Mixed rendering includes only non-empty domain sections.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from ai.response_renderer import ResponseRenderer


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------


def _make_response(
    status: str = "ok",
    intent: str = "vuln_lookup",
    data: Dict[str, Any] | None = None,
    conf_value: float = 0.95,
    conf_basis: str = "complete_chain",
    degradation: List[str] | None = None,
    provenance: List[Dict[str, Any]] | None = None,
    errors: List[str] | None = None,
) -> Dict[str, Any]:
    """Build a minimal but valid ResponseEnvelope for testing."""
    if data is None:
        if intent == "vuln_lookup":
            data = {
                "vulnerabilities": [
                    {
                        "cveId": "CVE-2021-44228",
                        "scores": [{"version": "3.1", "baseScore": 10.0}],
                        "weakness": {"cweId": "CWE-502"},
                    }
                ]
            }
        elif intent == "attack_path":
            data = {
                "techniques": [
                    {
                        "id": "T1059",
                        "name": "Command and Scripting Interpreter",
                        "tactics": ["Execution"],
                    }
                ],
                "attack_paths": [
                    {
                        "weakness_id": "CWE-502",
                        "pattern_id": "CAPEC-88",
                        "technique_id": "T1059",
                    }
                ],
            }
        elif intent == "coverage_map":
            data = {
                "mitigations": [{"d3fendId": "D3-PA", "name": "Process Analysis"}],
                "detections": [
                    {
                        "analyticId": "CAR-2020-04-001",
                        "title": "Shells",
                        "coverageLevel": "High",
                    }
                ],
                "deceptions": [],
                "engagements": [{"activityId": "EAC0002", "name": "Application Diversity"}],
                "summary": {"has_coverage": True},
            }
        elif intent == "mixed":
            data = {
                "vulnerabilities": [
                    {
                        "cveId": "CVE-2021-44228",
                        "scores": [{"version": "3.1", "baseScore": 10.0}],
                        "weakness": {"cweId": "CWE-502"},
                    }
                ],
                "techniques": [
                    {
                        "id": "T1059",
                        "name": "Command and Scripting Interpreter",
                        "tactics": ["Execution"],
                    }
                ],
                "attack_paths": [],
                "mitigations": [{"d3fendId": "D3-PA", "name": "Process Analysis"}],
                "detections": [],
                "deceptions": [],
                "engagements": [],
            }
        else:
            data = {}

    if provenance is None:
        provenance = [{"source": "NVD", "ids": ["CVE-2021-44228"]}]

    return {
        "status": status,
        "data": data,
        "confidence": {
            "value": conf_value,
            "basis": conf_basis,
            "signals": {},
            "degradation": degradation or [],
        },
        "provenance": provenance,
        "errors": errors or [],
    }


# ---------------------------------------------------------------------------
# TestResponseRendererRender — render() routing and common behavior
# ---------------------------------------------------------------------------


class TestResponseRendererRender:
    """Tests for ResponseRenderer.render() routing logic."""

    def setup_method(self) -> None:
        self.renderer = ResponseRenderer()

    def test_produces_non_empty_string(self) -> None:
        response = _make_response()
        result = self.renderer.render(response, "vuln_lookup")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_includes_provenance_section(self) -> None:
        response = _make_response(provenance=[{"source": "NVD", "ids": ["CVE-2021-44228"]}])
        result = self.renderer.render(response, "vuln_lookup")
        assert "Provenance:" in result

    def test_includes_confidence_section(self) -> None:
        response = _make_response(conf_value=0.9, conf_basis="complete_chain")
        result = self.renderer.render(response, "vuln_lookup")
        assert "Confidence:" in result

    def test_error_status_returns_failure_message(self) -> None:
        response = _make_response(status="error", errors=["NVD unreachable"])
        result = self.renderer.render(response, "vuln_lookup")
        assert result.startswith("Query failed:")
        assert "NVD unreachable" in result

    def test_empty_status_returns_fallback(self) -> None:
        response = _make_response(status="empty")
        result = self.renderer.render(response, "vuln_lookup")
        assert "No reliable results" in result

    def test_low_confidence_shows_warning_not_fallback(self) -> None:
        """conf=0.10 must prepend a warning AND still show results."""
        response = _make_response(conf_value=0.10, conf_basis="partial_chain")
        result = self.renderer.render(response, "vuln_lookup")
        # Warning prepended
        assert "Low confidence" in result
        assert "Results may be incomplete" in result
        # Results are still present
        assert "CVE-2021-44228" in result

    @pytest.mark.parametrize("intent", ["vuln_lookup", "attack_path", "coverage_map", "mixed"])
    def test_all_intents_produce_non_empty_output(self, intent: str) -> None:
        response = _make_response(intent=intent)
        result = self.renderer.render(response, intent)
        assert isinstance(result, str)
        assert len(result) > 0


# ---------------------------------------------------------------------------
# TestResponseRendererVulnLookup
# ---------------------------------------------------------------------------


class TestResponseRendererVulnLookup:
    """Tests for _render_vuln_lookup via render()."""

    def setup_method(self) -> None:
        self.renderer = ResponseRenderer()

    def test_cve_id_appears_in_output(self) -> None:
        response = _make_response(intent="vuln_lookup")
        result = self.renderer.render(response, "vuln_lookup")
        assert "CVE-2021-44228" in result

    def test_cvss_score_appears_in_output(self) -> None:
        response = _make_response(intent="vuln_lookup")
        result = self.renderer.render(response, "vuln_lookup")
        assert "10.0" in result

    def test_summary_line_present(self) -> None:
        response = _make_response(intent="vuln_lookup")
        result = self.renderer.render(response, "vuln_lookup")
        assert "Summary:" in result
        assert "Vulnerabilities: 1" in result


# ---------------------------------------------------------------------------
# TestResponseRendererAttackPath
# ---------------------------------------------------------------------------


class TestResponseRendererAttackPath:
    """Tests for _render_attack_path via render()."""

    def setup_method(self) -> None:
        self.renderer = ResponseRenderer()

    def test_technique_id_appears_in_output(self) -> None:
        response = _make_response(intent="attack_path")
        result = self.renderer.render(response, "attack_path")
        assert "T1059" in result

    def test_causal_link_rendered_from_attack_paths(self) -> None:
        response = _make_response(intent="attack_path")
        result = self.renderer.render(response, "attack_path")
        # Explicit attack_paths entry is rendered
        assert "CWE-502" in result
        assert "CAPEC-88" in result


# ---------------------------------------------------------------------------
# TestResponseRendererCoverageMap
# ---------------------------------------------------------------------------


class TestResponseRendererCoverageMap:
    """Tests for _render_coverage_map via render()."""

    def setup_method(self) -> None:
        self.renderer = ResponseRenderer()

    def test_mitigation_appears_in_output(self) -> None:
        response = _make_response(intent="coverage_map")
        result = self.renderer.render(response, "coverage_map")
        assert "D3-PA" in result

    def test_empty_deceptions_section_omitted(self) -> None:
        """deceptions=[] must not produce a 'Deceptions:' Key Findings section header.

        The Summary line may still show 'Deceptions: 0'; only the Key Findings
        section header (standalone line) must be absent.
        """
        response = _make_response(intent="coverage_map")
        # Default coverage_map data has deceptions=[]
        result = self.renderer.render(response, "coverage_map")
        # The section header appears on its own line: "\nDeceptions:\n"
        assert "\nDeceptions:\n" not in result


# ---------------------------------------------------------------------------
# TestResponseRendererMixed
# ---------------------------------------------------------------------------


class TestResponseRendererMixed:
    """Tests for _render_mixed via render()."""

    def setup_method(self) -> None:
        self.renderer = ResponseRenderer()

    def test_all_present_sections_rendered(self) -> None:
        """Mixed response with all three domains must include all three separator headers."""
        data = {
            "vulnerabilities": [
                {
                    "cveId": "CVE-2021-44228",
                    "scores": [{"version": "3.1", "baseScore": 10.0}],
                    "weakness": {"cweId": "CWE-502"},
                }
            ],
            "techniques": [{"id": "T1059", "name": "Command Execution", "tactics": []}],
            "attack_paths": [],
            "mitigations": [{"d3fendId": "D3-PA", "name": "Process Analysis"}],
            "detections": [],
            "deceptions": [],
            "engagements": [],
        }
        response = _make_response(intent="mixed", data=data)
        result = self.renderer.render(response, "mixed")
        assert "--- Vulnerabilities ---" in result
        assert "--- Attack Techniques ---" in result
        assert "--- Defensive Controls ---" in result

    def test_only_present_sections_rendered(self) -> None:
        """Data with only vuln fields must produce no attack/defense section headers."""
        data = {
            "vulnerabilities": [
                {
                    "cveId": "CVE-2022-22965",
                    "scores": [{"version": "3.1", "baseScore": 9.8}],
                    "weakness": {},
                }
            ]
        }
        response = _make_response(intent="mixed", data=data)
        result = self.renderer.render(response, "mixed")
        assert "--- Vulnerabilities ---" in result
        assert "--- Attack Techniques ---" not in result
        assert "--- Defensive Controls ---" not in result
