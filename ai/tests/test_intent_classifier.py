"""Regression tests for IntentClassifier.

Covers
------
1. Correct intent classification for each of the four KGCS intents.
2. Entity-presence signals driving correct classification.
3. ``UnsupportedQueryError`` for unrecognisable prompts.
4. ``_is_mixed()`` helper returns True only for end-to-end prompts.
5. Every returned value is in ``VALID_INTENTS``.
"""

import pytest

from ai.intent_classifier import IntentClassifier, UnsupportedQueryError


class TestIntentClassifierClassify:
    """Tests for IntentClassifier.classify()."""

    def setup_method(self) -> None:
        self.classifier = IntentClassifier()

    # ---- vuln_lookup -------------------------------------------------------

    def test_vuln_lookup_cve_id(self) -> None:
        result = self.classifier.classify(
            "What vulnerabilities are associated with CVE-2021-44228?"
        )
        assert result == "vuln_lookup"

    def test_vuln_lookup_platform_keywords(self) -> None:
        result = self.classifier.classify("Which CVEs affect Apache Log4j 2.14.1?")
        assert result == "vuln_lookup"

    def test_vuln_lookup_cpe_uri(self) -> None:
        result = self.classifier.classify(
            "List vulnerabilities for cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
        )
        assert result == "vuln_lookup"

    def test_vuln_lookup_vulnerability_keyword_only(self) -> None:
        result = self.classifier.classify(
            "What are the known vulnerabilities for CVE-2022-22965?"
        )
        assert result == "vuln_lookup"

    def test_vuln_lookup_patch_keyword(self) -> None:
        result = self.classifier.classify("Is there a patch for CVE-2021-44228?")
        assert result == "vuln_lookup"

    # ---- entity-first: ambiguous signals must not override CVE default -----

    def test_vuln_lookup_cve_with_exploitation_word(self) -> None:
        """'exploitation' is descriptive, not an explicit attack-path request.

        Without entity-first rule this used to return attack_path because
        'exploitation' matched the generic exploit pattern. CVE presence must
        win when no strong traversal keyword is present.
        """
        result = self.classifier.classify("Explain CVE-2021-44228 exploitation")
        assert result == "vuln_lookup"

    def test_vuln_lookup_cve_allow_rce(self) -> None:
        """'allow remote code execution' is a property description, not a
        traversal request. No keyword should redirect to attack_path."""
        result = self.classifier.classify(
            "Does CVE-2021-44228 allow remote code execution?"
        )
        assert result == "vuln_lookup"

    def test_vuln_lookup_cve_patched_question(self) -> None:
        """'patched' is a vulnerability-state keyword, NOT an attack signal.
        CVE + 'patched' must remain vuln_lookup."""
        result = self.classifier.classify("Is CVE-2021-44228 patched?")
        assert result == "vuln_lookup"

    # ---- attack_path -------------------------------------------------------

    def test_attack_path_cwe_keyword(self) -> None:
        result = self.classifier.classify("What attack patterns exploit CWE-502?")
        assert result == "attack_path"

    def test_attack_path_cve_plus_attack(self) -> None:
        result = self.classifier.classify(
            "What attack paths exist for CVE-2021-44228?"
        )
        assert result == "attack_path"

    def test_attack_path_exploit_keyword(self) -> None:
        result = self.classifier.classify(
            "How is CWE-89 exploited in the wild?"
        )
        assert result == "attack_path"

    def test_attack_path_technique_keyword_with_cwe(self) -> None:
        result = self.classifier.classify(
            "What ATT&CK techniques are linked to CWE-502?"
        )
        assert result == "attack_path"

    # ---- coverage_map ------------------------------------------------------

    def test_coverage_map_attack_id(self) -> None:
        result = self.classifier.classify("What defenses cover T1059?")
        assert result == "coverage_map"

    def test_coverage_map_subtechnique(self) -> None:
        result = self.classifier.classify(
            "Show mitigations for T1059.001."
        )
        assert result == "coverage_map"

    def test_coverage_map_mitigation_keyword(self) -> None:
        result = self.classifier.classify(
            "What mitigations exist for T1190?"
        )
        assert result == "coverage_map"

    def test_coverage_map_detection_keyword(self) -> None:
        result = self.classifier.classify(
            "How do I detect T1003 on my network?"
        )
        assert result == "coverage_map"

    # ---- mixed -------------------------------------------------------------

    def test_mixed_full_analysis_phrase(self) -> None:
        result = self.classifier.classify(
            "Give me a full analysis of CVE-2021-44228."
        )
        assert result == "mixed"

    def test_mixed_end_to_end_phrase(self) -> None:
        result = self.classifier.classify(
            "I want an end-to-end view of CVE-2021-44228."
        )
        assert result == "mixed"

    def test_mixed_attack_and_defense_explicit(self) -> None:
        result = self.classifier.classify(
            "For CVE-2021-44228, show attack paths and defensive mitigations."
        )
        assert result == "mixed"

    def test_mixed_three_domains_keywords(self) -> None:
        result = self.classifier.classify(
            "CVE-2021-44228: vulnerabilities, exploit techniques, and defenses."
        )
        assert result == "mixed"

    # ---- error cases -------------------------------------------------------

    def test_unsupported_query_raises(self) -> None:
        with pytest.raises(UnsupportedQueryError):
            self.classifier.classify("What is the capital of France?")

    def test_greeting_raises(self) -> None:
        with pytest.raises(UnsupportedQueryError):
            self.classifier.classify("Hello, how are you?")

    def test_result_always_in_valid_intents(self) -> None:
        prompts = [
            "What CVEs affect cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*?",
            "Exploit paths for CWE-502",
            "Defenses for T1059",
            "Full analysis for CVE-2021-44228",
        ]
        for prompt in prompts:
            result = self.classifier.classify(prompt)
            assert result in IntentClassifier.VALID_INTENTS, (
                f"classify({prompt!r}) returned {result!r}, not in VALID_INTENTS"
            )


class TestIntentClassifierIsMixed:
    """Tests for IntentClassifier._is_mixed()."""

    def setup_method(self) -> None:
        self.classifier = IntentClassifier()

    def test_single_cve_not_mixed(self) -> None:
        assert not self.classifier._is_mixed("Show CVEs for CVE-2021-44228.")

    def test_single_cwe_not_mixed(self) -> None:
        assert not self.classifier._is_mixed("What techniques exploit CWE-502?")

    def test_single_attack_id_not_mixed(self) -> None:
        assert not self.classifier._is_mixed("Defenses for T1059?")

    def test_full_analysis_phrase_is_mixed(self) -> None:
        assert self.classifier._is_mixed(
            "Give me a full analysis of the CVE-2021-44228 vulnerability."
        )

    def test_end_to_end_phrase_is_mixed(self) -> None:
        assert self.classifier._is_mixed(
            "I need an end-to-end assessment starting from CVE-2021-44228."
        )

    def test_attack_and_defense_phrase_is_mixed(self) -> None:
        assert self.classifier._is_mixed(
            "Show me attack paths and defensive coverage for this vulnerability."
        )


# ---------------------------------------------------------------------------
# TestIntentClassifierRefinements — targeted regression tests for recent fixes
# ---------------------------------------------------------------------------


class TestIntentClassifierRefinements:
    """Regression tests for the four classifier refinements.

    1. Defense pattern now covers "mitigated" (past tense -ed suffix).
    2. Threat actor pattern now covers plural forms ("actors", "groups").
    3. CVE + defense keywords + no ATT&CK ID → forced vuln_lookup to avoid
       coverage_map → EntityNotFoundError.
    """

    def setup_method(self) -> None:
        self.classifier = IntentClassifier()

    # ---- "mitigated" past-tense fix ----------------------------------------

    def test_vuln_lookup_cve_mitigated_past_tense(self) -> None:
        """'mitigated' (past tense) must now trigger a defense signal.

        Previously "mitigated" slipped through because the suffix -ed was absent
        from the regex. The CVE+defense guard then ensures the intent stays
        vuln_lookup rather than routing to coverage_map (which would fail
        extraction because no ATT&CK ID is present).
        """
        result = self.classifier.classify(
            "Is CVE-2021-44228 already mitigated by endpoint security tools in most environments?"
        )
        assert result == "vuln_lookup"

    # ---- threat actor plural fix -------------------------------------------

    def test_vuln_lookup_cve_threat_actors_plural(self) -> None:
        """'threat actors' (plural) must now fire the attack-signal pattern.

        Previously the singular-only regex `(?:actor|group|vector)` failed to
        match "actors" because the trailing 's' broke the word-boundary check.
        With the plural fix the attack signal fires, but no strong attack signal
        and no defence signal are present, so entity-first keeps it vuln_lookup.
        """
        result = self.classifier.classify(
            "Which threat actor groups have been observed exploiting CVE-2021-26855 in APT campaigns?"
        )
        assert result == "vuln_lookup"

    def test_vuln_lookup_cve_threat_groups_plural(self) -> None:
        """'threat groups' (plural) must also fire the pattern."""
        result = self.classifier.classify(
            "Are there known threat groups targeting CVE-2022-22965 in financial-sector environments?"
        )
        assert result == "vuln_lookup"

    # ---- CVE + defense → forced vuln_lookup --------------------------------

    def test_vuln_lookup_cve_with_remediate_keyword(self) -> None:
        """CVE + 'remediate' must route to vuln_lookup, not coverage_map.

        Before the CVE+defense guard, 'remediate' triggered defense_score and
        the entity-first rule returned coverage_map, which then failed extraction
        because no ATT&CK ID was present.
        """
        result = self.classifier.classify(
            "How should we remediate CVE-2021-21985 to eliminate the exposure across our ESXi fleet?"
        )
        assert result == "vuln_lookup"

    def test_vuln_lookup_cve_with_mitigating_keyword(self) -> None:
        """CVE + 'mitigating' (present participle) must route to vuln_lookup."""
        result = self.classifier.classify(
            "Are CDN providers actively mitigating CVE-2023-44487 in their edge filtering rulesets?"
        )
        assert result == "vuln_lookup"

    def test_vuln_lookup_cve_with_protection_keyword(self) -> None:
        """CVE + 'protection' must route to vuln_lookup, not coverage_map."""
        result = self.classifier.classify(
            "Is CVE-2022-30190 (Follina) detected by Windows Defender endpoint protection?"
        )
        assert result == "vuln_lookup"

    def test_vuln_lookup_cve_defence_language_no_attackid(self) -> None:
        """Any CVE + defence keyword combination without an ATT&CK ID must stay vuln_lookup."""
        result = self.classifier.classify(
            "What countermeasures are effective against CVE-2019-0708 (BlueKeep) on Windows?"
        )
        assert result == "vuln_lookup"

    # ---- CPE + defense still routes to coverage_map (unchanged) -----------

    def test_cpe_with_defense_keyword_routes_to_coverage_map(self) -> None:
        """CPE + defense keyword without a CVE is NOT affected by the CVE guard.

        The CVE+defense rule only fires when has_cve is True. When only a CPE
        is present the original coverage_map route is preserved.
        """
        result = self.classifier.classify(
            "What mitigations protect cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:* installations?"
        )
        assert result == "coverage_map"
