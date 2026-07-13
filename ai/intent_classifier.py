"""Intent Classifier — maps a natural-language prompt to a KGCS intent.

The classifier must return exactly one of the four valid KGCS intents:

    vuln_lookup   – the user is asking about vulnerabilities for a platform or CVE ID.
    attack_path   – the user is asking about attack techniques derived from a CWE or CVE.
    coverage_map  – the user is asking about defensive coverage for an ATT&CK technique.
    mixed         – the query spans all three domains end-to-end.

Classification strategy
-----------------------
Fully deterministic — uses regex patterns and keyword scoring, no LLM dependency.

1. Check for explicit mixed-intent phrases (``_MIXED_PHRASES``).
2. Detect entity presence (CVE, CWE, ATT&CK, CPE) using regex from
   ``entity_extractor``.
3. Score keyword signals for each of the three single-intent domains.
4. Entity-first rule:
   When CVE or CPE is the only structured entity (no CWE, no ATT&CK ID), the
   classifier defaults to ``vuln_lookup`` unless strong, unambiguous signals are
   present.  Weak descriptive words such as "exploitation", "attacker", or
   "technique" do NOT redirect away from ``vuln_lookup``.
5. General resolution (CWE or ATT&CK ID present, or no structured entity):
   Count active domains and resolve by priority rules.

Domain scoring
--------------
Each domain scores +1 for every keyword pattern match:
- Vulnerability domain: CVE/CVSS/NVD/patch/exposure keywords, or has_cve/has_cpe.
- Attack domain:       exploit/technique/CAPEC/attack-path keywords, or has_cwe.
- Defense domain:      mitigate/defense/coverage/protect/detect keywords, or has_attack_id.

Entity-first rule (step 4)
--------------------------
Applies when ``has_cve or has_cpe`` and ``not has_cwe`` and ``not has_attack_id``:
- Strong attack signals (``_STRONG_ATTACK_PATTERNS``) + any defense  → ``mixed``
- Strong attack signals only                                         → ``attack_path``
- Any defense only (no attack signals) + CVE present                 → ``vuln_lookup``
  (coverage_map extraction requires an ATT&CK ID which is absent)
- Any defense only (no attack signals) + CPE only (no CVE)           → ``coverage_map``
- All others (including weak-only attack signals)                    → ``vuln_lookup``

General resolution (step 6)
----------------------------
- active_domains >= 3  → ``mixed``
- active_domains == 2:
    • attack + defense only (no vuln)   → ``coverage_map``
    • vuln + attack only (no defense)   → ``attack_path``
    • vuln + defense only (no attack)   → ``coverage_map``
- active_domains == 1:
    • defense domain  → ``coverage_map``
    • attack domain   → ``attack_path``
    • vuln domain     → ``vuln_lookup``
- active_domains == 0  → ``UnsupportedQueryError``

Rules
-----
- Must NOT invent new intents.
- Must NOT fall back to free-form text generation.
- Raises ``UnsupportedQueryError`` if no intent can be confidently resolved.
- Uses ``orchestrator.constants.VALID_INTENTS`` as the single authoritative list.

Called at step 1 of ``LLMAdapter.process()``, before entity extraction.
"""

from __future__ import annotations

import re
from typing import List

from orchestrator.constants import VALID_INTENTS

from .entity_extractor import _CVE_RE, _CWE_RE, _ATTACK_ID_RE, _CPE_RE


class UnsupportedQueryError(Exception):
    """Raised when the prompt cannot be mapped to a supported KGCS intent."""


# ---------------------------------------------------------------------------
# Intent keyword patterns
# ---------------------------------------------------------------------------

_VULN_PATTERNS: List[re.Pattern] = [
    re.compile(r"\bvulnerabilit(?:y|ies)\b", re.I),
    re.compile(r"\bCVEs?\b", re.I),
    re.compile(r"\bsecurity[ -](?:flaw|issue|advisory|bug|hole|patch)\b", re.I),
    re.compile(r"\bpatch(?:ed)?\b", re.I),
    re.compile(r"\bNVD\b"),
    re.compile(r"\bCVSS\b"),
    re.compile(r"\bexposure\b", re.I),
    re.compile(r"\baffected version", re.I),
    re.compile(r"\bmatch(?:ing)? criteria\b", re.I),
    re.compile(r"\bcpe:", re.I),
    re.compile(r"\bcpeName\b", re.I),
]

_ATTACK_PATTERNS: List[re.Pattern] = [
    re.compile(r"\battack[ -](?:paths?|patterns?|techniques?|chains?|vectors?|surfaces?)\b", re.I),
    re.compile(r"\bexploit(?:s|ed|ing|ation|ability)?\b", re.I),
    re.compile(r"\bCAPEC\b"),
    re.compile(r"\bTTPs?\b"),
    re.compile(r"\btechnique\b", re.I),
    re.compile(r"\btactic(?:s)?\b", re.I),
    re.compile(r"\bthreat[ -](?:actors?|groups?|vectors?)\b", re.I),
    re.compile(r"\blateral movement\b", re.I),
    re.compile(r"\bprivilege escalation\b", re.I),
    re.compile(r"\battacker\b", re.I),
    re.compile(r"\bmalware\b", re.I),
    re.compile(r"\bATT&CK\b", re.I),
    re.compile(r"\boffensive\b", re.I),
]

_DEFENSE_PATTERNS: List[re.Pattern] = [
    re.compile(r"\bmitigation\b", re.I),
    re.compile(r"\bmitigat(?:e|ed|ion|ions|ing)\b", re.I),
    re.compile(r"\bdefens(?:e|es|ive|ively)\b", re.I),
    re.compile(r"\bcountermeasure\b", re.I),
    re.compile(r"\bprotect(?:ion|ive|ed)?\b", re.I),
    re.compile(r"\bdetect(?:ion|ed|ing|or)?\b", re.I),
    re.compile(r"\bcoverage\b", re.I),
    re.compile(r"\bD3FEND\b"),
    re.compile(r"\bSHIELD\b"),
    re.compile(r"\bCAR\b"),
    re.compile(r"\bENGAGE\b"),
    re.compile(r"\bprevent(?:ion|ive|s|ed|ing)?\b", re.I),
    re.compile(r"\bremediat(?:e|ion|ions)\b", re.I),
    re.compile(r"\bcountermeasures?\b", re.I),
    re.compile(r"\bdefensive\b", re.I),
]

# Strong attack signals: explicit traversal/chain requests.
# Used by the entity-first rule to decide whether to redirect a CVE query.
# Must be a subset of _ATTACK_PATTERNS and represent unambiguous intent to traverse
# the attack chain — not merely descriptive uses of "exploit" or "attack".
_STRONG_ATTACK_PATTERNS: List[re.Pattern] = [
    re.compile(r"\battack[ -](?:paths?|chains?|techniques?|vectors?|surfaces?)\b", re.I),
    re.compile(r"\bCAPEC\b"),
    re.compile(r"\bTTPs?\b"),
    re.compile(r"\blateral movement\b", re.I),
    re.compile(r"\bprivilege escalation\b", re.I),
    re.compile(r"\bexploit(?:ation)?[ -](?:path|chain|technique|vector)\b", re.I),
]

# Phrases that explicitly signal an end-to-end, mixed-intent query
_MIXED_PHRASES: List[re.Pattern] = [
    re.compile(r"\bfull analysis\b", re.I),
    re.compile(r"\bcomplete analysis\b", re.I),
    re.compile(r"\bend[- ]to[- ]end\b", re.I),
    re.compile(r"\bfull chain\b", re.I),
    re.compile(r"\bentire chain\b", re.I),
    re.compile(r"\bfrom vulnerability to\b", re.I),
    re.compile(r"\beverything about\b", re.I),
    re.compile(r"\ball aspects?\b", re.I),
    re.compile(r"\bvulnerabilit.{0,40}attack.{0,40}def(?:ens|end)", re.I | re.S),
    re.compile(r"\battack path.{0,40}(?:mitigat|defens|coverage)", re.I | re.S),
]


def _score(text: str, patterns: List[re.Pattern]) -> int:
    """Return the number of distinct patterns that match *text*."""
    return sum(1 for p in patterns if p.search(text))


class IntentClassifier:
    """Maps a natural-language prompt to one of the four KGCS intents.

    The classifier is stateless and safe to share across requests.
    """

    VALID_INTENTS: list[str] = list(VALID_INTENTS)

    def classify(self, prompt: str) -> str:
        """Classify a prompt and return the resolved KGCS intent string.

        Parameters
        ----------
        prompt:
            Raw natural-language input from the user.

        Returns
        -------
        str
            One of ``"vuln_lookup"``, ``"attack_path"``, ``"coverage_map"``,
            or ``"mixed"``.

        Raises
        ------
        UnsupportedQueryError
            If the prompt cannot be mapped to any supported intent.
        """
        # Step 1: Explicit mixed-intent phrases → short-circuit
        if self._is_mixed(prompt):
            return "mixed"

        # Step 2: Entity-presence signals (boolean)
        has_cve = bool(_CVE_RE.search(prompt))
        has_cwe = bool(_CWE_RE.search(prompt))
        has_attack_id = bool(_ATTACK_ID_RE.search(prompt))
        has_cpe = bool(_CPE_RE.search(prompt))

        # Step 3: Keyword scores per domain
        vuln_score = _score(prompt, _VULN_PATTERNS)
        attack_score = _score(prompt, _ATTACK_PATTERNS)
        defense_score = _score(prompt, _DEFENSE_PATTERNS)

        # Step 4: Entity-first rule
        # When CVE or CPE is the only structured entity (no CWE, no ATT&CK ID),
        # default to vuln_lookup unless strong, unambiguous signals are present.
        #
        # Rationale: words like "exploitation", "attacker", "technique" often appear
        # in vulnerability descriptions and should NOT redirect to attack_path.
        # Only explicit traversal signals ("attack paths", "CAPEC", "TTPs", …) should.
        #
        # - Any attack signal + any defense signal together  → mixed
        # - Strong attack signal only                        → attack_path
        # - Any defense signal only (no attack signals)     → coverage_map (explicit only)
        # - Weak/no attack, no defense                      → vuln_lookup (default)
        if (has_cve or has_cpe) and not has_cwe and not has_attack_id:
            strong_attack = bool(_score(prompt, _STRONG_ATTACK_PATTERNS))
            any_attack = bool(attack_score)
            any_defense = bool(defense_score)
            if (strong_attack or any_attack) and any_defense:
                return "mixed"
            if strong_attack:
                return "attack_path"
            if any_defense and not any_attack:
                # When CVE is present but no ATT&CK ID exists, routing to coverage_map
                # would always fail extraction (coverage_map requires an attackId).
                # Force vuln_lookup so the CVE entity is usable.
                if has_cve:
                    return "vuln_lookup"
                return "coverage_map"
            return "vuln_lookup"

        # Step 5: Active domain flags (general resolution — CWE or ATT&CK ID present,
        # or no structured entity at all)
        # ATT&CK ID activates the defense domain (it is the coverage_map input)
        vuln_active = bool(vuln_score or has_cve or has_cpe)
        attack_active = bool(attack_score or has_cwe)
        defense_active = bool(defense_score or has_attack_id)

        active_domains = sum([vuln_active, attack_active, defense_active])

        # Step 6: Resolution rules
        if active_domains >= 3:
            return "mixed"

        if active_domains == 2:
            # attack + defense only (no vuln context) → coverage_map
            if defense_active and attack_active and not vuln_active:
                return "coverage_map"
            # vuln + attack only (no defense) → attack_path (start from vuln)
            if vuln_active and attack_active and not defense_active:
                return "attack_path"
            # vuln + defense only (no attack) → coverage_map (what defenses mitigate this vuln?)
            if vuln_active and defense_active and not attack_active:
                return "coverage_map"
            # If we reach here, domain activation logic is inconsistent
            raise UnsupportedQueryError(
                f"Unexpected two-domain combination: active_domains={active_domains}, "
                f"vuln={vuln_active}, attack={attack_active}, defense={defense_active}. "
                "This should not happen."
            )

        if active_domains == 1:
            if defense_active:
                return "coverage_map"
            if attack_active:
                return "attack_path"
            if vuln_active:
                return "vuln_lookup"

        # active_domains == 0 — cannot resolve
        raise UnsupportedQueryError(
            f"Cannot determine a KGCS intent for prompt: {prompt[:100]!r}. "
            "Expected a query referencing vulnerabilities (CVE/CPE), attack "
            "techniques (CWE/ATT&CK), or defensive coverage."
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _is_mixed(self, prompt: str) -> bool:
        """Return True if the prompt contains explicit end-to-end analysis signals.

        Parameters
        ----------
        prompt:
            Raw natural-language input.

        Returns
        -------
        bool
            True only for prompts that unambiguously span vulnerability analysis,
            attack path enumeration, AND defensive coverage.
        """
        return any(p.search(prompt) for p in _MIXED_PHRASES)
