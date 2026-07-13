"""Entity Extractor — extracts structured KGCS entity identifiers from a prompt.

Supported entity types
----------------------
cveId           – e.g. ``"CVE-2021-44228"``
cweId           – e.g. ``"CWE-502"``
attackId        – e.g. ``"T1059"`` or ``"T1059.001"``
cpeName         – e.g. ``"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"``
matchCriteriaId – UUID-style NVD match criteria identifier

Rules
-----
- Never invents identifiers. Only extracts tokens that are *explicitly* present
  in the prompt text.
- Returns only the fields relevant to the resolved ``intent``, as defined in
  ``orchestrator.constants.INTENT_PAYLOAD_FIELDS``.
- Returns an empty dict (not an error) when no entities are found; the upstream
  caller validates missing payload.
- Each helper returns the **first** match found and raises ``MultipleEntitiesError``
  if more than one distinct identifier of the same type is present.

Called at step 2 of ``LLMAdapter.process()``, after intent classification and
before safety checking.

Module-level regex constants (``_CVE_RE``, ``_CWE_RE``, ``_ATTACK_ID_RE``,
``_CPE_RE``, ``_MATCH_CRITERIA_RE``) are imported by ``IntentClassifier`` for
entity-presence checks, keeping patterns in one place.
"""

from __future__ import annotations

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Module-level regex constants — imported by IntentClassifier for existence
# checks, used here for extraction.
# ---------------------------------------------------------------------------

# CVE-YYYY-NNNN+ (4-digit year, 4+ digit sequence number, case-insensitive)
_CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,})\b", re.IGNORECASE)

# CWE-NNN (one or more digits)
_CWE_RE = re.compile(r"\bCWE-(\d+)\b", re.IGNORECASE)

# ATT&CK technique: T followed by exactly 4 digits, optional sub-technique .NNN
_ATTACK_ID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")

# CPE 2.3 URI: cpe:2.3:<type>:<vendor>:... (stops at whitespace / quote)
# Accepts cpe:2.3 and tolerates cpe:2.2 for robustness
_CPE_RE = re.compile(r"\bcpe:2\.[23]:[aoh]:[^\s\"'<>]+", re.IGNORECASE)

# NVD matchCriteriaId: UUID v4 format (8-4-4-4-12 lowercase hex groups)
_MATCH_CRITERIA_RE = re.compile(
    r"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
    re.IGNORECASE,
)


class MultipleEntitiesError(Exception):
    """Raised when more than one identifier of the same type is found.

    Multi-entity queries are not supported. The caller must resubmit with a
    single, unambiguous identifier.
    """


class EntityExtractor:
    """Extracts structured KGCS entity payload from a natural-language prompt.

    The extractor is stateless and safe to share across requests.
    """

    def extract(self, prompt: str, intent: str) -> dict:
        """Extract entity identifiers relevant to the given intent.

        Parameters
        ----------
        prompt:
            Raw natural-language input from the user.
        intent:
            Resolved KGCS intent string (from ``IntentClassifier``).

        Returns
        -------
        dict
            Payload dict compatible with
            ``orchestrator.constants.INTENT_PAYLOAD_FIELDS[intent]``.
            May be empty if no recognisable entities are present.
        """
        cve = self._extract_cve(prompt)
        cwe = self._extract_cwe(prompt)
        attack_id = self._extract_attack_id(prompt)
        cpe = self._extract_cpe(prompt)
        match_criteria_id = self._extract_match_criteria_id(prompt)

        payload: dict = {}

        if intent in ("vuln_lookup", "mixed"):
            # Priority: matchCriteriaId > cveId > cpeName
            if match_criteria_id:
                payload["matchCriteriaId"] = match_criteria_id
            elif cve:
                payload["cveId"] = cve
            elif cpe:
                payload["cpeName"] = cpe

        elif intent == "attack_path":
            # Priority: cweId > cveId
            if cwe:
                payload["cweId"] = cwe
            elif cve:
                payload["cveId"] = cve

        elif intent == "coverage_map":
            if attack_id:
                payload["attackId"] = attack_id

        return payload

    # ------------------------------------------------------------------
    # Private per-entity helpers
    # ------------------------------------------------------------------

    def _extract_cve(self, text: str) -> Optional[str]:
        """Extract the first CVE identifier from ``text``, or None.

        Expected format: ``CVE-YYYY-NNNNN`` (case-insensitive).
        Normalised to uppercase on return.

        Raises
        ------
        MultipleEntitiesError
            If more than one CVE identifier is present in the text.
        """
        matches = list(_CVE_RE.finditer(text))
        if len(matches) > 1:
            found = ", ".join(
                f"CVE-{m.group(1)}-{m.group(2)}".upper() for m in matches
            )
            raise MultipleEntitiesError(
                f"Multiple CVE identifiers detected ({found}); "
                "multi-entity queries are not supported yet"
            )
        if matches:
            m = matches[0]
            return f"CVE-{m.group(1)}-{m.group(2)}".upper()
        return None

    def _extract_cwe(self, text: str) -> Optional[str]:
        """Extract the first CWE identifier from ``text``, or None.

        Expected format: ``CWE-NNN`` (case-insensitive).
        Normalised to ``CWE-NNN`` on return.

        Raises
        ------
        MultipleEntitiesError
            If more than one CWE identifier is present in the text.
        """
        matches = list(_CWE_RE.finditer(text))
        if len(matches) > 1:
            found = ", ".join(f"CWE-{m.group(1)}" for m in matches)
            raise MultipleEntitiesError(
                f"Multiple CWE identifiers detected ({found}); "
                "multi-entity queries are not supported yet"
            )
        if matches:
            m = matches[0]
            return f"CWE-{m.group(1)}"
        return None

    def _extract_attack_id(self, text: str) -> Optional[str]:
        """Extract the first ATT&CK technique identifier from ``text``, or None.

        Expected format: ``TNNNN`` or ``TNNNN.NNN`` (e.g. ``T1059``, ``T1059.001``).
        Uppercase ``T`` is required — lowercase ``tNNNN`` is not a valid ATT&CK ID.

        Raises
        ------
        MultipleEntitiesError
            If more than one ATT&CK technique identifier is present in the text.
        """
        matches = list(_ATTACK_ID_RE.finditer(text))
        if len(matches) > 1:
            found = ", ".join(m.group(1) for m in matches)
            raise MultipleEntitiesError(
                f"Multiple ATT&CK technique identifiers detected ({found}); "
                "multi-entity queries are not supported yet"
            )
        if matches:
            return matches[0].group(1)  # already uppercase T from pattern
        return None

    def _extract_cpe(self, text: str) -> Optional[str]:
        """Extract a CPE 2.3 URI from ``text``, or None.

        Supports ``cpe:2.3:`` formatted strings (case-insensitive match,
        returned in original case as found in the text).

        Raises
        ------
        MultipleEntitiesError
            If more than one CPE URI is present in the text.
        """
        matches = list(_CPE_RE.finditer(text))
        if len(matches) > 1:
            found = ", ".join(m.group(0).rstrip(".,;") for m in matches)
            raise MultipleEntitiesError(
                f"Multiple CPE URIs detected ({found}); "
                "multi-entity queries are not supported yet"
            )
        if matches:
            return matches[0].group(0).rstrip(".,;")  # strip trailing punctuation
        return None

    def _extract_match_criteria_id(self, text: str) -> Optional[str]:
        """Extract an NVD matchCriteriaId (UUID) from ``text``, or None.

        Only matches the canonical 8-4-4-4-12 lowercase hex UUID format.

        Raises
        ------
        MultipleEntitiesError
            If more than one UUID is present in the text.
        """
        matches = list(_MATCH_CRITERIA_RE.finditer(text))
        if len(matches) > 1:
            found = ", ".join(m.group(1).lower() for m in matches)
            raise MultipleEntitiesError(
                f"Multiple matchCriteriaId UUIDs detected ({found}); "
                "multi-entity queries are not supported yet"
            )
        if matches:
            return matches[0].group(1).lower()
        return None
