"""Safety Layer — validates classified intent + extracted payload before orchestrator dispatch.

This module operates on the *structured output* of the classifier and extractor
(intent string + payload dict). An optional raw-prompt parameter enables additional
heuristic scanning for known prompt-injection patterns.

Checks performed
----------------
1. Intent is one of the four valid KGCS intents (double-check after classification).
2. Payload does not contain clearly dangerous Cypher output markers.
3. (Optional) Raw prompt does not match known prompt-injection patterns.

Errors
------
``SafetyViolationError``   – raised when any check fails. The ``/ask`` handler
                             should catch this and return HTTP 400.
``UnsupportedQueryError``  – raised when the intent is not in ``VALID_INTENTS``.

Called at step 3 of ``LLMAdapter.process()``, after entity extraction and
before building the orchestrator request.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from orchestrator.constants import VALID_INTENTS


class SafetyViolationError(Exception):
    """Raised when the intent+payload combination violates a safety rule."""


class UnsupportedQueryError(Exception):
    """Raised when the intent is not in the list of supported KGCS intents."""


# ---------------------------------------------------------------------------
# Module-level safety constants
# ---------------------------------------------------------------------------

# Payload keywords that indicate Cypher query language fragments.
# Restricted to clearly dangerous Cypher output markers only; common English
# words such as "match" and "query" are excluded to avoid false positives.
_PAYLOAD_BANNED: frozenset = frozenset({"cypher", "return"})

# Heuristic patterns for prompt-injection detection.
_PROMPT_INJECTION: List[re.Pattern] = [
    re.compile(r"\bignore\b.{0,30}\bprevious\b.{0,30}\binstructions?\b", re.I | re.S),
    re.compile(r"\bgenerate\b.{0,20}\bcypher\b", re.I),
    re.compile(r"\bbypass\b", re.I),
]

# Uppercase Cypher query keywords for multi-keyword detection.
# Case-sensitive: natural English uses lowercase ("return", "where"), while
# Cypher queries conventionally appear in uppercase. Requiring a minimum of
# _CYPHER_QUERY_THRESHOLD distinct keywords before firing keeps false-positive
# risk low for prompts that legitimately contain one such word.
_CYPHER_QUERY_KEYWORDS: List[re.Pattern] = [
    re.compile(r"\bRETURN\b"),
    re.compile(r"\bWHERE\b"),
    re.compile(r"\bLIMIT\b"),
    re.compile(r"\bMATCH\b"),
    re.compile(r"\bMERGE\b"),
    re.compile(r"\bDELETE\b"),
]
_CYPHER_QUERY_THRESHOLD: int = 2


class SafetyChecker:
    """Validates a classified intent + extracted payload before orchestrator dispatch.

    The checker is stateless and safe to share across requests.
    """

    _VALID_INTENTS: frozenset = frozenset(VALID_INTENTS)

    def check(
        self,
        intent: str,
        payload: Dict[str, Any],
        prompt: Optional[str] = None,
    ) -> None:
        """Validate the intent, payload, and optional raw prompt.

        Parameters
        ----------
        intent:
            The resolved KGCS intent string (from ``IntentClassifier``).
        payload:
            The extracted entity payload dict (from ``EntityExtractor``).
        prompt:
            Optional raw natural-language input. When provided, scanned for
            known prompt-injection patterns.

        Raises
        ------
        UnsupportedQueryError
            If ``intent`` is not in ``VALID_INTENTS``.
        SafetyViolationError
            If the payload contains disallowed keywords, or the prompt matches
            a known injection pattern.
        """
        self._intent_is_valid(intent)
        self._payload_requests_cypher(payload)
        if prompt is not None:
            self._check_prompt_injection(prompt)
            self._check_cypher_query_pattern(prompt)

    # ------------------------------------------------------------------
    # Private guard methods
    # ------------------------------------------------------------------

    def _intent_is_valid(self, intent: str) -> bool:
        """Return True if ``intent`` is in the set of supported KGCS intents.

        Raises ``UnsupportedQueryError`` when the intent is not recognised.
        """
        if intent not in self._VALID_INTENTS:
            raise UnsupportedQueryError(
                f"Intent '{intent}' is not a supported KGCS intent. "
                f"Expected one of: {sorted(self._VALID_INTENTS)}"
            )
        return True

    def _payload_requests_cypher(self, payload: Dict[str, Any]) -> None:
        """Raise ``SafetyViolationError`` if any payload value contains a banned keyword.

        Performs a case-insensitive substring scan of all string values in the payload.
        """
        for value in payload.values():
            if isinstance(value, str):
                v_lower = value.lower()
                for kw in _PAYLOAD_BANNED:
                    if kw in v_lower:
                        raise SafetyViolationError(
                            f"Payload contains a disallowed keyword ({kw!r}). "
                            "Cypher query language fragments are not permitted in entity values."
                        )

    def _check_prompt_injection(self, prompt: str) -> None:
        """Raise ``SafetyViolationError`` if the prompt matches a known injection pattern."""
        for pattern in _PROMPT_INJECTION:
            if pattern.search(prompt):
                raise SafetyViolationError(
                    "Prompt contains a pattern associated with prompt-injection. "
                    "Request rejected for safety."
                )

    def _check_cypher_query_pattern(self, prompt: str) -> None:
        """Raise ``SafetyViolationError`` when the prompt resembles a Cypher read query.

        Scans for uppercase Cypher keywords (``RETURN``, ``WHERE``, ``LIMIT``, …).
        Case-sensitive matching is intentional: natural English uses lowercase
        forms ("return", "where") while Cypher queries conventionally appear in
        uppercase. Fires only when at least ``_CYPHER_QUERY_THRESHOLD`` distinct
        keywords are detected, keeping single-occurrence false positives low.
        """
        hit_count = sum(1 for p in _CYPHER_QUERY_KEYWORDS if p.search(prompt))
        if hit_count >= _CYPHER_QUERY_THRESHOLD:
            raise SafetyViolationError(
                f"Prompt contains {hit_count} Cypher-like query keywords. "
                "Raw query language fragments are not permitted in prompts."
            )

    def _payload_suppresses_provenance(self, payload: Dict[str, Any]) -> bool:  # noqa: ARG002
        """Return True if the payload suppresses provenance output.

        Full implementation is deferred; always returns False.
        """
        return False
