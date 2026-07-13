"""LLM Adapter — pipeline orchestrator for the KGCS AI interaction layer.

This module is the single entry point called by the ``/ask`` aiohttp endpoint.
It enforces a strict, sequential execution order and delegates each step to a
dedicated, focused class. It is intentionally NOT monolithic.

Execution order (must not be changed)
--------------------------------------
1. ``IntentClassifier.classify(prompt)``
   Maps the raw natural-language prompt to one of four KGCS intents.

2. ``EntityExtractor.extract(prompt, intent)``
   Extracts structured entity identifiers (cveId, cweId, attackId, cpeName, …)
   from the prompt, guided by the resolved intent.

3. ``SafetyChecker.check(intent, payload, prompt=prompt)``
   Validates the classified intent, extracted payload, and raw prompt (for
   injection heuristics). Raises ``SafetyViolationError`` if unsafe.

4. ``_build_request(intent, payload, correlation_id)``
   Assembles the orchestrator-compatible request envelope.

5. ``MasterOrchestrator.execute(request)``
   Runs the deterministic agent pipeline. This call is unchanged.

6. ``ResponseRenderer.render(response, intent)``
   Converts the structured ``ResponseEnvelope`` into a human-readable answer
   string. Provenance and confidence are always included.

Strict constraints
------------------
- Never generates Cypher queries.
- Never infers facts not present in the Knowledge Graph.
- Always propagates provenance and confidence from the orchestrator response.
- ``session_id`` is accepted and forwarded but no session logic is implemented yet.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional
from uuid import uuid4

if TYPE_CHECKING:
    from orchestrator.executor import MasterOrchestrator

from orchestrator.constants import INTENT_PAYLOAD_FIELDS
from .intent_classifier import IntentClassifier, UnsupportedQueryError
from .entity_extractor import EntityExtractor
from .safety import SafetyChecker
from .response_renderer import ResponseRenderer


class EntityNotFoundError(Exception):
    """Raised when no recognisable entities are extracted for the resolved intent."""


class LLMAdapter:
    """Pipeline orchestrator for the KGCS AI interaction layer.

    Instantiate once per request, passing the ``MasterOrchestrator`` instance
    that was created for the same request (same pattern as ``/query`` today).

    Parameters
    ----------
    orchestrator:
        A ``MasterOrchestrator`` instance, pre-constructed with the appropriate
        ``correlation_id`` by the aiohttp ``/ask`` handler.
        Optional — if omitted, ``process()`` will raise; ``process_prompt()``
        works without it.
    classifier:
        Optional ``IntentClassifier`` override (defaults to a new instance).
    extractor:
        Optional ``EntityExtractor`` override (defaults to a new instance).
    safety:
        Optional ``SafetyChecker`` override (defaults to a new instance).
    renderer:
        Optional ``ResponseRenderer`` override (defaults to a new instance).
    """

    def __init__(
        self,
        orchestrator: Optional["MasterOrchestrator"] = None,
        classifier: Optional[IntentClassifier] = None,
        extractor: Optional[EntityExtractor] = None,
        safety: Optional[SafetyChecker] = None,
        renderer: Optional[ResponseRenderer] = None,
    ) -> None:
        self._orchestrator = orchestrator
        self._classifier = classifier or IntentClassifier()
        self._extractor = extractor or EntityExtractor()
        self._safety = safety or SafetyChecker()
        self._renderer = renderer or ResponseRenderer()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_prompt(self, prompt: str) -> Dict[str, Any]:
        """Classify intent, extract entities, and build orchestrator request.

        Runs steps 1–4 of the pipeline without executing the orchestrator.
        Useful for testing and for building requests that will be sent separately.

        Parameters
        ----------
        prompt:
            Raw natural-language query from the user.

        Returns
        -------
        dict
            Orchestrator-compatible request envelope with keys:
            ``version``, ``agent``, ``intent``, ``payload``,
            ``correlation_id``.

        Raises
        ------
        UnsupportedQueryError
            If the prompt cannot be mapped to a KGCS intent.
        EntityNotFoundError
            If no recognisable entities are present for the resolved intent.
        """
        intent = self._classifier.classify(prompt)  # step 1

        payload = self._extractor.extract(prompt, intent)  # step 2

        if not payload:
            raise EntityNotFoundError(
                f"No recognisable entities found for intent '{intent}' in the prompt. "
                "Please include a specific CVE ID, CWE ID, ATT&CK technique ID, or CPE name."
            )

        # Use orchestrator correlation_id when available, otherwise generate one.
        correlation_id: str = (
            getattr(self._orchestrator, "correlation_id", None) or str(uuid4())
        )

        return self._build_request(intent, payload, correlation_id)  # step 4

    def process(
        self,
        prompt: str,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run the full NL-to-answer pipeline.

        Parameters
        ----------
        prompt:
            Raw natural-language query from the user.
        session_id:
            Optional session identifier. Accepted and forwarded but no session
            logic is implemented at this stage.

        Returns
        -------
        dict with keys:
            ``answer``  – human-readable, graph-grounded answer string.
            ``raw``     – the full ``ResponseEnvelope`` dict from the orchestrator.
            ``intent``  – resolved KGCS intent string.
            ``payload`` – entity payload dict sent to the orchestrator.

        Raises
        ------
        UnsupportedQueryError
            If the prompt cannot be mapped to a KGCS intent.
        EntityNotFoundError
            If no recognisable entities are present for the resolved intent.
        RuntimeError
            If no orchestrator was provided at construction time.
        """
        if self._orchestrator is None:
            raise RuntimeError(
                "LLMAdapter.process() requires an orchestrator instance. "
                "Pass orchestrator= at construction time."
            )

        # Step 1: Classify intent
        intent = self._classifier.classify(prompt)

        # Step 2: Extract entities
        payload = self._extractor.extract(prompt, intent)

        # Validate payload is not empty
        if not payload:
            raise EntityNotFoundError(
                f"No recognisable entities found for intent '{intent}' in the prompt. "
                "Please include a specific CVE ID, CWE ID, ATT&CK technique ID, or CPE name."
            )

        # Step 3: Safety check (intent + payload + raw prompt for injection heuristics)
        self._safety.check(intent, payload, prompt=prompt)

        # Step 4: Build orchestrator request envelope
        correlation_id: str = (
            getattr(self._orchestrator, "correlation_id", None) or str(uuid4())
        )
        request = self._build_request(intent, payload, correlation_id)

        # Step 5: Execute orchestrator (deterministic pipeline)
        raw = self._orchestrator.execute(request)

        # Step 6: Render response to human-readable answer
        answer = self._renderer.render(raw, intent)

        return {
            "answer": answer,
            "raw": raw,
            "intent": intent,
            "payload": payload,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _validate_payload_fields(self, intent: str, payload: Dict[str, Any]) -> None:
        """Validate payload fields against INTENT_PAYLOAD_FIELDS.

        This is the authoritative validation point where intent and payload are
        assembled into the final orchestrator request. Ensures payload contains
        only valid fields for the given intent.

        Parameters
        ----------
        intent:
            Validated KGCS intent string.
        payload:
            Entity payload extracted from the prompt.

        Raises
        ------
        ValueError:
            If payload contains invalid fields or no valid fields for the intent.
        """
        valid_fields = INTENT_PAYLOAD_FIELDS.get(intent, set())
        payload_keys = set(payload.keys())

        # Check at least one valid field is present
        if not payload_keys.intersection(valid_fields):
            raise ValueError(
                f"Payload for intent '{intent}' must contain at least one of {valid_fields}, "
                f"but got: {payload_keys}"
            )

        # Check no extraneous fields
        invalid_keys = payload_keys - valid_fields
        if invalid_keys:
            raise ValueError(
                f"Payload for intent '{intent}' contains invalid fields: {invalid_keys}. "
                f"Valid fields: {valid_fields}"
            )

    def _build_request(
        self,
        intent: str,
        payload: Dict[str, Any],
        correlation_id: str,
    ) -> Dict[str, Any]:
        """Assemble the orchestrator-compatible request envelope.

        Parameters
        ----------
        intent:
            Validated KGCS intent string.
        payload:
            Entity payload extracted from the prompt.
        correlation_id:
            Correlation ID to propagate through the orchestrator.

        Returns
        -------
        dict matching the shape expected by ``MasterOrchestrator.execute()``.
        """
        # Validate payload fields against INTENT_PAYLOAD_FIELDS
        self._validate_payload_fields(intent, payload)

        return {
            "version": "1.0",
            "agent": "master",
            "intent": intent,
            "payload": payload,
            "correlation_id": correlation_id,
        }
