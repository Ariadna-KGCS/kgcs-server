"""KGCS AI Interaction Layer.

Provides the NL->structured-request->rendered-answer pipeline that sits in front
of the deterministic KGCS orchestrator.

Public surface
--------------
LLMAdapter.process(prompt) -> dict

The LLMAdapter is the single entry point for all natural-language queries.
It enforces the strict execution order:
  classify -> extract -> safety -> build -> execute -> render

All downstream agents and the orchestrator remain unchanged and deterministic.
The LLM is strictly limited to intent classification, entity extraction, and
response rendering. It never generates Cypher or infers facts outside the KG.
"""

from .llm_adapter import LLMAdapter

__all__ = ["LLMAdapter"]
