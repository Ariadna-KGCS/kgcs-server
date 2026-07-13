"""KGCS Agent Runtimes

Multi-agent orchestration system for cybersecurity knowledge graph queries.

Subpackages:
- shared: Foundational utilities for all agents (confidence scoring, risk assessment, etc.)
- systems: Systems Agent (platform/CVE/CWE mapping)
- offensive: Offensive Agent (CWE/CAPEC/Technique attack path mapping)
- defensive: Defensive Agent (coverage mapping with mitigations/detections/deceptions)
- orchestrator: Master Orchestrator (request routing and result aggregation)

Phase 2C Implementation:
- Phase 2C-1: Shared Library (agents/shared/)  -- COMPLETE
- Phase 2C-2: Systems Agent (agents/systems/)
- Phase 2C-3: Offensive Agent (agents/offensive/)
- Phase 2C-4: Defensive Agent (agents/defensive/)
- Phase 2C-5: Master Orchestrator (agents/orchestrator/)
"""
