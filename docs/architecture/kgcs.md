# KGCS Overview

KGCS is a standards-backed cybersecurity knowledge graph that unifies NVD and MITRE taxonomies with a frozen ontology, SHACL governance, and a read-only Neo4j graph for AI reasoning.

## Core Principles

- Authoritative alignment with source standards; no invented semantics.
- Immutable core ontology; extensions add context only.
- Explicit provenance on every edge and node.
- RAG-safe traversal templates; no freeform shortcuts.

Ontology freeze baseline (v1.0):

- Core: `spec/ontology/core/core-ontology-v1.0.owl` (pinned kgcs-spec)
- Standards: `spec/ontology/standards/` (pinned kgcs-spec)
- Extensions: `spec/ontology/extensions/asset-extension-v1.0.owl` (pinned kgcs-spec)
- Namespace policy: `spec/docs/namespace-policy-v1.0.md` (pinned kgcs-spec)
- Canonical prefixes: `kgcs:` (core), standards prefixes (`cpe:`, `cve:`, `cwe:`, `cvss:`, `capec:`, `attack:`, `d3fend:`, `car:`, `shield:`, `engage:`), and `asset:` (extensions)

## Causal Chain

CPE → CVE → CWE → CAPEC → ATT&CK → {D3FEND, CAR, SHIELD, ENGAGE}

## What’s New (Multi-Agent)

- Master orchestrator with Systems, Offensive, and Defensive subagents.
- Inter-agent JSON contracts and confidence model.
- Risk scoring overlay (advisory, non-authoritative).
- Azure/Terraform deployment pattern.

## Where to Go Next

- Architecture: ../01-architecture/architecture.md
- Agent specs: ../05-agents/
- Graph schema: `spec/contracts/agent-consumable-schema.md` (pinned kgcs-spec)
- Pipeline: ../03-data-pipeline/pipeline-execution-guide.md
- Ontology and SHACL: ../02-ontology/
