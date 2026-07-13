# KGCS Architecture

## Purpose

Describe the end-to-end KGCS system with the new multi-agent cybersecurity orchestrator.

## Layers

- Ontology: frozen v1.0 OWL modules (core + standards) plus extensions.
- Governance: SHACL constraints and validation pipeline.
- Data: ETL → RDF → SHACL → Neo4j load.
- Graph: Neo4j with enforced causal chain and constraints.
- Agents: Orchestrator + Systems, Offensive, Defensive subagents.
- Infrastructure: Azure private, Terraform-managed.

## Multi-Agent Overview

- Orchestrator plans, routes, and aggregates; enforces causal chain; uses inter-agent contracts.
- Systems Agent: CPE/CVE/CWE, platform exposure, root-cause tracing.
- Offensive Agent: CAPEC/ATT&CK, attack-path reasoning.
- Defensive Agent: D3FEND/CAR/SHIELD/ENGAGE, mitigation/detection/deception coverage.
- Confidence Model: shared scoring for responses.
- Risk Scoring: advisory overlay; does not overwrite CVSS.

## Data Flow

1. Download authoritative datasets.
2. ETL to RDF per standard.
3. SHACL validation.
4. Load to Neo4j with constraints.
5. Agents query via approved traversal templates; responses include provenance and confidence.

## Key Invariants

- CPE → CVE → CWE → CAPEC → ATT&CK → {D3FEND, CAR, SHIELD, ENGAGE} (no skips).
- PlatformConfiguration, not Platform, for vulnerability impact.
- CVSS versions are separate nodes.
- Extensions never modify core semantics.
- Read-only graph access for agents.

## Pointers

- Core OWL (frozen v1.0): see `spec/ontology/core/core-ontology-v1.0.owl` (pinned kgcs-spec)
- Standards OWL modules (frozen v1.0): see `spec/ontology/standards/` (pinned kgcs-spec)
- Extension OWL baseline (v1.0): see `spec/ontology/extensions/asset-extension-v1.0.owl` (pinned kgcs-spec)
- Namespace policy: see `spec/docs/namespace-policy-v1.0.md` (pinned kgcs-spec)
- Namespace usage rule: `kgcs:` for core semantics, standards prefixes for standards facts, and `asset:` for extension-only concepts
- Schema capsule for agents: see `spec/contracts/agent-consumable-schema.md` (pinned kgcs-spec)
- Agent designs: see ../05-agents/
- Pipeline operations: see ../03-data-pipeline/pipeline-execution-guide.md
- Ontology and SHACL: see ../02-ontology/
- Infrastructure: see ../07-infrastructure/
