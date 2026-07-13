# Systems Agent — Schema View

Purpose

Provide a constrained, read-only view of KGCS for asset and vulnerability queries. The Systems Agent is authoritative for Platform/PlatformConfiguration ↔ Vulnerability mappings and root-cause traversal to Weakness.

Scope

- Node labels: `Platform`, `PlatformConfiguration`, `Vulnerability`, `VulnerabilityConfiguration`, `VulnerabilityConfigurationNode`, `Weakness`, `Score`, `Reference`.
- Relationship subset: `AFFECTS`, `HAS_CONFIGURATION`, `HAS_NODE`, `MATCHES_CRITERIA`, `MATCHES_PLATFORM`, `CAUSED_BY`, `HAS_SCORE`, `REFERENCES` (read-only).

Ontology Alignment (for future implementation)

- Core remains authoritative (`kgcs:` namespace) and immutable.
- Systems-agent compatibility aliases are defined in standards namespaces to match graph-facing edge names:
  - `AFFECTS` ↔ `cve:affects` (inverse of `kgcs:affected_by`)
  - `HAS_SCORE` ↔ `cvss:hasScore` (subPropertyOf `kgcs:scored_by`)
  - `REFERENCES` ↔ `cve:references` (subPropertyOf `kgcs:references`)
  - `CAUSED_BY` remains `kgcs:caused_by`
- Systems key fields are declared in standards modules for schema stability (`cpe:cpeUri`, `cpe:matchCriteriaId`, `cpe:criteria`, version bounds, `cpe:configStatus`, `cpe:vulnerable`, `cve:cveId`, `cwe:cweId`, `cvss:scoreId`, `cvss:baseScore`, `cvss:version`, etc.).

Labels & Key Properties

- `Platform`: `cpeUri`, `cpeNameId`, `part`, `vendor`, `product`, `version`
- `PlatformConfiguration`: `matchCriteriaId`, `criteria`, version bounds, `configStatus`, `vulnerable`, `created`, `lastModified`, `cpeLastModified`
- `VulnerabilityConfiguration`: `vcId`, `operator`, `negate`
- `VulnerabilityConfigurationNode`: `vcnId`, `operator`, `negate`
- `Vulnerability`: `cveId`, `published`, `lastModified`, `source`
- `Weakness`: `cweId`, `abstraction`
- `Score`: `scoreId`, `version`, `baseScore`

Allowed Traversals (examples)

- PlatformConfiguration <-[:AFFECTS]- Vulnerability
- Vulnerability -[:HAS_CONFIGURATION]-> VulnerabilityConfiguration
- VulnerabilityConfiguration -[:HAS_NODE]-> VulnerabilityConfigurationNode
- VulnerabilityConfigurationNode -[:MATCHES_CRITERIA]-> PlatformConfiguration
- PlatformConfiguration -[:MATCHES_PLATFORM]-> Platform
- Vulnerability -[:CAUSED_BY]-> Weakness
- Vulnerability -[:HAS_SCORE]-> Score
- Vulnerability -[:REFERENCES]-> Reference

Query Templates (must be parameterized)

- Find vulnerabilities for a platform config:

  MATCH (pc:PlatformConfiguration {matchCriteriaId:$id})<-[:AFFECTS]-(v:Vulnerability)

- Trace vulnerability root cause:

  MATCH (v:Vulnerability {cveId:$cve})-[:CAUSED_BY]->(w:Weakness)

Response Contract

Responses must conform to the canonical agent response JSON Schema in `spec/contracts/agent-consumable-schema.json` and include `provenance` and `confidence`.

Notes:

- `Platform.cpeUri` is the canonical CPE identity.
- `PlatformConfiguration` is authoritative through `matchCriteriaId`, `criteria`, version bounds, and `MATCHES_PLATFORM`.
- `AFFECTS` remains a compatibility projection; exact CVE applicability is preserved by `HAS_CONFIGURATION` / `HAS_NODE` / `MATCHES_CRITERIA`.

Example Response Shape

```json
{
  "vulnerabilities": [{
    "cveId": "CVE-2025-1234",
    "scores": [{"version":"3.1","baseScore":9.8}],
    "weakness": {"cweId":"CWE-79"},
    "resolvedPlatforms": [{"cpeUri": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}],
    "applicability": {
      "configurations": [{
        "vcId": "CVE-2025-1234::CFG::1",
        "operator": "OR",
        "negate": false,
        "nodes": [{
          "vcnId": "CVE-2025-1234::CFG::1::NODE::1",
          "operator": "OR",
          "negate": false,
          "criteria": [{
            "matchCriteriaId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "vulnerable": true,
            "resolvedPlatforms": [{"cpeUri": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}]
          }]
        }]
      }]
    }
  }],
  "provenance": [{ "source": "NVD", "ids": ["CVE-2025-1234"] }],
  "confidence": { "value": 0.82, "basis": "COMPLETE_CHAIN" }
}
```

Requirements & Guardrails

- Use only approved, parameterized Cypher templates supplied by the orchestrator.
- Ensure responses include authoritative provenance and a `confidence` object computed per `docs/05-agents/confidence-model/spec.md`.
- Do not perform schema or graph mutations.
