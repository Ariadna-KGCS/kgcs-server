# Governance

## Purpose

Define SHACL validation framework, provenance enforcement, and governance processes for KGCS integrity.

## Scope

- SHACL shapes and constraints
- Validation pipeline integration
- Provenance traceability
- CI/CD governance

## SHACL Validation Framework

KGCS uses SHACL (Shapes Constraint Language) to enforce semantic integrity:

- **Shapes Directory**: `shapes/` contains TTL files with constraints for each standard (e.g., `cve.shacl.ttl`).
- **Validation Phases**: Download → ETL → SHACL streaming validation → Load.
- **Error Handling**: Violations logged with provenance; blocks invalid data from graph.

Example shape for CVE:

```turtle
@prefix shape: <http://kgcs.motherhacker.me/shapes#> .

shape:VulnerabilityShape a sh:NodeShape ;
    sh:targetClass kgcs:Vulnerability ;
    sh:property [
        sh:path cve:cveId ;
        sh:datatype xsd:string ;
        sh:minCount 1 ;
    ] .
```

## Provenance Enforcement

Every node/edge must trace to authoritative source:

- **Sources**: NVD JSON, MITRE STIX, standards docs.
- **Metadata**: `source` property on nodes; `reference` relationships.
- **Validation**: SHACL checks for presence of provenance.

## CI/CD Integration

- **Pipeline**: Automated SHACL validation on PRs.
- **Governance**: No merges without passing shapes.
- **Audits**: Monthly reports on constraint coverage.

## Agent Governance

Agents must validate responses against SHACL-derived schemas.
