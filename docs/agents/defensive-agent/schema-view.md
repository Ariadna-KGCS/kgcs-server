# Defensive Agent — Schema View

Purpose

Return coverage maps for ATT&CK techniques: mitigations, detections, and deception controls. The Defensive Agent aggregates D3FEND, CAR, and SHIELD mappings per technique.

Scope

- Node labels: `Technique`, `DefensiveTechnique`, `DetectionAnalytic`, `DeceptionTechnique`, `EngagementConcept`.
- Relationship subset: `MITIGATED_BY`, `DETECTED_BY`, `COUNTERED_BY`, `DISRUPTS`.

Labels & Key Properties

- `DefensiveTechnique`: `d3fendId`, `sophisticationLevel` (extension), `costLevel` (extension)
- `DetectionAnalytic`: `analyticId`, `dataSources`
- `DeceptionTechnique`: `techniqueId`, `primaryObjective`
- `EngagementConcept`: `activityId` / `approachId` / `goalId`, `strategyType`

Allowed Traversals (examples)

- Technique -[:MITIGATED_BY]-> DefensiveTechnique
- Technique -[:DETECTED_BY]-> DetectionAnalytic
- Technique -[:COUNTERED_BY]-> DeceptionTechnique
- EngagementConcept -[:DISRUPTS]-> Technique

Query Templates (must be parameterized)

- Coverage map:

  MATCH (t:Technique {attackId:$id})
  OPTIONAL MATCH (t)-[:MITIGATED_BY]->(d:DefensiveTechnique)
  OPTIONAL MATCH (t)-[:DETECTED_BY]->(c:DetectionAnalytic)
  OPTIONAL MATCH (t)-[:COUNTERED_BY]->(s:DeceptionTechnique)
  RETURN collect(d.d3fendId) AS mitigations, collect(c.analyticId) AS detections, collect(s.techniqueId) AS deceptions

- Strategic disruptors:

  MATCH (e:EngagementConcept)-[:DISRUPTS]->(t:Technique {attackId:$id})

Response Contract

Responses must conform to the canonical agent response JSON Schema in `spec/contracts/agent-consumable-schema.json` and include `provenance` and `confidence`.

Example Response Shape

```json
{
  "mitigations": ["D3-PA"],
  "detections": ["CAR-2020-04-001"],
  "deceptions": ["SHIELD-A"],
  "engagements": [],
  "confidence": { "value": 0.74, "basis": "COVERAGE_MAP" }
}
```

Requirements & Guardrails

- Coverage counts are additive and do not modify causal edges.
- Use only approved traversal templates; include provenance and confidence.
