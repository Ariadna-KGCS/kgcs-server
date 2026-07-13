# Offensive Agent — Schema View

Purpose

Support safe attack-path reasoning (CWE→CAPEC→ATT&CK) without altering core KGCS semantics. The Offensive Agent focuses on mapping weaknesses to attack patterns and techniques.

Scope

- Node labels: `Weakness`, `AttackPattern`, `Technique`, `SubTechnique`, `Tactic`, `Reference`.
- Relationship subset: `DEMONSTRATED_BY`/`EXPLOITED_BY`, `IMPLEMENTS`, `PART_OF`, `SUBTECHNIQUE_OF`.

Labels & Key Properties

- `Weakness`: `cweId`, `abstraction`
- `AttackPattern`: `capecId`, `likelihood` (extension), `severity` (extension)
- `Technique`/`SubTechnique`: `attackId`, `name`, `external_references`
- `Tactic`: `attackId`, `phaseName`

Allowed Traversals (examples)

- Weakness -[:DEMONSTRATED_BY|:EXPLOITED_BY]-> AttackPattern
- AttackPattern -[:IMPLEMENTS]-> Technique
- Technique -[:PART_OF]-> Tactic
- SubTechnique -[:SUBTECHNIQUE_OF]-> Technique

Query Templates (must be parameterized)

- Map weakness to techniques:

  MATCH (w:Weakness {cweId:$cwe})-[:DEMONSTRATED_BY]->(:AttackPattern)-[:IMPLEMENTS]->(t:Technique)

- List subtechniques:

  MATCH (t:Technique {attackId:$techId})<-[:SUBTECHNIQUE_OF]-(s:SubTechnique)

Response Contract

Responses must conform to the canonical agent response JSON Schema in `spec/contracts/agent-consumable-schema.json` and include `provenance` and `confidence`.

Example Response Shape

```json
{
  "techniques": [{ "id": "T1059", "tactic": "Execution", "capec": ["CAPEC-242"] }],
  "provenance": [{"source":"MITRE CAPEC","ids":["CAPEC-242"]}],
  "confidence": { "value": 0.78, "basis": "COMPLETE_CHAIN" }
}
```

Requirements & Guardrails

- Enforce causal chain and do not shortcut to ATT&CK without CAPEC/CWE evidence.
- Use only approved traversal templates.
- Include provenance and confidence in every response.
