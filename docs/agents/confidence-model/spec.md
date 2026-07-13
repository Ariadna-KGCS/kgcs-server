# Confidence Model Spec

## Purpose

Standardize how agents express certainty in results returned from KGCS traversals.

## Scope

- Applies to orchestrator and all subagents.
- Output-only; no ontology changes.

## Components

- `value` (0–1 float)
- `basis` (enum): COMPLETE_CHAIN, PARTIAL_CHAIN, SINGLE_HOP, NO_MATCH, VALIDATED_BY_SHACL
- `signals`: row_count, hop_count, template_used, shape_validated (bool), freshness_days
- `degradation`: timeout, empty_branch, schema_drop

## Computation

- Start at 1.0 for COMPLETE_CHAIN with SHACL validation and more than zero rows.
- Subtract 0.2 for each missing hop in the causal chain.
- Subtract 0.1 if freshness_days > 365.
- Floor at 0.0; cap at 1.0.

## Output Example

```json
{
  "value": 0.78,
  "basis": "COMPLETE_CHAIN",
  "signals": { "rows": 12, "hops": 4, "shape_validated": true, "freshness_days": 120 },
  "degradation": []
}
```

## Governance

- Versioned model; changes require agent contract version bump.
- Logged with every response for audit.
