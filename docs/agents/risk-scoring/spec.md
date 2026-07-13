# Risk Scoring Spec

## Purpose

Define how to surface risk signals to the orchestrator without altering KGCS core semantics.

## Scope

- Consumes Risk Extension when present; otherwise derives a minimal heuristic from CVSS and coverage.

## Inputs

- CVSS base scores (per version, not merged)
- Coverage metrics: count of mitigations, detections, deceptions
- Optional RiskExtension nodes: RiskAssessment, RiskScenario, RiskScore

## Algorithm

1. If RiskScore exists: use provided value; annotate source and methodology.
2. Else compute heuristic:
   - severity = max(CVSSv4, CVSSv3, CVSSv2 normalized to 0–1)
   - coverage_penalty = exp(-0.15 * coverage_count)
   - risk = severity * coverage_penalty
3. Clamp to [0,1]; map to bands LOW (<0.3), MEDIUM (0.3–0.6), HIGH (>0.6).

## Output

```json
{
  "risk": { "value": 0.62, "band": "HIGH", "method": "heuristic-v1" },
  "inputs": { "cvss": { "v3": 9.8 }, "coverage_count": 2 },
  "provenance": ["NVD", "KGCS coverage"]
}
```

## Invariants

- Never overwrite CVSS; heuristic is advisory only.
- If RiskExtension is present, the heuristic is skipped.
