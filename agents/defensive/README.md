# Defensive Agent

Read-only microservice for attack coverage maps: D3FEND mitigations, CAR detections, SHIELD deceptions, and ENGAGE engagement concepts for ATT&CK techniques.

## Overview

The Defensive Agent implements the `coverage_map` intent via one query pathway:
1. **By Technique** (attackId) → all defensive controls (D3FEND/CAR/SHIELD/ENGAGE) that cover or counter that technique

## Architecture

```
agents/defensive/
├── __init__.py                  # Package export
├── executor.py                  # DefensiveAgent class (orchestrator entry point)
├── cypher_templates.py          # Parameterized Cypher template + validation
├── transformers.py              # Neo4j Record → coverage arrays transformation
├── constants.py                 # Configuration (expected hops, timeouts, guardrails)
├── errors.py                    # Custom exceptions
├── README.md                     # This file
└── tests/                        # Test suite (50+ tests, 85%+ coverage)
    ├── test_executor.py         # Request routing, response envelope, error handling
    ├── test_transformers.py     # Neo4j → dict transformation, deduplication
    ├── test_cypher_syntax.py    # Template validation (params, structure)
    └── test_integration.py      # End-to-end with mocked Neo4jClient
```

## Usage

### Basic Request/Response

```python
from agents.defensive import DefensiveAgent
from agents.shared.neo4j_client import Neo4jClient

# Initialize agent
agent = DefensiveAgent()

# Coverage map request
request = {
    "version": "1.0",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
    "agent": "defensive",
    "intent": "coverage_map",
    "payload": {
        "attackId": "T1059"
    }
}

response = agent.execute(request)
# Returns: {
#   "version": "1.0",
#   "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
#   "status": "ok",
#   "data": {
#     "technique_id": "T1059",
#     "mitigations": [
#       { "d3fendId": "D3-PA", "name": "Process Analysis" },
#       { "d3fendId": "D3-NTA", "name": "Network Traffic Analysis" }
#     ],
#     "detections": [
#       { "analyticId": "CAR-2020-04-001", "title": "Batch File Write to System32", "coverageLevel": "High" }
#     ],
#     "deceptions": [
#       { "techniqueId": "DTE0001", "name": "Admin User Account" }
#     ],
#     "engagements": [
#       { "activityId": "EAC0002", "name": "Application Diversity" }
#     ],
#     "summary": {
#       "total_mitigations": 2,
#       "total_detections": 1,
#       "total_deceptions": 1,
#       "total_engagements": 1,
#       "has_coverage": true
#     }
#   },
#   "provenance": [
#     {"source": "MITRE D3FEND", "ids": ["D3-PA", "D3-NTA"], "timestamp": "..."},
#     {"source": "MITRE CAR", "ids": ["CAR-2020-04-001"], "timestamp": "..."},
#     {"source": "MITRE SHIELD", "ids": ["DTE0001"], "timestamp": "..."},
#     {"source": "MITRE ENGAGE", "ids": ["EAC0002"], "timestamp": "..."}
#   ],
#   "confidence": {
#     "value": 1.0,
#     "basis": "COVERAGE_MAP",
#     "signals": {"rows": 5, "hops": 1},
#     "degradation": []
#   },
#   "errors": []
# }
```

## Request Contract

**Payload Fields**:
- `"attackId"`: ATT&CK technique ID (e.g., "T1059" or "T1059.001") — required, triggers T_DEF_01 template

**Response Envelope**: Matches `agent-consumable-schema.json` — contains:
- **version**: "1.0"
- **correlation_id**: UUID string (propagated from request)
- **status**: "ok" | "empty" | "error"
- **data**: Defensive Agent-specific payload (see below)
- **provenance**: List of {source, ids, timestamp}
- **confidence**: {value, basis, signals, degradation}
- **errors**: List of error messages (only populated if status=error)

## Response Data Shapes

### Coverage Map Response (T_DEF_01)

```json
{
  "technique_id": "T1059",
  "mitigations": [
    {
      "d3fendId": "D3-PA",
      "name": "Process Analysis"
    },
    {
      "d3fendId": "D3-NTA",
      "name": "Network Traffic Analysis"
    }
  ],
  "detections": [
    {
      "analyticId": "CAR-2020-04-001",
      "title": "Batch File Write to System32",
      "coverageLevel": "High"
    },
    {
      "analyticId": "CAR-2021-05-002",
      "title": "Powershell Execution",
      "coverageLevel": "Moderate"
    }
  ],
  "deceptions": [
    {
      "techniqueId": "DTE0001",
      "name": "Admin User Account"
    }
  ],
  "engagements": [
    {
      "activityId": "EAC0002",
      "name": "Application Diversity"
    },
    {
      "approachId": "SAP0001",
      "name": "Strategic Approach"
    },
    {
      "goalId": "SGO0001",
      "name": "Strategic Goal"
    }
  ],
  "summary": {
    "total_mitigations": 2,
    "total_detections": 2,
    "total_deceptions": 1,
    "total_engagements": 3,
    "has_coverage": true
  }
}
```

## Cypher Template

### T_DEF_01: Defensive Controls for a Technique

```cypher
MATCH (t:Technique {attackId: $attackId})
OPTIONAL MATCH (t)-[:MITIGATED_BY]->(d:DefensiveTechnique)
OPTIONAL MATCH (t)-[:DETECTED_BY]->(c:DetectionAnalytic)
OPTIONAL MATCH (t)-[:COUNTERED_BY]->(s:DeceptionTechnique)
OPTIONAL MATCH (e:EngagementConcept)-[:DISRUPTS]->(t)
RETURN t, collect(d) AS mitigations, collect(c) AS detections, collect(s) AS deceptions, collect(e) AS engagements
```

**Expected hops**: 1 (Technique → defensive controls)

## Confidence Scoring

Computed by `ConfidenceScorer.compute()` using framework coverage model:

- **Row count**: Number of defensive control records returned
- **Framework count**: How many of the 4 frameworks (D3FEND, CAR, SHIELD, ENGAGE) are represented
- **Expected frameworks**: 4 (all should be covered)
- **Shape validated**: Always False (Defensive Agent doesn't run SHACL)

**Basis values**:
- `COVERAGE_MAP`: Result count > 0 (defensive controls found)
- `NO_MATCH`: Result count == 0 (no defensive controls)

**Degradation model**:
- Start at 1.0 if rows > 0
- Subtract 0.1 per missing framework
- Example: only 2/4 frameworks present → 0.8 confidence

**Degradation factors**:
- Missing frameworks: -0.1 per missing D3FEND/CAR/SHIELD/ENGAGE
- Stale data (>365 days): -0.1 (if tracked)

## Error Handling

Three-tier error response:

1. **ValidationError** → User provided invalid payload
   - Missing "attackId" in payload
   - Invalid techniqueId format
   - Response status: "error" with [errors list]

2. **QueryExecutionError** → Neo4j query failed
   - Connection timeout, query timeout, row limit exceeded
   - Response status: "error" with [errors list]

3. **Exception** → Unexpected runtime error
   - Response status: "error" with ["Internal service error"]

All errors include correlation_id for tracing.

## Configuration

See `constants.py`:

```python
EXPECTED_HOPS = {
    "coverage_map": 1
}

MISSING_FRAMEWORK_PENALTY = 0.1
STALE_DATA_PENALTY = 0.1
STALE_DATA_THRESHOLD_DAYS = 365

QUERY_TIMEOUT_SECONDS = 30
MAX_RESULT_ROWS = 10000

VALID_INTENTS = ["coverage_map"]
VALID_PAYLOAD_FIELDS = {"attackId"}
```

## Testing

Run the test suite:

```bash
python -m pytest agents/defensive/tests/ -v
```

**Test coverage**:
- **test_cypher_syntax.py**: 6 tests — Template validation, parameterization
- **test_transformers.py**: 16 tests — Data aggregation, deduplication, provenance
- **test_executor.py**: 15 tests — Routing, response building, error handling
- **test_integration.py**: 11 tests — End-to-end flows, envelope structure, schema compliance

**Total**: 48 tests, all passing (targeting 85%+ coverage)

## Integration with Orchestrator

The Master Orchestrator calls the Defensive Agent for `coverage_map` intents:

```python
agent = DefensiveAgent()  # Instances created by orchestrator
response = agent.execute(request_envelope)  # Where intent="coverage_map"

# Extract and aggregate results
if response["status"] == "ok":
    techniques = response["data"]["techniques"]
    coverage = response["data"]["mitigations"]
    provenance = response["provenance"]
    confidence = response["confidence"]

    # Route to next phase if mixed intent requested
    if request["intent"] == "mixed":
        # Orchestrator may aggregate with other agents
```

## Dependencies

- `neo4j>=5.0.0`: Neo4j driver (read-only mode)
- `jsonschema>=0.28.0`: JSON Schema validation
- `agents.shared.*`: Shared library modules (types, confidence_scorer, response_builder, schema_validator, logger)

All dependencies defined in `requirements.txt`.

## Data Flow Example: T1059 Coverage Map

1. Request: `{"intent": "coverage_map", "payload": {"attackId": "T1059"}, ...}`
2. execute() → _select_template("coverage_map") → _execute_query()
3. Neo4j returns: 5 records (D3FEND + CAR + SHIELD + ENGAGE controls)
4. _transform_results() → deduplicates to coverage arrays, builds summary
5. extract_provenance() → [{source: "MITRE D3FEND", ids: [...]}, {source: "MITRE CAR", ids: [...]}, ...]
6. _compute_confidence() → {value: 1.0, basis: "COVERAGE_MAP", hops: 1}
7. response_builder.ok() → full envelope
8. schema_validator validates response against defensive-response.json
9. Return ResponseEnvelope dict

## Key Design Decisions

1. **Single Template Route**: Only one query pathway (coverage_map), simpler than Systems/Offensive agents
2. **Framework-Based Confidence**: Penalty model for missing frameworks (not causal chain hops)
3. **Summary Object**: Aggregate counts for rapid risk assessment
4. **Coverage Only**: No attackId aggregation; single technique per request
5. **Four-Source Provenance**: D3FEND, CAR, SHIELD, ENGAGE separated by source
6. **Engagement Type Variants**: Handle activityId/approachId/goalId as distinct fields per schema

## Phase Status

**Phase 2C-4**: ✓ Complete
- Cypher template management (1 template)
- Request routing (single attackId route)
- Neo4j → JSON transformation with deduplication
- Framework-based confidence scoring
- Four-source provenance tracking
- Error handling and validation
- Full test suite (48 tests)

**Next**: Phase 2C-5 (Master Orchestrator) → Phase 3 (Integration & Deployment)

