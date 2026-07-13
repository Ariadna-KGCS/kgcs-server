# Offensive Agent

Read-only microservice for attack path queries: Weakness ↔ AttackPattern ↔ Technique mappings.

## Overview

The Offensive Agent implements the `attack_path` intent via one query pathway:
1. **By CWE** (cweId) → all ATT&CK techniques that exploit or demonstrate that weakness

## Architecture

```
agents/offensive/
├── __init__.py                  # Package export
├── executor.py                  # OffensiveAgent class (orchestrator entry point)
├── cypher_templates.py          # Parameterized Cypher template + validation
├── transformers.py              # Neo4j Record → techniques array transformation
├── constants.py                 # Configuration (expected hops, timeouts, guardrails)
├── errors.py                    # Custom exceptions
├── README.md                     # This file
└── tests/                        # Test suite (55+ tests, 85%+ coverage)
    ├── test_executor.py         # Request routing, response envelope, error handling
    ├── test_transformers.py     # Neo4j → dict transformation, deduplication
    ├── test_cypher_syntax.py    # Template validation (params, structure)
    └── test_integration.py      # End-to-end with mocked Neo4jClient
```

## Usage

### Basic Request/Response

```python
from agents.offensive import OffensiveAgent
from agents.shared.neo4j_client import Neo4jClient

# Initialize agent
agent = OffensiveAgent()

# CWE lookup request
request = {
    "version": "1.0",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
    "agent": "offensive",
    "intent": "attack_path",
    "payload": {
        "cweId": "CWE-79"
    }
}

response = agent.execute(request)
# Returns: {
#   "version": "1.0",
#   "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
#   "status": "ok",
#   "data": {
#     "techniques": [
#       {
#         "id": "T1059",
#         "name": "Command and Scripting Interpreter",
#         "tactics": ["Execution"],
#         "capec": ["CAPEC-88", "CAPEC-242"],
#         "subtechniques": ["T1059.001", "T1059.002"]
#       }
#     ],
#     "attack_paths": [
#       {
#         "weakness_id": "CWE-79",
#         "pattern_id": "CAPEC-88",
#         "technique_id": "T1059"
#       }
#     ]
#   },
#   "provenance": [
#     {"source": "MITRE CAPEC", "ids": ["CAPEC-88", "CAPEC-242"], "timestamp": "..."},
#     {"source": "MITRE ATT&CK", "ids": ["T1059"], "timestamp": "..."}
#   ],
#   "confidence": {
#     "value": 0.95,
#     "basis": "COMPLETE_CHAIN",
#     "signals": {"rows": 3, "hops": 3},
#     "degradation": []
#   },
#   "errors": []
# }
```

## Request Contract

**Payload Fields**:
- `"cweId"`: CWE identifier string (e.g., "CWE-79") — required, triggers T_OFF_01 template

**Response Envelope**: Matches `agent-consumable-schema.json` — contains:
- **version**: "1.0"
- **correlation_id**: UUID string (propagated from request)
- **status**: "ok" | "empty" | "error"
- **data**: Offensive Agent-specific payload (see below)
- **provenance**: List of {source, ids, timestamp}
- **confidence**: {value, basis, signals, degradation}
- **errors**: List of error messages (only populated if status=error)

## Response Data Shapes

### Weakness Lookup Response (T_OFF_01)

```json
{
  "techniques": [
    {
      "id": "T1059",
      "name": "Command and Scripting Interpreter",
      "tactics": ["Execution", "Persistence"],
      "capec": ["CAPEC-88", "CAPEC-242"],
      "subtechniques": ["T1059.001", "T1059.002", "T1059.003"]
    },
    {
      "id": "T1202",
      "name": "Indirect Command Execution",
      "tactics": ["Execution"],
      "capec": ["CAPEC-242"],
      "subtechniques": []
    }
  ],
  "attack_paths": [
    {
      "weakness_id": "CWE-79",
      "attack_pattern_id": "CAPEC-88",
      "technique_id": "T1059"
    },
    {
      "weakness_id": "CWE-79",
      "attack_pattern_id": "CAPEC-242",
      "technique_id": "T1059"
    },
    {
      "weakness_id": "CWE-79",
      "attack_pattern_id": "CAPEC-242",
      "technique_id": "T1202"
    }
  ]
}
```

## Cypher Template

### T_OFF_01: ATT&CK Techniques Exploiting a Weakness

```cypher
MATCH (w:Weakness {cweId: $cweId})
  -[:DEMONSTRATED_BY|:EXPLOITED_BY]->(ap:AttackPattern)
  -[:IMPLEMENTS]->(t:Technique)
OPTIONAL MATCH (t)-[:PART_OF]->(tac:Tactic)
OPTIONAL MATCH (t)<-[:SUBTECHNIQUE_OF]-(st:SubTechnique)
RETURN w, ap, t, tac, st
ORDER BY t.attackId
```

**Expected hops**: 3 (Weakness → AttackPattern → Technique)

## Confidence Scoring

Computed by `ConfidenceScorer.compute()` using:

- **Row count**: Number of results from query
- **Hop count**: Actual hops traversed
- **Expected hops**: From template metadata (3 for weakness-to-techniques)
- **Shape validated**: Always False (Offensive Agent doesn't run SHACL yet)

**Basis values**:
- `COMPLETE_CHAIN`: Result count > 0, hops == 3
- `PARTIAL_CHAIN`: Result count > 0, hops < 3
- `NO_MATCH`: Result count == 0

**Degradation factors**:
- Missing hops: -0.2 per hop
- Stale data (>365 days): -0.1

## Error Handling

Three-tier error response:

1. **ValidationError** → User provided invalid payload
   - Missing "cweId" in payload
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
    "weakness": 3
}

STALE_DATA_PENALTY = 0.1
MISSING_HOP_PENALTY = 0.2
STALE_DATA_THRESHOLD_DAYS = 365

QUERY_TIMEOUT_SECONDS = 30
MAX_RESULT_ROWS = 10000

VALID_INTENTS = ["attack_path"]
VALID_PAYLOAD_FIELDS = {"cweId"}
```

## Testing

Run the test suite:

```bash
python -m pytest agents/offensive/tests/ -v
```

**Test coverage**:
- **test_cypher_syntax.py**: 6 tests — Template validation, parameterization
- **test_executor.py**: 19 tests — Routing, response building, error handling
- **test_transformers.py**: 14 tests — Data aggregation, deduplication, provenance
- **test_integration.py**: 15 tests — End-to-end flows, envelope structure

**Total**: 54 tests, all passing (targeting 85%+ coverage)

## Integration with Orchestrator

The Master Orchestrator calls the Offensive Agent for `attack_path` intents:

```python
agent = OffensiveAgent()  # Instances created by orchestrator
response = agent.execute(request_envelope)  # Where intent="attack_path"

# Extract and aggregate results
if response["status"] == "ok":
    techniques = response["data"]["techniques"]
    attack_paths = response["data"]["attack_paths"]
    provenance = response["provenance"]
    confidence = response["confidence"]

    # Route to Defensive Agent if mixed intent requested
    if request["intent"] == "mixed":
        defensive_response = defensive_agent.execute(...)
```

## Dependencies

- `neo4j>=5.0.0`: Neo4j driver (read-only mode)
- `jsonschema>=0.28.0`: JSON Schema validation
- `agents.shared.*`: Shared library modules (types, confidence_scorer, response_builder, schema_validator, logger)

All dependencies defined in `requirements.txt`.

## Data Flow Example: CWE-79 Lookup

1. Request: `{"intent": "attack_path", "payload": {"cweId": "CWE-79"}, ...}`
2. execute() → _select_template("weakness") → _execute_query()
3. Neo4j returns: 15 records (3 techniques with tactics/subtechniques)
4. _transform_results() → deduplicates to 3 techniques, extracts 5 CAPEC IDs
5. extract_provenance() → [{source: "MITRE CAPEC", ids: [...]}, {source: "MITRE ATT&CK", ids: [...]}]
6. _compute_confidence() → {value: 1.0, basis: "COMPLETE_CHAIN", hops: 3}
7. response_builder.ok() → full envelope
8. schema_validator validates response against offensive-response.json
9. Return ResponseEnvelope dict

## Key Design Decisions

1. **Single Template Route**: Only one query pathway (weakness-to-techniques), simpler than Systems Agent
2. **Attack Paths Array**: Full causal chain tracking for graph traceability
3. **Dual Provenance**: Separates MITRE CAPEC (AttackPattern) from MITRE ATT&CK (Technique) sources
4. **Deduplication by attackId**: Techniques aggregated, CAPEC/tactic/subtechnique arrays per technique
5. **Three-hop expectation**: Weakness → AttackPattern → Technique for confidence scoring

## Phase Status

**Phase 2C-3**: ✓ Complete
- Cypher template management (1 template)
- Request routing (single cweId route)
- Neo4j → JSON transformation with deduplication
- Error handling and confidence scoring
- Full test suite (54 tests)

**Next**: Phase 2C-4 (Defensive Agent) → Phase 2C-5 (Master Orchestrator)
