# Systems Agent

Read-only microservice for vulnerability queries: Platform/PlatformConfiguration ↔ Vulnerability ↔ Weakness mappings.

## Overview

The Systems Agent implements the `vuln_lookup` intent via three query pathways:
1. **By `matchCriteriaId`** → all CVEs affecting that platform configuration
2. **By `cpeName`** → resolve canonical Platform, then CVEs affecting matching configurations
3. **By CVE ID** → CVE details, root cause (CWE), and CVSS scores

## Architecture

```
agents/systems/
├── __init__.py                  # Package export
├── executor.py                  # SystemsAgent class (orchestrator entry point)
├── cypher_templates.py          # Parameterized Cypher templates + validation
├── transformers.py              # Neo4j Record → vulnerabilities array transformation
├── constants.py                 # Configuration (expected hops, timeouts, guardrails)
├── errors.py                    # Custom exceptions
└── tests/                       # Test suite (65 tests, 100% coverage path)
    ├── test_executor.py         # Request routing, response envelope, error handling
    ├── test_transformers.py     # Neo4j → dict transformation, deduplication
    ├── test_cypher_syntax.py    # Template validation (params, structure)
    └── test_integration.py      # End-to-end with mocked Neo4jClient
```

## Usage

### Basic Request/Response

```python
from agents.systems import SystemsAgent
from agents.shared.neo4j_client import Neo4jClient

# Initialize agent
agent = SystemsAgent()

# CVE lookup request
request = {
    "version": "1.0",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
    "agent": "systems",
    "intent": "vuln_lookup",
    "payload": {
        "cveId": "CVE-2021-44228"
    }
}

response = agent.execute(request)
# Returns: {
#   "version": "1.0",
#   "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
#   "status": "ok",
#   "data": {
#     "vulnerabilities": [
#       {
#         "cveId": "CVE-2021-44228",
#         "published": "2021-12-10",
#         "lastModified": "2024-01-01T00:00:00Z",
#         "scores": [
#           {"scoreId": "...", "version": "3.1", "baseScore": 9.8}
#         ],
#         "weakness": {"cweId": "CWE-91", "abstraction": "Variant"}
#       }
#     ]
#   },
#   "provenance": [
#     {"source": "NVD", "ids": ["CVE-2021-44228"], "timestamp": "..."}
#   ],
#   "confidence": {
#     "value": 0.95,
#     "basis": "COMPLETE_CHAIN",
#     "signals": {"rows": 2, "hops": 2},
#     "degradation": []
#   },
#   "errors": []
# }
```

### Platform Lookup Request

```python
request = {
    "version": "1.0",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
    "agent": "systems",
    "intent": "vuln_lookup",
    "payload": {
        "cpeName": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
    }
}

response = agent.execute(request)
# Returns: Same envelope structure with vulnerabilities array PLUS platforms field
```

## Request Contract

**Payload Fields** (choose one):
- `"matchCriteriaId"`: exact NVD CPE Match identifier (triggers PlatformConfiguration lookup)
- `"cpeName"`: canonical CPE 2.3 platform string (triggers Platform lookup)
- `"cpe"`: legacy compatibility alias; CPE 2.3 strings are treated as `cpeName`, other values as `matchCriteriaId`
- `"cveId"`: CVE-2021-44228 format (triggers T_SYS_02 template)

**Response Envelope**: Matches `agent-consumable-schema.json` — contains:
- **version**: "1.0"
- **correlation_id**: UUID string (propagated from request)
- **status**: "ok" | "empty" | "error"
- **data**: Systems-specific payload (see below)
- **provenance**: List of {source, ids, timestamp}
- **confidence**: {value, basis, signals, degradation}
- **errors**: List of error messages (only populated if status=error)

## Response Data Shapes

### CVE Lookup Response (T_SYS_02)

```json
{
  "vulnerabilities": [
    {
      "cveId": "CVE-2021-44228",
      "published": "2021-12-10",
      "lastModified": "2024-01-01T00:00:00Z",
      "source": "NVD",
      "scores": [
        {
          "scoreId": "CVE-2021-44228-v3.1",
          "version": "3.1",
          "baseScore": 9.8
        }
      ],
      "weakness": {
        "cweId": "CWE-91",
        "abstraction": "Variant",
        "name": "XML Injection"
      }
    }
  ]
}
```

### Platform Lookup Response (T_SYS_01)

Same as CVE response, plus:

```json
{
  "vulnerabilities": [...],
  "platforms": [
    {
      "matchCriteriaId": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
      "cpeUri": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
      "configStatus": "VULNERABLE"
    }
  ]
}
```

## Cypher Templates

### T_SYS_01: Vulnerabilities for a PlatformConfiguration

```cypher
MATCH (pc:PlatformConfiguration {matchCriteriaId: $matchCriteriaId})
  <-[:AFFECTS]-(v:Vulnerability)
OPTIONAL MATCH (v)-[:CAUSED_BY]->(w:Weakness)
OPTIONAL MATCH (v)-[:HAS_SCORE]->(s:Score)
OPTIONAL MATCH (pc)-[:MATCHES_PLATFORM]->(p:Platform)
RETURN v, w, s, pc, p
ORDER BY v.cveId
```

**Expected hops**: 3 (PlatformConfiguration → Vulnerability → Weakness)

### T_SYS_01B: Vulnerabilities for a canonical Platform CPE name

```cypher
MATCH (p:Platform {cpeUri: $cpeName})
MATCH (pc:PlatformConfiguration)-[:MATCHES_PLATFORM]->(p)
MATCH (pc)<-[:AFFECTS]-(v:Vulnerability)
OPTIONAL MATCH (v)-[:CAUSED_BY]->(w:Weakness)
OPTIONAL MATCH (v)-[:HAS_SCORE]->(s:Score)
RETURN v, w, s, pc, p
ORDER BY v.cveId
```

### T_SYS_02: Details and Root Cause for a CVE

```cypher
MATCH (v:Vulnerability {cveId: $cveId})
OPTIONAL MATCH (v)-[:CAUSED_BY]->(w:Weakness)
OPTIONAL MATCH (v)-[:HAS_SCORE]->(s:Score)
RETURN v, w, s
ORDER BY s.version
```

**Expected hops**: 2 (Vulnerability → Weakness)

## Confidence Scoring

Computed by `ConfidenceScorer.compute()` using:

- **Row count**: Number of results from query
- **Hop count**: Actual hops traversed (inferred from row count > 0)
- **Expected hops**: From template metadata
- **Shape validated**: Always False (Systems Agent doesn't run SHACL)
- **Freshness**: Not available from query

**Basis values**:
- `COMPLETE_CHAIN`: Result count > 0, hops == expected
- `SINGLE_HOP`: Result count > 0, hops < expected
- `NO_MATCH`: Result count == 0

**Degradation factors**:
- Missing hops (-0.2 per hop)
- Stale data >365 days (-0.1)

## Error Handling

Three-tier error response:

1. **ValidationError** → User provided invalid payload
   - Missing `matchCriteriaId`, `cpeName`, legacy `cpe`, and `cveId` in payload
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
    "matchCriteriaId": 3,
    "cpeName": 3,
    "cpe": 3,      # Legacy compatibility alias
    "cveId": 2     # Vulnerability → Weakness
}

STALE_DATA_PENALTY = 0.1
MISSING_HOP_PENALTY = 0.2
STALE_DATA_THRESHOLD_DAYS = 365

QUERY_TIMEOUT_SECONDS = 30
MAX_RESULT_ROWS = 10000  # Query execution limit

VALID_INTENTS = ["vuln_lookup"]
VALID_PAYLOAD_FIELDS = {"matchCriteriaId", "cpeName", "cpe", "cveId"}
```

## Testing

Run the test suite:

```bash
python -m pytest agents/systems/tests/ -v
```

**Test coverage**:
- **test_cypher_syntax.py**: 16 tests — Template validation, parameterization
- **test_executor.py**: 22 tests — Routing, response building, error handling
- **test_transformers.py**: 14 tests — Data aggregation, deduplication, provenance
- **test_integration.py**: 13 tests — End-to-end flows, envelope structure

**Total**: 65 tests, all passing

## Integration with Orchestrator

The Master Orchestrator calls the Systems Agent for `vuln_lookup` intents:

```python
agent = SystemsAgent()  # Instances created by orchestrator
response = agent.execute(request_envelope)  # Where intent="vuln_lookup"

# Extract and aggregate results
if response["status"] == "ok":
    vulnerabilities = response["data"]["vulnerabilities"]
    provenance = response["provenance"]
    confidence = response["confidence"]

    # Route to Offensive Agent if mixed intent requested
    if request["intent"] == "mixed":
        offensive_response = offensive_agent.execute(...)
```

## Dependencies

- `neo4j>=5.0.0`: Neo4j driver (read-only mode)
- `jsonschema>=0.28.0`: JSON Schema validation
- `agents.shared.*`: Shared library modules (types, confidence_scorer, response_builder, schema_validator, logger)

All dependencies defined in `requirements.txt`.

## Phase Status

**Phase 2C-2**: ✓ Complete
- Cypher template management (3 templates)
- Request routing (cpe vs cveId)
- Neo4j → JSON transformation with deduplication
- Error handling and confidence scoring
- Full test suite (65 tests)

**Next**: Phase 2C-3 (Offensive Agent) → Phase 2C-4 (Defensive Agent) → Phase 2C-5 (Master Orchestrator)
