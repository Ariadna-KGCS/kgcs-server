# Master Orchestrator

Composite agent coordination microservice for the KGCS cybersecurity knowledge graph.

Routes requests by intent to appropriate specialized agents (Systems, Offensive, Defensive) and aggregates responses for multi-agent queries.

## HTTP API

The orchestrator now includes an HTTP wrapper in `api.py` built with `aiohttp`.

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Liveness probe; returns service status only |
| `GET` | `/ready` | Readiness probe; checks schema loading and Neo4j env vars |
| `POST` | `/query` | Main orchestration endpoint; validates request schema and executes the orchestrator |

### Request Notes

- `POST /query` expects the same request envelope defined in `spec/contracts/request-schema.json`
- If `correlation_id` is omitted, the API generates one and returns it
- `X-Correlation-ID` is propagated on the response headers

### Authentication Integration Point

The API supports an optional API-key gate for `POST /query`.

- Set `KGCS_API_KEY` in the environment to enable auth
- Send the key using either:
  - `X-API-Key: <key>`
  - `Authorization: Bearer <key>`
- If `KGCS_API_KEY` is not set, auth is disabled by default for local development

### Local Run

```bash
python -m orchestrator.api
```

Optional environment variables:

```bash
export PORT=8080
export KGCS_API_KEY=your-api-key
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=yourpassword
```

### Example Request

```bash
curl -X POST http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -H "X-Correlation-ID: req-123" \
  -d '{
    "version": "1.0",
    "agent": "master",
    "intent": "vuln_lookup",
    "payload": {"cveId": "CVE-2021-44228"}
  }'
```

## Architecture

### Intent-Based Routing

```
User Request
    ↓
[MasterOrchestrator.execute()]
    ↓
    ├─→ intent="vuln_lookup"  → [SystemsAgent]     → Vulnerability lookup
    ├─→ intent="attack_path"  → [OffensiveAgent]   → Attack technique paths
    ├─→ intent="coverage_map" → [DefensiveAgent]   → Security coverage maps
    └─→ intent="mixed"        → [All 3 agents]     → Composite query
    ↓
Response Aggregation
    │├─ Provenance: Deduplicate by source + ID
    │├─ Confidence: Average/minimum/weighted merge
    │└─ Data: Combine from all agents
    ↓
[Response Envelope]
```

### Single-Intent Example

```
Request:
{
  "version": "1.0",
  "correlation_id": "req-123",
  "intent": "vuln_lookup",
  "payload": {"cveId": "CVE-2021-44228"}
}

Orchestrator:
1. Validate intent="vuln_lookup" ✓
2. Validate payload.cveId present ✓
3. Route to SystemsAgent
4. SystemsAgent.execute(request)
5. Validate response schema
6. Return response as-is (no aggregation)

Response:
{
  "version": "1.0",
  "correlation_id": "req-123",
  "status": "ok",
  "data": {
    "vulnerabilities": [{...}]
  },
  "provenance": [{source: "NVD", ids: ["CVE-2021-44228"], ...}],
  "confidence": {value: 1.0, basis: "COMPLETE_CHAIN", ...},
  "errors": []
}
```

### Mixed-Intent Example

```
Request:
{
  "version": "1.0",
  "correlation_id": "req-456",
  "intent": "mixed",
  "payload": {"cveId": "CVE-2021-44228"}
}

Orchestrator Sequence:
1. Validate intent="mixed" ✓
2. Validate payload.cveId present ✓
3. Execute Systems Agent
   - Request: intent="vuln_lookup", payload={cveId: "CVE-2021-44228"}
   - Response: vulnerabilities=[...], cveId identified
4. Execute Offensive Agent (if Systems succeeded)
   - Request: intent="attack_path", payload={cweId: from-weakness}
   - Response: techniques=[...], attack_paths=[...]
5. Execute Defensive Agent (if Offensive succeeded)
   - Request: intent="coverage_map", payload={attackId: from-technique}
   - Response: mitigations=[...], detections=[...], ...
6. Aggregate all 3 responses
   - Merge provenance: NVD + MITRE CAPEC + MITRE ATT&CK + D3FEND + CAR + SHIELD + ENGAGE
   - Average confidence scores
   - Combine data from all agents
7. Return aggregated response

Response:
{
  "version": "1.0",
  "correlation_id": "req-456",
  "status": "ok",
  "data": {
    "vulnerabilities": [...],  // from Systems
    "techniques": [...],        // from Offensive
    "attack_paths": [...],      // from Offensive
    "mitigations": [...],       // from Defensive
    "detections": [...],        // from Defensive
    // ... etc
  },
  "provenance": [
    {source: "NVD", ids: ["CVE-2021-44228"], ...},
    {source: "MITRE CAPEC", ids: ["CAPEC-88"], ...},
    {source: "MITRE ATT&CK", ids: ["T1059"], ...},
    {source: "MITRE D3FEND", ids: ["D3-PA"], ...},
    {source: "MITRE CAR", ids: ["CAR-2020-04-001"], ...},
    {source: "MITRE SHIELD", ids: ["DTE0001"], ...},
    {source: "MITRE ENGAGE", ids: ["EAC0002"], ...}
  ],
  "confidence": {
    value: 0.925,  // average of Systems (1.0), Offensive (0.9), Defensive (0.8)
    basis: "MULTI_AGENT_AVERAGE",
    signals: {agents: 3, individual_values: [1.0, 0.9, 0.8]},
    degradation: []
  },
  "errors": []
}
```

## Usage

### Initialization

```python
from orchestrator import MasterOrchestrator

# Create orchestrator (generates correlation_id if not provided)
orchestrator = MasterOrchestrator(correlation_id="req-123")

# Execute request
response = orchestrator.execute(request_envelope)
```

### Request Format

**All requests must include:**

```json
{
  "version": "1.0",
  "correlation_id": "unique-request-id",
  "agent": "master",
  "intent": "vuln_lookup | attack_path | coverage_map | mixed",
  "payload": {...}
}
```

**Payload Requirements by Intent:**

| Intent | Required Field(s) | Description |
|--------|------------------|-------------|
| `vuln_lookup` | `cveId` OR `matchCriteriaId` OR `cpeName` | CVE identifier, PlatformConfiguration key, or canonical CPE name |
| `attack_path` | `cweId` OR `cveId` | CWE weakness or CVE identifier |
| `coverage_map` | `attackId` | MITRE ATT&CK technique ID (T1059 or T1059.001) |
| `mixed` | `cveId` OR `matchCriteriaId` OR `cpeName` | CVE, PlatformConfiguration key, or canonical CPE entry point for full analysis chain |

### Response Format

All responses follow `agent-consumable-schema.json`:

```json
{
  "version": "1.0",
  "correlation_id": "unique-request-id",
  "status": "ok | empty | error",
  "data": {...},
  "provenance": [{source: "...", ids: [...], timestamp: "..."}],
  "confidence": {
    "value": 0.0-1.0,
    "basis": "COMPLETE_CHAIN | PARTIAL_CHAIN | NO_MATCH | COVERAGE_MAP | MULTI_AGENT_*",
    "signals": {...},
    "degradation": [...]
  },
  "errors": []
}
```

## Implementation Details

### Module Structure

```
orchestrator/
├── __init__.py              # Package export
├── constants.py             # Intent mappings, configuration
├── errors.py                # Exception types
├── router.py                # RequestRouter class - intent validation & routing logic
├── aggregator.py            # ResponseAggregator class - orchestrates response merging
├── executor.py              # MasterOrchestrator class - main orchestrator entry point
├── api.py                   # aiohttp HTTP wrapper (/health, /ready, /query)
├── README.md                # This file
└── tests/
    ├── test_router.py       # Routing logic tests (13 tests)
    ├── test_aggregator.py   # Aggregation logic tests (10 tests)
    ├── test_executor.py     # Orchestrator execution tests (14 tests)
    └── test_integration.py  # End-to-end orchestration tests (8 tests)
    └── test_api.py          # API endpoint tests
    └── __init__.py
```

### Key Classes and Methods

#### `RequestRouter` (router.py)

Static methods for intent validation and routing:

```python
@staticmethod
def validate_intent(intent: str) -> None:
    """Validate intent is one of: vuln_lookup, attack_path, coverage_map, mixed"""
    # Raises ValidationError if invalid

@staticmethod
def validate_payload(intent: str, payload: dict) -> None:
    """Validate payload has required fields for given intent"""
    # Raises ValidationError if missing fields

@staticmethod
def route_intent(intent: str) -> str:
    """Map intent to agent name: systems, offensive, or defensive"""
    # Returns: "systems" | "offensive" | "defensive"
    # Raises ValidationError if intent="mixed" (unmappable)

@staticmethod
def route_mixed_intent() -> list:
    """Return sequence of (agent_name, sub_intent) tuples for mixed orchestration"""
    # Returns: [("systems", "vuln_lookup"), ("offensive", "attack_path"), ("defensive", "coverage_map")]
```

#### `ResponseAggregator` (aggregator.py)

Static methods for merging multi-agent responses:

```python
@staticmethod
def merge_provenance(responses: List[Dict]) -> List[Dict]:
    """Deduplicate provenance by (source, id) across all agent responses"""
    # Returns: [{source: "NVD", ids: [...], timestamp: "..."}, ...]

@staticmethod
def merge_confidence(responses: List[Dict]) -> Dict:
    """Merge confidence scores using configured strategy (average/minimum/weighted)"""
    # Single response: returns as-is (clamped)
    # Multiple responses: applies merge strategy, returns "MULTI_AGENT_*" basis
    # Returns: {value: 0.0-1.0, basis: "...", signals: {...}, degradation: [...]}

@staticmethod
def aggregate_multi_agent_responses(responses: List[Dict]) -> Dict:
    """Combine all components from multi-agent responses"""
    # Merges: provenance, confidence, data, errors
    # Returns: Complete response envelope with aggregated data
```

#### `MasterOrchestrator` (executor.py)

Main orchestrator class:

```python
def __init__(self, correlation_id: Optional[str] = None):
    """Initialize with 3 agent instances and shared infrastructure"""

def execute(self, request: Dict[str, Any]) -> Dict[str, Any]:
    """Main entry point: validate, route, execute, aggregate, validate, return"""
    # Flow:
    # 1. Validate intent and payload
    # 2. Route to agent(s) by intent
    # 3. Execute agent(s)
    # 4. Aggregate responses (if multi-agent)
    # 5. Validate response schema
    # 6. Return response envelope
```

### Confidence Merging Strategies

**Configuration:** `CONFIDENCE_MERGE_STRATEGY` in `constants.py`

Three merging strategies for multi-agent responses:

1. **"average"** (default):
   ```
   merged_value = (conf1 + conf2 + conf3) / 3
   basis = "MULTI_AGENT_AVERAGE"
   ```

2. **"minimum"** (conservative):
   ```
   merged_value = min(conf1, conf2, conf3)
   basis = "MULTI_AGENT_MINIMUM"
   ```

3. **"weighted"** (row-count based):
   ```
   merged_value = (conf1 * rows1 + conf2 * rows2 + conf3 * rows3) / (rows1 + rows2 + rows3)
   basis = "MULTI_AGENT_WEIGHTED"
   ```

**Single-response handling:**
- If only 1 agent response: return it as-is with original basis (no MULTI_AGENT prefix)
- Always clamps confidence value to [0.0, 1.0]

### Error Handling

**Three-tier error handling:**

1. **ValidationError** (user input):
   - Invalid intent
   - Missing required payload field
   - Malformed request envelope

2. **RoutingError** (orchestration):
   - Agent not found
   - Routing logic failure

3. **AggregationError** (response merging):
   - No responses to aggregate
   - Aggregation logic failure

**All errors return error response:**
```json
{
  "version": "1.0",
  "correlation_id": "...",
  "status": "error",
  "data": null,
  "provenance": [],
  "confidence": {"value": 0.0, "basis": "NO_MATCH", "signals": {}, "degradation": []},
  "errors": ["Error message here"]
}
```

## Testing

### Test Coverage

**57 total tests across 5 test modules:**

- **test_router.py** (13 tests)
  - Intent validation
  - Payload validation
  - Intent routing logic

- **test_aggregator.py** (10 tests)
  - Provenance merging and deduplication
  - Confidence merging (single/multiple/no results/clamping)
  - Multi-agent response aggregation

- **test_executor.py** (14 tests)
  - Orchestrator initialization
  - Single-intent routing (vuln_lookup, attack_path, coverage_map)
  - Mixed-intent orchestration
  - Error handling and validation
  - Correlation ID propagation

- **test_integration.py** (8 tests)
  - Full vuln_lookup flow (CVE & CPE inputs)
  - Full attack_path flow
  - Full coverage_map flow
  - Mixed-intent orchestration
  - Error scenarios

- **test_api.py** (12 tests)
  - Health and readiness endpoints
  - Query endpoint for all supported intents
  - Validation failures
  - Invalid JSON handling
  - Downstream failure passthrough
  - API-key auth enforcement

### Running Tests

```bash
# Run all tests
python -m pytest orchestrator/tests/ -v

# Run specific test module
python -m pytest orchestrator/tests/test_router.py -v

# Run with coverage
python -m pytest orchestrator/tests/ --cov=orchestrator --cov-report=html
```

## Critical Design Decisions

1. **Single routing endpoint**: All request types flow through `MasterOrchestrator.execute()` with intent-based dispatch
2. **Dependency injection**: Agents injected in constructor for testability
3. **Stateless orchestration**: No request caching or state management
4. **Fail-safe multi-agent**: If one agent fails in mixed-intent, stop sequence and return aggregated results
5. **Provenance deduplication by (source, id)**: Prevents duplicate IDs within same source
6. **Confidence preservation for single responses**: Only applies "MULTI_AGENT_*" basis when aggregating 2+ agent responses
7. **Correlation ID propagation**: Same ID flows through all agents for end-to-end tracing

## Configuration

**File:** `orchestrator/constants.py`

```python
# Supported intents
VALID_INTENTS = ["vuln_lookup", "attack_path", "coverage_map", "mixed"]

# Intent to agent mapping
INTENT_TO_AGENT = {
    "vuln_lookup": "systems",
    "attack_path": "offensive",
    "coverage_map": "defensive"
}

# Mixed-intent execution sequence
MIXED_INTENT_SEQUENCE = [
    ("systems", "vuln_lookup"),
    ("offensive", "attack_path"),
    ("defensive", "coverage_map")
]

# Payload field requirements per intent
INTENT_PAYLOAD_FIELDS = {
    "vuln_lookup": {"matchCriteriaId", "cpeName", "cpe", "cveId"},
    "attack_path": {"cweId", "cveId"},    # at least one
    "coverage_map": {"attackId"},          # required
    "mixed": {"matchCriteriaId", "cpeName", "cpe", "cveId"}
}

# Confidence merging strategy
CONFIDENCE_MERGE_STRATEGY = "average"  # or "minimum", "weighted"
```

## Integration with Master System

### Orchestrator in System Architecture

```
                    ┌─→ SystemsAgent  (vuln_lookup)
                    │
User/API  → MasterOrchestrator
                    │
                    ├─→ OffensiveAgent (attack_path)
                    │
                    └─→ DefensiveAgent (coverage_map)

[All agents share Neo4j graph]
[All agents use shared library: ResponseBuilder, ConfidenceScorer, SchemaValidator, AgentLogger]
```

### Request Flow

1. **HTTP API** receives request → validates envelope
2. **MasterOrchestrator.execute()** called with request envelope
3. **RequestRouter** validates intent and payload
4. **Routing decision:**
   - Single-intent: pass request to agent, validate response, return
   - Mixed-intent: execute all agents in sequence, aggregate, return
5. **Response** returned to HTTP API

### Response Contract

All responses validate against `spec/contracts/agent-consumable-schema.json`

Orchestrator ensures:
- ✓ Envelope structure compliance (versioning, correlation_id, status)
- ✓ Provenance deduplication
- ✓ Confidence aggregation
- ✓ Data consistency across sources
- ✓ Error reporting

## Verification Checklist

- [x] All 45 tests passing (13 routing + 10 aggregation + 14 executor + 8 integration)
- [x] Single-intent routing verified (vuln_lookup → Systems, attack_path → Offensive, coverage_map → Defensive)
- [x] Mixed-intent orchestration verified (all 3 agents executed in sequence)
- [x] Error handling verified (invalid intent, missing payload, agent failure)
- [x] Correlation ID propagation verified (same ID through all agents)
- [x] Schema validation verified (responses validate against envelope schema)
- [x] Provenance deduplication verified (by source and ID)
- [x] Confidence merging verified (single response pass-through, multiple response averaging)

## Next Steps

1. **Integration Testing**: Test with real Neo4j database
2. **Performance Optimization**: Profile multi-agent query times
3. **Monitoring/Logging**: Enhanced observability for orchestrator flows
4. **Rate Limiting**: Add rate limiting for production deployments
5. **API Auth Hardening**: Replace the placeholder API-key model with production auth

## References

- Request Contract: `spec/contracts/request-schema.json`
- Response Envelope: `spec/contracts/agent-consumable-schema.json`
- Confidence Model: `docs/05-agents/confidence-model/spec.md`
- Systems Agent: `agents/systems/README.md`
- Offensive Agent: `agents/offensive/README.md`
- Defensive Agent: `agents/defensive/README.md`
