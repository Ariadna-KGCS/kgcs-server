# KGCS Release B — Internal Cybersecurity AI Agent

**Release:** B (Internal)  
**Date:** March 2026  
**Status:** CLOSED — all gate criteria met  
**Test baseline:** 468 passed, 0 skipped, 0 failed  
**Previous release:** Release A (Backend-Complete Graph Agent Platform)  

---

## Summary

Release B delivers the first usable internal AI agent on top of the KGCS knowledge-graph backend.
Users can ask natural-language cybersecurity questions and receive fully graph-grounded, provenance-traced answers.
The release also includes the minimum hardening required to operate the service safely: structured observability, API authentication, rate limiting, timeout and retry handling, and a Docker-based deployment stack.

The frozen OWL ontology and all v1.0 ETL artifacts introduced in Release A are unchanged.

---

## What Was in Release A

Release A established the backend platform:

- Neo4j Knowledge Graph loaded from ten MITRE/NIST standards (CPE, CVE, CVSS, CWE, CAPEC, ATT&CK, D3FEND, CAR, SHIELD, ENGAGE)
- Deterministic agents: SystemsAgent, OffensiveAgent, DefensiveAgent
- MasterOrchestrator with single-intent and mixed-intent routing
- aiohttp API service on port 8080 with `/health`, `/ready`, and `POST /query`
- Correlation-ID propagation, schema validation, and structured error responses
- Full test coverage across agents and orchestrator (290 tests)

---

## Release B Additions

### Priority 3 — NVD Applicability Semantics (P3)

The CVE applicability model was corrected to match NVD's actual structure.

**ETL changes:**

- `load_cpe.py` now preserves CPE match range and timestamp fields required for applicability reconstruction.
- `scripts/etl/cve_applicability.py` — new shared flattener that exposes the full `AND`/`OR`/`negate` applicability logic from NVD schemas; includes an inventory-aware evaluator for concrete CPE expansion.
- `load_cve.py` now derives its `AFFECTS` compatibility projection from the shared flattener and also emits the explicit applicability layer:

  ```
  Vulnerability -[:HAS_CONFIGURATION]-> VulnerabilityConfiguration
  VulnerabilityConfiguration -[:HAS_NODE]-> VulnerabilityConfigurationNode
  VulnerabilityConfigurationNode -[:MATCHES_CRITERIA]-> PlatformConfiguration
  ```

- New unique constraints in `init_constraints.py` for `VulnerabilityConfiguration.vcId` and `VulnerabilityConfigurationNode.vcnId`.

**Semantic corrections:**

- `PlatformConfiguration` stores `matchCriteriaId` (merge key) and `criteria` (CPE URI pattern); it does not synthesise a `cpeUri` field — that belongs to `Platform` nodes only.
- Canonical CPE URI expansion is done through `MATCHES_PLATFORM` edges to concrete `Platform` nodes.
- Systems-agent and orchestrator request handling now distinguishes `matchCriteriaId` from `cpeName` (shape-based: `cpe:2.3:` prefix = `cpeName`; UUID = `matchCriteriaId`); `payload.cpe` is retained as a compatibility alias.
- Systems responses now expose `resolvedPlatforms` (concrete Platform nodes) and `applicability.configurations[].nodes[].criteria[]` (explicit grouped CVE applicability).

**Validation additions (`validate_all_standards.py`):**

- `no_direct_platform_affects` — checks that `AFFECTS` edges are backed by explicit applicability leaves.
- `expanded_criteria_have_platform_targets` — confirms applicability criteria expand to concrete Platform nodes.

**Documented decision:** `PlatformConfiguration` intentionally omits a derived `cpeUri` field; this is recorded in `scripts/etl/load_cpe.py` and `tasks/todo.md`.

---

### Priority 4 — AI Interaction Layer (P4)

A deterministic natural-language interface on top of the existing orchestrator. No LLM is used for reasoning, Cypher generation, or inference.

**New package: `ai/`**

| File | Responsibility |
|---|---|
| `ai/__init__.py` | Exposes `LLMAdapter` |
| `ai/llm_adapter.py` | Pipeline orchestrator; delegates to all other components |
| `ai/intent_classifier.py` | NL → intent (regex scoring + entity-first rule) |
| `ai/entity_extractor.py` | NL → security identifiers (regex) |
| `ai/safety.py` | Pre-execution safety checks |
| `ai/response_renderer.py` | `ResponseEnvelope` → structured user-facing answer |

**Pipeline order (strictly enforced):**

```
classify → extract → safety → build → execute → render
```

**Intent classifier:**

- Supported intents: `vuln_lookup`, `attack_path`, `coverage_map`, `mixed`
- Fully deterministic (regex scoring); no LLM involved
- Entity-first rule: CVE ID or CPE string in the prompt defaults the intent to `vuln_lookup` unless a strong ATT&CK traversal signal overrides it
- Raises `MultipleEntitiesError` if more than one identifier of the same type is present

**Entity extractor:**

- `cveId` — `CVE-YYYY-NNNNN+`
- `cweId` — `CWE-NNN`
- `attackId` — `T\d{4}(\.\d{3})?`
- `cpeName` — `cpe:2.3:` URI
- `matchCriteriaId` — UUID v4

**Safety layer:**

1. Intent validation — must be in `VALID_INTENTS`
2. Payload keyword scan — scans values for `cypher`, `return`
3. Prompt injection detection — regex patterns for ignore-previous-instructions / generate-cypher / bypass
4. Cypher pattern detection — fires at ≥ 2 distinct uppercase Cypher keywords (`RETURN`, `WHERE`, `LIMIT`, `MATCH`, `MERGE`, `DELETE`)

A failed check raises `SafetyViolationError` and aborts before execution.

**Response renderer:**

- Formats `ResponseEnvelope` into: Summary, Key Findings (intent-specific), Provenance (by source), Confidence (percentage + basis + degradation reasons)
- Prepends a low-confidence warning when `confidence.value < 0.25`
- Never adds inferred claims; all facts originate from graph data

**New API endpoint:** `POST /ask` — wraps `LLMAdapter.process()`.
Response shape: `{"answer", "raw", "intent", "payload", "correlation_id"}`

**Test additions:** 136 new tests (intent classifier, entity extractor, LLM adapter, response renderer, safety checker).
Test baseline after P4: **426 passed**.

---

### Priority 5.1 — Observability

**Key files:** `agents/shared/logger.py`, `orchestrator/api.py`, `orchestrator/executor.py`, `agents/shared/neo4j_client.py`

**Delivered:**

- `JsonFormatter` — emits one JSON object per log record: `ts`, `level`, `logger`, `msg`, `correlation_id`, `agent`, `intent`, `latency_ms`, `status`
- `configure_json_logging()` — installs the JSON formatter at startup; `KGCS_LOG_FORMAT=text` falls back to plain-text (local dev)
- `AgentLogger.timed(label, **kwargs)` — context manager measuring and logging wall-clock duration
- `access_log_middleware` in `api.py` — records method/path/status/latency_ms per request
- Per-agent `latency_ms` logged in `executor.py` for single and mixed-intent paths
- Slow-query warning in `neo4j_client.py` when query elapsed > `NEO4J_SLOW_QUERY_MS` (default 5 000 ms)

**New environment variables:** `KGCS_LOG_FORMAT`, `NEO4J_SLOW_QUERY_MS`
**New tests:** 8 (`agents/shared/tests/test_logger.py`)
Test baseline after P5.1: **434 passed**.

---

### Priority 5.2 — Security and Control Plane

**Key file:** `orchestrator/api.py`

**New middlewares (order: `correlation → access_log → auth → rate_limit → request_size`):**

| Middleware | Behaviour |
|---|---|
| `auth_middleware` | Enforces `KGCS_API_KEY` on `/query` and `/ask`; accepts `X-API-Key` or `Authorization: Bearer <key>`; skips `/health`/`/ready`; no-op when no key is configured; returns structured JSON 401 |
| `rate_limit_middleware` | Per-client-IP fixed-window counter; default 60 req/min; `rate_limit=0` disables; skips `/health`/`/ready`; returns JSON 429 |
| `request_size_middleware` | Catches `HTTPRequestEntityTooLarge`; returns structured JSON 413; size enforced at transport layer via `client_max_size` |

**Factory overrides:** `create_app()` accepts `rate_limit=` and `max_request_size=` for test isolation.

**New environment variables:** `KGCS_API_KEY`, `KGCS_RATE_LIMIT`, `KGCS_MAX_REQUEST_SIZE`
**New tests:** 12 (`orchestrator/tests/test_security.py`)
Test baseline after P5.2: **453 passed**.

---

### Priority 5.3 — Failure Handling

**Key files:** `orchestrator/errors.py`, `agents/shared/neo4j_client.py`, `orchestrator/executor.py`, `orchestrator/api.py`

**Delivered:**

- `OrchestratorTimeoutError(OrchestratorError)` in `errors.py` — propagates uncaught through `executor.execute()` so the API returns HTTP 504 instead of 500
- `NEO4J_QUERY_TIMEOUT` env var (default 30 s) overrides the `Neo4jClient` constructor default
- Retry loop in `Neo4jClient.query()` — up to 2 retries with 100 ms / 200 ms back-off for `ServiceUnavailable` / `SessionExpired`; `TimeoutError` is raised immediately when the driver reports a timeout
- `KGCS_ORCHESTRATOR_TIMEOUT` env var (default 30 s) — wall-clock deadline checked before each agent dispatch; `TimeoutError` from agents is re-raised as `OrchestratorTimeoutError`
- Both `/query` and `/ask` handlers catch `OrchestratorTimeoutError` → HTTP 504 structured error body
- Safe re-raise pattern: `except OrchestratorTimeoutError: raise` placed before every broad `except Exception` block

**New environment variables:** `NEO4J_QUERY_TIMEOUT`, `KGCS_ORCHESTRATOR_TIMEOUT`
**New tests:** 7 (`orchestrator/tests/test_timeout.py`)
Test baseline after P5.3: **441 passed** (ordered before P5.2 in implementation; combined baseline is 453 post-P5.2).

---

### Priority 5.4 — Deployment and Smoke Checks

**New artifacts at repo root:**

**`Dockerfile`**

```
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agents/ agents/
COPY orchestrator/ orchestrator/
COPY ai/ ai/
COPY spec/contracts/ spec/contracts/
ENV PYTHONPATH=/app
ENV PORT=8080
EXPOSE 8080
CMD ["python", "-m", "orchestrator.api"]
```

**`docker-compose.yml`** — local dev stack with Neo4j 5 + orchestrator; health-check gated service dependency; configurable via `.env`.

**`.env.example`** — documents every environment variable introduced across P5.1–P5.4:

| Variable | Default | Purpose |
|---|---|---|
| `NEO4J_URI` | — | Neo4j bolt URI |
| `NEO4J_USER` | — | Neo4j username |
| `NEO4J_PASSWORD` | — | Neo4j password |
| `NEO4J_DATABASE` | — | Database name |
| `PORT` | 8080 | API listen port |
| `KGCS_API_KEY` | — | API authentication key (unset = open) |
| `KGCS_RATE_LIMIT` | 60 | Requests per minute per IP (0 = disabled) |
| `KGCS_MAX_REQUEST_SIZE` | 1048576 | Max request body in bytes |
| `KGCS_ORCHESTRATOR_TIMEOUT` | 30 | Orchestrator wall-clock deadline (seconds) |
| `NEO4J_QUERY_TIMEOUT` | 30 | Neo4j query timeout (seconds) |
| `KGCS_LOG_FORMAT` | json | `json` or `text` |
| `NEO4J_SLOW_QUERY_MS` | 5000 | Slow-query log threshold (ms) |
| `KGCS_API_URL` | — | Base URL for smoke test |

**`tests/test_api_integration.py`** — 15 integration tests exercising the full middleware stack against canonical fixtures; covers `/health`, `/ready`, all 5 intents, correlation-ID propagation, error handling, and multi-layer middleware interaction.

**`.github/workflows/smoke-tests.yml`** — updated from obsolete `/execute` route to `/query`; simplified to `scripts/smoke_test.py` invocation plus dedicated latency and throughput steps; added optional `api_key` workflow input.

**New tests:** 15 (`tests/test_api_integration.py`)
Test baseline after P5.4: **468 passed**.

---

### P2/P3 Fixture and Tooling Closure (2026-03-24)

Canonical test artifacts added:

| Path | Contents |
|---|---|
| `tests/fixtures/requests/` | 5 canonical request envelopes (vuln_lookup ×2, attack_path, coverage_map, mixed) |
| `tests/fixtures/responses/` | 4 representative response shapes |
| `tests/fixtures/edge_cases/` | 5 edge-case/failure examples (not_found, multi_entity, safety_violation, invalid_request, inherited_attack_path) |
| `scripts/smoke_test.py` | stdlib-only HTTP smoke test; covers all endpoints; `--base-url`/`--api-key` or env vars |

---

## Test Baseline Progression

| Milestone | Passing | New tests |
|---|---|---|
| Release A (P0–P2) | 290 | — |
| P3 applicability semantics | 320 | 30 |
| P4 AI interaction layer | 426 | 106 |
| P5.1 Observability | 434 | 8 |
| P5.3 Failure handling | 441 | 7 |
| P5.2 Security | 453 | 12 |
| P5.4 Deployment | **468** | 15 |

---

## API Surface at Release B

| Method | Path | Auth required | Description |
|---|---|---|---|
| GET | `/health` | No | Liveness probe |
| GET | `/ready` | No | Readiness probe (Neo4j env + schema) |
| POST | `/query` | Yes (if key set) | Structured JSON query via orchestrator |
| POST | `/ask` | Yes (if key set) | Natural-language query via AI layer |

**Request envelope (`POST /query`):**

```json
{
  "version": "1.0",
  "correlation_id": "<uuid>",
  "agent": "master",
  "intent": "vuln_lookup | attack_path | coverage_map | mixed",
  "payload": { "cveId": "CVE-2021-44228" }
}
```

**Response envelope:**

```json
{
  "status": "ok",
  "correlation_id": "<uuid>",
  "intent": "vuln_lookup",
  "data": { ... },
  "confidence": { "value": 0.85, "basis": "GRAPH_TRAVERSAL" },
  "provenance": [ { "source": "NVD", "id": "CVE-2021-44228" } ],
  "errors": []
}
```

---

## Causal Chain Invariant (Preserved)

```
CPE → CVE/CVSS → CWE → CAPEC → ATT&CK → {D3FEND, CAR, SHIELD, ENGAGE}
```

No shortcut edges. No direct `CVE → Technique` or `Platform → Vulnerability` links.

---

## Frozen Artifacts (Unchanged Since v1.0)

- `core/core-ontology-v1.0.owl`
- `standards/*/*-ontology-v1.0.owl`
- `extensions/asset-extension-v1.0.owl`
- Namespace policy: `docs/02-ontology/namespace-policy-v1.0.md`
- Canonical schema specs: `spec/contracts/`

---

## Known Limitations

| Limitation | Detail |
|---|---|
| Multi-entity queries | Not supported; `MultipleEntitiesError` raised explicitly |
| CVE + defense query | Routed to `vuln_lookup` (entity-first rule); by design |
| Mixed intent without CVE/CPE anchor | Raises `UnsupportedQueryError` |
| No session continuity | Pipeline is stateless; no follow-up context (planned in P6) |
| Safety checks are pattern-based | Not semantically aware; known bypass vectors exist |
| `PlatformConfiguration.cpeUri` may be null | Canonical lookup path is `matchCriteriaId`; literal CPE URI lookup may return empty |

---

## Next Release

**Release C — Production-Ready Analyst Platform** requires:

- Priority 6: Session and Investigation Layer (session IDs, follow-up queries, investigation exports)
- Priority 7 (required parts): Extension-driven intelligence (Risk, Incident, ThreatActor)

See `tasks/todo.md` and `kgcs_evolution_roadmap_v_2.md` for details.
