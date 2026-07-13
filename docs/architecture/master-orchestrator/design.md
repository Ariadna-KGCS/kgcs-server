# Master Orchestrator Design

## Purpose

Coordinate multi-agent reasoning: classify intents, route to specialist agents, enforce traversal guardrails, aggregate provenance and confidence, and return canonical responses for downstream systems.

## Scope

- Orchestration flows and routing policies
- Contract validation and schema enforcement
- Provenance aggregation and confidence reconciliation
- Observability, retries, and failure modes
- Security model for inter-agent communications

Applies to production multi-agent runtime on Azure.

Excludes ontology edits, pipeline ETL, and Neo4j schema changes.

## Architectural Overview

- Roles: Orchestrator, Systems Agent, Offensive Agent, Defensive Agent
- Message bus: authenticated channel carrying JSON-enveloped requests
- Guardrails: template-based read-only Cypher queries; causal chain enforcement

## Core Control Loop

1. Ingest request → classify intent
2. Select agents and sequence (e.g., Systems → Offensive → Defensive for mixed intents)
3. Build contract envelope (versioned) and send to subagent
4. Validate response with JSON Schema + SHACL-derived checks
5. Merge data arrays, reconcile/conflict-resolve on `confidence` and `provenance`
6. Return unified response; emit audit events

## Routing Policies (examples)

- `vuln_lookup` → Systems Agent
- `attack_path` → Offensive Agent
- `coverage_map` → Defensive Agent
- `mixed` → orchestrator composes sequentially: Systems then Offensive then Defensive

## Provenance & Confidence Aggregation

- Keep full provenance array of {source, ids, timestamp}
- Reconciliation rule: prefer highest `confidence.value` with explicit `basis` and provenance; preserve alternatives in `steps[]`

## Error Handling and Retries

- Timeout: retry up to 2 times, then return partial with `confidence` degraded
- Empty result: retry with narrowed scope; if still empty, return `status: empty` with `confidence.value` low
- Schema violation: reject response and request agent to resend with corrected schema

## Observability

- Emit per-hop metrics: latency, rows, template id, confidence, errors
- Log correlation_id end-to-end

## Security

- Use mutual TLS or HMAC for agent auth
- Contracts versioned and enforced; unversioned payloads rejected
- Agents run with least privilege (Neo4j reads only)

## Outputs

- Final JSON: { question, steps[], evidence[], confidence, risk_signal?, citations[] }
- Markdown rendering for human channels; JSON for API.

## Example Interaction

Request:

```json
{ "version":"1.0", "correlation_id":"uuid", "agent":"master", "intent":"attack_path", "payload":{"cpe":"cpe:..."}, "constraints":{"max_hops":4} }
```

Response:

```json
{ "status":"ok", "data":[...], "provenance":[...], "confidence":{"value":0.78,"basis":"COMPLETE_CHAIN"} }
```
