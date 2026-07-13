# Inter-Agent Contract Spec

## Purpose

Define JSON payloads for orchestrator and subagent exchanges to ensure deterministic, schema-validated interactions.

## Scope

- Request and response envelopes, error model, versioning, provenance, confidence fields.

## Envelope

```json
{
  "version": "1.0",
  "correlation_id": "uuid",
  "agent": "systems|offensive|defensive",
  "intent": "vuln_lookup|attack_path|coverage_map|mixed",
  "payload": {},
  "constraints": { "max_hops": 4, "allow_extensions": false }
}
```

## Responses

```json
{
  "version": "1.0",
  "correlation_id": "uuid",
  "status": "ok|empty|error",
  "data": {},
  "provenance": [{ "source": "NVD", "ids": ["CVE-2025-1234"] }],
  "confidence": { "value": 0.0, "basis": "template|coverage|partial" },
  "errors": []
}
```

## Error Model

- schema_violation
- timeout
- empty_result
- upstream_error

Retries are allowed for timeout and empty_result (maximum two attempts).

## Validation

- JSON Schema per agent; enforce required properties and allowed labels.
- Reject responses missing provenance or confidence.

## Security

- HMAC or internal service authentication.
- Correlation IDs logged end to end.
- No Cypher text in payloads; only result objects.
