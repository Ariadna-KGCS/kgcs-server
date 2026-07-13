# KGCS Test Fixtures

Canonical request/response examples for integration testing, smoke testing, and
contract verification.  These fixtures were captured during Priority 2 real-graph
validation against the `kgcs-v2` Neo4j database.

## Structure

```
tests/fixtures/
  requests/           — valid request envelopes (one per query type)
  responses/          — representative response envelopes (schema-correct shapes)
  edge_cases/         — known edge-case and failure examples
```

## Request fixtures

| File | Intent | Anchor | Validated |
|---|---|---|---|
| `requests/vuln_lookup_by_cve.json`       | vuln_lookup | CVE-2021-44228 | yes (Log4Shell) |
| `requests/vuln_lookup_by_cpe.json`       | vuln_lookup | cpeName        | yes |
| `requests/attack_path_by_cwe.json`       | attack_path | CWE-20         | yes |
| `requests/coverage_map_by_technique.json`| coverage_map| T1190          | yes |
| `requests/mixed_by_cve.json`             | mixed       | CVE-2021-44228 | yes |

## Response fixtures

Response fixtures capture the **envelope shape**, not live graph data.  Field
values reflect representative real-data runs but should not be used as exact
comparison targets in unit tests (use schema validation instead).

## Edge-case fixtures

| File | Scenario |
|---|---|
| `edge_cases/not_found_response.json`       | Graph returns empty for an unknown CVE |
| `edge_cases/multi_entity_error.json`       | /ask prompt contains two CVE IDs |
| `edge_cases/safety_violation_error.json`   | /ask prompt triggers injection heuristic |
| `edge_cases/invalid_request.json`          | /query with missing required field |

## Updating fixtures

When the graph schema or request contract changes, regenerate response fixtures
by running a one-off validated query against a live `kgcs-v2` instance and
saving the output here.  Always validate new fixture shapes against
`spec/contracts/` before committing.
