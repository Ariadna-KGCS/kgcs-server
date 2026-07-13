# kgcs-server

Serves grounded cybersecurity answers from the KGCS graph. Part of [Ariadna](../README.md).

## Layout

- `agents/` — Systems, Offensive, Defensive agents (read-only, schema-driven Cypher templates) + `agents/shared/` (Neo4j client, response builder, confidence/risk scorers, schema validator, logging, types)
- `orchestrator/` — routing, execution, aggregation, mixed-intent handling + `api.py` (hardened HTTP API: `/query`, `/ask`; auth, rate limiting, timeouts, JSON logs)
- `ai/` — deterministic AI layer: intent classification, entity extraction, safety, response rendering (LLM never generates Cypher, never invents facts)
- `mcp/` — Model Context Protocol server exposing KGCS tools to any AI assistant (Roadmap v3 · F3, pending)
- `tools/` — `sync_spec.py` (pin materialization), `verify_schemas.py` (contract validation against the pinned spec), `smoke_test.py`
- `tests/` — cross-component integration tests and fixtures
- `spec/` — pinned `kgcs-spec` materialization (gitignored; see below)
- `Dockerfile`, `docker-compose.yml` — local/dev deployment stack

## Spec Pin

`SPEC_VERSION` pins the `kgcs-spec` release (currently **1.0.0**). Materialize with:

```bash
python tools/sync_spec.py   # or: python tools/sync_spec.py --url <kgcs-spec-url>
```

The script is idempotent: it wipes and rebuilds the gitignored `spec/` from the pinned tag (hand-edits cannot survive), records tag+commit in `spec/.pin`, and `--check` verifies the pin without syncing. CI runs it unconditionally before tests. `agents/shared/schema_validator.py` loads response/request contracts from `spec/contracts/`.

## Rules

- Pins a released `kgcs-spec` version; response fields match its contracts exactly.
- Agents are read-only: parameterized Cypher templates only, validated by declared identity.
- Provenance stays source-separated; CVSS versions never merge.
- Traversals follow the causal chain; reverse traversal of existing edges allowed, shortcut edges never.
- Stop mixed-intent orchestration when an upstream agent fails.

## Status

Migrated from the seed repo (Release B baseline). **450 tests passing** (the remaining 18 of the historical 468 are ETL tests, now in `kgcs-pipeline`). Pinned to `kgcs-spec` **v1.0.0**. Docs under `docs/` (architecture, agents, security, release history).
