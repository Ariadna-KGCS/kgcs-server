# kgcs-server — Agent Instructions

This repo serves grounded answers from the KGCS graph. It consumes the KGCS standard from `kgcs-spec` at the version pinned in `SPEC_VERSION`.

## Spec Pin

- `SPEC_VERSION` holds the pinned `kgcs-spec` release tag (without `v`).
- Materialize: `python tools/sync_spec.py` (idempotent; wipes and rebuilds the gitignored `spec/` from the tag; `--check` verifies without syncing). CI runs it unconditionally before tests.
- `agents/shared/schema_validator.py` loads contracts from `spec/contracts/`; response fields must match those schemas exactly.
- Never read spec artifacts from a sibling checkout's working tree.

## Hard Rules

1. **Read-only graph access.** Agents use parameterized, read-only Cypher templates only. No write transactions, ever.
2. **Causal chain.** Traversals follow `CPE → CVE/CVSS → CWE → CAPEC → ATT&CK → {D3FEND, CAR, SHIELD, ENGAGE}`. Reverse traversal of existing edges is allowed; shortcut edges are not.
3. **LLM boundary.** The LLM never generates Cypher and never invents facts. The AI layer is deterministic: classify → extract → safety → build → execute → render.
4. **Routing keys ≠ Neo4j parameters.** Keep request-routing keys separate from Cypher parameter names when they differ.
5. **Template identity.** Validate templates by declared route/template identity, not content sniffing.
6. **Provenance & confidence.** Provenance stays source-separated; CVSS versions never merge; confidence logic aligns with query type.
7. **Fail fast.** Stop mixed-intent orchestration when an upstream agent fails; never cascade bad input.

## Layout

Packages: `agents/` (systems, offensive, defensive + `agents/shared/`), `orchestrator/` (router, executor, aggregator, `api.py` HTTP layer), `ai/` (deterministic AI pipeline), `mcp/` (MCP server — Roadmap v3 F3, pending), `tools/` (`verify_schemas.py`, `smoke_test.py`), `tests/` (cross-component integration + fixtures).

Shared logic goes in `agents/shared/`, never duplicated per agent.

## Verification

- Full suite: `pytest` from repo root — baseline 450 tests (the other 18 of the historical 468 live in `kgcs-pipeline`).
- Contract check: `python tools/verify_schemas.py` (validates `spec/contracts/` + fixtures).
- Smoke test against a running instance: `python tools/smoke_test.py`.
- Environment prerequisites (`.env`) load before checks that depend on them.

Part of the Ariadna umbrella (`../README.md`).
