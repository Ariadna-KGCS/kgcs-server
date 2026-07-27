# Contributing to kgcs-server

Thanks for looking at KGCS. This repo is in **private preview** (launched 2026-07-27,
built on the frozen `kgcs-spec` v1.0.0 baseline) — expect things to move, and please
read this before opening an issue or PR.

## Before anything else

- **Read [`CLAUDE.md`](CLAUDE.md).** It's the actual contract this codebase is built
  against: read-only Cypher only, the causal chain order
  (`CPE → CVE/CVSS → CWE → CAPEC → ATT&CK → {D3FEND, CAR, SHIELD, ENGAGE}`, no
  shortcut edges), the deterministic AI pipeline (classify → extract → safety →
  build → execute → render — the LLM never writes Cypher or invents facts), and the
  spec-pin discipline (`SPEC_VERSION` + `tools/sync_spec.py`). A PR that violates one
  of these will be asked to change regardless of how well-tested it is.
- **Try it first.** [`docs/mcp/quickstart.md`](docs/mcp/quickstart.md) gets you a
  running graph + MCP connection in ~10-15 minutes. Reporting friction from that
  process is itself a valuable contribution right now.

## Reporting a bug or friction point

Open a GitHub issue. Include:

- What you were trying to do (a prompt to Claude, a specific query, a setup step).
- What happened vs. what you expected.
- Your environment: OS, Neo4j version (community/enterprise), whether you loaded the
  graph via the dump (Option A) or the pipeline (Option B).

During the private preview, **friction reports on the install/quickstart path are as
valuable as code bugs** — this is exactly what the preview is for.

## Proposing a change

1. Open an issue first for anything beyond a typo or doc fix — this avoids work on a
   change that doesn't fit the architecture in `CLAUDE.md`.
2. Fork, branch, make the change.
3. Before opening a PR, run locally:
   ```bash
   pip install -r requirements.txt
   python tools/sync_spec.py        # materializes spec/ from the pinned kgcs-spec tag
   python -m pytest -q              # full suite (450 tests as of the v1.0.0 baseline)
   python tools/verify_schemas.py   # JSON Schema contract checks
   ```
   All three must pass. CI (`.github/workflows/test.yml`) runs the same commands on
   every PR.
4. Keep the diff scoped to one concern. Agents/orchestrator/AI layer changes that
   touch the causal chain or the read-only boundary need extra justification in the
   PR description.

## What this repo is not (yet)

- Not a place for spec/ontology changes — those belong in `kgcs-spec`; this repo
  only ever *consumes* a pinned release via `SPEC_VERSION`.
- Not a hosted service — every private-preview user runs their own local instance.
  There's no shared deployment to file infrastructure issues against.
- `mcp/` (the native KGCS MCP server, Roadmap v3 · F3) is an empty skeleton for now;
  the working MCP path today is the generic `mcp-neo4j-cypher` server described in
  the install guide.

## Windows note

If you're on Windows and this repo lives on a mounted/network drive (common with
some sandboxed dev setups), you may see every tracked file listed as `modified`
after a plain `git status`, with `old mode 100644` / `new mode 100755` diffs and
no content change. That mount reports all files as executable regardless of
content; Git faithfully tracks it if `core.filemode` is on. Fix once per clone:

```bash
git config core.filemode false
```

## License

Apache 2.0 ([`LICENSE`](LICENSE)). By contributing, you agree your contribution is
licensed under the same terms.
