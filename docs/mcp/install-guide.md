# KGCS MCP Server — Installation Guide

Step-by-step setup to query the KGCS knowledge graph from Claude (Desktop or Cowork) through the [`mcp-neo4j-cypher`](https://github.com/neo4j-contrib/mcp-neo4j/tree/main/servers/mcp-neo4j-cypher) MCP server. Written for a fresh machine — nothing pre-installed — so it works both for additional workstations and for peer reviewers / early users evaluating KGCS.

> **Note.** This uses the generic Neo4j Labs Cypher MCP server pointed at the KGCS graph. The KGCS-native MCP server (grounded tools on top of the agent layer, Roadmap v3 · F3) will live in `kgcs-server/mcp/` and get its own guide.

> **New here?** For the fast path (restore a ready-made dump, connect Claude Desktop, done in ~10-15 minutes) see [`quickstart.md`](quickstart.md) ([català: `quickstart.ca.md`](quickstart.ca.md)). This page is the full reference — every option, every failure mode.

```
Claude Desktop / Cowork ──stdio──> mcp-neo4j-cypher ──bolt://──> Neo4j (KGCS graph)
```

## 1. Prerequisites

- **Docker** (Desktop on Windows/macOS, engine on Linux) — for Neo4j.
- **Python 3.11+** — only needed for the ETL path (option B) and validation scripts.
- **uv** — runs the MCP server via `uvx`:
  - Windows: `winget install astral-sh.uv`
  - macOS: `brew install uv`
  - Linux: `curl -LsSf https://astral.sh/uv/install.sh | sh`
- **Claude Desktop** with an account that has MCP support.
- Hardware: the full graph is ~6M nodes / ~37M relationships. 8 GB RAM for Neo4j is comfortable; budget ~20 GB of free disk for data + raw feeds if you run the ETL.

## 2. Start Neo4j (with APOC)

The MCP schema tool requires the APOC plugin, so enable it from the start.

> **Note.** Neo4j has no separate install step here — the `docker run` command below
> pulls the official `neo4j:2026.05-community` image on first run (~1-2 minutes) and runs it as a
> container. If you're used to Neo4j Desktop: you don't need it for this guide, and the
> "reference setup" mentioned at the bottom of this doc (Neo4j Enterprise) is only what
> the KGCS graph was validated against, not a requirement for you.

```bash
docker run -d --name kgcs-neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/<choose-a-password> \
  -e NEO4J_PLUGINS='["apoc"]' \
  -v kgcs_neo4j_data:/data \
  neo4j:2026.05-community
```

Check it's up: open http://localhost:7474 and log in with `neo4j` / your password.

**Database name.** The Docker community image has a single database, `neo4j` — use that everywhere below. Named databases (e.g. `kgcs-dv` on the reference setup) require Neo4j Enterprise; if you have it, substitute your database name consistently.

## 3. Load the KGCS graph

Two options — the dump is fast, the ETL is fully reproducible.

### Option A — restore a dump (minutes)

Download the pre-built graph from the [`kgcs-pipeline` GitHub Release](https://github.com/Ariadna-KGCS/kgcs-pipeline/releases/download/dataset-v1.0.0/kgcs-dv-2026-07-27T10-51-43.dump) (v1.0.0, ~812 MB). The file name must match the target database name — rename it to `neo4j.dump` if loading into the default database. Then:

```bash
docker stop kgcs-neo4j

docker run --rm \
  -v kgcs_neo4j_data:/data \
  -v /path/to/folder-with-dump:/dumps \
  neo4j:2026.05-community \
  neo4j-admin database load neo4j --from-path=/dumps --overwrite-destination=true

docker start kgcs-neo4j
```

*(Maintainer side, to produce the dump: stop the database, then `neo4j-admin database dump <db> --to-path=<dir>`.)*

### Option B — build from sources with kgcs-pipeline (hours)

Downloads the 10 authoritative feeds (NVD, MITRE) and loads the graph in causal-chain order (constraints → nodes → relationships):

```bash
git clone https://github.com/Ariadna-KGCS/kgcs-pipeline.git
cd kgcs-pipeline
pip install -r requirements.txt
python sync_spec.py                # materialize the pinned kgcs-spec release
python download.py --standard all  # raw datasets (~GBs, be patient)
cp .env.example .env               # set NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD / NEO4J_DATABASE
python run_all_etl.py              # constraints → nodes → relationships
```

Heads-up: the pipeline's `.env` uses `NEO4J_USER`; the MCP server (step 5) uses `NEO4J_USERNAME`. Same value, different key.

## 4. Verify the graph

From `kgcs-pipeline` (works for both options):

```bash
python validation/extract_neo4j_stats.py --pretty --check-minimums
```

Or manually in the Neo4j browser:

```cypher
MATCH (n) RETURN count(n);   // expect ≈ 6,000,000
```

Expected minimum node counts: Vulnerability ≥ 250,000 · Platform ≥ 50,000 · Weakness ≥ 900 · AttackPattern ≥ 500 · Technique ≥ 350 · SubTechnique ≥ 400 · Tactic ≥ 14.

## 5. Configure the MCP server in Claude Desktop

Open **Settings → Developer → Edit Config** (`claude_desktop_config.json`) and add:

```json
{
  "mcpServers": {
    "kgcs-neo4j": {
      "command": "uvx",
      "args": ["mcp-neo4j-cypher@0.6.0", "--transport", "stdio"],
      "env": {
        "NEO4J_URI": "bolt://localhost:7687",
        "NEO4J_USERNAME": "neo4j",
        "NEO4J_PASSWORD": "<your-password>",
        "NEO4J_DATABASE": "neo4j",
        "NEO4J_READ_ONLY": "true"
      }
    }
  }
}
```

Restart Claude Desktop (fully quit, not just close the window). You should now see the tools `read_neo4j_cypher` and `get_neo4j_schema` (plus `write_neo4j_cypher` if you drop `NEO4J_READ_ONLY`).

Keep `NEO4J_READ_ONLY=true` unless you have a reason not to: KGCS agents are read-only by design, and it protects the graph from accidental writes during experiments.

## 6. Smoke test

Ask Claude to run these; both should succeed:

```cypher
// 1. Connectivity + volume
MATCH (n) RETURN count(n) AS totalNodes;

// 2. Full causal-chain traversal (CVE → CWE → CAPEC → ATT&CK)
MATCH (v:Vulnerability)-[:CAUSED_BY]-(w:Weakness)
      -[:DEMONSTRATED_BY]-(ap:AttackPattern)
      -[:IMPLEMENTS]-(t:Technique)
RETURN v.cveId, w.cweId, ap.capecId, t.attackId LIMIT 3;
```

If query 2 returns rows (e.g. `CVE-2017-2616 → CWE-267 → CAPEC-648 → T1113`), the graph and the causal chain are intact.

Property names in the graph are camelCase and source-specific (`cveId`, `cweId`, `capecId`, `attackId`); relationship types are SCREAMING_CASE (`CAUSED_BY`, `MITIGATED_BY`).

## 7. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Dump restore fails, gives wrong node counts, or Docker-based Neo4j "just doesn't work" while a native/Desktop Neo4j install works fine | Docker image on an incompatible major-version line. Neo4j moved to calendar versioning (2025+); `neo4j:5` is the old line and cannot cleanly load a dump from a `2026.x` instance. Use `neo4j:2026.05-community` (matches the reference setup and the published dump). |
| Tools don't appear in Claude after restart | `uvx` not on Claude's PATH. Replace `"command": "uvx"` with the absolute path (Windows: `%USERPROFILE%\.local\bin\uvx.exe`; macOS/Linux: `~/.local/bin/uvx`). Check logs under Claude's `logs/` folder (`mcp-server-kgcs-neo4j.log`). |
| `Authentication failure` | `NEO4J_PASSWORD` doesn't match the one set in `NEO4J_AUTH` at first container start. Auth is fixed at first boot; recreate the volume or reset the password. |
| `get_neo4j_schema` fails, queries work | APOC missing. Recreate the container with `NEO4J_PLUGINS='["apoc"]'`. |
| `Unable to get a routing table for database ...` / unknown database | `NEO4J_DATABASE` doesn't exist. Community edition only has `neo4j`; named databases need Enterprise. |
| Port already in use | Another Neo4j (or the `kgcs-server` docker-compose stack) is bound to 7474/7687. Stop it or remap ports consistently in both places. |
| Slow first MCP call | `uvx` downloads the package on first run; subsequent starts are cached. |

## Versions this guide was validated against

- Neo4j 2026.05.0 (Enterprise, reference setup) — use the `neo4j:2026.05-community` Docker image for the steps above (same calendar-versioned release line as the reference setup and the published dump). **Corrected 2026-07-27:** earlier revisions of this guide pinned `neo4j:5`, an older, incompatible major-version line (Neo4j moved to calendar versioning in 2025) — a dump from 2026.05.0 will not restore cleanly into it. If you already have a `neo4j:5`-based setup from before this fix, recreate the container with the tag above.
- `mcp-neo4j-cypher` 0.6.0
- KGCS graph per `kgcs-spec` v1.0.0 (6,007,052 nodes at validation time)
