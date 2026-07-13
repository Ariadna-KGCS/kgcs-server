# Agent Security

## Purpose

Ensure secure agent operation in Azure with read-only graph access and private networking.

## Scope

- Network security
- Data protection
- Observability

## Network Security

- **VNet**: Agents in private subnet.
- **Private Endpoints**: To Neo4j, OpenAI, Key Vault, Storage.
- **No Public Ingress**: All traffic internal.

## Data Security

- **Encryption**: At rest (Neo4j Aura), in transit (TLS).
- **Read-Only**: Agents use approved Cypher templates; no mutations.
- **Provenance**: All queries log correlation IDs.

## Observability

- **Logs**: Cypher text, row counts, confidence to Azure Monitor.
- **Alerts**: On errors, latency > threshold.
- **Audits**: Agent actions traceable.
