# RBAC

## Purpose

Define role-based access controls for agents and users in KGCS deployment.

## Scope

- Azure managed identities
- Neo4j roles
- Key Vault policies

## Agent Access

- **Managed Identity**: Each agent (orchestrator, systems, offensive, defensive) uses system-assigned MI.
- **Neo4j**: `agent_reader` role for read-only Cypher queries.
- **Key Vault**: Access to secrets (Neo4j creds, OpenAI keys) via policies.

## User Roles

- **Admin**: Full access to infrastructure.
- **Operator**: Deploy/manage agents.
- **Auditor**: Read logs/metrics.

## Policies

- Least privilege: Agents cannot write to graph.
- Private endpoints only.
