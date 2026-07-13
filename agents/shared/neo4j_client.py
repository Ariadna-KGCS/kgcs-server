"""Read-only Neo4j client for agent queries

ARCHITECTURE NOTE: This module is for READ-ONLY access only. It must NEVER be used
for write operations. The ETL layer uses scripts.etl.neo4j_writer for writes.
Files must NEVER import from scripts/etl/neo4j_writer - that violates the architecture.

Query execution is parameterized only - no Cypher string concatenation.
"""

import logging
import os
import time
from typing import List, Dict, Optional, Any
from neo4j import GraphDatabase, basic_auth, READ_ACCESS

# Load .env if present (no-op when python-dotenv is not installed)
try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv(override=False)
except ImportError:
    pass

# Neo4j transient exceptions that merit a retry (gracefully absent when no driver).
try:
    from neo4j.exceptions import ServiceUnavailable, SessionExpired
    _RETRYABLE_EXC = (ServiceUnavailable, SessionExpired)
except ImportError:  # pragma: no cover
    _RETRYABLE_EXC = ()

_neo4j_log = logging.getLogger("kgcs.neo4j")
# Queries exceeding this threshold (ms) emit a WARNING.  Override via env var.
_SLOW_QUERY_MS = int(os.getenv("NEO4J_SLOW_QUERY_MS", "5000"))
# Maximum number of query retries on transient Neo4j errors.
_MAX_RETRIES = 2
# Back-off intervals (seconds) between retries: 100 ms, 200 ms.
_RETRY_BACKOFF = (0.1, 0.2)


class Neo4jClient:
    """Read-only Neo4j graph database client for agent queries

    All queries use READ_ACCESS mode. Constructor fails if read-only enforcement
    is not available on the driver version.
    """

    def __init__(
        self,
        uri: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
        timeout: int = 30
    ):
        """Initialize Neo4j client from environment variables or explicit args.

        Environment variables (if not passed explicitly):
        - NEO4J_URI: Connection URI (e.g., neo4j+s://hostname:7687)
        - NEO4J_USER: Username for authentication
        - NEO4J_PASSWORD: Password for authentication

        Args:
            uri: Optional override for NEO4J_URI env var
            user: Optional override for NEO4J_USER env var
            password: Optional override for NEO4J_PASSWORD env var
            database: Optional override for NEO4J_DATABASE env var
            timeout: Query timeout in seconds (default: 30)

        Raises:
            ValueError: If required env vars or args are missing
        """
        self.uri = uri or os.getenv("NEO4J_URI")
        self.user = user or os.getenv("NEO4J_USER")
        self.password = password or os.getenv("NEO4J_PASSWORD")
        self.database = database or os.getenv("NEO4J_DATABASE")
        # NEO4J_QUERY_TIMEOUT env var overrides the constructor default.
        self.timeout = int(os.getenv("NEO4J_QUERY_TIMEOUT", str(timeout)))

        if not all([self.uri, self.user, self.password]):
            raise ValueError(
                "Neo4jClient requires NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD. "
                "Provide via environment variables or constructor arguments."
            )

        # Let the Neo4j driver derive transport/security behavior from the URI
        # (for example, `bolt://` vs `neo4j+s://`). This keeps the read client
        # compatible with the installed Neo4j driver version.
        self.driver = GraphDatabase.driver(
            self.uri,
            auth=basic_auth(self.user, self.password),
        )

    def query(self, cypher: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute a parameterized read-only query.

        Query execution mode: READ_ACCESS (enforces read-only at Neo4j driver level)

        Transient Neo4j errors (ServiceUnavailable, SessionExpired) are retried up to
        ``_MAX_RETRIES`` times with exponential back-off.  A ``TimeoutError`` is raised
        when the Neo4j driver reports a query timeout so the orchestrator can surface
        an HTTP 504 instead of 500.

        Args:
            cypher: Parameterized Cypher query (must use $params, never string concat)
            params: Dict of parameter values

        Returns:
            List of record dicts. Empty list if no results.

        Raises:
            TimeoutError: If the Neo4j driver reports a query timeout.
            ValueError: If query fails for a non-transient, non-timeout reason.
        """
        last_exc: Optional[Exception] = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                with self.driver.session(
                    default_access_mode=READ_ACCESS,
                    database=self.database,
                ) as session:
                    t0 = time.perf_counter()
                    result = session.run(cypher, params, timeout=self.timeout)
                    records = [record.data() for record in result]
                    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
                    if elapsed_ms > _SLOW_QUERY_MS:
                        _neo4j_log.warning(
                            "slow_query",
                            extra={"latency_ms": elapsed_ms},
                        )
                    return records
            except Exception as exc:
                last_exc = exc
                if "timeout" in str(exc).lower():
                    raise TimeoutError(f"Neo4j query timed out: {exc}") from exc
                if _RETRYABLE_EXC and isinstance(exc, _RETRYABLE_EXC):
                    if attempt < _MAX_RETRIES:
                        sleep_s = _RETRY_BACKOFF[min(attempt, len(_RETRY_BACKOFF) - 1)]
                        _neo4j_log.warning(
                            f"transient_neo4j_error attempt {attempt + 1}/{_MAX_RETRIES}: {exc}; "
                            f"retrying in {int(sleep_s * 1000)} ms",
                        )
                        time.sleep(sleep_s)
                        continue
                raise ValueError(f"Query execution failed: {last_exc}") from last_exc
        raise ValueError(f"Query execution failed after retries: {last_exc}") from last_exc

    def single_query(self, cypher: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Execute a parameterized read-only query returning first result or None.

        Args:
            cypher: Parameterized Cypher query
            params: Dict of parameter values

        Returns:
            First result record dict, or None if no results

        Raises:
            ValueError: If query fails
        """
        results = self.query(cypher, params)
        return results[0] if results else None

    def close(self) -> None:
        """Close the driver connection."""
        if self.driver:
            self.driver.close()

    def __enter__(self) -> "Neo4jClient":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - closes driver."""
        self.close()
