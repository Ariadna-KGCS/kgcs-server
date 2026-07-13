"""Systems Agent configuration constants

Drives confidence scoring, Neo4j query guardrails, and request validation
"""

# Expected hops per query type (from cypher templates)
# CPE lookup: PC -> V (AFFECTS) + V -> W (CAUSED_BY) + V -> S (HAS_SCORE) = 3 hops
# CVE lookup: V -> W (CAUSED_BY) + V -> S (HAS_SCORE) = 2 hops
EXPECTED_HOPS = {
    "matchCriteriaId": 3,
    "cpeName": 3,
    "cpe": 3,
    "cveId": 2
}

# Confidence penalty constants (from confidence-model/spec.md)
MISSING_HOP_PENALTY = 0.2
STALE_DATA_PENALTY = 0.1
STALE_DATA_THRESHOLD_DAYS = 365

# Neo4j query execution guardrails
QUERY_TIMEOUT_SECONDS = 30
MAX_RESULT_ROWS = 10000

# Request validation
VALID_INTENTS = ["vuln_lookup"]
VALID_PAYLOAD_FIELDS = {"matchCriteriaId", "cpeName", "cpe", "cveId"}

# Logging configuration
LOG_LEVEL = "INFO"
LOG_FORMAT = "[%(correlation_id)s] %(levelname)s: %(message)s"
