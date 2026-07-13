"""Configuration constants for Offensive Agent

Drives confidence scoring, Neo4j guardrails, and request validation.
"""

# Expected hops per template (used for confidence scoring)
# Weakness → AttackPattern → Technique = 3 hops
EXPECTED_HOPS = {
    "weakness": 3
}

# Confidence scoring penalties
STALE_DATA_PENALTY = 0.1
MISSING_HOP_PENALTY = 0.2
STALE_DATA_THRESHOLD_DAYS = 365

# Neo4j query guardrails
QUERY_TIMEOUT_SECONDS = 30
MAX_RESULT_ROWS = 10000

# Request validation
VALID_INTENTS = ["attack_path"]
VALID_PAYLOAD_FIELDS = {"cweId"}
