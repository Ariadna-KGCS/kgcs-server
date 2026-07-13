"""Configuration constants for Defensive Agent"""

# Expected hops per template
EXPECTED_HOPS = {
    "coverage_map": 1  # Technique → defensive controls (single hop)
}

# Confidence scoring penalties
MISSING_FRAMEWORK_PENALTY = 0.1  # -0.1 for each missing D3FEND/CAR/SHIELD/ENGAGE
STALE_DATA_PENALTY = 0.1
STALE_DATA_THRESHOLD_DAYS = 365

# Neo4j guardrails
QUERY_TIMEOUT_SECONDS = 30
MAX_RESULT_ROWS = 10000

# Request validation
VALID_INTENTS = ["coverage_map"]
VALID_PAYLOAD_FIELDS = {"attackId"}

# Pattern validation for framework identifiers
TECHNIQUE_PATTERN = r"^T\d{4}(\.\d{3})?$"  # Techniques and subtechniques
D3FEND_PATTERN = r"^D3-[A-Z][A-Z0-9]*$"
CAR_PATTERN = r"^CAR-\d{4}-\d{2}-\d{3}$"
SHIELD_PATTERN = r"^DTE\d{4}$"
ENGAGE_ACTIVITY_PATTERN = r"^EAC\d{4}$"
ENGAGE_APPROACH_PATTERN = r"^SAP\d{4}$"
ENGAGE_GOAL_PATTERN = r"^SGO\d{4}$"
