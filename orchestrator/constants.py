"""Configuration constants for Master Orchestrator"""

# Supported intents
VALID_INTENTS = [
    "vuln_lookup",   # Systems Agent: vulnerability lookup by criteria ID, CPE name, or CVE
    "attack_path",   # Offensive Agent: attack path from weakness to technique
    "coverage_map",  # Defensive Agent: defensive coverage for technique
    "mixed"          # Multi-agent: composite query (vuln_lookup + attack_path + coverage_map)
]

# Intent-to-agent mapping for single-intent requests
INTENT_TO_AGENT = {
    "vuln_lookup": "systems",
    "attack_path": "offensive",
    "coverage_map": "defensive"
}

# Multi-intent sequence: order in which agents are called for "mixed" intent
MIXED_INTENT_SEQUENCE = [
    ("systems", "vuln_lookup"),      # Get vulnerabilities from CPE/CVE
    ("offensive", "attack_path"),    # Get attack paths from CVE/CWE
    ("defensive", "coverage_map")    # Get defensive coverage for techniques
]

# Payload field requirements per intent
INTENT_PAYLOAD_FIELDS = {
    "vuln_lookup": {"matchCriteriaId", "cpeName", "cpe", "cveId"},
    "attack_path": {"cveId", "cweId"},   # At least one of these
    "coverage_map": {"attackId"},         # This one is required
    "mixed": {"matchCriteriaId", "cpeName", "cpe", "cveId"}
}

# Query timeouts and limits
QUERY_TIMEOUT_SECONDS = 30
MAX_RESULT_ROWS = 10000

# Confidence merging strategy for multi-agent responses
# Options: "average", "minimum", "weighted"
CONFIDENCE_MERGE_STRATEGY = "average"

# Agent call timeout (in case agent service is slow)
AGENT_CALL_TIMEOUT_SECONDS = 60
