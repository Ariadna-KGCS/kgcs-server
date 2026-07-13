"""Cypher query templates for Systems Agent

All templates are parameterized (use $params, never string concatenation).
Three query patterns:
- T_SYS_01: Vulnerabilities affecting a PlatformConfiguration
- T_SYS_02: Root cause (CWE) and scores for a CVE
- T_SYS_03: All platforms affected by a CVE (aggregates with T_SYS_02)
"""

# Template T_SYS_01: Vulnerabilities for a platform configuration
TEMPLATE_T_SYS_01_MATCH_CRITERIA = """
MATCH (pc:PlatformConfiguration)
WHERE pc.matchCriteriaId = $matchCriteriaId
MATCH (pc)<-[:AFFECTS]-(v:Vulnerability)
OPTIONAL MATCH (v)-[:CAUSED_BY]->(w:Weakness)
OPTIONAL MATCH (pc)-[:MATCHES_PLATFORM]->(p:Platform)
WITH v, pc, w, collect(DISTINCT p) AS platformMatches
OPTIONAL MATCH (v)-[:HAS_SCORE]->(s:Score)
WITH v, pc, w, platformMatches, collect(DISTINCT s) AS scores
CALL (v, pc) {
  OPTIONAL MATCH (v)-[:HAS_CONFIGURATION]->(vc:VulnerabilityConfiguration)-[:HAS_NODE]->(vcn:VulnerabilityConfigurationNode)-[mc:MATCHES_CRITERIA]->(pc)
  RETURN collect(DISTINCT {
    vc: properties(vc),
    vcn: properties(vcn),
    mc: properties(mc),
    pc_match: properties(pc)
  }) AS applicabilityRows
}
RETURN v, w, scores, pc, platformMatches, applicabilityRows
ORDER BY v.cveId
"""

# Template T_SYS_01B: Vulnerabilities for a canonical CPE name
TEMPLATE_T_SYS_01_CPE_NAME = """
MATCH (p:Platform {cpeUri: $cpeName})
MATCH (pc:PlatformConfiguration)-[:MATCHES_PLATFORM]->(p)
MATCH (pc)<-[:AFFECTS]-(v:Vulnerability)
OPTIONAL MATCH (v)-[:CAUSED_BY]->(w:Weakness)
WITH v, pc, w, collect(DISTINCT p) AS platformMatches
OPTIONAL MATCH (v)-[:HAS_SCORE]->(s:Score)
WITH v, pc, w, platformMatches, collect(DISTINCT s) AS scores
CALL (v, pc) {
  OPTIONAL MATCH (v)-[:HAS_CONFIGURATION]->(vc:VulnerabilityConfiguration)-[:HAS_NODE]->(vcn:VulnerabilityConfigurationNode)-[mc:MATCHES_CRITERIA]->(pc)
  RETURN collect(DISTINCT {
    vc: properties(vc),
    vcn: properties(vcn),
    mc: properties(mc),
    pc_match: properties(pc)
  }) AS applicabilityRows
}
RETURN v, w, scores, pc, platformMatches, applicabilityRows
ORDER BY v.cveId
"""

# Template T_SYS_02: Root-cause trace and CVSS scores for a CVE
TEMPLATE_T_SYS_02_CVE = """
MATCH (v:Vulnerability {cveId: $cveId})
OPTIONAL MATCH (v)-[:CAUSED_BY]->(w:Weakness)
WITH DISTINCT v, w
OPTIONAL MATCH (v)-[:HAS_SCORE]->(s:Score)
WITH v, w, collect(DISTINCT s) AS scores
CALL (v) {
  OPTIONAL MATCH (v)-[:HAS_CONFIGURATION]->(vc:VulnerabilityConfiguration)-[:HAS_NODE]->(vcn:VulnerabilityConfigurationNode)
  OPTIONAL MATCH (vcn)-[mc:MATCHES_CRITERIA]->(pc_match:PlatformConfiguration)
  OPTIONAL MATCH (pc_match)-[:MATCHES_PLATFORM]->(p_match:Platform)
  RETURN collect(DISTINCT {
    vc: properties(vc),
    vcn: properties(vcn),
    mc: properties(mc),
    pc_match: properties(pc_match),
    p_match: properties(p_match)
  }) AS applicabilityRows
}
RETURN v, w, scores, applicabilityRows
ORDER BY v.cveId
"""

# Template T_SYS_03: Platforms affected by a CVE (optional, may be combined with T_SYS_02)
TEMPLATE_T_SYS_03_AFFECTED_PLATFORMS = """
MATCH (v:Vulnerability {cveId: $cveId})
  <-[:AFFECTS]-(pc:PlatformConfiguration)
OPTIONAL MATCH (pc)-[:MATCHES_PLATFORM]->(p:Platform)
RETURN v, pc, p
ORDER BY pc.matchCriteriaId
"""

# Template metadata: maps intent/payload field to template definition
TEMPLATES = {
    "matchCriteriaId": {
        "template": TEMPLATE_T_SYS_01_MATCH_CRITERIA,
        "params": ["matchCriteriaId"],
        "expected_hops": 3,
        "description": "Find CVEs affecting a specific PlatformConfiguration"
    },
    "cpeName": {
        "template": TEMPLATE_T_SYS_01_CPE_NAME,
        "params": ["cpeName"],
        "expected_hops": 3,
        "description": "Find CVEs affecting a canonical Platform CPE name"
    },
    "cpe": {
        "template": TEMPLATE_T_SYS_01_MATCH_CRITERIA,
        "params": ["matchCriteriaId"],
        "expected_hops": 3,
        "description": "Legacy compatibility alias for PlatformConfiguration lookup"
    },
    "cveId": {
        "template": TEMPLATE_T_SYS_02_CVE,
        "params": ["cveId"],
        "expected_hops": 2,
        "description": "Find details and root cause for a CVE"
    }
}


def validate_template(name: str, template_string: str, params: list = None) -> None:
    """
    Validate Cypher template syntax.

    Args:
        name: Template name (for logging)
        template_string: Cypher query
        params: List of expected parameters (if provided)

    Raises:
        ValueError: If template is malformed (missing $params, invalid structure)
    """
    if not template_string or not isinstance(template_string, str):
        raise ValueError(f"Template '{name}' is empty or not a string")

    # Ensure template uses parameterized syntax (not string concat artifacts)
    has_match = "MATCH" in template_string or "OPTIONAL MATCH" in template_string
    if not has_match:
        raise ValueError(f"Template '{name}' missing MATCH clause")

    # Check for parameterized markers in expected templates
    # Validate based on template key name, not content sniffing
    if "matchcriteria" in name.lower() or name.lower() == "cpe":
        if "$matchCriteriaId" not in template_string:
            raise ValueError(f"Template '{name}' missing $matchCriteriaId parameter")
    elif "cpename" in name.lower():
        if "$cpeName" not in template_string:
            raise ValueError(f"Template '{name}' missing $cpeName parameter")
    elif "cve" in name.lower():
        if "$cveId" not in template_string:
            raise ValueError(f"Template '{name}' missing $cveId parameter")

    # Validate all expected params are present
    if params:
        for param in params:
            if f"${param}" not in template_string:
                raise ValueError(f"Template '{name}' missing ${param} parameter")


# Validate all templates at module load time
for template_key, meta in TEMPLATES.items():
    validate_template(template_key, meta["template"], meta.get("params", []))
