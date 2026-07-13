"""Cypher query templates for Offensive Agent

Parameterized template (uses $cweId, never string concatenation):
- T_OFF_01: Weakness → AttackPattern → Technique chain with MITRE mappings
"""

# Template T_OFF_01: Weakness to ATT&CK Techniques
TEMPLATE_T_OFF_01_WEAKNESS = """
MATCH (w:Weakness {cweId: $cweId})
  -[:DEMONSTRATED_BY]->(ap:AttackPattern)
MATCH p=(ap)-[:CHILD_OF*0..]->(mapped_ap:AttackPattern)-[:IMPLEMENTS]->(t:Technique)
OPTIONAL MATCH (t)-[:PART_OF]->(tac:Tactic)
OPTIONAL MATCH (t)<-[:SUBTECHNIQUE_OF]-(st:SubTechnique)
RETURN w, ap, mapped_ap, t, tac, st, length(p) - 1 AS hierarchyDepth
ORDER BY t.attackId, mapped_ap.capecId
"""

# Template metadata: maps request routing key to template definition
TEMPLATES = {
    "weakness": {
        "template": TEMPLATE_T_OFF_01_WEAKNESS,
        "params": ["cweId"],
        "expected_hops": 3,
        "description": "Find ATT&CK techniques that exploit or demonstrate a specific weakness"
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
    if "weakness" in name.lower():
        if "$cweId" not in template_string:
            raise ValueError(f"Template '{name}' missing $cweId parameter")

    # Validate all expected params are present
    if params:
        for param in params:
            if f"${param}" not in template_string:
                raise ValueError(f"Template '{name}' missing ${param} parameter")


# Validate all templates at module load time
for template_key, meta in TEMPLATES.items():
    validate_template(template_key, meta["template"], meta.get("params", []))
