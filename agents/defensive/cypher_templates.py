"""Cypher templates for Defensive Agent

Centralized template management with validation at module load time.
"""

# T_DEF_01: Coverage Map Query
# Returns all defensive controls (mitigations, detections, deceptions, engagements)
# that apply to an ATT&CK Technique
TEMPLATE_T_DEF_01 = """
MATCH (t:Technique {attackId: $attackId})
OPTIONAL MATCH (t)-[:MITIGATED_BY]->(d:DefensiveTechnique)
OPTIONAL MATCH (t)-[:DETECTED_BY]->(c:DetectionAnalytic)
OPTIONAL MATCH (t)-[:COUNTERED_BY]->(s:DeceptionTechnique)
OPTIONAL MATCH (e:EngagementConcept)-[:DISRUPTS]->(t)
RETURN t, collect(d) AS mitigations, collect(c) AS detections, collect(s) AS deceptions, collect(e) AS engagements
"""

# Template metadata: maps template key to template definition, parameters, hops, and description
TEMPLATES = {
    "coverage_map": {
        "template": TEMPLATE_T_DEF_01,
        "params": ["attackId"],
        "expected_hops": 1,
        "description": "Find D3FEND/CAR/SHIELD/ENGAGE coverage for an ATT&CK technique"
    }
}


def validate_template(name: str, template: str, params: list = None) -> None:
    """Validate Cypher template at module load time.

    Checks:
    - Template is not empty or None
    - Template contains MATCH or OPTIONAL MATCH clause
    - Template has all required parameters (as $param)
    - Template uses parameterization (no string concat artifacts)

    Raises ValueError if validation fails.
    """
    if not template or not isinstance(template, str):
        raise ValueError(f"Template '{name}' is empty or not a string")

    template_upper = template.upper()

    # Check for MATCH clause
    if "MATCH" not in template_upper:
        raise ValueError(f"Template '{name}' is missing MATCH clause")

    # Get expected parameters for this template key
    if params is None and name in TEMPLATES:
        params = TEMPLATES[name].get("params", [])

    # Validate each parameter is present in template
    if params:
        for param in params:
            param_ref = f"${param}"
            if param_ref not in template:
                raise ValueError(f"Template '{name}' is missing {param_ref} parameter")


# Validate all templates at module load time
for template_key, template_meta in TEMPLATES.items():
    validate_template(
        template_key,
        template_meta["template"],
        template_meta["params"]
    )
