"""Systems Agent: Read-only microservice for Platform/PlatformConfiguration ↔ Vulnerability queries

Implements vuln_lookup intent via three pathways:
1. By matchCriteriaId → affiliated Vulnerabilities
2. By canonical cpeName → matching Vulnerabilities through Platform nodes
3. By CVE ID → Vulnerability details + root cause (Weakness) + CVSS scores

Main entry point:
    from agents.systems import SystemsAgent
    agent = SystemsAgent()
    response = agent.execute(request)
"""

from .executor import SystemsAgent

__all__ = ["SystemsAgent"]
