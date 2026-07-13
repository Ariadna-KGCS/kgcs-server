"""Response Renderer — converts a KGCS ResponseEnvelope to a human-readable answer.

The renderer transforms the structured ``ResponseEnvelope`` dict returned by
``MasterOrchestrator.execute()`` into a grounded, structured answer string.

Rendering rules (all are mandatory)
-------------------------------------
1. Provenance must appear in every rendered answer.
2. Confidence value and basis must appear in every rendered answer.
3. Output uses neutral, structured sections (Summary / Key Findings / Provenance /
   Confidence). No narrative phrasing such as "Found N ...".
4. Low-confidence results are returned WITH a warning prepended — never discarded.
5. Technique-to-pattern mappings are rendered only from explicit ``attack_paths``
   data. No relationships are inferred.

Intent dispatch
---------------
The renderer picks a rendering strategy based on the resolved intent:

    vuln_lookup   → ``_render_vuln_lookup()``
    attack_path   → ``_render_attack_path()``
    coverage_map  → ``_render_coverage_map()``
    mixed         → ``_render_mixed()``

All other intents fall through to ``_render_fallback()``.

Called at step 6 of ``LLMAdapter.process()``, after the orchestrator response
has been received.
"""

from __future__ import annotations

from typing import Any, Dict, List

_LOW_CONFIDENCE_THRESHOLD = 0.25


class ResponseRenderer:
    """Converts a ``ResponseEnvelope`` dict into a human-readable answer string."""

    def render(self, response: Dict[str, Any], intent: str) -> str:
        """Return a structured, human-readable answer for the given intent.

        Parameters
        ----------
        response:
            Full ``ResponseEnvelope`` dict as returned by
            ``MasterOrchestrator.execute()``.
        intent:
            The KGCS intent that was used to produce the response.

        Returns
        -------
        str
            Human-readable answer. Never an empty string.
        """
        status = response.get("status", "unknown")

        if status == "error":
            errors = response.get("errors") or []
            error_text = "; ".join(str(e) for e in errors) if errors else "unknown error"
            return f"Query failed: {error_text}. See the 'raw' field for details."

        if status == "empty":
            return "No reliable results found in the knowledge graph for this query."

        data = response.get("data") or {}
        provenance = response.get("provenance") or []

        # Extract confidence — handle both dict and Pydantic-object forms.
        conf = response.get("confidence") or {}
        if hasattr(conf, "value"):
            conf_value: float = conf.value
            conf_basis: str = conf.basis or ""
            conf_degradation: List[str] = list(conf.degradation or [])
        else:
            conf_value = float(conf.get("value", 1.0))
            conf_basis = conf.get("basis", "") or ""
            conf_degradation = list(conf.get("degradation") or [])

        # Build the main rendered body.
        if intent == "vuln_lookup":
            body = self._render_vuln_lookup(data)
        elif intent == "attack_path":
            body = self._render_attack_path(data)
        elif intent == "coverage_map":
            body = self._render_coverage_map(data)
        elif intent == "mixed":
            body = self._render_mixed(data)
        else:
            body = self._render_fallback(f"unknown intent: {intent!r}")

        suffix = "\n\n".join(
            filter(
                None,
                [
                    self._render_provenance(provenance),
                    self._render_confidence(conf_value, conf_basis, conf_degradation),
                ],
            )
        )

        full = "\n\n".join(filter(None, [body, suffix]))

        # Prepend low-confidence warning when needed; results are still shown.
        if conf_value < _LOW_CONFIDENCE_THRESHOLD:
            pct = int(round(conf_value * 100))
            basis_display = conf_basis.replace("_", " ").title() if conf_basis else "Unknown"
            warning = (
                f"Note: Low confidence ({pct}%, {basis_display}). "
                "Results may be incomplete."
            )
            full = f"{warning}\n\n{full}"

        return full

    # ------------------------------------------------------------------
    # Intent-specific renderers
    # ------------------------------------------------------------------

    def _render_vuln_lookup(self, data: Dict[str, Any]) -> str:
        """Render a ``vuln_lookup`` response.

        Covers: CVE list, CVSS scores, CWE weaknesses.
        """
        vulns = data.get("vulnerabilities") or []
        lines = ["Summary:", f"* Vulnerabilities: {len(vulns)}", "", "Key Findings:"]
        if vulns:
            for v in vulns:
                cve_id = v.get("cveId", "unknown")
                scores = v.get("scores") or []
                if scores:
                    s = scores[0]
                    score_str = f"CVSS {s.get('baseScore', '?')} (v{s.get('version', '?')})"
                else:
                    score_str = "CVSS n/a"
                weakness = v.get("weakness") or {}
                cwe_id = weakness.get("cweId", "")
                weakness_str = f" | weakness: {cwe_id}" if cwe_id else ""
                lines.append(f"* {cve_id} | {score_str}{weakness_str}")
        else:
            lines.append("* No vulnerabilities found.")
        return "\n".join(lines)

    def _render_attack_path(self, data: Dict[str, Any]) -> str:
        """Render an ``attack_path`` response.

        Covers: ATT&CK techniques and explicit causal links from ``attack_paths``.
        Technique-to-pattern links are rendered only from the ``attack_paths`` list;
        no relationships are inferred.
        """
        techniques = data.get("techniques") or []
        attack_paths = data.get("attack_paths") or []
        lines = [
            "Summary:",
            f"* Techniques: {len(techniques)}",
            f"* Causal links: {len(attack_paths)}",
            "",
            "Key Findings:",
        ]
        if techniques:
            for t in techniques:
                tid = t.get("id", "unknown")
                name = t.get("name", "")
                tactics = t.get("tactics") or []
                tactic_str = f" [{tactics[0]}]" if tactics else ""
                name_str = f' "{name}"' if name else ""
                lines.append(f"* {tid}{name_str}{tactic_str}")
        else:
            lines.append("* No techniques found.")

        # Only render causal-link bullets when explicit attack_paths data is present.
        for ap in attack_paths:
            w = ap.get("weakness_id", "?")
            p = ap.get("pattern_id", "?")
            t = ap.get("technique_id", "?")
            lines.append(f"* {w} \u2192 {p} \u2192 {t}")

        return "\n".join(lines)

    def _render_coverage_map(self, data: Dict[str, Any]) -> str:
        """Render a ``coverage_map`` response.

        Covers: D3FEND mitigations, CAR detections, SHIELD deceptions,
        ENGAGE engagements. Only non-empty framework sections are included.
        """
        mitigations = data.get("mitigations") or []
        detections = data.get("detections") or []
        deceptions = data.get("deceptions") or []
        engagements = data.get("engagements") or []

        lines = [
            "Summary:",
            (
                f"* Mitigations: {len(mitigations)} | Detections: {len(detections)} "
                f"| Deceptions: {len(deceptions)} | Engagements: {len(engagements)}"
            ),
        ]

        findings: List[str] = []
        if mitigations:
            findings.append("Mitigations:")
            for m in mitigations:
                findings.append(f"  * {m.get('d3fendId', '?')}: {m.get('name', '')}")
        if detections:
            findings.append("Detections:")
            for d in detections:
                level = d.get("coverageLevel", "")
                level_str = f" [coverage: {level}]" if level else ""
                findings.append(
                    f"  * {d.get('analyticId', '?')}: {d.get('title', '')}{level_str}"
                )
        if deceptions:
            findings.append("Deceptions:")
            for dec in deceptions:
                findings.append(f"  * {dec.get('techniqueId', '?')}: {dec.get('name', '')}")
        if engagements:
            findings.append("Engagements:")
            for e in engagements:
                findings.append(f"  * {e.get('activityId', '?')}: {e.get('name', '')}")

        if findings:
            lines.append("")
            lines.append("Key Findings:")
            lines.extend(findings)

        return "\n".join(lines)

    def _render_mixed(self, data: Dict[str, Any]) -> str:
        """Render a ``mixed`` (end-to-end) response.

        Includes only sections whose data is present and non-empty.
        Separator headers mark each domain boundary.
        """
        sections: List[str] = []

        if data.get("vulnerabilities"):
            sections.append("--- Vulnerabilities ---")
            sections.append(self._render_vuln_lookup(data))

        if data.get("techniques"):
            sections.append("--- Attack Techniques ---")
            sections.append(self._render_attack_path(data))

        has_defense = any(
            data.get(k) for k in ("mitigations", "detections", "deceptions", "engagements")
        )
        if has_defense:
            sections.append("--- Defensive Controls ---")
            sections.append(self._render_coverage_map(data))

        if not sections:
            return self._render_fallback("no data in mixed response")

        return "\n\n".join(sections)

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _render_provenance(self, provenance: List[Dict[str, Any]]) -> str:
        """Render the provenance list as a labelled bullet section."""
        if not provenance:
            return ""
        lines = ["Provenance:"]
        for entry in provenance:
            source = entry.get("source", "unknown")
            ids = entry.get("ids") or []
            ids_str = ", ".join(str(i) for i in ids) if ids else "n/a"
            lines.append(f"* {source}: {ids_str}")
        return "\n".join(lines)

    def _render_confidence(
        self,
        value: float,
        basis: str,
        degradation: List[str],
    ) -> str:
        """Render the confidence value, basis, and any degradation reasons."""
        pct = int(round(value * 100))
        basis_display = basis.replace("_", " ").title() if basis else "Unknown"
        lines = ["Confidence:", f"* {pct}% ({basis_display})"]
        for reason in degradation:
            lines.append(f"* Degraded due to: {reason}")
        return "\n".join(lines)

    def _render_fallback(self, reason: str) -> str:  # noqa: ARG002
        """Return a safe message when no renderable data is available."""
        return "No data available to render a response."
