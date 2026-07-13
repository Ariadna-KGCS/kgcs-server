"""Data transformation from Neo4j query results to systems-response.json structure

Handles:
- Aggregation of multiple records into a single vulnerabilities array
- Deduplication by cveId, scoreId, matchCriteriaId
- Provenance extraction (always NVD source for Systems Agent)
"""

from typing import List, Dict, Any, Optional
from datetime import datetime


class SystemsTransformer:
    """Transforms Neo4j query results into systems-response.json structure"""

    @staticmethod
    def _without_none(data: Dict[str, Any]) -> Dict[str, Any]:
        """Drop optional fields that are null so JSON Schema optional strings remain valid."""
        return {key: value for key, value in data.items() if value is not None}

    @staticmethod
    def _build_resolved_platform(platform: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Normalize one concrete Platform node for response output."""
        if not platform:
            return None
        cpe_uri = platform.get("cpeUri")
        if not cpe_uri:
            return None
        return SystemsTransformer._without_none(
            {
                "cpeUri": cpe_uri,
                "cpeNameId": platform.get("cpeNameId"),
                "part": platform.get("part"),
                "vendor": platform.get("vendor"),
                "product": platform.get("product"),
                "version": platform.get("version"),
            }
        )

    @staticmethod
    def _ensure_applicability(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Get or create the applicability container for one vulnerability."""
        if "applicability" not in vulnerability:
            vulnerability["applicability"] = {"configurations": []}
            vulnerability["_applicability_index"] = {}
        return vulnerability["applicability"]

    @staticmethod
    def _add_applicability_record(vulnerability: Dict[str, Any], record: Dict[str, Any]) -> None:
        """Aggregate explicit applicability-layer records under one vulnerability."""
        vc = record.get("vc")
        vcn = record.get("vcn")
        mc = record.get("mc")
        pc_match = record.get("pc_match")
        p_match = record.get("p_match")

        if not vc or not vcn or not mc or not pc_match:
            return

        applicability = SystemsTransformer._ensure_applicability(vulnerability)
        config_index = vulnerability["_applicability_index"]
        vc_id = vc.get("vcId")
        if not vc_id:
            return

        if vc_id not in config_index:
            config_entry = {
                "vcId": vc_id,
                "operator": vc.get("operator"),
                "negate": bool(vc.get("negate", False)),
                "nodes": [],
            }
            applicability["configurations"].append(config_entry)
            config_index[vc_id] = {"entry": config_entry, "nodes": {}}

        config_state = config_index[vc_id]
        vcn_id = vcn.get("vcnId")
        if not vcn_id:
            return

        if vcn_id not in config_state["nodes"]:
            node_entry = {
                "vcnId": vcn_id,
                "operator": vcn.get("operator"),
                "negate": bool(vcn.get("negate", False)),
                "criteria": [],
            }
            config_state["entry"]["nodes"].append(node_entry)
            config_state["nodes"][vcn_id] = {"entry": node_entry, "criteria": {}}

        node_state = config_state["nodes"][vcn_id]
        match_criteria_id = pc_match.get("matchCriteriaId")
        if not match_criteria_id:
            return

        if match_criteria_id not in node_state["criteria"]:
            criterion_entry = SystemsTransformer._without_none(
                {
                    "matchCriteriaId": match_criteria_id,
                    "criteria": pc_match.get("criteria"),
                    "vulnerable": mc.get("vulnerable"),
                    "matchIndex": mc.get("matchIndex"),
                    "configStatus": pc_match.get("configStatus"),
                    "versionStartExcluding": pc_match.get("versionStartExcluding"),
                    "versionStartIncluding": pc_match.get("versionStartIncluding"),
                    "versionEndExcluding": pc_match.get("versionEndExcluding"),
                    "versionEndIncluding": pc_match.get("versionEndIncluding"),
                    "resolvedPlatforms": [],
                }
            )
            node_state["entry"]["criteria"].append(criterion_entry)
            node_state["criteria"][match_criteria_id] = criterion_entry

        criterion_entry = node_state["criteria"][match_criteria_id]
        resolved_platform = SystemsTransformer._build_resolved_platform(p_match)
        criterion_platform = None
        if resolved_platform:
            criterion_platform = SystemsTransformer._without_none(
                {
                    "cpeUri": resolved_platform.get("cpeUri"),
                    "cpeNameId": resolved_platform.get("cpeNameId"),
                }
            )
        if criterion_platform and not any(
            item.get("cpeUri") == criterion_platform["cpeUri"]
            for item in criterion_entry["resolvedPlatforms"]
        ):
            criterion_entry["resolvedPlatforms"].append(criterion_platform)
        if resolved_platform and not any(
            item.get("cpeUri") == resolved_platform["cpeUri"]
            for item in vulnerability["resolvedPlatforms"]
        ):
            vulnerability["resolvedPlatforms"].append(resolved_platform)

    @staticmethod
    def _add_applicability_rows(vulnerability: Dict[str, Any], applicability_rows: Any) -> None:
        """Aggregate a list of pre-collected applicability maps."""
        if not isinstance(applicability_rows, list):
            return
        for row in applicability_rows:
            if not isinstance(row, dict):
                continue
            SystemsTransformer._add_applicability_record(vulnerability, row)

    @staticmethod
    def _add_resolved_platforms(vulnerability: Dict[str, Any], platforms: Any) -> None:
        """Aggregate one or many resolved Platform nodes at the vulnerability level."""
        platform_list = platforms if isinstance(platforms, list) else [platforms]
        for platform in platform_list:
            if not isinstance(platform, dict):
                continue
            resolved_platform = SystemsTransformer._build_resolved_platform(platform)
            if resolved_platform and not any(
                item.get("cpeUri") == resolved_platform["cpeUri"]
                for item in vulnerability["resolvedPlatforms"]
            ):
                vulnerability["resolvedPlatforms"].append(resolved_platform)

    @staticmethod
    def transform_cpe_results(records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Transform results from T_SYS_01 (CPE lookup).

        Input: Neo4j records with {v, w, s, pc, p} nodes
        Output: {vulnerabilities: [...], platforms: [...]} structure

        Deduplicates:
        - By cveId: aggregates multiple vulnerability records into single entry
        - By scoreId: within each CVE, one score entry per version
        - By matchCriteriaId: aggregates platforms under each CVE

        Args:
            records: List of Neo4j result dicts from T_SYS_01 query

        Returns:
            Dict with vulnerabilities array and implicit platforms aggregation
        """
        vulnerabilities = {}  # cveId -> vulnerability dict

        for record in records:
            v = record.get("v", {})
            w = record.get("w")
            scores = record.get("scores")
            pc = record.get("pc")
            platform_matches = record.get("platformMatches")
            p = record.get("p")

            cve_id = v.get("cveId")
            if not cve_id:
                continue

            # Initialize vulnerability entry if not seen
            if cve_id not in vulnerabilities:
                vulnerabilities[cve_id] = {
                    "cveId": cve_id,
                    "published": v.get("published"),
                    "lastModified": v.get("lastModified"),
                    "source": v.get("source"),
                    "scores": [],
                    "weakness": None,
                    "platforms": [],
                    "resolvedPlatforms": []
                }

            # Add weakness (deduplicate by cweId)
            if w and not vulnerabilities[cve_id]["weakness"]:
                vulnerabilities[cve_id]["weakness"] = SystemsTransformer._without_none({
                    "cweId": w.get("cweId"),
                    "abstraction": w.get("abstraction"),
                    "name": w.get("name")
                })

            # Add score (deduplicate by scoreId)
            if isinstance(scores, list):
                for s in scores:
                    if not isinstance(s, dict):
                        continue
                    score_id = s.get("scoreId")
                    if score_id and not any(
                        score.get("scoreId") == score_id
                        for score in vulnerabilities[cve_id]["scores"]
                    ):
                        vulnerabilities[cve_id]["scores"].append({
                            "scoreId": score_id,
                            "version": s.get("version"),
                            "baseScore": s.get("baseScore")
                        })

            # Add platform (deduplicate by matchCriteriaId)
            if pc:
                pc_id = pc.get("matchCriteriaId")
                if pc_id and not any(
                    platform.get("matchCriteriaId") == pc_id
                    for platform in vulnerabilities[cve_id]["platforms"]
                ):
                    vulnerabilities[cve_id]["platforms"].append(SystemsTransformer._without_none({
                        "matchCriteriaId": pc_id,
                        "cpeUri": pc.get("cpeUri") or p.get("cpeUri") if p else pc.get("criteria"),
                        "configStatus": pc.get("configStatus")
                    }))

            SystemsTransformer._add_resolved_platforms(
                vulnerabilities[cve_id],
                platform_matches if isinstance(platform_matches, list) else p,
            )

            SystemsTransformer._add_applicability_rows(
                vulnerabilities[cve_id],
                record.get("applicabilityRows"),
            )

        serialized = []
        for vulnerability in vulnerabilities.values():
            vulnerability.pop("_applicability_index", None)
            if vulnerability.get("applicability") and not vulnerability["applicability"]["configurations"]:
                vulnerability.pop("applicability", None)
            serialized.append(SystemsTransformer._without_none(vulnerability))

        return {"vulnerabilities": serialized}

    @staticmethod
    def transform_cve_results(records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Transform results from T_SYS_02 (CVE lookup).

        Input: Neo4j records with {v, w, s} nodes
        Output: {vulnerabilities: [...]} (no platforms field)

        Args:
            records: List of Neo4j result dicts from T_SYS_02 query

        Returns:
            Dict with vulnerabilities array
        """
        vulnerabilities = {}  # cveId -> vulnerability dict

        for record in records:
            v = record.get("v", {})
            w = record.get("w")
            scores = record.get("scores")

            cve_id = v.get("cveId")
            if not cve_id:
                continue

            # Initialize vulnerability entry if not seen
            if cve_id not in vulnerabilities:
                vulnerabilities[cve_id] = {
                    "cveId": cve_id,
                    "published": v.get("published"),
                    "lastModified": v.get("lastModified"),
                    "source": v.get("source"),
                    "scores": [],
                    "weakness": None,
                    "resolvedPlatforms": []
                }

            # Add weakness (deduplicate)
            if w and not vulnerabilities[cve_id]["weakness"]:
                vulnerabilities[cve_id]["weakness"] = SystemsTransformer._without_none({
                    "cweId": w.get("cweId"),
                    "abstraction": w.get("abstraction"),
                    "name": w.get("name")
                })

            # Add score (deduplicate by scoreId)
            if isinstance(scores, list):
                for s in scores:
                    if not isinstance(s, dict):
                        continue
                    score_id = s.get("scoreId")
                    if score_id and not any(
                        score.get("scoreId") == score_id
                        for score in vulnerabilities[cve_id]["scores"]
                    ):
                        vulnerabilities[cve_id]["scores"].append({
                            "scoreId": score_id,
                            "version": s.get("version"),
                            "baseScore": s.get("baseScore")
                        })

            SystemsTransformer._add_applicability_rows(
                vulnerabilities[cve_id],
                record.get("applicabilityRows"),
            )

        serialized = []
        for vulnerability in vulnerabilities.values():
            vulnerability.pop("_applicability_index", None)
            if vulnerability.get("applicability") and not vulnerability["applicability"]["configurations"]:
                vulnerability.pop("applicability", None)
            serialized.append(SystemsTransformer._without_none(vulnerability))

        return {"vulnerabilities": serialized}

    @staticmethod
    def extract_provenance(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract provenance entries from query results.

        Systems Agent always sources from NVD for CVE/CVSS data.

        Args:
            records: List of Neo4j result dicts

        Returns:
            List of provenance entries [{source: "NVD", ids: [...], timestamp: ...}]
        """
        cve_ids = set()
        timestamps = []

        for record in records:
            v = record.get("v", {})
            if v.get("cveId"):
                cve_ids.add(v["cveId"])
            if v.get("lastModified"):
                timestamps.append(v["lastModified"])

        if not cve_ids:
            return []

        # Use the latest timestamp from all records
        latest_timestamp = None
        if timestamps:
            try:
                # Parse ISO 8601 timestamps
                parsed = [
                    datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    for ts in timestamps
                    if isinstance(ts, str)
                ]
                if parsed:
                    latest_timestamp = max(parsed)
            except (ValueError, AttributeError):
                pass

        return [
            {
                "source": "NVD",
                "ids": sorted(list(cve_ids)),
                "timestamp": latest_timestamp.isoformat() if latest_timestamp else None
            }
        ]
