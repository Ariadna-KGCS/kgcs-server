"""Data transformation for Offensive Agent

Transforms Neo4j records into offensive-response.json structure with:
- Deduplication by technique_id (attackId)
- CAPEC aggregation from AttackPattern nodes
- Tactic aggregation from Tactic nodes
- Attack path tracking (weakness → pattern → technique)
- Dual provenance (MITRE CAPEC + MITRE ATT&CK sources)
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class OffensiveTransformer:
    """Transform Neo4j records to offensive-response.json structure"""

    @staticmethod
    def transform_weakness_results(records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Transform Neo4j records from weakness-to-techniques query.

        Args:
            records: List of Neo4j record dicts with keys {w, ap, t, tac, st}

        Returns:
            Dict with "techniques" and "attack_paths" arrays
        """
        techniques = {}  # Key: technique_id (attackId)
        attack_paths = []  # Full causal chains
        attack_path_keys = set()

        for record in records:
            # Skip if no technique found
            t = record.get("t")
            if not t:
                continue

            t_id = t.get("attackId")
            if not t_id:
                continue

            # Initialize technique if not seen before
            if t_id not in techniques:
                techniques[t_id] = {
                    "id": t_id,
                    "name": t.get("name"),
                    "tactics": [],
                    "capec": [],
                    "subtechniques": []
                }

            # Aggregate CAPEC IDs from AttackPattern
            ap = record.get("ap")
            if ap:
                capec_id = ap.get("capecId")
                if capec_id and capec_id not in techniques[t_id]["capec"]:
                    techniques[t_id]["capec"].append(capec_id)

            # Aggregate tactics from Tactic nodes
            tac = record.get("tac")
            if tac:
                tactic_name = tac.get("name")
                if tactic_name and tactic_name not in techniques[t_id]["tactics"]:
                    techniques[t_id]["tactics"].append(tactic_name)

            # Aggregate subtechniques from SubTechnique nodes
            st = record.get("st")
            if st:
                sub_id = st.get("attackId")
                if sub_id and sub_id not in techniques[t_id]["subtechniques"]:
                    techniques[t_id]["subtechniques"].append(sub_id)

            mapped_ap = record.get("mapped_ap") or ap
            mapped_attack_pattern_id = mapped_ap.get("capecId") if mapped_ap else None
            hierarchy_depth = record.get("hierarchyDepth") or 0
            source_attack_pattern_id = ap.get("capecId") if ap else None
            mapping_type = "direct"
            if mapped_attack_pattern_id and source_attack_pattern_id:
                if mapped_attack_pattern_id != source_attack_pattern_id:
                    mapping_type = "inherited_via_parent_capec"

            # Track full causal path (weakness → pattern → technique)
            w = record.get("w")
            if w and ap:
                attack_path = {
                    "weakness_id": w.get("cweId"),
                    "attack_pattern_id": source_attack_pattern_id,
                    "technique_id": t_id,
                    "mapping_type": mapping_type,
                }
                if mapped_attack_pattern_id and mapped_attack_pattern_id != ap.get("capecId"):
                    attack_path["mapped_attack_pattern_id"] = mapped_attack_pattern_id
                if hierarchy_depth:
                    attack_path["hierarchy_depth"] = hierarchy_depth
                attack_path_key = (
                    attack_path["weakness_id"],
                    attack_path["attack_pattern_id"],
                    attack_path["technique_id"],
                    attack_path["mapping_type"],
                    attack_path.get("mapped_attack_pattern_id"),
                    attack_path.get("hierarchy_depth", 0),
                )
                if attack_path_key not in attack_path_keys:
                    attack_path_keys.add(attack_path_key)
                    attack_paths.append(attack_path)

        # Sort techniques by ID for consistent output
        sorted_technique_ids = sorted(techniques.keys())
        techniques_list = [techniques[t_id] for t_id in sorted_technique_ids]

        return {
            "techniques": techniques_list,
            "attack_paths": attack_paths
        }

    @staticmethod
    def extract_provenance(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract provenance from Neo4j records.

        Separates MITRE CAPEC (from AttackPattern) and MITRE ATT&CK (from Technique).

        Args:
            records: List of Neo4j record dicts

        Returns:
            List of provenance entries: [{source, ids, timestamp}]
        """
        capec_ids = set()
        technique_ids = set()

        for record in records:
            # Extract CAPEC IDs from AttackPattern nodes
            ap = record.get("ap")
            if ap:
                capec_id = ap.get("capecId")
                if capec_id:
                    capec_ids.add(capec_id)

            # Extract technique IDs from Technique nodes
            t = record.get("t")
            if t:
                t_id = t.get("attackId")
                if t_id:
                    technique_ids.add(t_id)

        provenance = []
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        # Add MITRE CAPEC provenance if we have CAPEC IDs
        if capec_ids:
            provenance.append({
                "source": "MITRE CAPEC",
                "ids": sorted(list(capec_ids)),
                "timestamp": timestamp
            })

        # Add MITRE ATT&CK provenance if we have technique IDs
        if technique_ids:
            provenance.append({
                "source": "MITRE ATT&CK",
                "ids": sorted(list(technique_ids)),
                "timestamp": timestamp
            })

        return provenance
