"""Transformation logic for Defensive Agent

Converts Neo4j records to defensive-response.json structure.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List


class DefensiveTransformer:
    """Transforms Neo4j query results to Defensive Agent response format"""

    @staticmethod
    def transform_coverage_results(records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Transform Neo4j coverage map records to response structure.

        Expected output schema fields:
        - mitigations[]:  {d3fendId, name} from DefensiveTechnique nodes (D3FEND)
        - detections[]:   {analyticId, title, coverageLevel} from DetectionAnalytic nodes (CAR)
        - deceptions[]:   {techniqueId, name} from DeceptionTechnique nodes (SHIELD)
        - engagements[]:  {activityId|approachId|goalId, name} from EngagementConcept nodes (ENGAGE)
        - summary:        {total_mitigations, total_detections, total_deceptions, total_engagements, has_coverage}

        Deduplicates by ID within each framework.
        Returns empty arrays if no results.
        """
        mitigations = {}  # Dict by d3fendId
        detections = {}   # Dict by analyticId
        deceptions = {}   # Dict by techniqueId
        engagements = {}  # Dict by ID (activity/approach/goal)

        # Iterate records and aggregate coverage
        for record in records:
            # D3FEND mitigations
            for mitigation in record.get("mitigations", []):
                if mitigation:
                    d3fend_id = mitigation.get("d3fendId")
                    if d3fend_id and d3fend_id not in mitigations:
                        mitigations[d3fend_id] = {
                            "d3fendId": d3fend_id,
                            "name": mitigation.get("name", "")
                        }

            # CAR detections
            for detection in record.get("detections", []):
                if detection:
                    analytic_id = detection.get("analyticId")
                    if analytic_id and analytic_id not in detections:
                        detections[analytic_id] = {
                            "analyticId": analytic_id,
                            "title": detection.get("title", ""),
                            "coverageLevel": detection.get("coverageLevel", "")
                        }

            # SHIELD deceptions
            for deception in record.get("deceptions", []):
                if deception:
                    technique_id = deception.get("techniqueId")
                    if technique_id and technique_id not in deceptions:
                        deceptions[technique_id] = {
                            "techniqueId": technique_id,
                            "name": deception.get("name", "")
                        }

            # ENGAGE engagement concepts
            for engagement in record.get("engagements", []):
                if engagement:
                    # Engagement concepts can have activityId, approachId, or goalId
                    activity_id = engagement.get("activityId")
                    approach_id = engagement.get("approachId")
                    goal_id = engagement.get("goalId")

                    # Use whichever ID is present
                    engagement_key = activity_id or approach_id or goal_id

                    if engagement_key and engagement_key not in engagements:
                        eng = {"name": engagement.get("name", "")}
                        if activity_id:
                            eng["activityId"] = activity_id
                        if approach_id:
                            eng["approachId"] = approach_id
                        if goal_id:
                            eng["goalId"] = goal_id
                        engagements[engagement_key] = eng

        # Build return structure with arrays
        mitigations_list = list(mitigations.values())
        detections_list = list(detections.values())
        deceptions_list = list(deceptions.values())
        engagements_list = list(engagements.values())

        # Determine has_coverage: true if ANY coverage type has results
        has_coverage = bool(mitigations_list or detections_list or deceptions_list)

        return {
            "mitigations": mitigations_list,
            "detections": detections_list,
            "deceptions": deceptions_list,
            "engagements": engagements_list,
            "summary": {
                "total_mitigations": len(mitigations_list),
                "total_detections": len(detections_list),
                "total_deceptions": len(deceptions_list),
                "total_engagements": len(engagements_list),
                "has_coverage": has_coverage
            }
        }

    @staticmethod
    def extract_provenance(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract provenance from records, grouped by framework source.

        Separates into 4 sources:
        - MITRE D3FEND (from DefensiveTechnique nodes)
        - MITRE CAR (from DetectionAnalytic nodes)
        - MITRE SHIELD (from DeceptionTechnique nodes)
        - MITRE ENGAGE (from EngagementConcept nodes)

        Returns list of provenance entries, one per source that has IDs.
        """
        d3fend_ids = set()
        car_ids = set()
        shield_ids = set()
        engage_ids = set()

        # Collect unique IDs from all records
        for record in records:
            for mitigation in record.get("mitigations", []):
                if mitigation and mitigation.get("d3fendId"):
                    d3fend_ids.add(mitigation["d3fendId"])

            for detection in record.get("detections", []):
                if detection and detection.get("analyticId"):
                    car_ids.add(detection["analyticId"])

            for deception in record.get("deceptions", []):
                if deception and deception.get("techniqueId"):
                    shield_ids.add(deception["techniqueId"])

            for engagement in record.get("engagements", []):
                if engagement:
                    eng_id = (
                        engagement.get("activityId") or
                        engagement.get("approachId") or
                        engagement.get("goalId")
                    )
                    if eng_id:
                        engage_ids.add(eng_id)

        # Build provenance entries for each source that has IDs
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        provenance = []

        if d3fend_ids:
            provenance.append({
                "source": "MITRE D3FEND",
                "ids": sorted(list(d3fend_ids)),
                "timestamp": timestamp
            })

        if car_ids:
            provenance.append({
                "source": "MITRE CAR",
                "ids": sorted(list(car_ids)),
                "timestamp": timestamp
            })

        if shield_ids:
            provenance.append({
                "source": "MITRE SHIELD",
                "ids": sorted(list(shield_ids)),
                "timestamp": timestamp
            })

        if engage_ids:
            provenance.append({
                "source": "MITRE ENGAGE",
                "ids": sorted(list(engage_ids)),
                "timestamp": timestamp
            })

        return provenance
