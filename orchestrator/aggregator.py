"""Response aggregation for Master Orchestrator

Combines results from multiple agents, merges provenance, and computes confidence.
"""

from typing import Any, Dict, List
from datetime import datetime, timezone

from .constants import CONFIDENCE_MERGE_STRATEGY
from .errors import AggregationError


class ResponseAggregator:
    """Aggregates responses from multiple agents"""

    @staticmethod
    def merge_provenance(responses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merge provenance from multiple agent responses.

        Deduplicates by (source, id), preserves timestamp of latest entry.
        Maintains separate array per source.

        Args:
            responses: List of agent response dicts

        Returns:
            Merged provenance list with deduplication by source and ID
        """
        # Dict to track unique (source, id) pairs
        provenance_dict = {}  # Key: (source, id), Value: {source, ids: [...], timestamp}

        for response in responses:
            if response.get("status") != "ok":
                continue

            prov_items = response.get("provenance", [])
            for prov in prov_items:
                source = prov.get("source")
                ids = prov.get("ids", [])

                if not source:
                    continue

                # Create or update entry for this source
                key = source
                if key not in provenance_dict:
                    provenance_dict[key] = {
                        "source": source,
                        "ids": set(),
                        "timestamp": prov.get("timestamp")
                    }

                # Add IDs to this source
                for id_val in ids:
                    provenance_dict[key]["ids"].add(id_val)

                # Update timestamp (use latest)
                if prov.get("timestamp"):
                    provenance_dict[key]["timestamp"] = prov["timestamp"]

        # Convert back to list format with sorted IDs
        provenance = []
        for key in sorted(provenance_dict.keys()):
            entry = provenance_dict[key]
            provenance.append({
                "source": entry["source"],
                "ids": sorted(list(entry["ids"])),
                "timestamp": entry.get("timestamp") or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            })

        return provenance

    @staticmethod
    def merge_confidence(responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge confidence scores from multiple agent responses.

        If only 1 response, returns it as-is (no MULTI_AGENT prefix).
        For multiple responses, uses strategy from CONFIDENCE_MERGE_STRATEGY constant:
        - "average": Mean of all confidence values
        - "minimum": Minimum confidence value (conservative)
        - "weighted": Weighted by row count (more results = more reliable)

        Args:
            responses: List of agent response dicts

        Returns:
            Merged confidence score dict
        """
        confidences = []
        signals_list = []
        original_confidences = []

        for response in responses:
            conf = response.get("confidence", {})
            if "value" in conf:
                confidences.append(conf["value"])
                original_confidences.append(conf)
                signals_list.append(conf.get("signals", {}))

        if not confidences:
            return {
                "value": 0.0,
                "basis": "NO_MATCH",
                "signals": {},
                "degradation": ["No agent produced results"]
            }

        # If only 1 response, return it as-is but ensure value is clamped
        if len(confidences) == 1:
            conf = original_confidences[0].copy()
            conf["value"] = max(0.0, min(1.0, conf["value"]))
            return conf

        # Compute merged confidence based on strategy
        if CONFIDENCE_MERGE_STRATEGY == "average":
            merged_value = sum(confidences) / len(confidences)
            basis = "MULTI_AGENT_AVERAGE"
        elif CONFIDENCE_MERGE_STRATEGY == "minimum":
            merged_value = min(confidences)
            basis = "MULTI_AGENT_MINIMUM"
        elif CONFIDENCE_MERGE_STRATEGY == "weighted":
            # Weight by row count from signals
            total_rows = sum(s.get("rows", 0) for s in signals_list)
            if total_rows > 0:
                weighted_sum = sum(c * s.get("rows", 0) for c, s in zip(confidences, signals_list))
                merged_value = weighted_sum / total_rows
                basis = "MULTI_AGENT_WEIGHTED"
            else:
                merged_value = sum(confidences) / len(confidences)
                basis = "MULTI_AGENT_AVERAGE"
        else:
            merged_value = sum(confidences) / len(confidences)
            basis = "MULTI_AGENT_AVERAGE"

        # Clamp to [0.0, 1.0]
        merged_value = max(0.0, min(1.0, merged_value))

        return {
            "value": merged_value,
            "basis": basis,
            "signals": {
                "agents": len(responses),
                "individual_values": confidences
            },
            "degradation": []
        }

    @staticmethod
    def aggregate_single_agent_response(response: Dict[str, Any]) -> Dict[str, Any]:
        """Pass through single-agent response (no aggregation needed).

        Args:
            response: Single agent response

        Returns:
            Same response (no modification)
        """
        return response

    @staticmethod
    def aggregate_multi_agent_responses(responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate responses from multiple agents (mixed intent).

        Merges:
        - Provenance (deduplicate by source and ID)
        - Confidence (via merge_confidence strategy)
        - Data (combine from all agents)
        - Errors (include if any agent failed)

        Args:
            responses: List of agent response dicts (one per agent in sequence)

        Returns:
            Aggregated response dict matching agent-consumable-schema.json
        """
        if not responses:
            raise AggregationError("No responses to aggregate")

        # Use correlation_id and version from first response
        first_response = responses[0]
        correlation_id = first_response.get("correlation_id")
        version = first_response.get("version", "1.0")

        # Check if all responses succeeded
        all_ok = all(r.get("status") == "ok" for r in responses)

        # Merge provenance from all agents
        provenance = ResponseAggregator.merge_provenance(responses)

        # Merge confidence from all agents
        confidence = ResponseAggregator.merge_confidence(responses)

        # Aggregate data from all agents
        # For mixed intent: combine all data under top-level keys
        data = {}
        for response in responses:
            if response.get("status") == "ok" and response.get("data"):
                agent_data = response["data"]
                # Merge into aggregated data (flatten for simplicity)
                data.update(agent_data)

        # Collect errors from all agents
        errors = []
        for response in responses:
            if response.get("status") == "error":
                errors.extend(response.get("errors", []))

        return {
            "version": version,
            "correlation_id": correlation_id,
            "status": "ok" if all_ok else "error",
            "data": data,
            "provenance": provenance,
            "confidence": confidence,
            "errors": errors
        }
