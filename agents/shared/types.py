"""Shared data structures for KGCS agents

Pydantic models that match the JSON Schema contracts in spec/contracts/
"""

from __future__ import annotations
from enum import Enum
from datetime import datetime
from typing import Optional, Union
from pydantic import BaseModel, Field, ConfigDict


class ConfidenceBasis(str, Enum):
    """Basis for confidence scoring"""
    COMPLETE_CHAIN = "COMPLETE_CHAIN"
    PARTIAL_CHAIN = "PARTIAL_CHAIN"
    SINGLE_HOP = "SINGLE_HOP"
    NO_MATCH = "NO_MATCH"
    VALIDATED_BY_SHACL = "VALIDATED_BY_SHACL"
    COVERAGE_MAP = "COVERAGE_MAP"
    MULTI_AGENT_AVERAGE = "MULTI_AGENT_AVERAGE"
    MULTI_AGENT_MINIMUM = "MULTI_AGENT_MINIMUM"
    MULTI_AGENT_WEIGHTED = "MULTI_AGENT_WEIGHTED"


class RiskBand(str, Enum):
    """Risk severity bands"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConfidenceSignals(BaseModel):
    """Signals contributing to confidence score"""
    rows: Optional[int] = Field(None, ge=0, description="Number of result rows")
    hops: Optional[int] = Field(None, ge=0, description="Number of graph hops traversed")
    shape_validated: Optional[bool] = Field(None, description="SHACL shape validation passed")
    freshness_days: Optional[float] = Field(None, ge=0, description="Data age in days")


class ConfidenceSignal(BaseModel):
    """Confidence score with basis and signals"""
    value: float = Field(..., ge=0.0, le=1.0, description="Confidence value [0.0-1.0]")
    basis: ConfidenceBasis = Field(..., description="Basis for this confidence score")
    signals: ConfidenceSignals = Field(default_factory=ConfidenceSignals, description="Contributing signals")
    degradation: list[str] = Field(default_factory=list, description="Reasons for degradation")


class ResponseStatus(str, Enum):
    """Response status codes"""
    OK = "ok"
    EMPTY = "empty"
    ERROR = "error"


class ProvenanceEntry(BaseModel):
    """Provenance record for a result"""
    source: str = Field(..., description="Source system or standard (e.g., NVD, MITRE)")
    ids: list[str] = Field(..., min_length=1, description="Source identifiers (CVE, etc.)")
    timestamp: Optional[datetime] = Field(None, description="Timestamp of the record")


class ResponseEnvelope(BaseModel):
    """Agent response envelope matching agent-consumable-schema.json"""
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "version": "1.0",
                    "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
                    "status": "ok",
                    "data": {},
                    "provenance": [{"source": "NVD", "ids": ["CVE-2021-44228"]}],
                    "confidence": {
                        "value": 0.95,
                        "basis": "COMPLETE_CHAIN",
                        "signals": {"rows": 5, "hops": 4, "shape_validated": True},
                        "degradation": []
                    },
                    "errors": []
                }
            ]
        }
    )

    version: str = Field(default="1.0", description="Schema version")
    correlation_id: str = Field(..., description="Request correlation ID (UUID)")
    status: ResponseStatus = Field(..., description="Response status")
    data: Union[dict, list, None] = Field(default=None, description="Agent-specific payload data")
    provenance: list[ProvenanceEntry] = Field(default_factory=list, description="Data provenance")
    confidence: ConfidenceSignal = Field(..., description="Confidence score with basis")
    errors: list[str] = Field(default_factory=list, description="Error messages if status=error")


class RiskSignal(BaseModel):
    """Risk advisory (not part of envelope, used by orchestrator)"""
    value: float = Field(..., ge=0.0, le=1.0, description="Risk value [0.0-1.0]")
    band: RiskBand = Field(..., description="Risk severity band")
    method: str = Field(default="heuristic-v1", description="Risk calculation method")
    inputs: dict = Field(default_factory=dict, description="Input values for traceability")
    provenance: list[str] = Field(default_factory=list, description="Risk calculation steps")


class RequestIntentEnum(str, Enum):
    """Valid request intents"""
    VULN_LOOKUP = "vuln_lookup"
    ATTACK_PATH = "attack_path"
    COVERAGE_MAP = "coverage_map"
    MIXED = "mixed"


class RequestAgentEnum(str, Enum):
    """Valid agent names"""
    SYSTEMS = "systems"
    OFFENSIVE = "offensive"
    DEFENSIVE = "defensive"
    MASTER = "master"
