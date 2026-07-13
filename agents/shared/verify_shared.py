#!/usr/bin/env python3
"""Verification script for Phase 2C Shared Library

Run from project root: python agents/shared/verify_shared.py
"""

import sys

def verify_imports():
    """Verify all shared library modules are importable"""
    print("=== VERIFYING IMPORTS ===")
    modules = [
        ("agents.shared", "Package __init__"),
        ("agents.shared.types", "Data types (10 classes)"),
        ("agents.shared.neo4j_client", "Neo4j read-only client"),
        ("agents.shared.confidence_scorer", "Confidence scoring"),
        ("agents.shared.risk_scorer", "Risk assessment heuristic"),
        ("agents.shared.schema_validator", "JSON Schema validation"),
        ("agents.shared.response_builder", "Response envelope builder"),
        ("agents.shared.logger", "Structured logging"),
    ]

    for module_name, description in modules:
        try:
            __import__(module_name)
            print(f"[OK] {module_name:40} - {description}")
        except Exception as e:
            print(f"[FAIL] {module_name:40} - {description}: {e}")
            return False

    return True


def verify_confidence_scorer():
    """Verify ConfidenceScorer.compute() returns correct structure"""
    print("\n=== VERIFYING CONFIDENCE SCORER ===")
    from agents.shared.confidence_scorer import ConfidenceScorer

    scorer = ConfidenceScorer()

    # Test 1: Complete chain
    result = scorer.compute(row_count=5, hop_count=4, hops_expected=4,
                           shape_validated=True, freshness_days=30)
    assert result["value"] == 1.0, f"Expected 1.0, got {result['value']}"
    assert result["basis"] == "COMPLETE_CHAIN"
    assert "signals" in result
    assert "degradation" in result
    print("[OK] Complete chain scoring")

    # Test 2: Partial chain (missing 2 hops)
    result = scorer.compute(row_count=5, hop_count=2, hops_expected=4,
                           shape_validated=True)
    assert result["value"] == 0.6, f"Expected 0.6, got {result['value']}"
    assert result["basis"] == "PARTIAL_CHAIN"
    print("[OK] Partial chain degradation (-0.2 per hop)")

    # Test 3: Stale data
    result = scorer.compute(row_count=5, hop_count=4, hops_expected=4,
                           shape_validated=True, freshness_days=400)
    assert result["value"] == 0.9, f"Expected 0.9, got {result['value']}"
    assert "stale_data" in result["degradation"]
    print("[OK] Stale data degradation (-0.1)")

    # Test 4: No results
    result = scorer.compute(row_count=0, hop_count=0, hops_expected=4,
                           shape_validated=False)
    assert result["value"] == 0.0
    assert result["basis"] == "NO_MATCH"
    print("[OK] No results = 0.0 confidence")

    return True


def verify_risk_scorer():
    """Verify RiskScorer.compute() applies correct formula"""
    print("\n=== VERIFYING RISK SCORER ===")
    from agents.shared.risk_scorer import RiskScorer

    scorer = RiskScorer()

    # Test 1: High CVSS + no defenses = high risk
    result = scorer.compute(cvss_v4=9.8, mitigation_count=0,
                           detection_count=0, deception_count=0)
    assert result["value"] > 0.9, f"Expected > 0.9, got {result['value']}"
    assert result["band"] == "CRITICAL"
    print("[OK] High CVSS + no defenses = CRITICAL")

    # Test 2: High CVSS + good defenses = low risk
    result = scorer.compute(cvss_v4=9.8, mitigation_count=5,
                           detection_count=3, deception_count=2)
    assert result["value"] < 0.25, f"Expected < 0.25, got {result['value']}"
    assert result["band"] == "LOW"
    print("[OK] High CVSS + good defenses = LOW")

    # Test 3: Risk bands
    result_low = scorer.compute(cvss_v3=2.0)
    assert result_low["band"] == "LOW"
    result_med = scorer.compute(cvss_v3=5.0)
    assert result_med["band"] == "MEDIUM"
    result_high = scorer.compute(cvss_v3=7.0)
    assert result_high["band"] == "HIGH"
    print("[OK] Risk bands assigned correctly")

    return True


def verify_response_builder():
    """Verify ResponseBuilder constructs valid envelopes"""
    print("\n=== VERIFYING RESPONSE BUILDER ===")
    from agents.shared.response_builder import ResponseBuilder
    from uuid import uuid4

    builder = ResponseBuilder()
    corr_id = str(uuid4())

    # Test 1: OK response
    response = builder.ok(
        data={"test": "data"},
        provenance=[{"source": "NVD", "ids": ["CVE-2021-44228"]}],
        confidence={"value": 0.95, "basis": "COMPLETE_CHAIN", "signals": {}, "degradation": []},
        correlation_id=corr_id
    )
    assert response["status"] == "ok"
    assert "version" in response
    assert response["correlation_id"] == corr_id
    print("[OK] OK response envelope")

    # Test 2: Empty response
    response = builder.empty(
        confidence={"value": 0.0, "basis": "NO_MATCH", "signals": {}, "degradation": []},
        correlation_id=corr_id
    )
    assert response["status"] == "empty"
    assert response["data"] == []
    print("[OK] Empty response envelope")

    # Test 3: Error response
    response = builder.error(
        errors=["Query failed"],
        correlation_id=corr_id
    )
    assert response["status"] == "error"
    assert len(response["errors"]) > 0
    print("[OK] Error response envelope")

    return True


def main():
    """Run all verification checks"""
    print("Phase 2C Shared Library Verification\n")

    all_passed = True

    # Check imports (critical)
    if not verify_imports():
        print("\n[FAIL] Import verification failed")
        return False

    # Check individual modules
    try:
        if not verify_confidence_scorer():
            all_passed = False
    except Exception as e:
        print(f"[FAIL] Confidence scorer verification failed: {e}")
        import traceback
        traceback.print_exc()
        all_passed = False

    try:
        if not verify_risk_scorer():
            all_passed = False
    except Exception as e:
        print(f"[FAIL] Risk scorer verification failed: {e}")
        import traceback
        traceback.print_exc()
        all_passed = False

    try:
        if not verify_response_builder():
            all_passed = False
    except Exception as e:
        print(f"[FAIL] Response builder verification failed: {e}")
        import traceback
        traceback.print_exc()
        all_passed = False

    # Summary
    print("\n" + "="*50)
    if all_passed:
        print("[SUCCESS] ALL VERIFICATIONS PASSED")
        print("="*50)
        return True
    else:
        print("[FAIL] SOME VERIFICATIONS FAILED")
        print("="*50)
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
