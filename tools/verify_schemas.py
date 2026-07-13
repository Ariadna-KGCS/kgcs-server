"""
Verification script for Phase 2B JSON Schema files.

Checks:
1. All 5 schemas are valid JSON Schema Draft-07 (meta-validation)
2. Example agent responses validate against the envelope schema
3. Request schema enforces per-intent payload requirements
4. Per-agent data schemas validate their examples

Usage: python scripts/utilities/verify_schemas.py
"""
import json
import sys
from pathlib import Path

try:
    from jsonschema import Draft7Validator, SchemaError
except ImportError:
    print("ERROR: jsonschema not installed. Run: pip install jsonschema")
    sys.exit(1)

SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "spec" / "contracts"

SCHEMA_FILES = [
    "agent-consumable-schema.json",
    "request-schema.json",
    "systems-response.json",
    "offensive-response.json",
    "defensive-response.json",
]

failures = []


def check(label, valid, validator, instance):
    errs = list(validator.iter_errors(instance))
    if valid:
        if errs:
            print(f"  FAIL  {label}: {errs[0].message}")
            failures.append(label)
        else:
            print(f"  PASS  {label}")
    else:
        if errs:
            print(f"  PASS (correctly rejected)  {label}")
        else:
            print(f"  FAIL (should have rejected)  {label}")
            failures.append(label + " [should have failed]")


# ---------------------------------------------------------------------------
# 1. Meta-validation
# ---------------------------------------------------------------------------
print("=== 1. Meta-validation: all schemas are valid JSON Schema Draft-07 ===")
schemas = {}
for name in SCHEMA_FILES:
    path = SCHEMAS_DIR / name
    with open(path) as f:
        schema = json.load(f)
    try:
        Draft7Validator.check_schema(schema)
        print(f"  PASS  {name}")
        schemas[name] = schema
    except SchemaError as e:
        print(f"  FAIL  {name}: {e.message}")
        failures.append(name)

# ---------------------------------------------------------------------------
# 2. Envelope: example responses from schema-view.md
# ---------------------------------------------------------------------------
print()
print("=== 2. Envelope: example responses validate against agent-consumable-schema.json ===")
envelope = schemas["agent-consumable-schema.json"]
ev = Draft7Validator(envelope)

sys_ok = {
    "version": "1.0",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "ok",
    "data": {
        "vulnerabilities": [
            {"cveId": "CVE-2025-1234", "scores": [{"version": "3.1", "baseScore": 9.8}], "weakness": {"cweId": "CWE-79"}}
        ]
    },
    "provenance": [{"source": "NVD", "ids": ["CVE-2025-1234"]}],
    "confidence": {"value": 0.82, "basis": "COMPLETE_CHAIN"},
}
check("Systems Agent ok response", True, ev, sys_ok)

off_ok = {
    "version": "1.0",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440001",
    "status": "ok",
    "data": {"techniques": [{"id": "T1059", "tactic": "Execution", "capec": ["CAPEC-242"]}]},
    "provenance": [{"source": "MITRE CAPEC", "ids": ["CAPEC-242"]}],
    "confidence": {"value": 0.78, "basis": "COMPLETE_CHAIN"},
}
check("Offensive Agent ok response", True, ev, off_ok)

def_ok = {
    "version": "1.0",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440002",
    "status": "ok",
    "data": {"mitigations": ["D3-PA"], "detections": ["CAR-2020-04-001"], "deceptions": ["SHIELD-A"], "engagements": []},
    "provenance": [{"source": "D3FEND", "ids": ["D3-PA"]}],
    "confidence": {"value": 0.74, "basis": "COVERAGE_MAP"},
}
check("Defensive Agent ok response", True, ev, def_ok)

empty_ok = {
    "version": "1.0",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440003",
    "status": "empty",
    "data": {},
    "provenance": [],
    "confidence": {"value": 0.0, "basis": "NO_MATCH"},
}
check("Empty status with provenance=[] (allowed)", True, ev, empty_ok)

ok_no_prov = {
    "version": "1.0",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440004",
    "status": "ok",
    "data": {},
    "provenance": [],
    "confidence": {"value": 0.5, "basis": "SINGLE_HOP"},
}
check("ok status + empty provenance must be rejected", False, ev, ok_no_prov)

error_ok = {
    "version": "1.0",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440005",
    "status": "error",
    "data": {},
    "provenance": [],
    "confidence": {"value": 0.0, "basis": "NO_MATCH"},
    "errors": ["Cypher query timed out after 30s"],
}
check("Error status response", True, ev, error_ok)

# ---------------------------------------------------------------------------
# 3. Request schema: per-intent enforcement
# ---------------------------------------------------------------------------
print()
print("=== 3. Request schema: required payload fields enforced per intent ===")
req = schemas["request-schema.json"]
rv = Draft7Validator(req)

def req_ok(intent, payload, extra=None):
    return {
        "version": "1.0",
        "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
        "agent": "master",
        "intent": intent,
        "payload": payload,
        **(extra or {}),
    }

check("vuln_lookup + cveId (valid)", True, rv, req_ok("vuln_lookup", {"cveId": "CVE-2021-44228"}))
check("vuln_lookup + cpe (valid)", True, rv, req_ok("vuln_lookup", {"cpe": "cpe:2.3:a:apache:log4j:*"}))
check("vuln_lookup + empty payload (must reject)", False, rv, req_ok("vuln_lookup", {}))

check("attack_path + cweId (valid)", True, rv, req_ok("attack_path", {"cweId": "CWE-917"}))
check("attack_path + cveId (valid)", True, rv, req_ok("attack_path", {"cveId": "CVE-2021-44228"}))
check("attack_path + empty payload (must reject)", False, rv, req_ok("attack_path", {}))

check("coverage_map + attackId (valid)", True, rv, req_ok("coverage_map", {"attackId": "T1190"}))
check("coverage_map + subtechnique T####.### (valid)", True, rv, req_ok("coverage_map", {"attackId": "T1059.001"}))
check("coverage_map + missing attackId (must reject)", False, rv, req_ok("coverage_map", {}))
check("coverage_map + bad attackId format (must reject)", False, rv, req_ok("coverage_map", {"attackId": "TA0001"}))

check("mixed + cveId (valid)", True, rv, req_ok("mixed", {"cveId": "CVE-2021-44228"}))
check("mixed + cpe (valid)", True, rv, req_ok("mixed", {"cpe": "cpe:2.3:a:apache:log4j:*"}))
check("mixed + only attackId (must reject)", False, rv, req_ok("mixed", {"attackId": "T1059"}))

check("missing intent (must reject)", False, rv, {
    "version": "1.0", "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
    "agent": "systems", "payload": {"cveId": "CVE-2021-44228"},
})
check("invalid intent value (must reject)", False, rv, req_ok("pwn", {"cveId": "CVE-2021-44228"}))

# ---------------------------------------------------------------------------
# 4. Per-agent data schemas
# ---------------------------------------------------------------------------
print()
print("=== 4. Per-agent data schemas validate their payloads ===")

sys_schema = schemas["systems-response.json"]
sv = Draft7Validator(sys_schema)

sys_data = {
    "vulnerabilities": [
        {
            "cveId": "CVE-2021-44228",
            "published": "2021-12-10T00:00:00Z",
            "scores": [
                {"scoreId": "CVE-2021-44228_3.1", "version": "3.1", "baseScore": 10.0},
                {"scoreId": "CVE-2021-44228_2.0", "version": "2.0", "baseScore": 9.3},
            ],
            "weakness": {"cweId": "CWE-917", "abstraction": "Base", "name": "EL Injection"},
        }
    ]
}
check("systems-response valid data", True, sv, sys_data)

sys_empty = {"vulnerabilities": []}
check("systems-response empty list", True, sv, sys_empty)

sys_bad_cve = {"vulnerabilities": [{"cveId": "INVALID-FORMAT"}]}
check("systems-response bad cveId pattern (must reject)", False, sv, sys_bad_cve)

off_schema = schemas["offensive-response.json"]
ov = Draft7Validator(off_schema)

off_data = {
    "techniques": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "capec": ["CAPEC-242"], "subtechniques": ["T1059.001"]},
        {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution", "parent_technique": "T1059"},
    ],
    "attack_paths": [{"weakness_id": "CWE-917", "attack_pattern_id": "CAPEC-242", "technique_id": "T1059"}],
}
check("offensive-response valid data", True, ov, off_data)

off_empty = {"techniques": []}
check("offensive-response empty techniques", True, ov, off_empty)

off_bad_id = {"techniques": [{"id": "TA0001"}]}
check("offensive-response bad attackId pattern (must reject)", False, ov, off_bad_id)

def_schema = schemas["defensive-response.json"]
dv = Draft7Validator(def_schema)

def_data = {
    "technique_id": "T1190",
    "mitigations": [{"d3fendId": "D3-PA", "name": "Process Analysis"}],
    "detections": [{"analyticId": "CAR-2021-05-002", "title": "Test", "coverageLevel": "Moderate"}],
    "deceptions": [{"techniqueId": "DTE0001", "name": "Admin Account"}],
    "engagements": [{"activityId": "EAC0002", "name": "App Diversity"}],
    "summary": {"total_mitigations": 1, "total_detections": 1, "total_deceptions": 1, "total_engagements": 1, "has_coverage": True},
}
check("defensive-response valid data", True, dv, def_data)

def_empty = {"mitigations": [], "detections": [], "deceptions": [], "engagements": []}
check("defensive-response all empty arrays", True, dv, def_empty)

def_bad_car = {"mitigations": [], "detections": [{"analyticId": "INVALID-001"}], "deceptions": [], "engagements": []}
check("defensive-response bad CAR analyticId format (must reject)", False, dv, def_bad_car)

engagement_no_id = {"mitigations": [], "detections": [], "deceptions": [], "engagements": [{"name": "No ID"}]}
check("defensive-response engagement missing id (must reject)", False, dv, engagement_no_id)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print()
if failures:
    print(f"FAILED: {len(failures)} check(s) failed:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
else:
    print("ALL CHECKS PASSED")
    sys.exit(0)
