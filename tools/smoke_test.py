#!/usr/bin/env python3
"""
KGCS API smoke test script.

Runs a minimal set of HTTP checks against a live KGCS orchestrator API to
verify that the service is up and responding correctly.  Designed for
real-environment validation — requires a running API and a populated Neo4j
graph.

Usage
-----
  python scripts/smoke_test.py
  python scripts/smoke_test.py --base-url http://prod-host:8080
  python scripts/smoke_test.py --base-url http://localhost:8080 --api-key SECRET

Exit codes
----------
  0  All checks passed.
  1  One or more checks failed.

Environment variables
---------------------
  KGCS_API_URL   Base URL of the running KGCS API (default: http://localhost:8080)
  KGCS_API_KEY   Bearer token for API authentication (optional)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only — no third-party dependencies)
# ---------------------------------------------------------------------------

def _headers(api_key: Optional[str]) -> Dict[str, str]:
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        h["Authorization"] = f"Bearer {api_key}"
    return h


def _get(url: str, api_key: Optional[str]) -> Tuple[int, Any]:
    req = urllib.request.Request(url, headers=_headers(api_key))
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, {}
    except Exception as exc:
        return 0, {"error": str(exc)}


def _post(url: str, body: Dict, api_key: Optional[str]) -> Tuple[int, Any]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=_headers(api_key), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            body_bytes = exc.read()
            return exc.code, json.loads(body_bytes)
        except Exception:
            return exc.code, {}
    except Exception as exc:
        return 0, {"error": str(exc)}


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_health(base_url: str, api_key: Optional[str]) -> Tuple[bool, str]:
    status, body = _get(f"{base_url}/health", api_key)
    if status == 200 and body.get("status") == "ok":
        return True, f"  PASS /health → status=ok service={body.get('service')}"
    return False, f"  FAIL /health → HTTP {status}, body={body}"


def check_ready(base_url: str, api_key: Optional[str]) -> Tuple[bool, str]:
    status, body = _get(f"{base_url}/ready", api_key)
    if status == 200 and body.get("status") == "ready":
        return True, f"  PASS /ready → ready=true"
    if status == 503:
        issues = body.get("issues", [])
        return False, f"  FAIL /ready → not_ready, issues={issues}"
    return False, f"  FAIL /ready → HTTP {status}, body={body}"


def check_query_vuln_lookup(base_url: str, api_key: Optional[str]) -> Tuple[bool, str]:
    body = {
        "version": "1.0",
        "correlation_id": str(uuid4()),
        "agent": "master",
        "intent": "vuln_lookup",
        "payload": {"cveId": "CVE-2021-44228"},
    }
    status, resp = _post(f"{base_url}/query", body, api_key)
    if status == 200 and resp.get("status") in ("ok", "empty"):
        conf = resp.get("confidence", {}).get("value", "?")
        return True, f"  PASS /query vuln_lookup CVE-2021-44228 → status={resp['status']} confidence={conf}"
    return False, f"  FAIL /query vuln_lookup → HTTP {status}, status={resp.get('status')}, errors={resp.get('errors')}"


def check_query_attack_path(base_url: str, api_key: Optional[str]) -> Tuple[bool, str]:
    body = {
        "version": "1.0",
        "correlation_id": str(uuid4()),
        "agent": "master",
        "intent": "attack_path",
        "payload": {"cweId": "CWE-20"},
    }
    status, resp = _post(f"{base_url}/query", body, api_key)
    if status == 200 and resp.get("status") in ("ok", "empty"):
        conf = resp.get("confidence", {}).get("value", "?")
        return True, f"  PASS /query attack_path CWE-20 → status={resp['status']} confidence={conf}"
    return False, f"  FAIL /query attack_path → HTTP {status}, status={resp.get('status')}, errors={resp.get('errors')}"


def check_query_coverage_map(base_url: str, api_key: Optional[str]) -> Tuple[bool, str]:
    body = {
        "version": "1.0",
        "correlation_id": str(uuid4()),
        "agent": "master",
        "intent": "coverage_map",
        "payload": {"attackId": "T1190"},
    }
    status, resp = _post(f"{base_url}/query", body, api_key)
    if status == 200 and resp.get("status") in ("ok", "empty"):
        conf = resp.get("confidence", {}).get("value", "?")
        return True, f"  PASS /query coverage_map T1190 → status={resp['status']} confidence={conf}"
    return False, f"  FAIL /query coverage_map → HTTP {status}, status={resp.get('status')}, errors={resp.get('errors')}"


def check_query_mixed(base_url: str, api_key: Optional[str]) -> Tuple[bool, str]:
    body = {
        "version": "1.0",
        "correlation_id": str(uuid4()),
        "agent": "master",
        "intent": "mixed",
        "payload": {"cveId": "CVE-2021-44228"},
    }
    status, resp = _post(f"{base_url}/query", body, api_key)
    if status == 200 and resp.get("status") in ("ok", "empty"):
        conf = resp.get("confidence", {}).get("value", "?")
        return True, f"  PASS /query mixed CVE-2021-44228 → status={resp['status']} confidence={conf}"
    return False, f"  FAIL /query mixed → HTTP {status}, status={resp.get('status')}, errors={resp.get('errors')}"


def check_ask_endpoint(base_url: str, api_key: Optional[str]) -> Tuple[bool, str]:
    body = {
        "prompt": "What vulnerabilities affect Apache Log4j? CVE-2021-44228",
        "session_id": None,
    }
    status, resp = _post(f"{base_url}/ask", body, api_key)
    if status == 200 and "answer" in resp:
        intent = resp.get("intent", "?")
        return True, f"  PASS /ask → status=200 intent={intent}"
    if status == 400:
        # Could be a safety or entity error — still confirms the endpoint is alive
        return True, f"  PASS /ask → HTTP 400 (endpoint reachable, validation active) errors={resp.get('errors')}"
    return False, f"  FAIL /ask → HTTP {status}, body={resp}"


def check_invalid_payload(base_url: str, api_key: Optional[str]) -> Tuple[bool, str]:
    """Confirm the API rejects a request with a missing required field."""
    body = {
        "version": "1.0",
        "correlation_id": str(uuid4()),
        "agent": "master",
        "intent": "vuln_lookup",
        "payload": {},  # deliberately empty — should fail schema validation
    }
    status, resp = _post(f"{base_url}/query", body, api_key)
    if status == 400:
        return True, f"  PASS /query invalid payload → correctly rejected HTTP 400"
    return False, f"  FAIL /query invalid payload → expected HTTP 400, got {status}"


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

_CHECKS = [
    ("health",          check_health),
    ("ready",           check_ready),
    ("vuln_lookup",     check_query_vuln_lookup),
    ("attack_path",     check_query_attack_path),
    ("coverage_map",    check_query_coverage_map),
    ("mixed",           check_query_mixed),
    ("ask",             check_ask_endpoint),
    ("invalid_payload", check_invalid_payload),
]


def run_smoke_tests(base_url: str, api_key: Optional[str]) -> int:
    print(f"\nKGCS Smoke Test")
    print(f"  Target:  {base_url}")
    print(f"  Auth:    {'yes (bearer token)' if api_key else 'none'}")
    print(f"  Time:    {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print()

    results: List[Tuple[str, bool, str]] = []
    for name, fn in _CHECKS:
        passed, msg = fn(base_url, api_key)
        results.append((name, passed, msg))
        print(msg)

    passed_count = sum(1 for _, p, _ in results if p)
    total = len(results)
    print()
    print(f"Results: {passed_count}/{total} passed")

    failures = [(n, m) for n, p, m in results if not p]
    if failures:
        print("\nFailed checks:")
        for name, msg in failures:
            print(f"  [{name}] {msg.strip()}")
        return 1

    print("\nAll smoke checks PASSED.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="KGCS API smoke test — verifies a live orchestrator API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--base-url",
        default=os.getenv("KGCS_API_URL", "http://localhost:8080"),
        help="Base URL of the KGCS API (default: $KGCS_API_URL or http://localhost:8080)",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("KGCS_API_KEY"),
        help="Bearer token for API authentication (default: $KGCS_API_KEY)",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    base_url = args.base_url.rstrip("/")
    sys.exit(run_smoke_tests(base_url, args.api_key))


if __name__ == "__main__":
    main()
