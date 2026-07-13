"""Integration-level API tests exercising the full KGCS middleware stack.

These tests verify the end-to-end HTTP contract of the orchestrator API using
canonical request fixtures from ``tests/fixtures/requests/``.  They exercise
all five middleware layers (correlation, access_log, auth, rate_limit,
request_size) plus the handler logic, without requiring a live Neo4j instance.

The tests reside here — not under ``orchestrator/tests/`` — because they
cross package boundaries: they load shared fixtures, exercise the full
orchestrator service boundary, and serve as the deployment-readiness gate.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, Optional

import pytest
from aiohttp.test_utils import TestClient, TestServer

from orchestrator.api import create_app

# ---------------------------------------------------------------------------
# Fixture root
# ---------------------------------------------------------------------------

_FIXTURE_DIR = Path(__file__).parent / "fixtures"
_REQUEST_DIR = _FIXTURE_DIR / "requests"
_EDGE_CASE_DIR = _FIXTURE_DIR / "edge_cases"


def _load(path: Path) -> Dict[str, Any]:
    """Load a JSON fixture, stripping the leading ``_comment`` field."""
    data = json.loads(path.read_text(encoding="utf-8"))
    data.pop("_comment", None)
    return data


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------

class _DummyValidator:
    def validate_request(self, payload):
        pass


class _StrictValidator:
    """Mimics the real SchemaValidator: rejects requests missing intent or payload."""

    def validate_request(self, payload):
        if not payload.get("intent"):
            raise ValueError("intent is required")
        if not isinstance(payload.get("payload"), dict) or not payload["payload"]:
            raise ValueError("payload must be a non-empty object")


class _DummyOrchestrator:
    def __init__(self, correlation_id: Optional[str] = None):
        self.correlation_id = correlation_id

    def execute(self, request: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "version": "1.0",
            "correlation_id": request["correlation_id"],
            "status": "ok",
            "data": {"echo_intent": request.get("intent")},
            "provenance": [
                {"source": "TEST", "ids": ["INT-1"], "timestamp": "2026-03-24T00:00:00Z"}
            ],
            "confidence": {
                "value": 1.0,
                "basis": "COMPLETE_CHAIN",
                "signals": {},
                "degradation": [],
            },
            "errors": [],
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    return asyncio.run(coro)


def _make_app(**kwargs):
    defaults: dict = {
        "orchestrator_factory": _DummyOrchestrator,
        "schema_validator_factory": _DummyValidator,
        "readiness_check": lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
    }
    defaults.update(kwargs)
    return create_app(**defaults)


async def _create_client(app):
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    return client


# ---------------------------------------------------------------------------
# Health and readiness
# ---------------------------------------------------------------------------

class TestHealthAndReadiness:
    """The liveness and readiness endpoints must always be reachable."""

    def test_health_returns_ok(self):
        async def go():
            client = await _create_client(_make_app())
            try:
                resp = await client.get("/health")
                assert resp.status == 200
                body = await resp.json()
                assert body["status"] == "ok"
                assert "service" in body
            finally:
                await client.close()
        _run(go())

    def test_ready_returns_ready(self):
        async def go():
            client = await _create_client(_make_app())
            try:
                resp = await client.get("/ready")
                assert resp.status == 200
                body = await resp.json()
                assert body["status"] == "ready"
                assert "checks" in body
            finally:
                await client.close()
        _run(go())

    def test_health_open_when_api_key_configured(self):
        """Auth middleware must never gate /health."""
        async def go():
            client = await _create_client(_make_app(api_key="secret"))
            try:
                resp = await client.get("/health")
                assert resp.status == 200
            finally:
                await client.close()
        _run(go())


# ---------------------------------------------------------------------------
# Canonical fixture requests → 200
# ---------------------------------------------------------------------------

class TestCanonicalRequests:
    """Each canonical request fixture must produce an HTTP 200 with a valid envelope."""

    _ENVELOPE_FIELDS = {"version", "correlation_id", "status", "data", "provenance", "confidence"}

    async def _post_fixture(self, filename: str) -> tuple:
        body = _load(_REQUEST_DIR / filename)
        client = await _create_client(_make_app())
        try:
            resp = await client.post("/query", json=body)
            resp_body = await resp.json()
            return resp.status, resp_body, resp.headers
        finally:
            await client.close()

    def _assert_envelope(self, status: int, body: dict):
        assert status == 200, f"Expected 200 but got {status}: {body}"
        for field in self._ENVELOPE_FIELDS:
            assert field in body, f"Missing envelope field: {field}"
        assert body["status"] in ("ok", "empty", "error")

    def test_vuln_lookup_by_cve(self):
        status, body, _ = _run(self._post_fixture("vuln_lookup_by_cve.json"))
        self._assert_envelope(status, body)
        assert body["data"]["echo_intent"] == "vuln_lookup"

    def test_vuln_lookup_by_cpe(self):
        status, body, _ = _run(self._post_fixture("vuln_lookup_by_cpe.json"))
        self._assert_envelope(status, body)
        assert body["data"]["echo_intent"] == "vuln_lookup"

    def test_attack_path_by_cwe(self):
        status, body, _ = _run(self._post_fixture("attack_path_by_cwe.json"))
        self._assert_envelope(status, body)
        assert body["data"]["echo_intent"] == "attack_path"

    def test_coverage_map_by_technique(self):
        status, body, _ = _run(self._post_fixture("coverage_map_by_technique.json"))
        self._assert_envelope(status, body)
        assert body["data"]["echo_intent"] == "coverage_map"

    def test_mixed_by_cve(self):
        status, body, _ = _run(self._post_fixture("mixed_by_cve.json"))
        self._assert_envelope(status, body)
        assert body["data"]["echo_intent"] == "mixed"

    def test_correlation_id_returned_in_response_header(self):
        """X-Correlation-ID must be echoed back by correlation_middleware."""
        async def go():
            body = _load(_REQUEST_DIR / "vuln_lookup_by_cve.json")
            client = await _create_client(_make_app())
            try:
                resp = await client.post(
                    "/query",
                    json=body,
                    headers={"X-Correlation-ID": "integration-test-corr-001"},
                )
                assert resp.headers.get("X-Correlation-ID") == "integration-test-corr-001"
            finally:
                await client.close()
        _run(go())

    def test_request_correlation_id_propagated_to_response_body(self):
        """The correlation_id in the request body must appear in the response envelope."""
        async def go():
            body = _load(_REQUEST_DIR / "vuln_lookup_by_cve.json")
            client = await _create_client(_make_app())
            try:
                resp = await client.post("/query", json=body)
                resp_body = await resp.json()
                assert resp_body["correlation_id"] == body["correlation_id"]
            finally:
                await client.close()
        _run(go())


# ---------------------------------------------------------------------------
# Error handling — invalid and edge-case requests
# ---------------------------------------------------------------------------

class TestErrorHandling:
    """Invalid requests must be rejected with 400 and a structured error envelope."""

    def test_missing_intent_returns_400(self):
        async def go():
            client = await _create_client(_make_app(schema_validator_factory=_StrictValidator))
            try:
                resp = await client.post(
                    "/query",
                    json={
                        "version": "1.0",
                        "correlation_id": "int-err-001",
                        "agent": "master",
                        # no intent
                        "payload": {"cveId": "CVE-2021-44228"},
                    },
                )
                assert resp.status == 400
                body = await resp.json()
                assert body.get("status") == "error"
                assert body.get("errors")
            finally:
                await client.close()
        _run(go())

    def test_empty_payload_returns_400(self):
        """An empty payload for vuln_lookup must be rejected by the validator."""
        async def go():
            client = await _create_client(_make_app(schema_validator_factory=_StrictValidator))
            try:
                resp = await client.post(
                    "/query",
                    json={
                        "version": "1.0",
                        "correlation_id": "int-err-002",
                        "agent": "master",
                        "intent": "vuln_lookup",
                        "payload": {},
                    },
                )
                assert resp.status == 400
                body = await resp.json()
                assert body.get("status") == "error"
            finally:
                await client.close()
        _run(go())

    def test_malformed_json_returns_400(self):
        async def go():
            client = await _create_client(_make_app())
            try:
                resp = await client.post(
                    "/query",
                    data=b"not-json",
                    headers={"Content-Type": "application/json"},
                )
                assert resp.status == 400
            finally:
                await client.close()
        _run(go())


# ---------------------------------------------------------------------------
# Full-stack middleware interaction
# ---------------------------------------------------------------------------

class TestFullStackMiddlewareInteraction:
    """Spot-checks that all middleware layers cooperate on a real request."""

    def test_auth_plus_rate_limit_plus_canonical_request(self):
        """An authenticated request within the rate limit must reach the handler."""
        async def go():
            app = _make_app(api_key="integration-key", rate_limit=10)
            client = await _create_client(app)
            try:
                body = _load(_REQUEST_DIR / "vuln_lookup_by_cve.json")
                resp = await client.post(
                    "/query",
                    json=body,
                    headers={"X-API-Key": "integration-key"},
                )
                assert resp.status == 200
                resp_body = await resp.json()
                assert resp_body["status"] == "ok"
            finally:
                await client.close()
        _run(go())

    def test_unauthenticated_request_blocked_before_rate_limit(self):
        """auth_middleware fires before rate_limit_middleware — auth check 401 first."""
        async def go():
            app = _make_app(api_key="integration-key", rate_limit=1)
            client = await _create_client(app)
            try:
                body = _load(_REQUEST_DIR / "vuln_lookup_by_cve.json")
                # Missing key — must be 401, not consuming any rate-limit quota.
                r1 = await client.post("/query", json=body)
                r2 = await client.post("/query", json=body)
                assert r1.status == 401
                assert r2.status == 401  # still 401, not 429
            finally:
                await client.close()
        _run(go())
