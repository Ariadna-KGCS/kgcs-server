"""Tests for P5.2 security controls — auth, request-size limits, rate limiting.

Covers:
- auth_middleware: 401 when KGCS_API_KEY is configured and credentials are missing/wrong
- auth_middleware: accepts X-API-Key header and Authorization: Bearer header
- auth_middleware: /health and /ready are always open
- auth_middleware: no-op when no API key is configured
- request_size_middleware: 413 when body exceeds limit; passes through when within limit
- rate_limit_middleware: 429 after the configured limit is exhausted in a window
- rate_limit_middleware: /health and /ready are exempt from rate limiting
- rate_limit_middleware: rate_limit=0 disables rate limiting
"""

import asyncio

from aiohttp.test_utils import TestClient, TestServer

from orchestrator.api import create_app


class _DummyValidator:
    def validate_request(self, payload):
        pass


class _DummyOrchestrator:
    def __init__(self, correlation_id=None):
        self.correlation_id = correlation_id

    def execute(self, request):
        return {
            "version": "1.0",
            "correlation_id": request["correlation_id"],
            "status": "ok",
            "data": {},
            "provenance": [{"source": "TEST", "ids": ["T-1"], "timestamp": "2026-03-24T00:00:00Z"}],
            "confidence": {"value": 1.0, "basis": "COMPLETE_CHAIN", "signals": {}, "degradation": []},
            "errors": [],
        }


def _run(coro):
    return asyncio.run(coro)


async def _client(app):
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    return client


_QUERY_BODY = {
    "version": "1.0",
    "correlation_id": "test-security-001",
    "agent": "systems",
    "intent": "vuln_lookup",
    "payload": {"cveId": "CVE-2021-44228"},
}


# ---------------------------------------------------------------------------
# Auth middleware tests
# ---------------------------------------------------------------------------

class TestAuthMiddleware:
    """auth_middleware enforces KGCS_API_KEY on /query and /ask."""

    def _app(self, api_key="test-secret"):
        return create_app(
            orchestrator_factory=_DummyOrchestrator,
            schema_validator_factory=_DummyValidator,
            readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
            api_key=api_key,
        )

    def test_missing_key_returns_401(self):
        async def go():
            client = await _client(self._app())
            try:
                resp = await client.post("/query", json=_QUERY_BODY)
                assert resp.status == 401
                body = await resp.json()
                assert "Unauthorized" in str(body.get("errors", ""))
            finally:
                await client.close()
        _run(go())

    def test_wrong_key_returns_401(self):
        async def go():
            client = await _client(self._app())
            try:
                resp = await client.post("/query", json=_QUERY_BODY, headers={"X-API-Key": "wrong"})
                assert resp.status == 401
            finally:
                await client.close()
        _run(go())

    def test_correct_x_api_key_header_allowed(self):
        async def go():
            client = await _client(self._app())
            try:
                resp = await client.post(
                    "/query", json=_QUERY_BODY, headers={"X-API-Key": "test-secret"}
                )
                assert resp.status == 200
            finally:
                await client.close()
        _run(go())

    def test_correct_bearer_token_allowed(self):
        async def go():
            client = await _client(self._app())
            try:
                resp = await client.post(
                    "/query",
                    json=_QUERY_BODY,
                    headers={"Authorization": "Bearer test-secret"},
                )
                assert resp.status == 200
            finally:
                await client.close()
        _run(go())

    def test_health_open_without_key(self):
        async def go():
            client = await _client(self._app())
            try:
                resp = await client.get("/health")
                assert resp.status == 200
            finally:
                await client.close()
        _run(go())

    def test_ready_open_without_key(self):
        async def go():
            client = await _client(self._app())
            try:
                resp = await client.get("/ready")
                assert resp.status in (200, 503)  # depends on env; just not 401
            finally:
                await client.close()
        _run(go())

    def test_no_api_key_configured_allows_all(self):
        async def go():
            app = create_app(
                orchestrator_factory=_DummyOrchestrator,
                schema_validator_factory=_DummyValidator,
                readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
                api_key=None,
            )
            client = await _client(app)
            try:
                # No credentials — should still succeed since no key is configured.
                resp = await client.post("/query", json=_QUERY_BODY)
                assert resp.status == 200
            finally:
                await client.close()
        _run(go())


# ---------------------------------------------------------------------------
# Request-size middleware tests
# ---------------------------------------------------------------------------

class TestRequestSizeMiddleware:
    """request_size_middleware converts oversized-body errors to structured 413."""

    def test_oversized_body_returns_413(self):
        async def go():
            # Set a very small limit — 10 bytes — so our query body triggers 413.
            app = create_app(
                orchestrator_factory=_DummyOrchestrator,
                schema_validator_factory=_DummyValidator,
                readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
                max_request_size=10,
            )
            client = await _client(app)
            try:
                resp = await client.post("/query", json=_QUERY_BODY)
                assert resp.status == 413
                body = await resp.json()
                assert "too large" in str(body.get("errors", "")).lower()
            finally:
                await client.close()
        _run(go())

    def test_body_within_limit_passes_through(self):
        async def go():
            app = create_app(
                orchestrator_factory=_DummyOrchestrator,
                schema_validator_factory=_DummyValidator,
                readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
                max_request_size=1 * 1024 * 1024,  # 1 MiB — well above our test body
            )
            client = await _client(app)
            try:
                resp = await client.post("/query", json=_QUERY_BODY)
                assert resp.status == 200
            finally:
                await client.close()
        _run(go())


# ---------------------------------------------------------------------------
# Rate-limit middleware tests
# ---------------------------------------------------------------------------

class TestRateLimitMiddleware:
    """rate_limit_middleware returns 429 once the per-IP window is exhausted."""

    def test_exceeding_limit_returns_429(self):
        async def go():
            # Limit set to 2 — the third request must be 429.
            app = create_app(
                orchestrator_factory=_DummyOrchestrator,
                schema_validator_factory=_DummyValidator,
                readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
                rate_limit=2,
            )
            client = await _client(app)
            try:
                r1 = await client.post("/query", json=_QUERY_BODY)
                r2 = await client.post("/query", json=_QUERY_BODY)
                r3 = await client.post("/query", json=_QUERY_BODY)
                assert r1.status == 200
                assert r2.status == 200
                assert r3.status == 429
                body = await r3.json()
                assert "Too many requests" in str(body.get("errors", ""))
            finally:
                await client.close()
        _run(go())

    def test_health_exempt_from_rate_limit(self):
        async def go():
            # Limit set to 1 — /health must never get 429.
            app = create_app(
                orchestrator_factory=_DummyOrchestrator,
                schema_validator_factory=_DummyValidator,
                readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
                rate_limit=1,
            )
            client = await _client(app)
            try:
                for _ in range(5):
                    resp = await client.get("/health")
                    assert resp.status == 200
            finally:
                await client.close()
        _run(go())

    def test_rate_limit_zero_disables(self):
        async def go():
            app = create_app(
                orchestrator_factory=_DummyOrchestrator,
                schema_validator_factory=_DummyValidator,
                readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
                rate_limit=0,
            )
            client = await _client(app)
            try:
                # Fire many requests — none should be 429.
                for _ in range(10):
                    resp = await client.post("/query", json=_QUERY_BODY)
                    assert resp.status == 200
            finally:
                await client.close()
        _run(go())
