"""Tests for the orchestrator HTTP API wrapper."""

import asyncio

from aiohttp.test_utils import TestClient, TestServer

from orchestrator.api import create_app


class DummyValidator:
    """Validator stub for API tests."""

    def __init__(self, should_fail: bool = False):
        self.should_fail = should_fail

    def validate_request(self, payload):
        if self.should_fail:
            raise ValueError("bad request")


class DummyOrchestrator:
    """Orchestrator stub for API tests."""

    def __init__(self, correlation_id=None):
        self.correlation_id = correlation_id

    def execute(self, request):
        return {
            "version": "1.0",
            "correlation_id": request["correlation_id"],
            "status": "ok",
            "data": {"echo_intent": request["intent"]},
            "provenance": [{"source": "TEST", "ids": ["REQ-1"], "timestamp": "2026-03-17T00:00:00Z"}],
            "confidence": {"value": 1.0, "basis": "COMPLETE_CHAIN", "signals": {}, "degradation": []},
            "errors": [],
        }


class ErrorOrchestrator:
    """Orchestrator stub that simulates downstream failure."""

    def __init__(self, correlation_id=None):
        self.correlation_id = correlation_id

    def execute(self, request):
        return {
            "version": "1.0",
            "correlation_id": request["correlation_id"],
            "status": "error",
            "data": {},
            "provenance": [],
            "confidence": {"value": 0.0, "basis": "NO_MATCH", "signals": {}, "degradation": ["query_failed"]},
            "errors": ["Downstream agent failure"],
        }


def run_async(coro):
    """Run an async test helper without pytest async plugins."""
    return asyncio.run(coro)


async def create_client(app):
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    return client


class TestOrchestratorApi:
    """API endpoint coverage."""

    def test_health_endpoint(self):
        async def scenario():
            app = create_app(
                orchestrator_factory=DummyOrchestrator,
                schema_validator_factory=DummyValidator,
                readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
            )
            client = await create_client(app)
            try:
                response = await client.get("/health")
                payload = await response.json()
                assert response.status == 200
                assert payload["status"] == "ok"
                assert payload["service"] == "kgcs-orchestrator-api"
            finally:
                await client.close()

        run_async(scenario())

    def test_ready_endpoint_ready(self):
        async def scenario():
            app = create_app(
                orchestrator_factory=DummyOrchestrator,
                schema_validator_factory=DummyValidator,
                readiness_check=lambda: (True, {"status": "ready", "checks": {"schemas_loaded": True}, "issues": []}),
            )
            client = await create_client(app)
            try:
                response = await client.get("/ready")
                payload = await response.json()
                assert response.status == 200
                assert payload["status"] == "ready"
            finally:
                await client.close()

        run_async(scenario())

    def test_ready_endpoint_not_ready(self):
        async def scenario():
            app = create_app(
                orchestrator_factory=DummyOrchestrator,
                schema_validator_factory=DummyValidator,
                readiness_check=lambda: (False, {"status": "not_ready", "checks": {}, "issues": ["missing_env"]}),
            )
            client = await create_client(app)
            try:
                response = await client.get("/ready")
                payload = await response.json()
                assert response.status == 503
                assert payload["status"] == "not_ready"
                assert payload["issues"] == ["missing_env"]
            finally:
                await client.close()

        run_async(scenario())

    def test_query_endpoint_success(self):
        async def scenario():
            app = create_app(
                orchestrator_factory=DummyOrchestrator,
                schema_validator_factory=DummyValidator,
                readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
            )
            client = await create_client(app)
            try:
                response = await client.post(
                    "/query",
                    json={
                        "version": "1.0",
                        "agent": "master",
                        "intent": "vuln_lookup",
                        "payload": {"cveId": "CVE-2021-44228"},
                    },
                    headers={"X-Correlation-ID": "corr-123"},
                )
                payload = await response.json()
                assert response.status == 200
                assert payload["status"] == "ok"
                assert payload["correlation_id"] == "corr-123"
                assert payload["data"]["echo_intent"] == "vuln_lookup"
                assert response.headers["X-Correlation-ID"] == "corr-123"
            finally:
                await client.close()

        run_async(scenario())

    def test_query_endpoint_attack_path_success(self):
        async def scenario():
            app = create_app(
                orchestrator_factory=DummyOrchestrator,
                schema_validator_factory=DummyValidator,
                readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
            )
            client = await create_client(app)
            try:
                response = await client.post(
                    "/query",
                    json={
                        "version": "1.0",
                        "correlation_id": "550e8400-e29b-41d4-a716-446655440010",
                        "agent": "master",
                        "intent": "attack_path",
                        "payload": {"cweId": "CWE-79"},
                    },
                )
                payload = await response.json()
                assert response.status == 200
                assert payload["status"] == "ok"
                assert payload["data"]["echo_intent"] == "attack_path"
            finally:
                await client.close()

        run_async(scenario())

    def test_query_endpoint_coverage_map_success(self):
        async def scenario():
            app = create_app(
                orchestrator_factory=DummyOrchestrator,
                schema_validator_factory=DummyValidator,
                readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
            )
            client = await create_client(app)
            try:
                response = await client.post(
                    "/query",
                    json={
                        "version": "1.0",
                        "correlation_id": "550e8400-e29b-41d4-a716-446655440011",
                        "agent": "master",
                        "intent": "coverage_map",
                        "payload": {"attackId": "T1059"},
                    },
                )
                payload = await response.json()
                assert response.status == 200
                assert payload["status"] == "ok"
                assert payload["data"]["echo_intent"] == "coverage_map"
            finally:
                await client.close()

        run_async(scenario())

    def test_query_endpoint_mixed_success(self):
        async def scenario():
            app = create_app(
                orchestrator_factory=DummyOrchestrator,
                schema_validator_factory=DummyValidator,
                readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
            )
            client = await create_client(app)
            try:
                response = await client.post(
                    "/query",
                    json={
                        "version": "1.0",
                        "correlation_id": "550e8400-e29b-41d4-a716-446655440012",
                        "agent": "master",
                        "intent": "mixed",
                        "payload": {"cveId": "CVE-2021-44228"},
                    },
                )
                payload = await response.json()
                assert response.status == 200
                assert payload["status"] == "ok"
                assert payload["data"]["echo_intent"] == "mixed"
            finally:
                await client.close()

        run_async(scenario())

    def test_query_endpoint_validation_failure(self):
        async def scenario():
            app = create_app(
                orchestrator_factory=DummyOrchestrator,
                schema_validator_factory=lambda: DummyValidator(should_fail=True),
                readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
            )
            client = await create_client(app)
            try:
                response = await client.post(
                    "/query",
                    json={
                        "version": "1.0",
                        "agent": "master",
                        "intent": "vuln_lookup",
                        "payload": {"cveId": "CVE-2021-44228"},
                    },
                )
                payload = await response.json()
                assert response.status == 400
                assert payload["status"] == "error"
                assert "Request validation failed" in payload["errors"][0]
            finally:
                await client.close()

        run_async(scenario())

    def test_query_endpoint_downstream_failure_passthrough(self):
        async def scenario():
            app = create_app(
                orchestrator_factory=ErrorOrchestrator,
                schema_validator_factory=DummyValidator,
                readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
            )
            client = await create_client(app)
            try:
                response = await client.post(
                    "/query",
                    json={
                        "version": "1.0",
                        "correlation_id": "550e8400-e29b-41d4-a716-446655440013",
                        "agent": "master",
                        "intent": "vuln_lookup",
                        "payload": {"cveId": "CVE-2021-44228"},
                    },
                )
                payload = await response.json()
                assert response.status == 200
                assert payload["status"] == "error"
                assert payload["errors"] == ["Downstream agent failure"]
            finally:
                await client.close()

        run_async(scenario())

    def test_query_endpoint_invalid_json(self):
        async def scenario():
            app = create_app(
                orchestrator_factory=DummyOrchestrator,
                schema_validator_factory=DummyValidator,
                readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
            )
            client = await create_client(app)
            try:
                response = await client.post(
                    "/query",
                    data="not-json",
                    headers={"Content-Type": "application/json"},
                )
                payload = await response.json()
                assert response.status == 400
                assert payload["status"] == "error"
                assert payload["errors"] == ["Invalid JSON request body"]
            finally:
                await client.close()

        run_async(scenario())

    def test_query_endpoint_requires_api_key_when_configured(self):
        async def scenario():
            app = create_app(
                orchestrator_factory=DummyOrchestrator,
                schema_validator_factory=DummyValidator,
                readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
                api_key="secret-key",
            )
            client = await create_client(app)
            try:
                response = await client.post(
                    "/query",
                    json={
                        "version": "1.0",
                        "correlation_id": "550e8400-e29b-41d4-a716-446655440014",
                        "agent": "master",
                        "intent": "vuln_lookup",
                        "payload": {"cveId": "CVE-2021-44228"},
                    },
                )
                payload = await response.json()
                assert response.status == 401
                assert payload["status"] == "error"
                assert payload["errors"] == ["Unauthorized"]
            finally:
                await client.close()

        run_async(scenario())

    def test_query_endpoint_accepts_bearer_api_key(self):
        async def scenario():
            app = create_app(
                orchestrator_factory=DummyOrchestrator,
                schema_validator_factory=DummyValidator,
                readiness_check=lambda: (True, {"status": "ready", "checks": {}, "issues": []}),
                api_key="secret-key",
            )
            client = await create_client(app)
            try:
                response = await client.post(
                    "/query",
                    json={
                        "version": "1.0",
                        "correlation_id": "550e8400-e29b-41d4-a716-446655440015",
                        "agent": "master",
                        "intent": "coverage_map",
                        "payload": {"attackId": "T1059"},
                    },
                    headers={"Authorization": "Bearer secret-key"},
                )
                payload = await response.json()
                assert response.status == 200
                assert payload["status"] == "ok"
                assert payload["data"]["echo_intent"] == "coverage_map"
            finally:
                await client.close()

        run_async(scenario())
