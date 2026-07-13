"""HTTP API wrapper for the KGCS master orchestrator."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Callable, Dict, Optional, Tuple
from uuid import uuid4

from aiohttp import web

from agents.shared.logger import configure_json_logging
from agents.shared.response_builder import ResponseBuilder
from agents.shared.schema_validator import SchemaValidator

from .errors import OrchestratorTimeoutError
from .executor import MasterOrchestrator

# AI layer imports — only used by the /ask endpoint.
# Imported here so missing-module errors surface at startup, not at first request.
from ai import LLMAdapter
from ai.entity_extractor import MultipleEntitiesError
from ai.safety import SafetyViolationError, UnsupportedQueryError as AIUnsupportedQueryError


JsonDict = Dict[str, Any]
ReadinessResult = Tuple[bool, JsonDict]
ORCHESTRATOR_FACTORY_KEY = web.AppKey("orchestrator_factory", object)
SCHEMA_VALIDATOR_FACTORY_KEY = web.AppKey("schema_validator_factory", object)
READINESS_CHECK_KEY = web.AppKey("readiness_check", object)
RESPONSE_BUILDER_KEY = web.AppKey("response_builder", ResponseBuilder)
API_KEY_KEY = web.AppKey("api_key", object)

# P5.2 security controls — configurable via environment variables.
_MAX_REQUEST_SIZE_BYTES = int(os.getenv("KGCS_MAX_REQUEST_SIZE", str(1 * 1024 * 1024)))  # 1 MiB
_RATE_LIMIT = int(os.getenv("KGCS_RATE_LIMIT", "60"))   # requests per minute; 0 = disabled
_RATE_WINDOW_S = 60.0                                    # fixed 1-minute window

# App keys for per-instance rate-limiting state (avoids mutable module-level globals).
_RATE_DATA_KEY = web.AppKey("rate_data", object)
_RATE_LOCK_KEY = web.AppKey("rate_lock", object)
_RATE_LIMIT_APP_KEY = web.AppKey("rate_limit_val", int)

# Endpoints exempt from authentication and rate limiting.
_OPEN_PATHS = frozenset({"/health", "/ready"})

_api_log = logging.getLogger("kgcs.api")


def _default_readiness_check() -> ReadinessResult:
    """Return service readiness based on local dependencies and configuration."""
    issues = []

    try:
        SchemaValidator()
    except Exception as exc:  # pragma: no cover - exercised via injection in tests
        issues.append(f"schema_validation_unavailable: {exc}")

    required_env = ["NEO4J_URI", "NEO4J_USER", "NEO4J_PASSWORD"]
    missing_env = [name for name in required_env if not os.getenv(name)]
    if missing_env:
        issues.append(f"missing_env: {', '.join(missing_env)}")

    ready = not issues
    return ready, {
        "status": "ready" if ready else "not_ready",
        "checks": {
            "schemas_loaded": not any(issue.startswith("schema_validation_unavailable") for issue in issues),
            "neo4j_env_present": not missing_env,
        },
        "issues": issues,
    }


# ---------------------------------------------------------------------------
# Middleware stack (applied outermost → innermost in the list order)
# ---------------------------------------------------------------------------

@web.middleware
async def correlation_middleware(request: web.Request, handler: Callable[[web.Request], Any]) -> web.StreamResponse:
    """Ensure every request/response carries a correlation ID."""
    correlation_id = request.headers.get("X-Correlation-ID") or str(uuid4())
    request["correlation_id"] = correlation_id

    response = await handler(request)
    response.headers["X-Correlation-ID"] = correlation_id
    return response


@web.middleware
async def access_log_middleware(request: web.Request, handler: Callable[[web.Request], Any]) -> web.StreamResponse:
    """Record method, path, status, and wall-clock latency for every request."""
    t0 = time.perf_counter()
    response = await handler(request)
    latency_ms = round((time.perf_counter() - t0) * 1000, 1)
    _api_log.info(
        "request",
        extra={
            "correlation_id": request.get("correlation_id"),
            "method":         request.method,
            "path":           request.path,
            "status":         response.status,
            "latency_ms":     latency_ms,
        },
    )
    return response


@web.middleware
async def auth_middleware(request: web.Request, handler: Callable[[web.Request], Any]) -> web.StreamResponse:
    """Enforce API-key authentication on protected endpoints.

    Skips ``/health`` and ``/ready``.  When ``KGCS_API_KEY`` is not configured
    (or the app was created without an ``api_key``), all requests are allowed
    through unchanged.

    Accepts the key in either of two headers::

        X-API-Key: <key>
        Authorization: Bearer <key>
    """
    if request.path in _OPEN_PATHS:
        return await handler(request)

    configured_key: Optional[str] = request.app[API_KEY_KEY]
    if not configured_key:
        return await handler(request)

    provided_key = request.headers.get("X-API-Key")
    if not provided_key:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            provided_key = auth_header.removeprefix("Bearer ").strip()

    if provided_key != configured_key:
        response_builder: ResponseBuilder = request.app[RESPONSE_BUILDER_KEY]
        error = response_builder.error(
            errors=["Unauthorized"],
            correlation_id=request.get("correlation_id", ""),
        )
        return web.json_response(error, status=401)

    return await handler(request)


@web.middleware
async def rate_limit_middleware(request: web.Request, handler: Callable[[web.Request], Any]) -> web.StreamResponse:
    """Apply a per-client-IP fixed-window rate limit on protected endpoints.

    Skips ``/health`` and ``/ready``.  When the configured limit is ``0`` the
    middleware is a no-op.  The window and limit are set at ``create_app()``
    time from ``KGCS_RATE_LIMIT`` (default 60 req/min).
    """
    if request.path in _OPEN_PATHS:
        return await handler(request)

    effective_limit: int = request.app[_RATE_LIMIT_APP_KEY]
    if effective_limit == 0:
        return await handler(request)

    client_key = request.remote or "unknown"
    now = time.monotonic()

    lock: asyncio.Lock = request.app[_RATE_LOCK_KEY]
    async with lock:
        data: dict = request.app[_RATE_DATA_KEY]
        window_start, count = data.get(client_key, (now, 0))

        if now - window_start >= _RATE_WINDOW_S:
            # Start a fresh window.
            data[client_key] = (now, 1)
        elif count >= effective_limit:
            response_builder: ResponseBuilder = request.app[RESPONSE_BUILDER_KEY]
            error = response_builder.error(
                errors=["Too many requests"],
                correlation_id=request.get("correlation_id", ""),
            )
            return web.json_response(error, status=429)
        else:
            data[client_key] = (window_start, count + 1)

    return await handler(request)


@web.middleware
async def request_size_middleware(request: web.Request, handler: Callable[[web.Request], Any]) -> web.StreamResponse:
    """Convert oversized-body errors to a structured JSON 413 response.

    aiohttp raises ``HTTPRequestEntityTooLarge`` when a handler reads a body
    that exceeds ``client_max_size``.  This middleware catches that exception
    and returns a consistent error envelope instead of the default HTML page.
    """
    try:
        return await handler(request)
    except web.HTTPRequestEntityTooLarge:
        response_builder: ResponseBuilder = request.app[RESPONSE_BUILDER_KEY]
        error = response_builder.error(
            errors=["Request body too large"],
            correlation_id=request.get("correlation_id", ""),
        )
        return web.json_response(error, status=413)


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app(
    *,
    orchestrator_factory: Callable[..., Any] = MasterOrchestrator,
    schema_validator_factory: Callable[..., Any] = SchemaValidator,
    readiness_check: Callable[[], ReadinessResult] = _default_readiness_check,
    api_key: Optional[str] = None,
    rate_limit: Optional[int] = None,
    max_request_size: Optional[int] = None,
) -> web.Application:
    """Create the aiohttp application for KGCS orchestration.

    Parameters
    ----------
    orchestrator_factory:
        Callable that returns a ``MasterOrchestrator``-compatible object.
    schema_validator_factory:
        Callable that returns a ``SchemaValidator``-compatible object.
    readiness_check:
        Zero-arg callable that returns ``(is_ready, payload_dict)``.
    api_key:
        Override for the ``KGCS_API_KEY`` environment variable.  When both
        are absent, authentication is disabled.
    rate_limit:
        Requests-per-minute cap per client IP.  ``0`` disables rate limiting.
        Defaults to the ``KGCS_RATE_LIMIT`` env var (default 60).
    max_request_size:
        Maximum allowed request body size in bytes.  Defaults to the
        ``KGCS_MAX_REQUEST_SIZE`` env var (default 1 MiB).
    """
    effective_rate_limit = _RATE_LIMIT if rate_limit is None else rate_limit
    effective_max_size = _MAX_REQUEST_SIZE_BYTES if max_request_size is None else max_request_size

    app = web.Application(
        middlewares=[
            correlation_middleware,
            access_log_middleware,
            auth_middleware,
            rate_limit_middleware,
            request_size_middleware,
        ],
        client_max_size=effective_max_size,
    )
    app[ORCHESTRATOR_FACTORY_KEY] = orchestrator_factory
    app[SCHEMA_VALIDATOR_FACTORY_KEY] = schema_validator_factory
    app[READINESS_CHECK_KEY] = readiness_check
    app[RESPONSE_BUILDER_KEY] = ResponseBuilder()
    app[API_KEY_KEY] = api_key if api_key is not None else os.getenv("KGCS_API_KEY")
    app[_RATE_DATA_KEY] = {}
    app[_RATE_LOCK_KEY] = asyncio.Lock()
    app[_RATE_LIMIT_APP_KEY] = effective_rate_limit

    # ------------------------------------------------------------------
    # Route handlers
    # ------------------------------------------------------------------

    async def health(_: web.Request) -> web.Response:
        return web.json_response({"status": "ok", "service": "kgcs-orchestrator-api"})

    async def ready(request: web.Request) -> web.Response:
        is_ready, payload = request.app[READINESS_CHECK_KEY]()
        status = 200 if is_ready else 503
        return web.json_response(payload, status=status)

    async def query(request: web.Request) -> web.Response:
        correlation_id = request["correlation_id"]
        response_builder = request.app[RESPONSE_BUILDER_KEY]

        try:
            body = await request.json()
        except web.HTTPRequestEntityTooLarge:
            raise  # propagate to request_size_middleware
        except Exception:
            error = response_builder.error(
                errors=["Invalid JSON request body"],
                correlation_id=correlation_id,
            )
            return web.json_response(error, status=400)

        if not isinstance(body, dict):
            error = response_builder.error(
                errors=["Request body must be a JSON object"],
                correlation_id=correlation_id,
            )
            return web.json_response(error, status=400)

        body = dict(body)
        body["correlation_id"] = body.get("correlation_id") or correlation_id

        try:
            validator = request.app[SCHEMA_VALIDATOR_FACTORY_KEY]()
            validator.validate_request(body)
        except Exception as exc:
            error = response_builder.error(
                errors=[f"Request validation failed: {exc}"],
                correlation_id=body["correlation_id"],
            )
            return web.json_response(error, status=400)

        try:
            orchestrator = request.app[ORCHESTRATOR_FACTORY_KEY](correlation_id=body["correlation_id"])
            result = orchestrator.execute(body)
        except OrchestratorTimeoutError:
            error = response_builder.error(
                errors=["Request timed out"],
                correlation_id=body["correlation_id"],
            )
            return web.json_response(error, status=504)
        except Exception as exc:  # pragma: no cover - defensive wrapper
            error = response_builder.error(
                errors=[f"Internal API error: {exc}"],
                correlation_id=body["correlation_id"],
            )
            return web.json_response(error, status=500)

        return web.json_response(result, status=200)

    async def ask(request: web.Request) -> web.Response:
        """POST /ask — natural-language query endpoint.

        Accepts a plain-English cybersecurity question and returns a
        graph-grounded answer produced by the AI interaction layer.

        Request body (JSON)
        -------------------
        ``prompt``     – required, non-empty string.
        ``session_id`` – optional string (accepted, no session logic yet).

        Response body (JSON)
        --------------------
        ``answer``         – human-readable, graph-grounded answer.
        ``raw``            – full ResponseEnvelope from the orchestrator.
        ``intent``         – resolved KGCS intent string.
        ``payload``        – entity payload sent to the orchestrator.
        ``correlation_id`` – propagated correlation ID.

        Note: returns HTTP 501 while the AI layer is at scaffold stage.
        """
        correlation_id = request["correlation_id"]
        response_builder = request.app[RESPONSE_BUILDER_KEY]

        # -- Parse body ---------------------------------------------------
        try:
            body = await request.json()
        except web.HTTPRequestEntityTooLarge:
            raise  # propagate to request_size_middleware
        except Exception:
            error = response_builder.error(
                errors=["Invalid JSON request body"],
                correlation_id=correlation_id,
            )
            return web.json_response(error, status=400)

        if not isinstance(body, dict):
            error = response_builder.error(
                errors=["Request body must be a JSON object"],
                correlation_id=correlation_id,
            )
            return web.json_response(error, status=400)

        prompt: Any = body.get("prompt")
        if not prompt or not isinstance(prompt, str) or not prompt.strip():
            error = response_builder.error(
                errors=["'prompt' field is required and must be a non-empty string"],
                correlation_id=correlation_id,
            )
            return web.json_response(error, status=400)

        session_id: Optional[str] = body.get("session_id")

        # -- Execute AI pipeline ------------------------------------------
        try:
            orchestrator = request.app[ORCHESTRATOR_FACTORY_KEY](correlation_id=correlation_id)
            adapter = LLMAdapter(orchestrator=orchestrator)
            result = adapter.process(prompt.strip(), session_id)
        except (SafetyViolationError, AIUnsupportedQueryError, MultipleEntitiesError) as exc:
            error = response_builder.error(
                errors=[str(exc)],
                correlation_id=correlation_id,
            )
            return web.json_response(error, status=400)
        except NotImplementedError:
            # Expected at scaffold stage — pipeline logic is not yet implemented.
            return web.json_response(
                {
                    "status": "not_implemented",
                    "message": "AI layer scaffold: logic not yet implemented.",
                    "correlation_id": correlation_id,
                },
                status=501,
            )
        except OrchestratorTimeoutError:
            error = response_builder.error(
                errors=["Request timed out"],
                correlation_id=correlation_id,
            )
            return web.json_response(error, status=504)
        except Exception as exc:  # pragma: no cover - defensive wrapper
            error = response_builder.error(
                errors=[f"Internal API error: {exc}"],
                correlation_id=correlation_id,
            )
            return web.json_response(error, status=500)

        result["correlation_id"] = correlation_id
        return web.json_response(result, status=200)

    app.router.add_get("/health", health)
    app.router.add_get("/ready", ready)
    app.router.add_post("/query", query)
    app.router.add_post("/ask", ask)

    return app


def main() -> None:
    """Run the API locally."""
    configure_json_logging()
    app = create_app()
    web.run_app(app, host="0.0.0.0", port=int(os.getenv("PORT", "8080")))


if __name__ == "__main__":
    main()
