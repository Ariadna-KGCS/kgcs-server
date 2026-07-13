"""Custom exceptions for Master Orchestrator"""


class OrchestratorError(Exception):
    """Base exception for Master Orchestrator"""
    pass


class RoutingError(OrchestratorError):
    """Raised when request routing fails"""
    pass


class ValidationError(OrchestratorError):
    """Raised when request validation fails"""
    pass


class AggregationError(OrchestratorError):
    """Raised when response aggregation fails"""
    pass


class AgentExecutionError(OrchestratorError):
    """Raised when agent execution fails"""
    pass


class OrchestratorTimeoutError(OrchestratorError):
    """Raised when the orchestration pipeline exceeds its configured deadline.

    Propagates uncaught through executor.execute() so the API layer can
    return HTTP 504 instead of a generic 500.
    """
    pass
