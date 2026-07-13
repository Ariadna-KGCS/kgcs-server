"""Custom exceptions for Systems Agent"""


class SystemsAgentError(Exception):
    """Base exception for Systems Agent errors"""
    pass


class TemplateError(SystemsAgentError):
    """Raised when Cypher template is invalid or malformed"""
    pass


class QueryExecutionError(SystemsAgentError):
    """Raised when Neo4j query execution fails"""
    pass


class ValidationError(SystemsAgentError):
    """Raised when request or response validation fails"""
    pass
