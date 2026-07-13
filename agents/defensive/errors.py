"""Custom exceptions for Defensive Agent"""


class DefensiveAgentError(Exception):
    """Base exception for Defensive Agent"""
    pass


class TemplateError(DefensiveAgentError):
    """Raised when Cypher template validation fails"""
    pass


class QueryExecutionError(DefensiveAgentError):
    """Raised when Neo4j query execution fails"""
    pass


class ValidationError(DefensiveAgentError):
    """Raised when user input validation fails"""
    pass
