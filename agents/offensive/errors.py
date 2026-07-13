"""Custom exceptions for Offensive Agent

Exception hierarchy:
- OffensiveAgentError (base)
  - TemplateError (template syntax/validation)
  - QueryExecutionError (Neo4j failures)
  - ValidationError (user input validation)
"""


class OffensiveAgentError(Exception):
    """Base exception for Offensive Agent"""
    pass


class TemplateError(OffensiveAgentError):
    """Raised when Cypher template is invalid"""
    pass


class QueryExecutionError(OffensiveAgentError):
    """Raised when Neo4j query fails"""
    pass


class ValidationError(OffensiveAgentError):
    """Raised when user input/request is invalid"""
    pass
