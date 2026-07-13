"""Systems Agent test suite

Tests for the Systems Agent microservice, covering:
- test_executor.py: Request routing, response envelope building, error handling
- test_transformers.py: Neo4j → JSON transformation, deduplication, provenance
- test_cypher_syntax.py: Cypher template validation at module load
- test_integration.py: End-to-end integration with mocked Neo4jClient
"""
