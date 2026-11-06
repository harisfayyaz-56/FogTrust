"""
FogTrust cryptography package (Member 2).

Plain Python. It must never import Django, Django REST Framework or any
other web framework, so it can be tested alone (the brief asks for an
independently testable security engine). The API layer calls into it;
it never calls into the API layer. A test enforces this rule.
"""

__version__ = "0.1.0"