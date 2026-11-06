"""Fail if this package's reason codes drift from backend/core/errors.py (the source of truth)."""

import ast
import re
from pathlib import Path

from fogtrust_crypto import codes

BACKEND = Path(__file__).resolve().parents[2]


def _api_codes():
    text = (BACKEND / "core" / "errors.py").read_text(encoding="utf-8")
    return dict(re.findall(r'^\s+([A-Z_]+) = "([A-Z_]+)"$', text, re.MULTILINE))


def test_every_code_exists_in_the_api_error_catalog_with_the_same_value():
    api = _api_codes()
    for code in codes.ALL_CODES:
        assert api.get(code) == code, f"{code} is missing from or different in backend/core/errors.py"


def test_package_never_imports_a_web_framework():
    """Brief: the security engine must be independently testable, so no Django or DRF inside."""
    forbidden = {"django", "rest_framework", "fastapi", "flask", "starlette"}
    package = BACKEND / "fogtrust_crypto"
    for source in package.glob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module]
            for name in names:
                assert name.split(".")[0] not in forbidden, f"{source.name} imports {name}"