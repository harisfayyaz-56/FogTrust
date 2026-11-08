"""
Redaction of audit event details (docs/data-model.md, section 5.5).

Every `details` dict passes through redact_details() before it is stored, so a
caller who accidentally passes a password, token or cookie never leaks it into
the permanent, un-deletable audit log.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping

REDACTED = "[REDACTED]"
TRUNCATED_MARK = "…[truncated]"

MAX_STRING = 256
MAX_ITEMS = 50
MAX_DEPTH = 4
MAX_BYTES = 4096

# Any key containing one of these (case-insensitive) is replaced with REDACTED.
SENSITIVE_FRAGMENTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "private",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "session",
    "csrf",
    "signature",
    "proof",
    "credential",
)

# Identifiers that contain a sensitive word but are not secret themselves.
SAFE_KEYS = frozenset({"token_id", "token_label"})


def is_sensitive_key(key) -> bool:
    name = str(key).lower()
    if name in SAFE_KEYS:
        return False
    return any(fragment in name for fragment in SENSITIVE_FRAGMENTS)


def _truncate(text: str) -> str:
    if len(text) <= MAX_STRING:
        return text
    return text[: MAX_STRING - len(TRUNCATED_MARK)] + TRUNCATED_MARK


def redact(value, depth: int = 0):
    """Return a JSON-safe, size-limited copy of `value` with secret keys replaced."""
    if depth > MAX_DEPTH:
        return "[depth limit]"
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, str):
        return _truncate(value)
    if isinstance(value, Mapping):
        cleaned = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_ITEMS:
                cleaned["_omitted_keys"] = len(value) - MAX_ITEMS
                break
            name = _truncate(str(key))[:64]
            cleaned[name] = REDACTED if is_sensitive_key(key) else redact(item, depth + 1)
        return cleaned
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        cleaned = [redact(item, depth + 1) for item in items[:MAX_ITEMS]]
        if len(items) > MAX_ITEMS:
            cleaned.append(f"[{len(items) - MAX_ITEMS} more items omitted]")
        return cleaned
    # UUIDs, datetimes, Decimals, model instances: store their text form only.
    return _truncate(str(value))


def redact_details(details) -> dict:
    if details is None:
        return {}
    if not isinstance(details, Mapping):
        details = {"value": details}
    cleaned = redact(details)
    if len(json.dumps(cleaned)) > MAX_BYTES:
        cleaned = {"_truncated": True, "keys": sorted(cleaned)[:20]}
    return cleaned
