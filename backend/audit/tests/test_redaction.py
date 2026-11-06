"""Secrets never reach the permanent audit log (threat ID-10)."""

import json
import uuid

import pytest

from audit.redaction import MAX_BYTES, MAX_STRING, REDACTED, redact_details
from audit.services import log_event


def test_sensitive_keys_are_redacted_at_any_depth():
    cleaned = redact_details(
        {
            "password": "hunter2",
            "new_Password": "x",
            "enrollment_token": "q8Zr-secret",
            "headers": {"Authorization": "Bearer abc", "Cookie": "fogtrust_session=xyz", "X-CSRFToken": "t"},
            "proof": "sig",
            "private_key": "k",
            "nested": [{"api_key": "k2"}],
        }
    )
    text = json.dumps(cleaned)
    for secret in ("hunter2", "q8Zr-secret", "Bearer abc", "xyz", "sig", "k2"):
        assert secret not in text
    assert cleaned["password"] == REDACTED
    assert cleaned["headers"]["Authorization"] == REDACTED
    assert cleaned["nested"][0]["api_key"] == REDACTED


def test_identifiers_are_kept():
    cleaned = redact_details({"token_id": "c1d2", "token_label": "lab 2", "node_name": "gateway-03"})
    assert cleaned == {"token_id": "c1d2", "token_label": "lab 2", "node_name": "gateway-03"}


def test_long_strings_are_truncated():
    cleaned = redact_details({"reason": "x" * 5000})
    assert len(cleaned["reason"]) == MAX_STRING
    assert cleaned["reason"].endswith("[truncated]")


def test_oversized_details_are_replaced():
    cleaned = redact_details({f"field{i}": "y" * 200 for i in range(40)})
    assert len(json.dumps(cleaned)) <= MAX_BYTES
    assert cleaned["_truncated"] is True


def test_non_json_values_become_text():
    node_id = uuid.uuid4()
    cleaned = redact_details({"node": node_id, "ratio": float("nan"), "ids": (1, 2)})
    assert cleaned == {"node": str(node_id), "ratio": "nan", "ids": [1, 2]}


@pytest.mark.django_db
def test_log_event_always_redacts():
    event = log_event("auth.login", "failure", actor_type="anonymous", details={"password": "hunter2"})
    assert event.details == {"password": REDACTED}
