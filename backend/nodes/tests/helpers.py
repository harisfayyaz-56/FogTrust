"""Shared builders for the nodes tests."""

import json

from audit.models import AuditEvent
from fogtrust_crypto.keys import generate_private_key, public_key_to_b64, sign_enrollment_proof

ENROLL_URL = "/api/v1/nodes/enroll/"


def new_keypair():
    key = generate_private_key()
    return key, public_key_to_b64(key.public_key())


def enroll_payload(raw_token, *, name="gateway-01", key=None, capacity=4, **overrides):
    """A valid enrollment body for `raw_token`. `overrides` replace fields to build attack variants."""
    key = key or generate_private_key()
    body = {
        "enrollment_token": raw_token,
        "name": name,
        "public_key": public_key_to_b64(key.public_key()),
        "capacity": capacity,
        "proof": sign_enrollment_proof(key, raw_token, name),
    }
    body.update(overrides)
    return body


def post_json(client, url, body, **extra):
    return client.post(url, data=json.dumps(body), content_type="application/json", **extra)


def error_code(response) -> str:
    return response.json()["error"]["code"]


def audit_events(action, outcome=None):
    queryset = AuditEvent.objects.filter(action=action).order_by("sequence")
    return list(queryset.filter(outcome=outcome) if outcome else queryset)


def last_audit(action, outcome=None):
    events = audit_events(action, outcome)
    assert events, f"no {action} audit event recorded"
    return events[-1]
