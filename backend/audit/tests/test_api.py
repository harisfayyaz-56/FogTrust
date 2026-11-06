"""GET /api/v1/audit/ and POST /api/v1/audit/verify/ (admin only)."""

import pytest
from django.db import connection

from audit.models import AuditEvent
from audit.services import log_event

pytestmark = pytest.mark.django_db

LIST_URL = "/api/v1/audit/"
VERIFY_URL = "/api/v1/audit/verify/"


@pytest.fixture
def admin(client_as):
    return client_as("admin")


@pytest.fixture
def some_events():
    log_event("node.revoke", "success", actor_type="system", target_type="node", target_id="n1")
    log_event("auth.login", "failure", actor_type="anonymous", reason_code="AUTH_INVALID_CREDENTIALS")
    log_event("auth.login", "success", actor_type="system")


def test_admin_lists_events_newest_first(admin, some_events):
    response = admin.get(LIST_URL)

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 3
    sequences = [event["sequence"] for event in body["results"]]
    assert sequences == sorted(sequences, reverse=True)
    assert {"hash", "prev_hash", "request_id", "details"} <= set(body["results"][0])


def test_filters(admin, some_events):
    assert admin.get(LIST_URL, {"action": "auth.login"}).json()["count"] == 2
    assert admin.get(LIST_URL, {"action": "auth.login", "outcome": "failure"}).json()["count"] == 1
    assert admin.get(LIST_URL, {"reason_code": "AUTH_INVALID_CREDENTIALS"}).json()["count"] == 1
    assert admin.get(LIST_URL, {"page_size": 1}).json()["next"] is not None


@pytest.mark.parametrize(
    "params",
    [
        {"since": "yesterday"},
        {"outcome": "maybe"},
        {"page_size": 1000},
        {"unexpected": "1"},
        {"since": "2026-11-10T00:00:00Z", "until": "2026-11-01T00:00:00Z"},
        {"action": "x' OR '1'='1"},
    ],
)
def test_invalid_filters_are_rejected(admin, params):
    response = admin.get(LIST_URL, params)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.parametrize("role", ["operator", "viewer"])
def test_non_admins_are_denied(client_as, role):
    client = client_as(role)
    assert client.get(LIST_URL).status_code == 403
    assert client.post(VERIFY_URL).status_code == 403


def test_anonymous_is_denied(api_client):
    assert api_client.get(LIST_URL).status_code == 401


def test_verify_reports_valid_chain_and_records_itself(admin, some_events):
    response = admin.post(VERIFY_URL)

    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True
    assert body["events_checked"] == 3
    latest = AuditEvent.objects.order_by("-sequence").first()
    assert (latest.action, latest.actor_id) == ("audit.verify", "admin1")


def test_verify_reports_tampering(admin, some_events):
    with connection.cursor() as cursor:
        cursor.execute("DROP TRIGGER audit_event_no_update")
        cursor.execute("UPDATE audit_event SET target_id = 'n2' WHERE sequence = 1")

    body = admin.post(VERIFY_URL).json()
    assert body["valid"] is False
    assert body["first_broken_sequence"] == 1
    assert body["problem"] == "hash_mismatch"
    latest = AuditEvent.objects.order_by("-sequence").first()
    assert (latest.outcome, latest.reason_code) == ("failure", "AUDIT_CHAIN_BROKEN")
