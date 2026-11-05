import uuid

import pytest

HEALTH_URL = "/api/v1/health/"


@pytest.mark.django_db
def test_health_is_public_and_reports_ok(api_client):
    response = api_client.get(HEALTH_URL)

    assert response.status_code == 200
    assert response["Content-Type"].startswith("application/json")
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert body["service"] == "fogtrust-broker"


@pytest.mark.django_db
def test_health_reveals_no_configuration(api_client):
    body = api_client.get(HEALTH_URL).json()
    assert set(body) == {"status", "service", "version", "database"}


@pytest.mark.django_db
def test_every_response_has_server_generated_request_id(api_client):
    response = api_client.get(HEALTH_URL, HTTP_X_REQUEST_ID="attacker-chosen-id")

    request_id = response["X-Request-ID"]
    assert request_id != "attacker-chosen-id"
    uuid.UUID(request_id)  # raises if not a valid UUID


@pytest.mark.django_db
def test_security_headers_present(api_client):
    response = api_client.get(HEALTH_URL)
    assert response["X-Frame-Options"] == "DENY"
    assert response["X-Content-Type-Options"] == "nosniff"
    assert response["Referrer-Policy"] == "same-origin"


@pytest.mark.django_db
def test_wrong_method_returns_stable_error(api_client):
    response = api_client.post(HEALTH_URL, {}, format="json")

    assert response.status_code == 405
    assert response.json()["error"]["code"] == "METHOD_NOT_ALLOWED"
