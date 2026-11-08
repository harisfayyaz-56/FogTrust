"""
The standard error envelope and the "never expose stack traces" rule.

These are early T-final evidence: malformed input, oversized input,
unauthorized request and safe failure behaviour.
"""

import pytest
from django.test import override_settings
from rest_framework.test import APIClient

from core.errors import ERROR_CATALOG, APIError, ErrorCode

pytestmark = [pytest.mark.django_db, pytest.mark.urls("core.tests.support_urls")]


def assert_envelope(response, status, code):
    assert response.status_code == status, response.content
    body = response.json()
    assert set(body) == {"error"}
    error = body["error"]
    assert error["code"] == code
    assert isinstance(error["message"], str) and error["message"]
    assert error["request_id"] == response["X-Request-ID"]
    return error


def test_unknown_url_returns_json_not_html(api_client):
    response = api_client.get("/does-not-exist/")
    assert response["Content-Type"].startswith("application/json")
    assert_envelope(response, 404, "NOT_FOUND")


def test_unauthenticated_request_is_rejected(api_client):
    response = api_client.post("/t/echo/", {"a": 1}, format="json")
    assert_envelope(response, 401, "AUTH_REQUIRED")


def test_permission_denied_is_generic(api_client, make_user):
    api_client.force_authenticate(make_user())
    response = api_client.get("/t/forbidden/")

    error = assert_envelope(response, 403, "PERMISSION_DENIED")
    assert error["message"] == "Access denied."
    assert b"should never be returned" not in response.content


def test_malformed_json_is_rejected(api_client):
    response = api_client.post("/t/public-echo/", data="{not json", content_type="application/json")
    assert_envelope(response, 400, "MALFORMED_REQUEST")


def test_non_json_content_type_is_rejected(api_client):
    response = api_client.post("/t/public-echo/", data="a=1", content_type="application/x-www-form-urlencoded")
    assert_envelope(response, 415, "UNSUPPORTED_MEDIA_TYPE")


@override_settings(DATA_UPLOAD_MAX_MEMORY_SIZE=1024)
def test_oversized_body_is_rejected(api_client):
    big = {"data": "x" * 5000}
    response = api_client.post("/t/public-echo/", big, format="json")
    assert_envelope(response, 413, "PAYLOAD_TOO_LARGE")


def test_crash_hides_internal_details(api_client):
    client = APIClient(raise_request_exception=False)
    response = client.get("/t/crash/")

    assert_envelope(response, 500, "INTERNAL_ERROR")
    for leaked in (b"hunter2", b"Traceback", b"secret.py", b"RuntimeError"):
        assert leaked not in response.content


def test_domain_error_uses_catalog(api_client):
    response = api_client.get("/t/domain-error/")
    error = assert_envelope(response, 403, "NODE_REVOKED")
    assert error["message"] == ERROR_CATALOG[ErrorCode.NODE_REVOKED][1]


def test_rate_limit_returns_429_with_retry_after(api_client):
    assert api_client.get("/t/throttled/").status_code == 200
    assert api_client.get("/t/throttled/").status_code == 200

    response = api_client.get("/t/throttled/")
    assert_envelope(response, 429, "RATE_LIMITED")
    assert int(response["Retry-After"]) > 0


def test_csrf_enforced_for_session_users(make_user):
    user = make_user()
    client = APIClient(enforce_csrf_checks=True)
    client.force_login(user)

    response = client.post("/t/echo/", {"a": 1}, format="json")
    assert_envelope(response, 403, "CSRF_FAILED")


def test_unknown_error_code_cannot_be_raised():
    with pytest.raises(ValueError):
        APIError("MADE_UP_CODE")


def test_every_catalog_entry_is_well_formed():
    for code, (status, message) in ERROR_CATALOG.items():
        assert code.isupper()
        assert 400 <= status <= 599
        assert message and len(message) < 120


def test_validation_errors_never_echo_input(api_client):
    payload = "<script>alert(1)</script>"
    response = api_client.post("/t/choice/", {"role": payload}, format="json")

    error = assert_envelope(response, 400, "VALIDATION_ERROR")
    assert error["details"]["fields"]["role"] == ["Not a valid choice."]
    assert b"script" not in response.content


def test_unknown_fields_are_rejected_without_echoing_them(api_client):
    response = api_client.post("/t/choice/", {"role": "admin", "is_superuser": True}, format="json")

    assert_envelope(response, 400, "VALIDATION_ERROR")
    assert b"is_superuser" not in response.content


def test_non_object_body_is_rejected(api_client):
    response = api_client.post("/t/choice/", ["admin"], format="json")
    assert_envelope(response, 400, "VALIDATION_ERROR")
