"""
Login, logout, /me and session expiry (threats ID-1, ID-2, ID-3).
"""

import time
from datetime import timedelta

import pytest
from django.conf import settings
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.utils import timezone
from rest_framework.test import APIClient

from accounts.authentication import LOGIN_AT_SESSION_KEY
from accounts.throttles import LoginUsernameThrottle
from audit.models import AuditEvent
from conftest import DEFAULT_PASSWORD

pytestmark = pytest.mark.django_db

CSRF_URL = "/api/v1/auth/csrf/"
LOGIN_URL = "/api/v1/auth/login/"
LOGOUT_URL = "/api/v1/auth/logout/"
ME_URL = "/api/v1/auth/me/"


def login(client, username, password=DEFAULT_PASSWORD):
    return client.post(LOGIN_URL, {"username": username, "password": password}, format="json")


def browser_client():
    """A client that behaves like the dashboard: CSRF enforced, token sent in a header."""
    client = APIClient(enforce_csrf_checks=True)
    token = client.get(CSRF_URL).json()["csrf_token"]
    client.credentials(HTTP_X_CSRFTOKEN=token)
    return client


def last_event(action):
    return AuditEvent.objects.filter(action=action).order_by("-sequence").first()


def error_code(response):
    return response.json()["error"]["code"]


# --------------------------------------------------------------------- CSRF


def test_csrf_endpoint_sets_cookie(api_client):
    response = api_client.get(CSRF_URL)

    assert response.status_code == 200
    assert settings.CSRF_COOKIE_NAME in response.cookies
    assert response.json()["csrf_token"]


def test_login_requires_csrf_token(make_user):
    make_user(username="op1", role="operator")
    client = APIClient(enforce_csrf_checks=True)

    response = login(client, "op1")
    assert response.status_code == 403
    assert error_code(response) == "CSRF_FAILED"
    assert last_event("access.denied").reason_code == "CSRF_FAILED"


def test_logout_requires_csrf_token(client_as):
    client = client_as("operator", enforce_csrf=True)
    response = client.post(LOGOUT_URL)
    assert response.status_code == 403
    assert error_code(response) == "CSRF_FAILED"


# -------------------------------------------------------------------- login


def test_login_success_starts_secure_session(make_user):
    make_user(username="op1", role="operator")
    client = browser_client()

    response = login(client, "op1")

    assert response.status_code == 200
    assert response.json() == {
        "user": {"username": "op1", "role": "operator"},
        "session_expires_in": settings.SESSION_COOKIE_AGE,
    }
    cookie = response.cookies[settings.SESSION_COOKIE_NAME]
    assert cookie["httponly"]
    assert cookie["samesite"] == "Strict"
    assert client.get(ME_URL).status_code == 200

    event = last_event("auth.login")
    assert (event.outcome, event.actor_id, event.actor_role) == ("success", "op1", "operator")


def test_wrong_password_and_unknown_user_look_identical(make_user):
    make_user(username="op1", role="operator")
    client = browser_client()

    wrong_password = login(client, "op1", "not-the-password")
    unknown_user = login(client, "nobody", "not-the-password")

    for response in (wrong_password, unknown_user):
        assert response.status_code == 401
        assert error_code(response) == "AUTH_INVALID_CREDENTIALS"
    strip = lambda r: {k: v for k, v in r.json()["error"].items() if k != "request_id"}  # noqa: E731
    assert strip(wrong_password) == strip(unknown_user)


def test_failed_login_is_audited_without_the_password(make_user):
    make_user(username="op1", role="operator")
    login(browser_client(), "op1", "guess-123")

    event = last_event("auth.login")
    assert (event.outcome, event.reason_code, event.target_id) == ("failure", "AUTH_INVALID_CREDENTIALS", "op1")
    assert event.actor_type == "anonymous"
    assert event.details == {"username_known": True}
    assert "guess-123" not in str(AuditEvent.objects.values_list("details", flat=True))


def test_disabled_account_gets_generic_error_but_precise_audit(make_user):
    make_user(username="old", role="operator", is_active=False)
    response = login(browser_client(), "old")

    assert response.status_code == 401
    assert error_code(response) == "AUTH_INVALID_CREDENTIALS"
    assert last_event("auth.login").reason_code == "AUTH_ACCOUNT_DISABLED"


def test_login_rotates_session_key(make_user):
    """Session fixation: a session ID planted before login must not survive it."""
    make_user(username="op1", role="operator")
    planted = SessionStore()
    planted["planted"] = True
    planted.create()

    client = browser_client()
    client.cookies[settings.SESSION_COOKIE_NAME] = planted.session_key
    response = login(client, "op1")

    assert response.cookies[settings.SESSION_COOKIE_NAME].value != planted.session_key


@pytest.mark.parametrize(
    "body",
    [
        {"username": "op1"},
        {"username": "op1", "password": DEFAULT_PASSWORD, "role": "admin"},  # unknown field
        {"username": "op1", "password": "p" * 129},  # over the hashing cap
        {"username": "", "password": "x"},
        ["op1", DEFAULT_PASSWORD],  # not an object
    ],
)
def test_malformed_login_bodies_are_rejected(make_user, body):
    make_user(username="op1", role="operator")
    response = browser_client().post(LOGIN_URL, body, format="json")

    assert response.status_code == 400
    assert error_code(response) == "VALIDATION_ERROR"


def test_sql_injection_in_username_is_harmless(make_user):
    make_user(username="admin1", role="admin")
    response = login(browser_client(), "admin1' OR '1'='1' --", "anything")
    assert response.status_code == 401
    assert error_code(response) == "AUTH_INVALID_CREDENTIALS"


# -------------------------------------------------------------- rate limits


def test_login_is_rate_limited_per_client(make_user):
    make_user(username="op1", role="operator")
    client = browser_client()

    statuses = [login(client, "op1", f"guess-{i}").status_code for i in range(5)]
    assert statuses == [401] * 5

    blocked = login(client, "op1", DEFAULT_PASSWORD)  # even the right password is refused now
    assert blocked.status_code == 429
    assert error_code(blocked) == "RATE_LIMITED"
    assert int(blocked["Retry-After"]) > 0


def test_rate_limit_is_audited_once_per_window(make_user):
    make_user(username="op1", role="operator")
    client = browser_client()
    for i in range(9):
        login(client, "op1", f"guess-{i}")

    events = AuditEvent.objects.filter(action="request.rate_limited")
    assert events.count() == 1
    assert events.first().details["scope"] == "login"


def test_login_is_rate_limited_per_username_across_ips(make_user, monkeypatch):
    """An attacker rotating IP addresses still cannot keep guessing one account."""
    monkeypatch.setattr(LoginUsernameThrottle, "rate", "3/hour", raising=False)
    make_user(username="op1", role="operator")

    statuses = []
    for i in range(4):
        client = browser_client()
        body = {"username": "op1", "password": "wrong"}
        statuses.append(client.post(LOGIN_URL, body, format="json", REMOTE_ADDR=f"10.0.0.{i}").status_code)

    assert statuses == [401, 401, 401, 429]


# ---------------------------------------------------------------- me/logout


def test_me_returns_role_and_permissions(client_as):
    body = client_as("viewer").get(ME_URL).json()

    assert body["username"] == "viewer1"
    assert body["role"] == "viewer"
    assert "nodes.view" in body["permissions"]
    assert "nodes.revoke" not in body["permissions"]


def test_me_requires_login(api_client):
    response = api_client.get(ME_URL)
    assert response.status_code == 401
    assert error_code(response) == "AUTH_REQUIRED"


def test_logout_ends_server_side_session(make_user):
    make_user(username="op1", role="operator")
    client = browser_client()
    session_key = login(client, "op1").cookies[settings.SESSION_COOKIE_NAME].value
    client.credentials(HTTP_X_CSRFTOKEN=client.cookies[settings.CSRF_COOKIE_NAME].value)

    assert client.post(LOGOUT_URL).status_code == 204
    assert not Session.objects.filter(session_key=session_key).exists()
    assert client.get(ME_URL).status_code == 401
    assert last_event("auth.logout").actor_id == "op1"


def test_old_session_cookie_is_useless_after_logout(make_user):
    """A copied cookie stops working the moment the user logs out."""
    make_user(username="op1", role="operator")
    client = browser_client()
    session_key = login(client, "op1").cookies[settings.SESSION_COOKIE_NAME].value
    client.credentials(HTTP_X_CSRFTOKEN=client.cookies[settings.CSRF_COOKIE_NAME].value)
    client.post(LOGOUT_URL)

    thief = APIClient()
    thief.cookies[settings.SESSION_COOKIE_NAME] = session_key
    response = thief.get(ME_URL)
    assert response.status_code == 401
    assert error_code(response) == "AUTH_SESSION_EXPIRED"


# ------------------------------------------------------------ session expiry


def test_session_is_stored_server_side_and_survives_a_new_client(client_as):
    """Restart recovery: nothing about the session lives in server memory."""
    client = client_as("operator")
    fresh = APIClient()
    fresh.cookies[settings.SESSION_COOKIE_NAME] = client.cookies[settings.SESSION_COOKIE_NAME].value
    assert fresh.get(ME_URL).status_code == 200


def test_idle_session_expires(client_as):
    client = client_as("operator")
    Session.objects.update(expire_date=timezone.now() - timedelta(seconds=1))

    response = client.get(ME_URL)
    assert response.status_code == 401
    assert error_code(response) == "AUTH_SESSION_EXPIRED"


def test_activity_extends_idle_timeout(client_as):
    client = client_as("operator")
    before = Session.objects.get().expire_date
    time.sleep(0.01)
    client.get(ME_URL)
    assert Session.objects.get().expire_date > before


def test_absolute_session_timeout(client_as):
    client = client_as("operator")
    key = client.cookies[settings.SESSION_COOKIE_NAME].value
    session = SessionStore(session_key=key)
    session[LOGIN_AT_SESSION_KEY] = time.time() - settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS - 1
    session.save()

    response = client.get(ME_URL)
    assert response.status_code == 401
    assert error_code(response) == "AUTH_SESSION_EXPIRED"
    assert not Session.objects.filter(session_key=key).exists()
    event = last_event("auth.session_expired")
    assert (event.actor_id, event.details["kind"]) == ("operator1", "absolute")
