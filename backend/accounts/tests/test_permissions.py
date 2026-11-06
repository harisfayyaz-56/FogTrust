"""
Server-side role enforcement (threat ID-4, privilege escalation).

Every role is tried against every access level, directly against the API,
exactly as an attacker who ignores the dashboard would do.
"""

import pytest
from django.core.exceptions import ImproperlyConfigured
from rest_framework.test import APIClient

from accounts.models import Role
from accounts.permissions import CAPABILITIES, capabilities_for, require
from audit.models import AuditEvent

pytestmark = [pytest.mark.django_db, pytest.mark.urls("accounts.tests.support_urls")]

MATRIX = {
    #               viewer operator admin
    "/t/view/": (200, 200, 200),
    "/t/operate/": (403, 200, 200),
    "/t/admin/": (403, 403, 200),
}
ROLES = ("viewer", "operator", "admin")


@pytest.mark.parametrize("url", MATRIX)
@pytest.mark.parametrize("role_index", range(3))
def test_role_matrix(client_as, url, role_index):
    role = ROLES[role_index]
    client = client_as(role)
    expected = MATRIX[url][role_index]

    for method in (client.get, client.post):
        response = method(url, format="json") if method == client.post else method(url)
        assert response.status_code == expected, f"{role} {url}"
        if expected == 403:
            assert response.json()["error"] == {
                "code": "PERMISSION_DENIED",
                "message": "Access denied.",
                "request_id": response["X-Request-ID"],
            }


def test_denied_request_is_audited(client_as):
    client = client_as("viewer")
    response = client.post("/t/admin/", format="json")

    event = AuditEvent.objects.get(action="access.denied")
    assert (event.actor_id, event.actor_role, event.outcome) == ("viewer1", "viewer", "denied")
    assert event.reason_code == "PERMISSION_DENIED"
    assert event.request_id == response["X-Request-ID"]
    assert event.details == {"method": "POST", "path": "/t/admin/"}


@pytest.mark.parametrize("url", MATRIX)
def test_anonymous_gets_401_everywhere(url):
    response = APIClient().get(url)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_REQUIRED"


def test_disabled_user_is_denied_even_with_live_session(client_as):
    client = client_as("admin")
    client.user.is_active = False
    client.user.save()
    assert client.get("/t/view/").status_code in (401, 403)


def test_admin_has_every_capability():
    assert capabilities_for(Role.ADMIN) == sorted(CAPABILITIES)


def test_viewer_is_read_only():
    assert all(name.endswith(".view") for name in capabilities_for(Role.VIEWER))


def test_every_capability_uses_known_roles():
    known = set(Role.values)
    for roles in CAPABILITIES.values():
        assert roles and set(roles) <= known


def test_unknown_capability_fails_fast():
    with pytest.raises(ImproperlyConfigured):
        require("nodes.delete_everything")
