"""
T-final: unauthorized requests, across every endpoint added in Week 3 (threat ID-4).

Each endpoint is called as anonymous, viewer, operator and admin. The expectation comes from the
capability table in accounts/permissions.py (docs/api-contract.md, section 3), written out here
independently so a mistake in one place cannot hide in the other:
  anonymous -> 401, signed-in but not allowed -> 403 PERMISSION_DENIED (generic), allowed -> anything else.
A denied call changes nothing and is recorded as access.denied.
"""

import pytest

from audit.models import AuditEvent
from nodes.models import EnrollmentToken, Node

ALL = {"admin", "operator", "viewer"}
ADMIN = {"admin"}

# (method, path template, roles allowed)   {node} and {token} are filled in per test
ENDPOINTS = [
    ("get", "/api/v1/nodes/", ALL),
    ("get", "/api/v1/nodes/{node}/", ALL),
    ("post", "/api/v1/nodes/{node}/revoke/", ADMIN),
    ("get", "/api/v1/decisions/", ALL),
    ("get", "/api/v1/enrollment-tokens/", ADMIN),
    ("post", "/api/v1/enrollment-tokens/", ADMIN),
    ("post", "/api/v1/enrollment-tokens/{token}/cancel/", ADMIN),
    ("get", "/api/v1/users/", ADMIN),
    ("post", "/api/v1/users/", ADMIN),
    ("patch", "/api/v1/users/1/", ADMIN),
    ("get", "/api/v1/audit/", ADMIN),
    ("post", "/api/v1/audit/verify/", ADMIN),
]
IDS = [f"{method.upper()} {path}" for method, path, _ in ENDPOINTS]


@pytest.fixture
def world(node_factory, token_factory):
    node, _ = node_factory(name="gateway-03")
    token, _ = token_factory()
    return {"node": str(node.id), "token": str(token.id)}


def call(client, method, path, world):
    return getattr(client, method)(path.format(**world), {}, format="json")


@pytest.mark.django_db
@pytest.mark.parametrize("method,path,allowed", ENDPOINTS, ids=IDS)
class TestAccessMatrix:
    def test_anonymous_is_refused_with_401(self, api_client, world, method, path, allowed):
        response = call(api_client, method, path, world)

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "AUTH_REQUIRED"

    @pytest.mark.parametrize("role", ["viewer", "operator", "admin"])
    def test_each_role(self, client_as, world, method, path, allowed, role):
        before = (Node.objects.filter(status="revoked").count(), EnrollmentToken.objects.count())
        response = call(client_as(role), method, path, world)

        if role in allowed:
            assert response.status_code not in (401, 403), (role, response.status_code)
        else:
            assert response.status_code == 403
            body = response.json()["error"]
            assert body["code"] == "PERMISSION_DENIED" and body["message"] == "Access denied."
            assert "gateway-03" not in response.content.decode()
            assert AuditEvent.objects.filter(action="access.denied", actor_role=role).exists()
            assert (Node.objects.filter(status="revoked").count(), EnrollmentToken.objects.count()) == before


@pytest.mark.django_db
def test_every_route_in_the_api_is_covered_by_this_matrix(world):
    """Fails when someone adds an endpoint without adding it to the matrix above."""
    from django.urls import get_resolver

    covered = {path.split("{")[0] for _, path, _ in ENDPOINTS}
    public = {"/api/v1/health/", "/api/v1/auth/csrf/", "/api/v1/auth/login/", "/api/v1/nodes/enroll/"}
    auth_routes = {"/api/v1/auth/logout/", "/api/v1/auth/me/"}  # tested in accounts/tests

    def walk(patterns, prefix=""):
        for pattern in patterns:
            route = prefix + str(pattern.pattern)
            if hasattr(pattern, "url_patterns"):
                yield from walk(pattern.url_patterns, route)
            else:
                yield route

    routes = {"/" + r.replace("<str:node_id>", "{node}").replace("<str:token_id>", "{token}").replace("<str:user_id>", "1")
              for r in walk(get_resolver().url_patterns)
              if r.startswith("api/v1/")}
    unlisted = {r for r in routes if r.split("{")[0] not in covered and r not in public | auth_routes}
    assert not unlisted, f"endpoints missing from the access matrix: {sorted(unlisted)}"
