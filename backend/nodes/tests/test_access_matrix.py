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

OPERATORS = {"admin", "operator"}

# (method, path template, roles allowed)   {node}, {token}, {task} and {user} are filled in per test
ENDPOINTS = [
    ("get", "/api/v1/nodes/", ALL),
    ("get", "/api/v1/nodes/{node}/", ALL),
    ("post", "/api/v1/nodes/{node}/revoke/", ADMIN),
    ("get", "/api/v1/nodes/{node}/heartbeats/", ALL),
    ("get", "/api/v1/decisions/", ALL),
    ("get", "/api/v1/enrollment-tokens/", ADMIN),
    ("post", "/api/v1/enrollment-tokens/", ADMIN),
    ("post", "/api/v1/enrollment-tokens/{token}/cancel/", ADMIN),
    ("get", "/api/v1/users/", ADMIN),
    ("post", "/api/v1/users/", ADMIN),
    ("patch", "/api/v1/users/{user}/", ADMIN),
    ("get", "/api/v1/audit/", ADMIN),
    ("post", "/api/v1/audit/verify/", ADMIN),
    # Member 3's endpoints
    ("get", "/api/v1/nodes/{node}/trust/", ALL),
    ("get", "/api/v1/policy/", ALL),
    ("post", "/api/v1/policy/", ADMIN),
    ("post", "/api/v1/tasks/", OPERATORS),
    ("get", "/api/v1/tasks/list/", ALL),
    ("get", "/api/v1/tasks/{task}/", ALL),
    ("post", "/api/v1/tasks/{task}/cancel/", OPERATORS),
    ("get", "/api/v1/tasks/{task}/result/", OPERATORS),
]
IDS = [f"{method.upper()} {path}" for method, path, _ in ENDPOINTS]


@pytest.fixture
def world(node_factory, token_factory, django_user_model):
    from tasks.models import Task

    node, _ = node_factory(name="gateway-03")
    token, _ = token_factory()
    owner = django_user_model.objects.create_user("task-owner", password="Str0ng-Passw0rd!", role="operator")
    task = Task.objects.create(task_type="checksum", payload={"file": "a.bin"}, priority=1, idempotency_key="matrix-1", created_by=owner)
    return {"node": str(node.id), "token": str(token.id), "task": str(task.id), "user": str(owner.pk)}


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
def test_every_route_in_the_api_is_covered_by_this_matrix():
    """Fails when someone adds an endpoint without adding it to the matrix above (exact route templates)."""
    from django.urls import get_resolver

    listed = {path for _, path, _ in ENDPOINTS}
    public = {"/api/v1/health/", "/api/v1/auth/csrf/", "/api/v1/auth/login/", "/api/v1/nodes/enroll/"}
    auth_routes = {"/api/v1/auth/logout/", "/api/v1/auth/me/"}  # tested in accounts/tests
    node_routes = {"/api/v1/node-api/tasks/next/", "/api/v1/node-api/heartbeat/", "/api/v1/node-api/tasks/{task}/result/"}  # signed requests: test_node_authentication.py, heartbeats/tests, results/tests

    def walk(patterns, prefix=""):
        for pattern in patterns:
            route = prefix + str(pattern.pattern)
            if hasattr(pattern, "url_patterns"):
                yield from walk(pattern.url_patterns, route)
            else:
                yield route

    placeholders = {"<str:node_id>": "{node}", "<uuid:node_id>": "{node}", "<str:token_id>": "{token}",
                    "<uuid:id>": "{task}", "<str:task_id>": "{task}", "<str:user_id>": "{user}"}
    routes = set()
    for route in walk(get_resolver().url_patterns):
        if route.startswith("api/v1/"):
            for old, new in placeholders.items():
                route = route.replace(old, new)
            routes.add("/" + route)

    unlisted = routes - listed - public - auth_routes - node_routes
    assert not unlisted, f"endpoints missing from the access matrix: {sorted(unlisted)}"
    stale = (listed | node_routes) - routes
    assert not stale, f"the matrix lists routes that no longer exist: {sorted(stale)}"


@pytest.mark.django_db
class TestHumansCannotUseTheNodeEndpoint:
    """A signed-in administrator is not a node: only a valid node signature opens /node-api/."""

    @pytest.mark.parametrize("role", ["admin", "operator", "viewer"])
    def test_a_staff_session_is_not_a_node_credential(self, client_as, node_factory, role):
        node, _ = node_factory()
        client = client_as(role)
        response = client.get("/api/v1/node-api/tasks/next/", HTTP_X_NODE_ID=str(node.id))

        assert response.status_code == 401 and response.json()["error"]["code"] == "NODE_SIGNATURE_MISSING"

    def test_a_node_signature_is_not_a_staff_credential(self, api_client, node_factory):
        from fogtrust_crypto.node_auth import sign_request

        node, key = node_factory()
        path = "/api/v1/nodes/"
        headers = {"HTTP_" + n.upper().replace("-", "_"): v for n, v in sign_request(key, str(node.id), "GET", path, b"").items()}
        assert api_client.get(path, **headers).status_code == 401