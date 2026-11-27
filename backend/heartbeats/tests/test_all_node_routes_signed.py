"""
Security review of the whole API, automated (docs/security-review-api.md).

Every route under /api/v1/node-api/ is a machine-to-machine endpoint. None of them may answer a caller that has not
signed the request: not with no headers, not with only an X-Node-Id, not with garbage signature headers. The test walks
the real URL table, so a node-api route added later is checked automatically.
"""

import uuid

import pytest
from django.urls import URLPattern, URLResolver, get_resolver

PREFIX = "api/v1/node-api/"
METHODS = ("get", "post", "put", "patch", "delete")


def walk(patterns, prefix=""):
    for pattern in patterns:
        if isinstance(pattern, URLResolver):
            yield from walk(pattern.url_patterns, prefix + str(pattern.pattern))
        elif isinstance(pattern, URLPattern):
            yield prefix + str(pattern.pattern), pattern.callback


def node_api_routes():
    import re

    found = []
    for route, callback in walk(get_resolver().url_patterns):
        if not route.startswith(PREFIX):
            continue
        cls = getattr(callback, "cls", None) or getattr(callback, "view_class", None)
        methods = [m for m in METHODS if cls is not None and hasattr(cls, m)]
        url = "/" + re.sub(r"<[^>]+>", lambda _: str(uuid.uuid4()), route)
        found.append((route, url, methods))
    return found


def call(client, method, url, **headers):
    if method == "get":
        return client.get(url, **headers)
    return getattr(client, method)(url, data=b"{}", content_type="application/json", **headers)


def test_the_walk_really_finds_the_node_routes():
    routes = {route for route, _, _ in node_api_routes()}
    assert "api/v1/node-api/heartbeat/" in routes
    assert "api/v1/node-api/tasks/next/" in routes
    assert any(r.endswith("/result/") for r in routes)


@pytest.mark.django_db
@pytest.mark.parametrize("route,url,methods", node_api_routes())
def test_no_node_route_answers_an_unsigned_caller(api_client, node_factory, route, url, methods):
    node, _ = node_factory(name="victim")
    assert methods, f"{route} has no HTTP method handler"
    callers = {
        "no headers": {},
        "only a node id (the old, unsafe way)": {"HTTP_X_NODE_ID": str(node.id)},
        "garbage signature headers": {
            "HTTP_X_NODE_ID": str(node.id), "HTTP_X_NODE_TIMESTAMP": "1", "HTTP_X_NODE_NONCE": "0" * 32,
            "HTTP_X_NODE_SIGNATURE": "A" * 88,
        },
    }
    for method in methods:
        for who, headers in callers.items():
            response = call(api_client, method, url, **headers)
            assert response.status_code in (401, 403, 413, 429), f"{method.upper()} {route} answered {response.status_code} to: {who}"
            assert "Traceback" not in response.content.decode()


@pytest.mark.django_db
@pytest.mark.parametrize("route,url,methods", node_api_routes())
def test_a_signed_in_human_is_not_a_node(client_as, route, url, methods):
    """A browser session (even an admin's) must not be accepted by a machine endpoint."""
    admin = client_as("admin")
    for method in methods:
        response = call(admin, method, url)
        assert response.status_code in (401, 403, 413, 429), f"{method.upper()} {route} answered {response.status_code} to an admin session"