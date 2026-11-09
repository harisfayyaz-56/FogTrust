"""Listing and inspecting nodes (every signed-in role may read). Threats ID-4, ID-10, ID-11."""

import pytest

from nodes.models import Node

from .helpers import error_code

LIST = "/api/v1/nodes/"


@pytest.mark.django_db
class TestDetail:
    @pytest.mark.parametrize("role", ["admin", "operator", "viewer"])
    def test_every_role_can_read_a_node(self, client_as, node_factory, role):
        node, _ = node_factory(name="gateway-03", capacity=4)
        response = client_as(role).get(f"{LIST}{node.id}/")

        assert response.status_code == 200
        body = response.json()
        assert body["id"] == str(node.id) and body["name"] == "gateway-03" and body["status"] == "active"
        assert body["capacity"] == 4 and body["current_load"] == 0 and body["trust_score"] == 80
        assert body["revoked_at"] is None and body["revoke_reason"] is None and body["revoked_by"] is None
        assert body["key_fingerprint"] == node.key_fingerprint

    def test_the_public_key_is_never_returned(self, client_as, node_factory):
        node, _ = node_factory()
        text = client_as("viewer").get(f"{LIST}{node.id}/").content.decode() + client_as("admin", username="a2").get(LIST).content.decode()

        assert node.public_key not in text
        assert "public_key" not in text and "last_counter" not in text and "token" not in text

    def test_unknown_and_malformed_ids_are_404(self, client_as):
        client = client_as("viewer")
        for bad in ("3f2b8c1e-0000-4000-8000-000000000000", "not-a-uuid", "%27%20OR%201=1"):
            response = client.get(f"{LIST}{bad}/")
            assert response.status_code == 404 and error_code(response) == "NOT_FOUND"

    def test_anonymous_gets_401(self, api_client, node_factory):
        node, _ = node_factory()
        assert api_client.get(f"{LIST}{node.id}/").status_code == 401


@pytest.mark.django_db
class TestList:
    @pytest.fixture
    def fleet(self, node_factory):
        nodes = {name: node_factory(name=name)[0] for name in ("alpha-node", "beta-node", "gamma-node")}
        Node.objects.filter(pk=nodes["alpha-node"].pk).update(trust_score=90)
        Node.objects.filter(pk=nodes["beta-node"].pk).update(trust_score=40)
        Node.objects.filter(pk=nodes["gamma-node"].pk).update(
            status="revoked", revoked_at="2026-11-19T10:00:00Z", revoke_reason="test revoke reason", trust_score=10
        )
        return nodes

    def names(self, response):
        assert response.status_code == 200, response.content
        return [row["name"] for row in response.json()["results"]]

    def test_paginated_shape_and_default_order(self, client_as, fleet):
        body = client_as("viewer").get(LIST).json()

        assert set(body) == {"count", "next", "previous", "results"} and body["count"] == 3
        assert [row["name"] for row in body["results"]] == ["alpha-node", "beta-node", "gamma-node"]

    def test_filter_by_status(self, client_as, fleet):
        client = client_as("operator")
        assert self.names(client.get(LIST, {"status": "active"})) == ["alpha-node", "beta-node"]
        assert self.names(client.get(LIST, {"status": "revoked"})) == ["gamma-node"]

    def test_filter_by_minimum_trust(self, client_as, fleet):
        client = client_as("viewer")
        assert self.names(client.get(LIST, {"min_trust": 50})) == ["alpha-node"]
        assert self.names(client.get(LIST, {"min_trust": 0})) == ["alpha-node", "beta-node", "gamma-node"]

    def test_search_by_name_is_case_insensitive(self, client_as, fleet):
        client = client_as("viewer")
        assert self.names(client.get(LIST, {"search": "BETA"})) == ["beta-node"]
        assert self.names(client.get(LIST, {"search": "nothing"})) == []

    def test_filters_combine(self, client_as, fleet):
        assert self.names(client_as("viewer").get(LIST, {"status": "active", "min_trust": 50, "search": "node"})) == ["alpha-node"]

    def test_pagination_limits(self, client_as, fleet):
        client = client_as("viewer")
        body = client.get(LIST, {"page_size": 2}).json()
        assert len(body["results"]) == 2 and body["next"]
        assert error_code(client.get(LIST, {"page_size": 101})) == "VALIDATION_ERROR"
        assert error_code(client.get(LIST, {"page_size": 0})) == "VALIDATION_ERROR"

    @pytest.mark.parametrize(
        "params",
        [{"status": "bogus"}, {"min_trust": 101}, {"min_trust": -1}, {"min_trust": "high"}, {"search": "x" * 65}, {"unknown": "1"}, {"search": "a\nb"}],
    )
    def test_invalid_filters_are_rejected(self, client_as, fleet, params):
        response = client_as("viewer").get(LIST, params)
        assert response.status_code == 400 and error_code(response) == "VALIDATION_ERROR"

    def test_search_cannot_be_used_for_sql_injection(self, client_as, fleet):
        client = client_as("viewer")
        for text in ("' OR '1'='1", "%", "_", "x'); DROP TABLE nodes_node;--", "\\"):
            response = client.get(LIST, {"search": text})
            assert response.status_code == 200 and response.json()["count"] <= 3
        assert Node.objects.count() == 3

    def test_anonymous_gets_401(self, api_client, fleet):
        assert api_client.get(LIST).status_code == 401
