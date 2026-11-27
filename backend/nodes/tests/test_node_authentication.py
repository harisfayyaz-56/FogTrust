"""
Signed-request authentication of nodes, exercised through a real endpoint
(GET /api/v1/node-api/tasks/next/).  T1 spoofed node, T2 replay, T5 revoked, T-final.

Regression: until Week 4 this endpoint trusted a bare `X-Node-Id` header, so anyone who knew a
node's UUID could read that node's tasks. `test_the_old_unsigned_header_no_longer_works` pins it.
"""

import time
import uuid

import pytest
from django.core.cache import cache

from audit.models import AuditEvent
from core.models import Decision
from fogtrust_crypto.keys import generate_private_key
from fogtrust_crypto.node_auth import sign_request
from nodes.authentication import NodeRequestThrottle, policy_window_s, verify_signed_request
from nodes.models import Node, NodeNonce
from nodes.replay_store import DatabaseReplayStore
from tasks.models import Task
from trust.models import PolicyConfig

from .helpers import error_code

URL = "/api/v1/node-api/tasks/next/"


def as_django(headers):
    return {"HTTP_" + name.upper().replace("-", "_"): value for name, value in headers.items()}


def signed_get(client, key, node_id, path=URL, **options):
    return client.get(path, **as_django(sign_request(key, str(node_id), "GET", path, b"", **options)))


def failures():
    return list(AuditEvent.objects.filter(action="node.auth", outcome="failure").order_by("sequence"))


@pytest.mark.django_db
class TestHonestNode:
    def test_a_correctly_signed_request_is_accepted(self, api_client, node_factory):
        node, key = node_factory()
        response = signed_get(api_client, key, node.id)

        assert response.status_code == 200 and response.json() == {"task": None}
        assert not failures()

    def test_routine_requests_do_not_write_decisions_or_audit_rows(self, api_client, node_factory):
        node, key = node_factory()
        before = (Decision.objects.count(), AuditEvent.objects.count())
        for _ in range(5):
            signed_get(api_client, key, node.id)
        assert (Decision.objects.count(), AuditEvent.objects.count()) == before

    def test_a_node_sees_only_its_own_task(self, api_client, node_factory, django_user_model):
        first, first_key = node_factory(name="node-one")
        second, second_key = node_factory(name="node-two")
        operator = django_user_model.objects.create_user("op9", password="Str0ng-Passw0rd!", role="operator")
        task = Task.objects.create(
            task_type="checksum", payload={"file": "a.bin"}, priority=1, status=Task.Status.ASSIGNED,
            assigned_node=first, idempotency_key="k-1", created_by=operator,
        )

        assert signed_get(api_client, first_key, first.id).json()["task"]["id"] == str(task.id)
        assert signed_get(api_client, second_key, second.id).json() == {"task": None}

    def test_an_authenticated_poll_does_not_count_as_a_heartbeat(self, api_client, node_factory):
        node, key = node_factory()
        signed_get(api_client, key, node.id)
        node.refresh_from_db()
        assert node.last_seen_at is None and node.last_counter == 0


@pytest.mark.django_db
class TestT1SpoofedNodeCannotPoll:
    def test_the_old_unsigned_header_no_longer_works(self, api_client, node_factory):
        """The Week 3 defect: knowing a node's id was enough. Now it earns a 401."""
        node, _ = node_factory()
        response = api_client.get(URL, HTTP_X_NODE_ID=str(node.id))

        assert response.status_code == 401 and error_code(response) == "NODE_SIGNATURE_MISSING"

    def test_no_headers_at_all(self, api_client):
        response = api_client.get(URL)
        assert response.status_code == 401 and error_code(response) == "NODE_SIGNATURE_MISSING"

    def test_a_real_task_is_never_returned_to_an_unauthenticated_caller(self, api_client, node_factory, django_user_model):
        node, _ = node_factory()
        operator = django_user_model.objects.create_user("op9", password="Str0ng-Passw0rd!", role="operator")
        Task.objects.create(task_type="checksum", payload={"secret": "payload"}, priority=1, status=Task.Status.ASSIGNED,
                            assigned_node=node, idempotency_key="k-1", created_by=operator)

        response = api_client.get(URL, HTTP_X_NODE_ID=str(node.id))
        assert response.status_code == 401 and "payload" not in response.content.decode()

    def test_unknown_node(self, api_client):
        response = signed_get(api_client, generate_private_key(), uuid.uuid4())
        assert response.status_code == 401 and error_code(response) == "NODE_UNKNOWN"

    @pytest.mark.parametrize("bad_id", ["not-a-uuid", "1' OR '1'='1", "../../etc/passwd", "x" * 500])
    def test_a_malformed_node_id_is_refused_not_a_server_error(self, api_client, bad_id):
        response = api_client.get(URL, HTTP_X_NODE_ID=bad_id, HTTP_X_NODE_TIMESTAMP=str(int(time.time())),
                                  HTTP_X_NODE_NONCE="a" * 32, HTTP_X_NODE_SIGNATURE="A" * 88)
        assert response.status_code == 401 and error_code(response) == "NODE_UNKNOWN"

    def test_genuine_node_id_with_the_attackers_key(self, api_client, node_factory):
        node, _ = node_factory()
        response = signed_get(api_client, generate_private_key(), node.id)

        assert response.status_code == 401 and error_code(response) == "NODE_SIGNATURE_INVALID"
        event = failures()[-1]
        assert event.reason_code == "NODE_SIGNATURE_INVALID"
        assert event.actor_type == "anonymous"  # the node id is only a claim until the signature checks out
        assert event.details["claimed_node_id"] == str(node.id)

    def test_tampering_with_the_query_string_breaks_the_signature(self, api_client, node_factory):
        node, key = node_factory()
        headers = sign_request(key, str(node.id), "GET", URL, b"")
        response = api_client.get(URL + "?node=other", **as_django(headers))
        assert response.status_code == 401 and error_code(response) == "NODE_SIGNATURE_INVALID"

    def test_a_signature_for_another_method_or_path_is_useless(self, api_client, node_factory):
        node, key = node_factory()
        headers = sign_request(key, str(node.id), "POST", URL, b"")
        assert api_client.get(URL, **as_django(headers)).status_code == 401

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda h: {**h, "X-Node-Nonce": "XYZ"},
            lambda h: {**h, "X-Node-Timestamp": "yesterday"},
            lambda h: {**h, "X-Node-Signature": "not base64!!"},
            lambda h: {**h, "X-Node-Signature": "AAAA"},
        ],
    )
    def test_malformed_headers_are_refused(self, api_client, node_factory, mutate):
        node, key = node_factory()
        headers = mutate(sign_request(key, str(node.id), "GET", URL, b""))
        response = api_client.get(URL, **as_django(headers))
        assert response.status_code == 401 and error_code(response) == "NODE_SIGNATURE_INVALID"

    def test_every_refusal_is_audited_and_explained(self, api_client, node_factory):
        node, _ = node_factory()
        signed_get(api_client, generate_private_key(), node.id)

        decision = Decision.objects.get(subject_type="node", decision="deny")
        assert decision.reason_code == "NODE_SIGNATURE_INVALID" and decision.subject_id == str(node.id)
        rules = {r["rule"]: r["passed"] for r in decision.rules_fired}
        assert rules["node_known"] is True and rules["signature_valid"] is False

    def test_the_client_cannot_tell_an_unknown_node_from_a_bad_signature(self, api_client, node_factory):
        node, _ = node_factory()
        unknown = signed_get(api_client, generate_private_key(), uuid.uuid4())
        invalid = signed_get(api_client, generate_private_key(), node.id)

        assert unknown.status_code == invalid.status_code == 401
        assert unknown.json()["error"]["message"] == invalid.json()["error"]["message"] == "Node authentication failed."


@pytest.mark.django_db
class TestT2Replay:
    def test_the_same_request_twice(self, api_client, node_factory):
        node, key = node_factory()
        headers = as_django(sign_request(key, str(node.id), "GET", URL, b""))

        assert api_client.get(URL, **headers).status_code == 200
        second = api_client.get(URL, **headers)

        assert second.status_code == 401 and error_code(second) == "HEARTBEAT_REPLAYED"
        assert failures()[-1].reason_code == "HEARTBEAT_REPLAYED"

    def test_a_stale_request_is_refused(self, api_client, node_factory):
        node, key = node_factory()
        response = signed_get(api_client, key, node.id, timestamp=int(time.time()) - 300)
        assert response.status_code == 401 and error_code(response) == "HEARTBEAT_STALE"

    def test_a_request_from_the_future_is_refused(self, api_client, node_factory):
        node, key = node_factory()
        response = signed_get(api_client, key, node.id, timestamp=int(time.time()) + 300)
        assert response.status_code == 401 and error_code(response) == "HEARTBEAT_STALE"

    def test_a_replay_is_still_refused_after_the_server_restarts(self, api_client, node_factory):
        """Nonces live in the database, not in memory. Dropping every in-process cache must not reopen the window."""
        node, key = node_factory()
        headers = as_django(sign_request(key, str(node.id), "GET", URL, b""))
        assert api_client.get(URL, **headers).status_code == 200

        cache.clear()  # what a restart does to anything kept in the process
        assert api_client.get(URL, **headers).status_code == 401
        assert NodeNonce.objects.filter(node=node).count() == 1

    def test_a_refused_request_leaves_the_replay_state_alone(self, api_client, node_factory):
        node, key = node_factory()
        signed_get(api_client, generate_private_key(), node.id)  # bad signature
        assert NodeNonce.objects.count() == 0  # only authenticated requests may touch the store

    def test_the_policy_window_is_honoured_and_bounded(self, node_factory):
        node, key = node_factory()
        PolicyConfig.objects.create(version=2, values={"timestamp_window_s": 10, "weights": {}}, change_reason="tight window")
        old = sign_request(key, str(node.id), "GET", URL, b"", timestamp=int(time.time()) - 20)
        assert verify_signed_request(old, "GET", URL, b"").reason_code == "HEARTBEAT_STALE"

        PolicyConfig.objects.create(version=3, values={"timestamp_window_s": 100000, "weights": {}}, change_reason="absurd")
        assert policy_window_s() == 30  # an out-of-range value falls back instead of disabling the check
        PolicyConfig.objects.create(version=4, values={"timestamp_window_s": True, "weights": {}}, change_reason="wrong type")
        assert policy_window_s() == 30


@pytest.mark.django_db
class TestT5RevokedNode:
    def test_a_revoked_node_is_refused_on_its_very_next_poll(self, api_client, client_as, node_factory):
        node, key = node_factory(name="gateway-03")
        assert signed_get(api_client, key, node.id).status_code == 200

        client_as("admin").post(
            f"/api/v1/nodes/{node.id}/revoke/",
            {"reason": "3 integrity failures in 10 minutes", "confirm_name": "gateway-03"}, format="json",
        )

        response = signed_get(api_client, key, node.id)
        assert response.status_code == 403 and error_code(response) == "NODE_REVOKED"
        assert failures()[-1].reason_code == "NODE_REVOKED"

    def test_a_revoked_node_never_receives_a_task(self, api_client, node_factory, django_user_model):
        node, key = node_factory()
        operator = django_user_model.objects.create_user("op9", password="Str0ng-Passw0rd!", role="operator")
        Task.objects.create(task_type="checksum", payload={"x": 1}, priority=1, status=Task.Status.ASSIGNED,
                            assigned_node=node, idempotency_key="k-1", created_by=operator)
        Node.objects.filter(pk=node.pk).update(status="revoked", revoked_at="2026-11-19T10:00:00Z", revoke_reason="test revoke reason")

        response = signed_get(api_client, key, node.id)
        assert response.status_code == 403 and "task" not in response.json()


@pytest.mark.django_db
class TestFailureFloodsAndLimits:
    def test_a_flood_of_bad_requests_cannot_flood_the_audit_log(self, api_client, node_factory):
        node, _ = node_factory()
        attacker = generate_private_key()
        statuses = {signed_get(api_client, attacker, node.id).status_code for _ in range(60)}

        assert statuses == {401}  # still refused every time, never blocked or crashed
        assert len(failures()) <= 30
        assert AuditEvent.objects.filter(action="request.rate_limited").count() == 1  # one summary a minute

    def test_a_flood_cannot_lock_an_honest_node_out(self, api_client, node_factory):
        honest, honest_key = node_factory(name="honest-node")
        victim, _ = node_factory(name="victim-node")
        for _ in range(60):
            signed_get(api_client, generate_private_key(), victim.id)  # same client address as the honest node

        assert signed_get(api_client, honest_key, honest.id).status_code == 200

    def test_a_failed_signature_does_not_lower_the_nodes_trust_score(self, api_client, node_factory):
        """The node id is public; if bad signatures cost trust, anyone could get an honest node revoked."""
        node, _ = node_factory()
        before = Node.objects.get(pk=node.pk).trust_score
        for _ in range(10):
            signed_get(api_client, generate_private_key(), node.id)

        refreshed = Node.objects.get(pk=node.pk)
        assert refreshed.trust_score == before and refreshed.status == "active"

    def test_an_oversized_body_is_refused_before_it_is_verified(self, api_client, node_factory):
        node, key = node_factory()
        headers = as_django(sign_request(key, str(node.id), "GET", URL, b"x" * 70_000))
        response = api_client.generic("GET", URL, b"x" * 70_000, **headers)

        assert response.status_code == 413 and error_code(response) == "PAYLOAD_TOO_LARGE"

    def test_each_node_has_its_own_request_budget(self, api_client, node_factory, monkeypatch):
        busy, busy_key = node_factory(name="busy-node")
        quiet, quiet_key = node_factory(name="quiet-node")
        monkeypatch.setitem(NodeRequestThrottle.THROTTLE_RATES, "node_request", "3/min")

        assert [signed_get(api_client, busy_key, busy.id).status_code for _ in range(5)] == [200, 200, 200, 429, 429]
        assert signed_get(api_client, quiet_key, quiet.id).status_code == 200


@pytest.mark.django_db
class TestDatabaseReplayStore:
    def test_a_nonce_is_accepted_once(self, node_factory):
        node, _ = node_factory()
        store = DatabaseReplayStore()
        future = int(time.time()) + 60

        assert store.add_nonce(str(node.id), "a" * 32, future) is True
        assert store.add_nonce(str(node.id), "a" * 32, future) is False

    def test_the_same_nonce_is_fine_for_a_different_node(self, node_factory):
        first, _ = node_factory(name="node-one")
        second, _ = node_factory(name="node-two")
        store = DatabaseReplayStore()
        future = int(time.time()) + 60

        assert store.add_nonce(str(first.id), "b" * 32, future) and store.add_nonce(str(second.id), "b" * 32, future)

    def test_a_second_instance_sees_what_the_first_stored(self, node_factory):
        node, _ = node_factory()
        DatabaseReplayStore().add_nonce(str(node.id), "c" * 32, int(time.time()) + 60)
        assert DatabaseReplayStore().add_nonce(str(node.id), "c" * 32, int(time.time()) + 60) is False

    def test_the_counter_only_moves_forward(self, node_factory):
        node, _ = node_factory()
        store = DatabaseReplayStore()

        assert store.advance_counter(str(node.id), 5) is True
        assert store.advance_counter(str(node.id), 5) is False
        assert store.advance_counter(str(node.id), 4) is False
        assert store.advance_counter(str(node.id), 6) is True
        assert store.last_counter(str(node.id)) == 6

    def test_last_counter_defaults_to_zero(self, node_factory):
        node, _ = node_factory()
        assert DatabaseReplayStore().last_counter(str(node.id)) == 0
        assert DatabaseReplayStore().last_counter(str(uuid.uuid4())) == 0

    def test_purge_removes_only_expired_nonces(self, node_factory):
        node, _ = node_factory()
        store = DatabaseReplayStore()
        now = int(time.time())
        store.add_nonce(str(node.id), "d" * 32, now - 5)
        store.add_nonce(str(node.id), "e" * 32, now + 60)

        assert store.purge(now) == 1
        assert list(NodeNonce.objects.values_list("nonce", flat=True)) == ["e" * 32]
