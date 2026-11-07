"""
The Node table driving Member 2's signature engine: T1 case (f) and the engine half of T5.

These run the real engine (fogtrust_crypto.heartbeat.verify_heartbeat) with `lookup_node`, the
same adapter the heartbeat endpoint uses, against nodes enrolled through the real enrollment
service. They prove that:
  * a request signed with the wrong key is refused even with a genuine node id  (T1 f)
  * an unknown node id is refused                                               (T1 f)
  * a revoked node is refused on its very next request, before its signature is looked at (T5)
  * an engine decision can be stored and read back through the evidence view
"""

import json
import time
import uuid
from datetime import datetime, timezone

import pytest

from core.decisions import record_decision_dict
from fogtrust_crypto.heartbeat import verify_heartbeat
from fogtrust_crypto.keys import generate_private_key
from fogtrust_crypto.node_auth import sign_request
from fogtrust_crypto.replay import InMemoryReplayStore
from nodes.node_auth import lookup_node


HEARTBEAT_PATH = "/api/v1/node-api/heartbeat/"


def heartbeat_request(key, node_id, counter=1, load=0):
    body = json.dumps(
        {"counter": counter, "reported_load": load, "sent_at": datetime.now(timezone.utc).isoformat()}, separators=(",", ":")
    ).encode()
    return sign_request(key, str(node_id), "POST", HEARTBEAT_PATH, body), body


def verify(headers, body, store):
    return verify_heartbeat(headers, "POST", HEARTBEAT_PATH, body, lookup_node, store)


@pytest.mark.django_db
class TestLookupAdapter:
    def test_known_node(self, node_factory):
        node, _ = node_factory()
        info = lookup_node(str(node.id))
        assert info.public_key == node.public_key and info.status == "active"

    @pytest.mark.parametrize("bad", ["", "not-a-uuid", "1; DROP TABLE nodes_node", str(uuid.uuid4())])
    def test_unknown_or_malformed_ids_return_none(self, bad):
        assert lookup_node(bad) is None


@pytest.mark.django_db
class TestT1SpoofedNodeAgainstTheEngine:
    def test_an_honest_enrolled_node_is_accepted(self, node_factory):
        node, key = node_factory()
        result = verify(*heartbeat_request(key, node.id), InMemoryReplayStore())

        assert result.accepted and result.reason_code == "OK"

    def test_t1f_genuine_node_id_but_the_attackers_own_key(self, node_factory):
        node, _ = node_factory(name="gateway-03")
        attacker = generate_private_key()
        result = verify(*heartbeat_request(attacker, node.id), InMemoryReplayStore())

        assert not result.accepted and result.reason_code == "NODE_SIGNATURE_INVALID"
        rules = {r["rule"]: r["passed"] for r in result.rules_fired}
        assert rules["node_known"] is True and rules["signature_valid"] is False

    def test_an_unknown_node_id_is_refused(self, node_factory):
        _, key = node_factory()
        result = verify(*heartbeat_request(key, uuid.uuid4()), InMemoryReplayStore())

        assert not result.accepted and result.reason_code == "NODE_UNKNOWN"

    def test_a_node_cannot_borrow_another_nodes_identity(self, node_factory):
        victim, _ = node_factory(name="victim-node")
        _, other_key = node_factory(name="other-node")  # a genuinely enrolled node, wrong identity
        result = verify(*heartbeat_request(other_key, victim.id), InMemoryReplayStore())

        assert result.reason_code == "NODE_SIGNATURE_INVALID"


@pytest.mark.django_db
class TestT5RevokedNodeIsRefused:
    def revoke(self, client_as, node):
        response = client_as("admin").post(
            f"/api/v1/nodes/{node.id}/revoke/",
            {"reason": "3 integrity failures in 10 minutes", "confirm_name": node.name},
            format="json",
        )
        assert response.status_code == 200

    def test_the_next_heartbeat_after_revocation_is_refused(self, client_as, node_factory):
        node, key = node_factory(name="gateway-03")
        store = InMemoryReplayStore()
        assert verify(*heartbeat_request(key, node.id, counter=1), store).accepted

        self.revoke(client_as, node)

        after = verify(*heartbeat_request(key, node.id, counter=2), store)
        assert not after.accepted and after.reason_code == "NODE_REVOKED"
        assert store.last_counter(str(node.id)) == 1  # a refused request changes nothing

    def test_revocation_is_checked_before_the_signature(self, client_as, node_factory):
        """Even a request with a bad signature gets NODE_REVOKED: the status is checked first (contract step 3)."""
        node, _ = node_factory()
        self.revoke(client_as, node)
        result = verify(*heartbeat_request(generate_private_key(), node.id), InMemoryReplayStore())

        assert result.reason_code == "NODE_REVOKED"
        assert [r["rule"] for r in result.rules_fired][-1] == "node_active"

    def test_revocation_needs_no_restart_and_no_cache_flush(self, client_as, node_factory):
        node, key = node_factory()
        started = time.perf_counter()
        self.revoke(client_as, node)
        result = verify(*heartbeat_request(key, node.id), InMemoryReplayStore())

        assert result.reason_code == "NODE_REVOKED"
        assert time.perf_counter() - started < 2  # effective on the very next call

    def test_other_nodes_keep_working(self, client_as, node_factory):
        revoked, _ = node_factory(name="node-one")
        healthy, healthy_key = node_factory(name="node-two")
        self.revoke(client_as, revoked)

        assert verify(*heartbeat_request(healthy_key, healthy.id), InMemoryReplayStore()).accepted


@pytest.mark.django_db
class TestEngineDecisionsReachTheEvidenceView:
    def test_a_denial_is_stored_and_listed_without_secrets(self, client_as, node_factory):
        node, key = node_factory(name="gateway-03")
        result = verify(*heartbeat_request(generate_private_key(), node.id), InMemoryReplayStore())
        stored = record_decision_dict(result.to_decision("heartbeat"))

        assert stored.decision == "deny" and stored.reason_code == "NODE_SIGNATURE_INVALID"
        response = client_as("viewer").get("/api/v1/decisions/", {"subject_type": "heartbeat"})
        assert response.status_code == 200
        row = response.json()["results"][0]
        assert row["reason_code"] == "NODE_SIGNATURE_INVALID" and row["subject_id"] == str(node.id)
        assert row["engine_name"] == "node_request_verifier"
        assert any(rule["rule"] == "signature_valid" and rule["passed"] is False for rule in row["rules_fired"])
        text = json.dumps(row)
        assert node.public_key not in text
