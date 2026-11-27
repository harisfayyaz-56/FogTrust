"""
Crypto evidence meets the trust score (FR-4).

Rule under test: only failures that an attacker CANNOT cause may lower a node's trust. A damaged result needs the
node's own signature, so it counts. Spoofed, replayed, stale or reordered requests can all be sent by a stranger
who only knows the node's id, so they must leave the victim's score alone (threat model CR-20). With the default
weights (-20 per signature failure, auto-revoke below 10) counting them would let anyone ban any node with 4 requests.
"""

import json
import time

import pytest

from core.models import Decision
from fogtrust_crypto.keys import generate_private_key
from fogtrust_crypto.node_auth import sign_request
from nodes.models import Node
from results.models import TaskResult
from trust.models import TrustScoreRecord

from .test_result_api import PLAINTEXT, enrolled, flip, make_task, post, server_key, submission  # noqa: F401

HEARTBEAT = "/api/v1/node-api/heartbeat/"


def meta(headers):
    return {"HTTP_" + k.upper().replace("-", "_"): v for k, v in headers.items()}


def heartbeat(client, key, node_id, counter=1, *, ts=None):
    body = json.dumps({"counter": counter, "reported_load": 0, "sent_at": "2026-11-19T10:20:31Z"}, separators=(",", ":")).encode()
    headers = sign_request(key, str(node_id), "POST", HEARTBEAT, body, timestamp=ts)
    return client.post(HEARTBEAT, data=body, content_type="application/json", **meta(headers)), headers, body


@pytest.mark.django_db
class TestVerifiedWorkEarnsTrust:
    def test_completing_a_task_frees_the_load_slot_and_raises_trust(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        task = make_task(node)
        Node.objects.filter(pk=node.pk).update(current_load=1)  # what assign_next_task does
        assert post(api_client, *submission(key, node.id, task.id, server_key[1])).status_code == 201
        node.refresh_from_db()
        assert node.current_load == 0 and node.trust_score == 85
        record = TrustScoreRecord.objects.get(node=node)
        assert (record.previous_score, record.score) == (80, 85)

    def test_load_never_goes_below_zero(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        task = make_task(node)
        assert node.current_load == 0
        post(api_client, *submission(key, node.id, task.id, server_key[1]))
        node.refresh_from_db()
        assert node.current_load == 0

    def test_a_node_that_keeps_finishing_tasks_is_never_full(self, api_client, enrolled, server_key, make_task):
        """The bug this guards against: load only went up, so after `capacity` tasks the node counted as full for ever."""
        node, key = enrolled
        for _ in range(node.capacity + 2):
            task = make_task(node)
            Node.objects.filter(pk=node.pk).update(current_load=1)
            assert post(api_client, *submission(key, node.id, task.id, server_key[1])).status_code == 201
        node.refresh_from_db()
        assert node.current_load == 0 and node.current_load < node.capacity


@pytest.mark.django_db
class TestIntegrityFailureCostsTrust:
    def tamper(self, client, node, key, task, server_pub):
        return post(client, *submission(key, node.id, task.id, server_pub, mutate=lambda e: {**e, "ciphertext": flip(e["ciphertext"])}))

    def test_one_altered_result_drops_the_score_below_the_threshold(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        assert self.tamper(api_client, node, key, make_task(node), server_key[1]).status_code == 422
        node.refresh_from_db()
        assert node.trust_score == 55 and node.trust_score < 60  # no longer eligible for tasks
        record = TrustScoreRecord.objects.get(node=node)
        assert [r["rule"] for r in record.rules_fired] == ["integrity_failures"]

    def test_repeated_tampering_ends_in_automatic_revocation(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        for expected in (55, 30):
            self.tamper(api_client, node, key, make_task(node), server_key[1])
            node.refresh_from_db()
            assert node.trust_score == expected and node.status == "active"
        self.tamper(api_client, node, key, make_task(node), server_key[1])
        node.refresh_from_db()
        assert node.status == "revoked" and node.trust_score == 5
        assert Decision.objects.filter(subject_type="node", subject_id=str(node.id)).exists()
        after = post(api_client, *submission(key, node.id, make_task(node).id, server_key[1]))
        assert after.status_code == 403 and after.json()["error"]["code"] == "NODE_REVOKED"

    def test_a_good_result_after_a_bad_one_still_counts(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        task = make_task(node)
        self.tamper(api_client, node, key, task, server_key[1])
        assert post(api_client, *submission(key, node.id, task.id, server_key[1])).status_code == 201
        node.refresh_from_db()
        assert node.trust_score == 60  # 80 - 25 + 5


@pytest.mark.django_db
class TestAnAttackerCannotPoisonAVictimsTrust:
    """CR-20. Everything below is something a stranger can do knowing only the victim's node id."""

    def assert_untouched(self, node):
        node.refresh_from_db()
        assert node.trust_score == 80 and node.status == "active"
        assert not TrustScoreRecord.objects.filter(node=node).exists()

    def test_forged_signatures_on_heartbeats_and_results(self, api_client, enrolled, server_key, make_task):
        node, _ = enrolled
        task = make_task(node)
        attacker = generate_private_key()
        for counter in range(1, 31):
            assert heartbeat(api_client, attacker, node.id, counter)[0].status_code == 401
        for _ in range(10):
            assert post(api_client, *submission(attacker, node.id, task.id, server_key[1])).status_code == 401
        self.assert_untouched(node)

    def test_replays_of_the_victims_own_messages(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        first, headers, body = heartbeat(api_client, key, node.id, 1)
        assert first.status_code == 200
        for _ in range(20):
            again = api_client.post(HEARTBEAT, data=body, content_type="application/json", **meta(headers))
            assert again.json()["error"]["code"] == "HEARTBEAT_REPLAYED"
        task = make_task(node)
        path, result_headers, result_body = submission(key, node.id, task.id, server_key[1])
        assert post(api_client, path, result_headers, result_body).status_code == 201
        node.refresh_from_db()
        score_after_success = node.trust_score
        for _ in range(20):
            assert post(api_client, path, result_headers, result_body).status_code == 401  # replayed result
        node.refresh_from_db()
        assert node.trust_score == score_after_success and node.status == "active"

    def test_stale_and_reordered_messages_delivered_late(self, api_client, enrolled):
        node, key = enrolled
        assert heartbeat(api_client, key, node.id, 5)[0].status_code == 200
        for counter in range(1, 6):  # old captures delivered after the node moved on: the counter goes backwards
            assert heartbeat(api_client, key, node.id, counter)[0].status_code == 401
        for _ in range(10):  # captures from an hour ago
            assert heartbeat(api_client, key, node.id, 100, ts=int(time.time()) - 3600)[0].status_code == 401
        node.refresh_from_db()
        assert node.trust_score == 80 and node.status == "active"
        assert not TrustScoreRecord.objects.filter(node=node).exists()

    def test_a_result_for_a_task_that_is_not_the_nodes(self, api_client, node_factory, server_key, make_task):
        owner, owner_key = node_factory(name="owner")
        other, other_key = node_factory(name="other")
        task = make_task(owner)
        assert post(api_client, *submission(other_key, other.id, task.id, server_key[1])).status_code == 403
        other.refresh_from_db()
        assert other.trust_score == 80  # asking for the wrong task is refused, not punished