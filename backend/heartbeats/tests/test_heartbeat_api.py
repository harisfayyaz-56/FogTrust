"""
FR-2 end to end through Django: the real endpoint, the real database, the real engine.
Covers T1 (spoofed node), T2 (replayed heartbeat), T5 (revoked node) and the T-final items
for this endpoint (oversized and malformed input, repeated submission, restart recovery).
"""

import json
import time

import pytest
from django.utils import timezone

from audit.models import AuditEvent
from core.models import Decision
from fogtrust_crypto.keys import generate_private_key
from fogtrust_crypto.node_auth import sign_request
from heartbeats.models import Heartbeat
from heartbeats.throttles import IPHeartbeatThrottle, NodeHeartbeatThrottle
from nodes.models import Node, NodeNonce
from nodes.replay_store import DatabaseReplayStore

URL = "/api/v1/node-api/heartbeat/"


def body_for(counter=1, load=1):
    return json.dumps({"counter": counter, "reported_load": load, "sent_at": timezone.now().isoformat()}, separators=(",", ":")).encode()


def meta(headers):
    return {"HTTP_" + k.upper().replace("-", "_"): v for k, v in headers.items()}


def send(client, key, node_id, counter=1, *, ts=None, nonce=None, body=None, headers=None):
    """Sign and POST one heartbeat. Returns (response, headers, body) so a test can resend the same bytes."""
    body = body if body is not None else body_for(counter)
    headers = headers or sign_request(key, str(node_id), "POST", URL, body, timestamp=ts, nonce=nonce)
    return client.post(URL, data=body, content_type="application/json", **meta(headers)), headers, body


def resend(client, headers, body):
    return client.post(URL, data=body, content_type="application/json", **meta(headers))


def error_code(response):
    return response.json()["error"]["code"]


@pytest.fixture
def enrolled(node_factory):
    return node_factory(name="gateway-03")


@pytest.mark.django_db
class TestAcceptedHeartbeat:
    def test_honest_heartbeat_is_accepted_and_recorded(self, api_client, enrolled):
        node, key = enrolled
        response, _, _ = send(api_client, key, node.id, counter=1)

        assert response.status_code == 200
        body = response.json()
        assert body["accepted"] is True and body["next_heartbeat_in"] == 10 and body["server_time"].endswith("Z")
        node.refresh_from_db()
        assert node.last_counter == 1 and node.last_seen_at is not None
        row = Heartbeat.objects.get()
        assert (row.node_id, row.counter, row.accepted, row.reason_code, row.reported_load) == (node.id, 1, True, "", 1)
        assert not Decision.objects.filter(subject_type="heartbeat").exists()  # accepted heartbeats stay out of the evidence view
        assert not AuditEvent.objects.filter(action="heartbeat.rejected").exists()

    def test_a_sequence_with_gaps_is_accepted(self, api_client, enrolled):
        node, key = enrolled
        for counter in (1, 2, 7, 50):
            assert send(api_client, key, node.id, counter)[0].status_code == 200
        node.refresh_from_db()
        assert node.last_counter == 50 and Heartbeat.objects.filter(accepted=True).count() == 4

    def test_response_is_not_cacheable(self, api_client, enrolled):
        node, key = enrolled
        assert send(api_client, key, node.id)[0]["Cache-Control"] == "no-store"


@pytest.mark.django_db
class TestT1SpoofedNode:
    def test_wrong_key_is_refused_and_explained(self, api_client, enrolled):
        node, _ = enrolled
        response, _, _ = send(api_client, generate_private_key(), node.id)

        assert response.status_code == 401 and error_code(response) == "NODE_SIGNATURE_INVALID"
        assert response.json()["error"]["message"] == "Node authentication failed."  # generic text
        decision = Decision.objects.get(subject_type="heartbeat")
        assert (decision.decision, decision.reason_code, decision.subject_id) == ("deny", "NODE_SIGNATURE_INVALID", str(node.id))
        assert decision.rules_fired[-1]["rule"] == "signature_valid" and decision.rules_fired[-1]["passed"] is False
        assert decision.request_id == response["X-Request-ID"]
        event = AuditEvent.objects.get(action="heartbeat.rejected")
        assert (event.outcome, event.reason_code, event.actor_type, event.target_id) == ("failure", "NODE_SIGNATURE_INVALID", "node", str(node.id))

    def test_a_spoofer_changes_no_state(self, api_client, enrolled):
        node, _ = enrolled
        send(api_client, generate_private_key(), node.id, counter=99)
        node.refresh_from_db()
        assert node.last_counter == 0 and node.last_seen_at is None
        assert NodeNonce.objects.count() == 0  # an unauthenticated caller cannot fill the nonce table

    def test_rejection_is_in_the_node_history(self, api_client, enrolled):
        node, _ = enrolled
        send(api_client, generate_private_key(), node.id)
        row = Heartbeat.objects.get()
        assert (row.accepted, row.reason_code, row.node_id) == (False, "NODE_SIGNATURE_INVALID", node.id)

    def test_unknown_node_is_refused_and_audited_but_not_stored(self, api_client, node_factory):
        import uuid

        response, _, _ = send(api_client, generate_private_key(), uuid.uuid4())
        assert response.status_code == 401 and error_code(response) == "NODE_UNKNOWN"
        assert Heartbeat.objects.count() == 0  # no node to attach it to
        assert Decision.objects.filter(reason_code="NODE_UNKNOWN").exists()
        assert AuditEvent.objects.filter(action="heartbeat.rejected", reason_code="NODE_UNKNOWN").exists()

    def test_missing_headers(self, api_client, enrolled):
        response = api_client.post(URL, data=body_for(), content_type="application/json")
        assert response.status_code == 401 and error_code(response) == "NODE_SIGNATURE_MISSING"


@pytest.mark.django_db
class TestT2ReplayedHeartbeat:
    def test_exact_copy_is_refused_with_the_nonce_reason(self, api_client, enrolled):
        node, key = enrolled
        first, headers, body = send(api_client, key, node.id, counter=1)
        assert first.status_code == 200
        replay = resend(api_client, headers, body)

        assert replay.status_code == 401 and error_code(replay) == "HEARTBEAT_REPLAYED"
        assert replay.json()["error"]["message"] == "Heartbeat rejected."
        decision = Decision.objects.get(reason_code="HEARTBEAT_REPLAYED")
        assert decision.rules_fired[-1] == {"rule": "nonce_unique", "passed": False, "detail": "nonce already used by this node inside the window"}
        assert [r["passed"] for r in decision.rules_fired[:5]] == [True] * 5  # the copy is validly signed and fresh
        assert decision.thresholds["timestamp_window_s"] == 30

    def test_replay_changes_no_state_and_is_visible_in_history(self, api_client, enrolled):
        node, key = enrolled
        _, headers, body = send(api_client, key, node.id, counter=1)
        for _ in range(3):
            resend(api_client, headers, body)
        node.refresh_from_db()
        assert node.last_counter == 1 and NodeNonce.objects.count() == 1
        assert Heartbeat.objects.filter(accepted=True).count() == 1
        assert Heartbeat.objects.filter(accepted=False, reason_code="HEARTBEAT_REPLAYED").count() == 3

    def test_old_capture_is_stale(self, api_client, enrolled):
        node, key = enrolled
        response, _, _ = send(api_client, key, node.id, ts=int(time.time()) - 3600)
        assert response.status_code == 401 and error_code(response) == "HEARTBEAT_STALE"
        decision = Decision.objects.get(reason_code="HEARTBEAT_STALE")
        assert "limit 30 s" in decision.rules_fired[-1]["detail"]

    def test_counter_going_backwards_is_refused(self, api_client, enrolled):
        node, key = enrolled
        send(api_client, key, node.id, counter=5)
        response, _, _ = send(api_client, key, node.id, counter=3)
        assert response.status_code == 401 and error_code(response) == "HEARTBEAT_COUNTER_REGRESSED"
        node.refresh_from_db()
        assert node.last_counter == 5
        assert Decision.objects.get(reason_code="HEARTBEAT_COUNTER_REGRESSED").evidence["last_counter"] == 5


@pytest.mark.django_db
class TestT5Revocation:
    def test_revoked_node_is_refused_on_its_next_request(self, api_client, enrolled):
        node, key = enrolled
        assert send(api_client, key, node.id, counter=1)[0].status_code == 200
        Node.objects.filter(pk=node.pk).update(status="revoked", revoked_at=timezone.now(), revoke_reason="test")

        response, _, _ = send(api_client, key, node.id, counter=2)
        assert response.status_code == 403 and error_code(response) == "NODE_REVOKED"
        assert "signature_valid" not in [r["rule"] for r in Decision.objects.get(reason_code="NODE_REVOKED").rules_fired]
        node.refresh_from_db()
        assert node.last_counter == 1


@pytest.mark.django_db
class TestInputLimitsAndSafeErrors:
    def test_oversized_body_is_refused_before_it_is_read(self, api_client, enrolled):
        node, key = enrolled
        response = api_client.post(URL, data=b"x" * 3000, content_type="application/json", **meta(sign_request(key, str(node.id), "POST", URL, b"x")))
        assert response.status_code == 413 and error_code(response) == "PAYLOAD_TOO_LARGE"
        assert AuditEvent.objects.filter(action="heartbeat.rejected", reason_code="PAYLOAD_TOO_LARGE").exists()
        assert Heartbeat.objects.count() == 0

    def test_signed_but_malformed_json_is_refused(self, api_client, enrolled):
        node, key = enrolled
        response, _, _ = send(api_client, key, node.id, body=b"not json")
        assert response.status_code == 400 and error_code(response) == "MALFORMED_REQUEST"

    @pytest.mark.parametrize("body", [b"[]", b'{"counter":1}', b'{"counter":"1","reported_load":0,"sent_at":"2026-11-19T10:20:31Z"}',
                                      b'{"counter":1,"reported_load":0,"sent_at":"2026-11-19T10:20:31Z","admin":true}'])
    def test_signed_but_invalid_body_is_refused(self, api_client, enrolled, body):
        node, key = enrolled
        response, _, _ = send(api_client, key, node.id, body=body)
        assert response.status_code == 400 and error_code(response) == "VALIDATION_ERROR"
        node.refresh_from_db()
        assert node.last_counter == 0

    def test_garbage_headers_never_cause_a_server_error(self, api_client, enrolled):
        node, key = enrolled
        _, headers, body = send(api_client, key, node.id)
        for name in headers:
            for junk in ("", "\u00e9\u00e9", "x" * 5000, "' OR 1=1 --"):
                response = resend(api_client, {**headers, name: junk}, body)
                assert response.status_code in (400, 401, 403, 429), (name, junk, response.status_code)
                assert "Traceback" not in response.content.decode() and "error" in response.json()

    def test_errors_never_echo_input(self, api_client, enrolled):
        node, key = enrolled
        response, _, _ = send(api_client, key, node.id, body=b'{"secret-marker-123": 1}')
        assert "secret-marker-123" not in response.content.decode()
        assert "secret-marker-123" not in json.dumps(list(Decision.objects.values("explanation", "evidence", "rules_fired")))

    def test_wrong_method_is_refused(self, api_client):
        assert api_client.get(URL).status_code == 405


@pytest.mark.django_db
class TestRateLimits:
    def test_a_node_over_its_limit_gets_429_and_others_are_unaffected(self, api_client, node_factory, monkeypatch):
        monkeypatch.setattr(NodeHeartbeatThrottle, "rate", "3/min")
        a, key_a = node_factory(name="a")
        b, key_b = node_factory(name="b")
        assert [send(api_client, key_a, a.id, c)[0].status_code for c in (1, 2, 3)] == [200, 200, 200]
        limited = send(api_client, key_a, a.id, 4)[0]
        assert limited.status_code == 429 and error_code(limited) == "RATE_LIMITED"
        assert send(api_client, key_b, b.id, 1)[0].status_code == 200

    def test_spraying_random_node_ids_hits_the_ip_cap(self, api_client, monkeypatch):
        import uuid

        monkeypatch.setattr(IPHeartbeatThrottle, "rate", "5/min")
        codes = [send(api_client, generate_private_key(), uuid.uuid4())[0].status_code for _ in range(7)]
        assert codes[:5] == [401] * 5 and codes[5:] == [429, 429]

    def test_a_stranger_cannot_burn_a_victims_quota(self, api_client, node_factory, monkeypatch):
        monkeypatch.setattr(NodeHeartbeatThrottle, "rate", "2/min")
        victim, victim_key = node_factory(name="victim")
        for _ in range(5):  # the attacker uses the victim's id from another address
            api_client.post(URL, data=b"{}", content_type="application/json", REMOTE_ADDR="203.0.113.9", **meta({"X-Node-Id": str(victim.id)}))
        assert send(api_client, victim_key, victim.id, 1)[0].status_code == 200


@pytest.mark.django_db
class TestRestartAndPurge:
    def test_replay_is_still_refused_after_a_restart(self, api_client, enrolled):
        """State is in the database, so a new process (a fresh store object, a cleared cache) still knows the nonce."""
        from django.core.cache import cache

        node, key = enrolled
        _, headers, body = send(api_client, key, node.id, counter=1)
        cache.clear()  # throttle counters are lost on restart too
        replay = resend(api_client, headers, body)
        assert error_code(replay) == "HEARTBEAT_REPLAYED"
        assert DatabaseReplayStore().last_counter(str(node.id)) == 1

    def test_purge_removes_only_expired_nonces(self, enrolled, monkeypatch):
        monkeypatch.setattr(DatabaseReplayStore, "PURGE_ONE_IN", 10**9)  # no random purge while the test counts rows
        node, _ = enrolled
        store = DatabaseReplayStore()
        assert store.add_nonce(str(node.id), "a" * 32, 1000) and store.add_nonce(str(node.id), "b" * 32, 2000)
        assert store.purge(1500) == 1
        assert list(NodeNonce.objects.values_list("nonce", flat=True)) == ["b" * 32]

    def test_purge_command(self, enrolled, capsys):
        from django.core.management import call_command

        node, _ = enrolled
        DatabaseReplayStore().add_nonce(str(node.id), "c" * 32, 1)  # long expired
        call_command("purge_nonces")
        assert "Purged 1 expired nonce" in capsys.readouterr().out and NodeNonce.objects.count() == 0


@pytest.mark.django_db
class TestAtomicity:
    """
    The guarantee against two simultaneous copies comes from the database, not from Python:
    a unique constraint for the nonce and ONE conditional UPDATE for the counter. A multi-connection
    race cannot be run here (the audit log's append-only trigger stops transactional tests from
    cleaning up, see audit/migrations/0002), so these tests check the mechanisms themselves.
    The same race IS exercised with 20 threads against the in-memory store in fogtrust_crypto/tests/test_replay.py.
    """

    def test_the_database_rejects_a_reused_nonce_even_by_raw_sql(self, enrolled):
        from django.db import IntegrityError, transaction

        node, _ = enrolled
        NodeNonce.objects.create(node=node, nonce="d" * 32, expires_at=9999999999)
        with pytest.raises(IntegrityError), transaction.atomic():
            NodeNonce.objects.bulk_create([NodeNonce(node=node, nonce="d" * 32, expires_at=1)])

    def test_add_nonce_reports_the_loser(self, enrolled):
        node, _ = enrolled
        store = DatabaseReplayStore()
        assert [store.add_nonce(str(node.id), "e" * 32, 9999999999) for _ in range(5)] == [True, False, False, False, False]
        assert NodeNonce.objects.count() == 1

    def test_advance_counter_is_one_conditional_statement(self, enrolled, django_assert_num_queries):
        node, _ = enrolled
        store = DatabaseReplayStore()
        with django_assert_num_queries(1):  # no read-then-write gap for another request to slip into
            assert store.advance_counter(str(node.id), 7) is True
        assert [store.advance_counter(str(node.id), c) for c in (7, 6, 1, 8)] == [False, False, False, True]
        node.refresh_from_db()
        assert node.last_counter == 8

    def test_the_same_nonce_may_be_accepted_only_once_in_history(self, enrolled):
        from django.db import IntegrityError, transaction

        node, _ = enrolled
        Heartbeat.objects.create(node=node, nonce="f" * 32, accepted=True, counter=1)
        Heartbeat.objects.create(node=node, nonce="f" * 32, accepted=False, reason_code="HEARTBEAT_REPLAYED")  # a rejected copy is fine
        with pytest.raises(IntegrityError), transaction.atomic():
            Heartbeat.objects.create(node=node, nonce="f" * 32, accepted=True, counter=2)

    def test_a_rejected_row_must_carry_a_reason(self, enrolled):
        from django.db import IntegrityError, transaction

        node, _ = enrolled
        with pytest.raises(IntegrityError), transaction.atomic():
            Heartbeat.objects.create(node=node, accepted=False, reason_code="")


@pytest.mark.django_db
class TestHistoryEndpoint:
    def test_viewer_sees_history_and_can_filter_rejections(self, client_as, api_client, enrolled):
        node, key = enrolled
        send(api_client, key, node.id, counter=1)
        send(api_client, generate_private_key(), node.id, counter=2)
        viewer = client_as("viewer")

        everything = viewer.get(f"/api/v1/nodes/{node.id}/heartbeats/").json()
        assert everything["count"] == 2
        rejected = viewer.get(f"/api/v1/nodes/{node.id}/heartbeats/?accepted=false").json()
        assert [r["reason_code"] for r in rejected["results"]] == ["NODE_SIGNATURE_INVALID"]
        by_code = viewer.get(f"/api/v1/nodes/{node.id}/heartbeats/?reason_code=NODE_SIGNATURE_INVALID").json()
        assert by_code["count"] == 1

    def test_history_never_shows_the_full_nonce(self, client_as, api_client, enrolled):
        node, key = enrolled
        _, headers, _ = send(api_client, key, node.id)
        row = client_as("viewer").get(f"/api/v1/nodes/{node.id}/heartbeats/").json()["results"][0]
        assert row["nonce_prefix"] == headers["X-Node-Nonce"][:4] and headers["X-Node-Nonce"] not in json.dumps(row)

    def test_unknown_node_and_bad_filter(self, client_as, enrolled):
        import uuid

        viewer = client_as("viewer")
        assert viewer.get(f"/api/v1/nodes/{uuid.uuid4()}/heartbeats/").status_code == 404
        assert viewer.get("/api/v1/nodes/not-a-uuid/heartbeats/").status_code == 404
        node, _ = enrolled
        assert viewer.get(f"/api/v1/nodes/{node.id}/heartbeats/?reason_code=drop%20table").status_code == 400

    def test_anonymous_is_refused(self, api_client, enrolled):
        node, _ = enrolled
        assert api_client.get(f"/api/v1/nodes/{node.id}/heartbeats/").status_code == 401