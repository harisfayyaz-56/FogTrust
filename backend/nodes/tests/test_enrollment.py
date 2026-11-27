"""
FR-1 node enrollment and test T1 (spoofed nodes).  Threats ID-5, ID-6, ID-7, ID-12.

T1 cases (docs/test-evidence/identity-T1-T5.md):
  a  no token                      d  token reused
  b  forged token                  e  valid token, attacker's proof (wrong key / wrong name)
  c  expired token                 f  (heartbeat with wrong key: test_node_engine_integration.py)
The client always sees the same generic error for a token failure; the audit log and the
Decision hold the precise reason.
"""

import json

from datetime import timedelta

import pytest
from django.conf import settings
from django.utils import timezone

from audit.models import AuditEvent
from core.models import Decision
from fogtrust_crypto.keys import generate_private_key, public_key_fingerprint, public_key_to_b64, sign_enrollment_proof
from nodes import services
from nodes.models import EnrollmentToken, Node

from .helpers import ENROLL_URL, enroll_payload, error_code, last_audit, post_json


def refusal_decision():
    return Decision.objects.filter(subject_type="enrollment", decision="deny").order_by("-decided_at").first()


@pytest.mark.django_db
class TestHappyPath:
    def test_valid_enrollment_creates_an_active_node(self, api_client, token_factory):
        token, raw = token_factory()
        key = generate_private_key()
        response = post_json(api_client, ENROLL_URL, enroll_payload(raw, name="gateway-03", key=key, capacity=4))

        assert response.status_code == 201
        body = response.json()
        node = Node.objects.get()
        assert body["node_id"] == str(node.id)
        assert body["name"] == "gateway-03" and body["status"] == "active" and body["capacity"] == 4
        assert body["key_fingerprint"] == public_key_fingerprint(key.public_key())
        assert "server_public_key" in body
        assert response["Cache-Control"] == "no-store"
        assert node.public_key == public_key_to_b64(key.public_key())
        assert node.trust_score == 80 and node.current_load == 0 and node.last_counter == 0  # policy default

    def test_token_is_marked_used_by_exactly_this_node(self, api_client, token_factory):
        token, raw = token_factory()
        post_json(api_client, ENROLL_URL, enroll_payload(raw))

        token.refresh_from_db()
        node = Node.objects.get()
        assert token.used_at is not None and token.used_by_node_id == node.id
        assert node.enrolled_via_id == token.id
        assert token.state() == EnrollmentToken.State.USED

    def test_success_is_audited_and_explained(self, api_client, token_factory):
        token, raw = token_factory(label="lab 2")
        post_json(api_client, ENROLL_URL, enroll_payload(raw, name="gateway-03"))
        node = Node.objects.get()

        event = last_audit("node.enroll", "success")
        assert (event.actor_type, event.actor_id, event.actor_role) == ("node", str(node.id), "node")
        assert event.target_id == str(node.id)
        assert event.details["token_id"] == str(token.id) and event.details["node_name"] == "gateway-03"

        decision = Decision.objects.get(subject_type="enrollment", decision="allow")
        assert decision.subject_id == str(node.id) and decision.reason_code == "OK"
        assert [rule["rule"] for rule in decision.rules_fired] == [
            "token_valid", "key_well_formed", "proof_of_possession", "key_unused", "name_unused",
            "initial_trust_from_policy", "token_redeemed_once",
        ]
        assert all(rule["passed"] for rule in decision.rules_fired)
        assert decision.engine_name == "enrollment_gate" and decision.latency_ms >= 0

    def test_nothing_secret_reaches_the_audit_log_or_the_decision(self, api_client, token_factory):
        _, raw = token_factory()
        key = generate_private_key()
        body = enroll_payload(raw, key=key)
        post_json(api_client, ENROLL_URL, body)

        stored = " ".join(str(e.details) for e in AuditEvent.objects.all()) + " ".join(
            str(d.evidence) + str(d.rules_fired) for d in Decision.objects.all()
        )
        for secret in (raw, body["proof"], body["public_key"]):
            assert secret not in stored

    def test_the_starting_trust_score_comes_from_the_policy_and_is_recorded(self, api_client, token_factory):
        from trust.models import PolicyConfig

        PolicyConfig.objects.create(version=1, values={"initial_score": 65, "weights": {}}, change_reason="lab policy")
        PolicyConfig.objects.create(version=2, values={"initial_score": 55, "weights": {}}, change_reason="stricter policy")
        _, raw = token_factory()
        post_json(api_client, ENROLL_URL, enroll_payload(raw))

        assert Node.objects.get().trust_score == 55  # the CURRENT policy, version 2
        decision = Decision.objects.get(subject_type="enrollment", decision="allow")
        assert decision.policy_version == 2 and decision.thresholds == {"initial_score": 55}
        assert decision.evidence["initial_trust_score"] == 55

    def test_a_nonsense_policy_value_falls_back_to_the_safe_default(self, api_client, token_factory):
        from trust.models import PolicyConfig

        PolicyConfig.objects.create(version=1, values={"initial_score": 9999, "weights": {}}, change_reason="bad value")
        _, raw = token_factory()
        post_json(api_client, ENROLL_URL, enroll_payload(raw))
        assert Node.objects.get().trust_score == settings.INITIAL_TRUST_SCORE  # whatever the environment configures

    def test_capacity_defaults_when_omitted(self, api_client, token_factory):
        _, raw = token_factory()
        body = enroll_payload(raw)
        del body["capacity"]
        assert post_json(api_client, ENROLL_URL, body).status_code == 201
        assert Node.objects.get().capacity == 4

    def test_needs_no_cookie_and_no_csrf_token(self, token_factory):
        from rest_framework.test import APIClient

        _, raw = token_factory()
        client = APIClient(enforce_csrf_checks=True)
        assert post_json(client, ENROLL_URL, enroll_payload(raw)).status_code == 201


@pytest.mark.django_db
class TestT1TokenFailures:
    """The client sees ENROLL_TOKEN_INVALID in every case. The audit log says which."""

    def assert_rejected(self, response, audit_reason, *, node_count=0):
        assert response.status_code == 401
        assert error_code(response) == "ENROLL_TOKEN_INVALID"
        assert response.json()["error"]["message"] == "Enrollment rejected."
        assert Node.objects.count() == node_count
        event = last_audit("node.enroll", "failure")
        assert event.reason_code == audit_reason
        assert event.actor_type == "anonymous"
        decision = refusal_decision()
        assert decision.reason_code == audit_reason
        assert decision.rules_fired[-1]["rule"] == "token_valid" and decision.rules_fired[-1]["passed"] is False

    def test_a_no_token_is_a_validation_error_and_is_audited(self, api_client):
        body = enroll_payload("x" * 43)
        del body["enrollment_token"]
        response = post_json(api_client, ENROLL_URL, body)

        assert response.status_code == 400 and error_code(response) == "VALIDATION_ERROR"
        event = last_audit("node.enroll", "failure")
        assert event.reason_code == "VALIDATION_ERROR" and event.details == {"fields": ["enrollment_token"]}

    def test_b_forged_token(self, api_client, token_factory):
        token_factory()  # a real token exists, the attacker does not have it
        response = post_json(api_client, ENROLL_URL, enroll_payload("A" * 43))
        self.assert_rejected(response, "ENROLL_TOKEN_INVALID")

    def test_c_expired_token(self, api_client, token_factory):
        token, raw = token_factory()
        EnrollmentToken.objects.filter(pk=token.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
        response = post_json(api_client, ENROLL_URL, enroll_payload(raw))
        self.assert_rejected(response, "ENROLL_TOKEN_EXPIRED")
        assert "expired" in refusal_decision().explanation

    def test_d_reused_token(self, api_client, token_factory):
        _, raw = token_factory()
        assert post_json(api_client, ENROLL_URL, enroll_payload(raw, name="first-node")).status_code == 201
        response = post_json(api_client, ENROLL_URL, enroll_payload(raw, name="second-node"))
        self.assert_rejected(response, "ENROLL_TOKEN_USED", node_count=1)
        assert Node.objects.get().name == "first-node"

    def test_cancelled_token(self, api_client, token_factory):
        token, raw = token_factory()
        EnrollmentToken.objects.filter(pk=token.pk).update(cancelled_at=timezone.now())
        response = post_json(api_client, ENROLL_URL, enroll_payload(raw))
        self.assert_rejected(response, "ENROLL_TOKEN_INVALID")
        assert last_audit("node.enroll", "failure").details["state"] == "cancelled"

    def test_the_client_cannot_tell_the_token_failures_apart(self, api_client, token_factory):
        used, used_raw = token_factory()
        post_json(api_client, ENROLL_URL, enroll_payload(used_raw, name="first-node"))
        expired, expired_raw = token_factory()
        EnrollmentToken.objects.filter(pk=expired.pk).update(expires_at=timezone.now() - timedelta(seconds=1))

        responses = [
            post_json(api_client, ENROLL_URL, enroll_payload(raw, name="other-node"))
            for raw in ("B" * 43, used_raw, expired_raw)
        ]
        bodies = {json.dumps({**r.json()["error"], "request_id": ""}, sort_keys=True) for r in responses}
        assert len(bodies) == 1 and {r.status_code for r in responses} == {401}

    def test_a_stale_token_object_cannot_win_a_race(self, api_client, token_factory, monkeypatch):
        """
        Two requests hold the same valid token. The first redeems it; the second, which already
        passed its own check, must still lose at the conditional UPDATE and leave no node behind.
        """
        token, raw = token_factory()
        stale = EnrollmentToken.objects.get(pk=token.pk)  # what request B read before request A finished
        assert post_json(api_client, ENROLL_URL, enroll_payload(raw, name="winner-node")).status_code == 201

        monkeypatch.setattr(services, "find_token", lambda _raw: stale)
        response = post_json(api_client, ENROLL_URL, enroll_payload(raw, name="loser-node"))

        assert response.status_code == 401 and error_code(response) == "ENROLL_TOKEN_INVALID"
        assert [n.name for n in Node.objects.all()] == ["winner-node"]
        assert last_audit("node.enroll", "failure").reason_code == "ENROLL_TOKEN_USED"

    def test_failed_attempts_do_not_burn_the_token(self, api_client, token_factory):
        _, raw = token_factory()
        wrong = generate_private_key()
        bad = enroll_payload(raw, proof=sign_enrollment_proof(wrong, raw, "gateway-01"))
        assert post_json(api_client, ENROLL_URL, bad).status_code == 401

        assert post_json(api_client, ENROLL_URL, enroll_payload(raw)).status_code == 201


@pytest.mark.django_db
class TestT1ProofOfPossession:
    """e: the attacker has a valid token but cannot prove they hold the private key they submit."""

    def assert_proof_rejected(self, response):
        assert response.status_code == 401 and error_code(response) == "ENROLL_PROOF_INVALID"
        assert Node.objects.count() == 0
        assert last_audit("node.enroll", "failure").reason_code == "ENROLL_PROOF_INVALID"
        rules = {r["rule"]: r["passed"] for r in refusal_decision().rules_fired}
        assert rules["token_valid"] is True and rules["proof_of_possession"] is False

    def test_someone_elses_public_key_with_my_own_signature(self, api_client, token_factory):
        _, raw = token_factory()
        victim = generate_private_key()
        attacker = generate_private_key()
        body = enroll_payload(raw, key=attacker, public_key=public_key_to_b64(victim.public_key()))
        self.assert_proof_rejected(post_json(api_client, ENROLL_URL, body))

    def test_proof_signed_for_a_different_name(self, api_client, token_factory):
        _, raw = token_factory()
        key = generate_private_key()
        body = enroll_payload(raw, name="gateway-01", key=key, proof=sign_enrollment_proof(key, raw, "other-name"))
        self.assert_proof_rejected(post_json(api_client, ENROLL_URL, body))

    def test_proof_signed_for_a_different_token(self, api_client, token_factory):
        _, raw = token_factory()
        key = generate_private_key()
        body = enroll_payload(raw, key=key, proof=sign_enrollment_proof(key, "C" * 43, "gateway-01"))
        self.assert_proof_rejected(post_json(api_client, ENROLL_URL, body))

    def test_garbage_proofs(self, api_client, token_factory):
        _, raw = token_factory()
        for proof in ("not base64 !!", "AAAA", "A" * 88):
            response = post_json(api_client, ENROLL_URL, enroll_payload(raw, proof=proof))
            assert response.status_code == 401 and error_code(response) == "ENROLL_PROOF_INVALID"
        assert Node.objects.count() == 0


@pytest.mark.django_db
class TestKeyAndNameRules:
    @pytest.mark.parametrize("public_key", ["short", "!" * 44, "A" * 44, "A" * 43 + "B"])
    def test_malformed_keys_are_rejected_as_invalid_keys(self, api_client, token_factory, public_key):
        _, raw = token_factory()
        response = post_json(api_client, ENROLL_URL, enroll_payload(raw, public_key=public_key))

        assert response.status_code == 400 and error_code(response) == "ENROLL_KEY_INVALID"
        assert Node.objects.count() == 0
        assert last_audit("node.enroll", "failure").reason_code == "ENROLL_KEY_INVALID"

    def test_a_key_cannot_be_registered_twice(self, api_client, token_factory):
        key = generate_private_key()
        _, first = token_factory()
        _, second = token_factory()
        assert post_json(api_client, ENROLL_URL, enroll_payload(first, name="node-one", key=key)).status_code == 201
        response = post_json(api_client, ENROLL_URL, enroll_payload(second, name="node-two", key=key))

        assert response.status_code == 409 and error_code(response) == "ENROLL_KEY_IN_USE"
        assert Node.objects.count() == 1
        assert EnrollmentToken.objects.get(token_hash=services.hash_token(second)).used_at is None

    def test_a_name_cannot_be_taken_twice(self, api_client, token_factory):
        _, first = token_factory()
        _, second = token_factory()
        assert post_json(api_client, ENROLL_URL, enroll_payload(first, name="gateway-01")).status_code == 201
        response = post_json(api_client, ENROLL_URL, enroll_payload(second, name="gateway-01"))

        assert response.status_code == 409 and error_code(response) == "NODE_NAME_TAKEN"
        assert Node.objects.count() == 1

    @pytest.mark.parametrize("name", ["", "ab", "Gateway-01", "-gateway", "gate way", "gate_way", "x" * 65, "gateway/../1"])
    def test_invalid_names_are_rejected(self, api_client, token_factory, name):
        _, raw = token_factory()
        response = post_json(api_client, ENROLL_URL, enroll_payload(raw, name=name))
        assert response.status_code == 400 and error_code(response) == "VALIDATION_ERROR"

    @pytest.mark.parametrize("capacity", [0, -1, 101, "four", 2.5, None, True])
    def test_invalid_capacity_is_rejected(self, api_client, token_factory, capacity):
        _, raw = token_factory()
        response = post_json(api_client, ENROLL_URL, enroll_payload(raw, capacity=capacity))
        assert response.status_code == 400 and error_code(response) == "VALIDATION_ERROR"

    def test_a_revoked_node_cannot_re_enroll_with_its_old_key(self, api_client, token_factory, node_factory):
        node, key = node_factory(name="gateway-01")
        Node.objects.filter(pk=node.pk).update(status="revoked", revoked_at=timezone.now(), revoke_reason="test revoke reason")
        _, raw = token_factory()
        response = post_json(api_client, ENROLL_URL, enroll_payload(raw, name="gateway-02", key=key))

        assert response.status_code == 409 and error_code(response) == "ENROLL_KEY_IN_USE"


@pytest.mark.django_db
class TestMalformedAndOversizedInput:
    """T-final: malformed and oversized input is refused safely, and recorded."""

    def test_unknown_fields_are_rejected(self, api_client, token_factory):
        _, raw = token_factory()
        response = post_json(api_client, ENROLL_URL, enroll_payload(raw, status="revoked", is_admin=True))
        assert response.status_code == 400 and error_code(response) == "VALIDATION_ERROR"
        assert Node.objects.count() == 0

    def test_invalid_json(self, api_client):
        response = api_client.post(ENROLL_URL, data="{not json", content_type="application/json")
        assert response.status_code == 400 and error_code(response) == "MALFORMED_REQUEST"
        assert last_audit("node.enroll", "failure").reason_code == "MALFORMED_REQUEST"

    @pytest.mark.parametrize("payload", ["[]", "null", '"text"', "42"])
    def test_json_that_is_not_an_object(self, api_client, payload):
        response = api_client.post(ENROLL_URL, data=payload, content_type="application/json")
        assert response.status_code == 400 and error_code(response) == "VALIDATION_ERROR"

    def test_wrong_content_type(self, api_client):
        response = api_client.post(ENROLL_URL, data="a=b", content_type="application/x-www-form-urlencoded")
        assert response.status_code == 415 and error_code(response) == "UNSUPPORTED_MEDIA_TYPE"
        assert last_audit("node.enroll", "failure").reason_code == "UNSUPPORTED_MEDIA_TYPE"

    def test_body_over_the_enrollment_cap_is_refused_before_parsing(self, api_client):
        response = api_client.post(ENROLL_URL, data=json.dumps({"padding": "x" * 5000}), content_type="application/json")
        assert response.status_code == 413 and error_code(response) == "PAYLOAD_TOO_LARGE"
        assert last_audit("node.enroll", "failure").reason_code == "PAYLOAD_TOO_LARGE"

    def test_huge_values_are_refused(self, api_client, token_factory):
        _, raw = token_factory()
        for field in ("enrollment_token", "public_key", "proof", "name"):
            response = post_json(api_client, ENROLL_URL, enroll_payload(raw, **{field: "x" * 300}))
            assert response.status_code == 400, field

    def test_validation_errors_do_not_echo_what_was_sent(self, api_client, token_factory):
        _, raw = token_factory()
        marker = "<script>alert(1)</script>"
        response = post_json(api_client, ENROLL_URL, enroll_payload(raw, name=marker))
        assert marker not in response.content.decode()
        assert marker not in str(last_audit("node.enroll", "failure").details)

    def test_sql_injection_in_name_and_token_is_harmless(self, api_client, token_factory):
        _, raw = token_factory()
        injections = ["x'; DROP TABLE nodes_node;--", "' OR '1'='1"]
        for text in injections:
            assert post_json(api_client, ENROLL_URL, enroll_payload(raw, name=text)).status_code == 400
            assert post_json(api_client, ENROLL_URL, enroll_payload(text.ljust(43, "x"))).status_code == 400
        assert post_json(api_client, ENROLL_URL, enroll_payload(raw)).status_code == 201

    def test_get_is_not_allowed(self, api_client):
        assert api_client.get(ENROLL_URL).status_code == 405


@pytest.mark.django_db
class TestRateLimit:
    def test_enrollment_is_throttled_per_client(self, api_client):
        statuses = [post_json(api_client, ENROLL_URL, {}).status_code for _ in range(12)]

        assert statuses[:10] == [400] * 10
        assert statuses[10:] == [429, 429]
        event = last_audit("request.rate_limited")
        assert event.reason_code == "RATE_LIMITED" and event.details["scope"] == "enroll"

    def test_a_forged_forwarded_for_header_does_not_bypass_the_limit(self, api_client):
        statuses = [
            post_json(api_client, ENROLL_URL, {}, HTTP_X_FORWARDED_FOR=f"203.0.113.{i}").status_code for i in range(12)
        ]
        assert 429 in statuses
