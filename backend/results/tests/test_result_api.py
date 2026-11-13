"""
FR-5 end to end through Django: encrypted results, T4 (altered result) and the T-final items for this endpoint.
Real endpoint, real database, real engine, real server key file.
"""

import base64
import json
import uuid

import pytest
from django.utils import timezone

from audit.models import AuditEvent
from core.models import Decision
from fogtrust_crypto.keys import (
    generate_private_key,
    generate_x25519_private_key,
    save_x25519_private_key,
    x25519_public_to_b64,
)
from fogtrust_crypto.node_auth import sign_request
from fogtrust_crypto.results import encrypt_result
from nodes.models import Node
from results.models import TaskResult
from results.throttles import NodeResultThrottle
from tasks.models import Task

MARKER = "SECRET-RESULT-MARKER-91f2"
PLAINTEXT = json.dumps({"checksum": "ab12", "note": MARKER}).encode()


@pytest.fixture
def server_key(tmp_path, settings):
    from nodes import server_keys

    key = generate_x25519_private_key()
    path = tmp_path / "keys" / "server.key"
    save_x25519_private_key(key, path)
    settings.RESULT_KEY_FILE = str(path)
    server_keys._load.cache_clear()
    yield key, x25519_public_to_b64(key.public_key())
    server_keys._load.cache_clear()


@pytest.fixture
def enrolled(node_factory):
    return node_factory(name="gateway-03")


@pytest.fixture
def make_task(make_user):
    admin = make_user(username="creator", role="admin")

    def _make(node, status=Task.Status.ASSIGNED):
        return Task.objects.create(
            task_type="checksum", payload={}, status=status, assigned_node=node,
            idempotency_key=uuid.uuid4().hex, created_by=admin, assigned_at=timezone.now(),
        )

    return _make


def path_for(task_id):
    return f"/api/v1/node-api/tasks/{task_id}/result/"


def meta(headers):
    return {"HTTP_" + k.upper().replace("-", "_"): v for k, v in headers.items()}


def submission(key, node_id, task_id, server_pub, *, plaintext=PLAINTEXT, ts=None, nonce=None, envelope=None, mutate=None):
    """Return (path, headers, body) for a signed result submission."""
    env = envelope or encrypt_result(server_pub, str(node_id), str(task_id), plaintext)
    if mutate:
        env = mutate(env)
    body = json.dumps(env, separators=(",", ":")).encode()
    path = path_for(task_id)
    return path, sign_request(key, str(node_id), "POST", path, body, timestamp=ts, nonce=nonce), body


def post(client, path, headers, body):
    return client.post(path, data=body, content_type="application/json", **meta(headers))


def flip(b64):
    raw = bytearray(base64.b64decode(b64))
    raw[0] ^= 1
    return base64.b64encode(bytes(raw)).decode()


def code_of(response):
    return response.json()["error"]["code"]


@pytest.mark.django_db
class TestAcceptedResult:
    def test_honest_result_completes_the_task_and_stores_only_ciphertext(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        task = make_task(node)
        response = post(api_client, *submission(key, node.id, task.id, server_key[1]))

        assert response.status_code == 201
        assert response.json() == {"accepted": True, "task_id": str(task.id), "status": "completed"}
        task.refresh_from_db()
        assert task.status == "completed" and task.completed_at is not None
        row = TaskResult.objects.get()
        assert row.integrity_valid and row.reason_code == "" and len(row.plaintext_sha256) == 64
        assert (len(row.ephemeral_public_key), len(row.nonce)) == (44, 16)
        everything = json.dumps(list(TaskResult.objects.values()), default=str)
        assert MARKER not in everything and "ab12" not in everything  # the plaintext is nowhere in the database
        decision = Decision.objects.get(subject_type="result")
        assert (decision.decision, decision.subject_id) == ("allow", str(task.id))
        assert decision.rules_fired[-1]["rule"] == "aes_gcm_tag" and decision.rules_fired[-1]["passed"] is True
        assert AuditEvent.objects.filter(action="result.accepted").count() == 1

    def test_nothing_secret_reaches_decisions_or_audit(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        task = make_task(node)
        post(api_client, *submission(key, node.id, task.id, server_key[1]))
        seen = json.dumps(list(Decision.objects.values("explanation", "evidence", "rules_fired")), default=str)
        seen += json.dumps(list(AuditEvent.objects.values("details", "action")), default=str)
        assert MARKER not in seen and "ab12" not in seen


@pytest.mark.django_db
class TestT4AlteredResult:
    def test_ciphertext_altered_before_signing_fails_the_integrity_check(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        task = make_task(node)
        response = post(api_client, *submission(key, node.id, task.id, server_key[1],
                                                mutate=lambda e: {**e, "ciphertext": flip(e["ciphertext"])}))

        assert response.status_code == 422 and code_of(response) == "RESULT_INTEGRITY_FAILED"
        task.refresh_from_db()
        assert task.status == "assigned" and task.completed_at is None  # the task still waits for a good result
        row = TaskResult.objects.get()
        assert (row.integrity_valid, row.reason_code, row.plaintext_sha256) == (False, "RESULT_INTEGRITY_FAILED", None)
        decision = Decision.objects.get(subject_type="result")
        assert (decision.decision, decision.reason_code) == ("deny", "RESULT_INTEGRITY_FAILED")
        assert decision.rules_fired[3] == {"rule": "signature_valid", "passed": True, "detail": "Ed25519 signature matches the registered key"}
        assert decision.rules_fired[-1]["rule"] == "aes_gcm_tag" and decision.rules_fired[-1]["passed"] is False
        assert AuditEvent.objects.filter(action="result.rejected", reason_code="RESULT_INTEGRITY_FAILED").exists()

    def test_a_good_result_is_still_accepted_after_a_tampered_one(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        task = make_task(node)
        post(api_client, *submission(key, node.id, task.id, server_key[1], mutate=lambda e: {**e, "ciphertext": flip(e["ciphertext"])}))
        assert post(api_client, *submission(key, node.id, task.id, server_key[1])).status_code == 201
        assert TaskResult.objects.filter(integrity_valid=True).count() == 1 and TaskResult.objects.count() == 2

    def test_ciphertext_altered_in_transit_fails_the_signature(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        task = make_task(node)
        path, headers, body = submission(key, node.id, task.id, server_key[1])
        altered = body.replace(json.loads(body)["ciphertext"][:6].encode(), flip(json.loads(body)["ciphertext"][:8])[:6].encode(), 1)
        assert altered != body
        response = post(api_client, path, headers, altered)
        assert response.status_code == 401 and code_of(response) == "NODE_SIGNATURE_INVALID"
        assert TaskResult.objects.count() == 0

    def test_ciphertext_made_for_another_task_is_refused(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        task, other = make_task(node), make_task(node)
        env = encrypt_result(server_key[1], str(node.id), str(other.id), PLAINTEXT)  # bound to the other task
        response = post(api_client, *submission(key, node.id, task.id, server_key[1], envelope=env))
        assert response.status_code == 422 and code_of(response) == "RESULT_INTEGRITY_FAILED"


@pytest.mark.django_db
class TestRepeatsAndOwnership:
    def test_exact_replay_is_refused(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        task = make_task(node)
        path, headers, body = submission(key, node.id, task.id, server_key[1])
        assert post(api_client, path, headers, body).status_code == 201
        replay = post(api_client, path, headers, body)
        assert replay.status_code == 401 and code_of(replay) == "HEARTBEAT_REPLAYED"
        assert TaskResult.objects.count() == 1

    def test_a_second_fresh_submission_for_a_completed_task_is_refused(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        task = make_task(node)
        assert post(api_client, *submission(key, node.id, task.id, server_key[1])).status_code == 201
        second = post(api_client, *submission(key, node.id, task.id, server_key[1]))  # new nonce, validly signed
        assert second.status_code == 409 and code_of(second) == "TASK_INVALID_STATE"
        assert TaskResult.objects.filter(integrity_valid=True).count() == 1
        denial = Decision.objects.get(reason_code="TASK_INVALID_STATE")
        assert denial.rules_fired[-1]["rule"] == "task_state"

    def test_task_assigned_to_another_node_is_refused(self, api_client, node_factory, server_key, make_task):
        owner, _ = node_factory(name="owner")
        intruder, intruder_key = node_factory(name="intruder")
        task = make_task(owner)
        response = post(api_client, *submission(intruder_key, intruder.id, task.id, server_key[1]))
        assert response.status_code == 403 and code_of(response) == "RESULT_NOT_ASSIGNED"
        task.refresh_from_db()
        assert task.status == "assigned" and TaskResult.objects.count() == 0

    @pytest.mark.parametrize("task_id", [str(uuid.uuid4()), "not-a-uuid", "A" * 36])
    def test_unknown_or_malformed_task_ids_look_the_same_as_not_assigned(self, api_client, enrolled, server_key, task_id):
        """Same answer for "no such task" and "not yours", so a node cannot probe which task ids exist."""
        node, key = enrolled
        path, body = path_for(task_id), b"{}"
        headers = sign_request(key, str(node.id), "POST", path, body)
        response = api_client.post(path, data=body, content_type="application/json", **meta(headers))
        assert response.status_code == 403 and code_of(response) == "RESULT_NOT_ASSIGNED"
        assert "Traceback" not in response.content.decode()

    def test_queued_task_cannot_receive_a_result(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        task = make_task(node, status=Task.Status.QUEUED)
        response = post(api_client, *submission(key, node.id, task.id, server_key[1]))
        assert response.status_code == 409 and code_of(response) == "TASK_INVALID_STATE"

    def test_revoked_node_cannot_submit(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        task = make_task(node)
        Node.objects.filter(pk=node.pk).update(status="revoked", revoked_at=timezone.now(), revoke_reason="test")
        response = post(api_client, *submission(key, node.id, task.id, server_key[1]))
        assert response.status_code == 403 and code_of(response) == "NODE_REVOKED"

    def test_stale_submission_is_refused(self, api_client, enrolled, server_key, make_task):
        import time

        node, key = enrolled
        task = make_task(node)
        response = post(api_client, *submission(key, node.id, task.id, server_key[1], ts=int(time.time()) - 3600))
        assert response.status_code == 401 and code_of(response) == "HEARTBEAT_STALE"

    def test_spoofed_node_is_refused(self, api_client, enrolled, server_key, make_task):
        node, _ = enrolled
        task = make_task(node)
        response = post(api_client, *submission(generate_private_key(), node.id, task.id, server_key[1]))
        assert response.status_code == 401 and code_of(response) == "NODE_SIGNATURE_INVALID"


@pytest.mark.django_db
class TestInputLimitsAndConfiguration:
    def test_oversized_body_is_refused_before_it_is_read(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        task = make_task(node)
        path = path_for(task.id)
        headers = sign_request(key, str(node.id), "POST", path, b"x")
        response = api_client.post(path, data=b"x" * 70_000, content_type="application/json", **meta(headers))
        assert response.status_code == 413 and code_of(response) == "PAYLOAD_TOO_LARGE"

    def test_signed_non_json_and_bad_envelopes_are_refused(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        task = make_task(node)
        path = path_for(task.id)
        for body, expected in ((b"not json", "MALFORMED_REQUEST"), (b'{"ciphertext":"AAAA"}', "VALIDATION_ERROR"),
                               (b'{"ephemeral_public_key":1,"nonce":2,"ciphertext":3}', "VALIDATION_ERROR")):
            headers = sign_request(key, str(node.id), "POST", path, body)
            response = api_client.post(path, data=body, content_type="application/json", **meta(headers))
            assert code_of(response) == expected, body
        assert TaskResult.objects.count() == 0

    def test_missing_server_key_is_a_clean_500_without_details(self, api_client, enrolled, make_task, settings):
        from nodes import server_keys

        settings.RESULT_KEY_FILE = ""
        server_keys._load.cache_clear()
        node, key = enrolled
        task = make_task(node)
        key_b64 = x25519_public_to_b64(generate_x25519_private_key().public_key())
        response = post(api_client, *submission(key, node.id, task.id, key_b64))
        assert response.status_code == 500 and code_of(response) == "INTERNAL_ERROR"
        assert "RESULT_KEY_FILE" not in response.content.decode()
        assert AuditEvent.objects.filter(action="result.rejected", reason_code="INTERNAL_ERROR").exists()

    def test_rate_limit(self, api_client, enrolled, server_key, make_task, monkeypatch):
        monkeypatch.setattr(NodeResultThrottle, "rate", "2/min")
        node, key = enrolled
        task = make_task(node)
        codes = [post(api_client, *submission(key, node.id, task.id, server_key[1])).status_code for _ in range(3)]
        assert codes[:2] == [201, 409] and codes[2] == 429

    def test_database_allows_one_valid_result_per_task(self, enrolled, make_task):
        from django.db import IntegrityError, transaction

        node, _ = enrolled
        task = make_task(node)
        fields = dict(task=task, node=node, ephemeral_public_key="A" * 44, nonce="B" * 16, ciphertext="C" * 40, integrity_valid=True)
        TaskResult.objects.create(**fields)
        with pytest.raises(IntegrityError), transaction.atomic():
            TaskResult.objects.create(**fields)
        TaskResult.objects.create(**{**fields, "integrity_valid": False, "reason_code": "RESULT_INTEGRITY_FAILED"})  # failed attempts may repeat


@pytest.mark.django_db
class TestViewingResults:
    def submitted(self, api_client, enrolled, server_key, make_task):
        node, key = enrolled
        task = make_task(node)
        assert post(api_client, *submission(key, node.id, task.id, server_key[1])).status_code == 201
        return task

    def test_operator_sees_the_decrypted_result_and_the_view_is_audited(self, api_client, client_as, enrolled, server_key, make_task):
        task = self.submitted(api_client, enrolled, server_key, make_task)
        response = client_as("operator").get(f"/api/v1/tasks/{task.id}/result/")
        assert response.status_code == 200
        body = response.json()
        assert body["integrity_valid"] is True and body["result"] == {"checksum": "ab12", "note": MARKER}
        assert body["plaintext_sha256"] and response["Cache-Control"] == "no-store"
        assert AuditEvent.objects.filter(action="result.view", target_id=str(task.id)).count() == 1

    def test_viewer_and_anonymous_are_refused(self, api_client, client_as, enrolled, server_key, make_task):
        task = self.submitted(api_client, enrolled, server_key, make_task)
        assert client_as("viewer").get(f"/api/v1/tasks/{task.id}/result/").status_code == 403
        assert api_client.get(f"/api/v1/tasks/{task.id}/result/").status_code == 401

    def test_unknown_task_and_bad_id_are_404(self, client_as, server_key):
        operator = client_as("operator")
        assert operator.get(f"/api/v1/tasks/{uuid.uuid4()}/result/").status_code == 404
        assert operator.get("/api/v1/tasks/not-a-uuid/result/").status_code == 404

    def test_tampering_with_the_stored_ciphertext_is_caught_when_it_is_read(self, api_client, client_as, enrolled, server_key, make_task):
        task = self.submitted(api_client, enrolled, server_key, make_task)
        row = TaskResult.objects.get()
        TaskResult.objects.filter(pk=row.pk).update(ciphertext=flip(row.ciphertext))  # someone edits the database
        body = client_as("operator").get(f"/api/v1/tasks/{task.id}/result/").json()
        assert body["integrity_valid"] is False and body["reason_code"] == "RESULT_INTEGRITY_FAILED"
        assert body["result"] is None and MARKER not in json.dumps(body)
        assert AuditEvent.objects.filter(action="result.integrity_failure_at_rest").exists()

    def test_a_failed_attempt_is_shown_as_failed(self, api_client, client_as, enrolled, server_key, make_task):
        node, key = enrolled
        task = make_task(node)
        post(api_client, *submission(key, node.id, task.id, server_key[1], mutate=lambda e: {**e, "ciphertext": flip(e["ciphertext"])}))
        body = client_as("admin").get(f"/api/v1/tasks/{task.id}/result/").json()
        assert body["integrity_valid"] is False and body["reason_code"] == "RESULT_INTEGRITY_FAILED" and body["result"] is None