"""
POST /node-api/tasks/{id}/result/  (FR-5, T4)   and   GET /tasks/{id}/result/

As with heartbeats the view is thin: fogtrust_crypto.verify_result_request makes the security decisions
(signature, freshness, nonce, assigned node, envelope, AES-GCM tag). This file adds what only the database
knows: the task's state, so a task can only be completed once, and the stored record.

What is stored, and where:
  accepted  -> TaskResult (ciphertext + SHA-256), Task completed, an `allow` Decision, audit `result.accepted`
  rejected  -> a `deny` Decision and audit `result.rejected`; a tampered ciphertext (T4) also keeps a failed TaskResult
Plaintext is never stored, logged or put in a Decision.
"""

import json
import uuid

from django.db import transaction
from django.utils import timezone
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import require
from audit.services import log_event
from core.decisions import record_decision_dict
from core.errors import APIError, ErrorCode
from fogtrust_crypto import codes
from fogtrust_crypto.node_auth import declared_length_too_large
from fogtrust_crypto.results import MAX_CIPHERTEXT_B64, MAX_RESULT_BODY_BYTES, decrypt_envelope, verify_result_request
from heartbeats.policy import current_policy
from nodes.replay_store import DatabaseReplayStore
from nodes.node_auth import lookup_node
from nodes.server_keys import load_server_private_key
from tasks.models import Task

from .models import TaskResult
from .throttles import IPResultThrottle, NodeResultThrottle


def _uuid_or_none(value):
    try:
        parsed = uuid.UUID(str(value))
    except ValueError:
        return None
    return parsed if str(parsed) == str(value) else None


def _stored_envelope(raw_body: bytes):
    """The three envelope fields, but only if they are shaped so they can be stored (None otherwise)."""
    try:
        env = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(env, dict) or set(env) != {"ephemeral_public_key", "nonce", "ciphertext"}:
        return None
    ek, nonce, ct = env["ephemeral_public_key"], env["nonce"], env["ciphertext"]
    if not all(isinstance(v, str) for v in (ek, nonce, ct)) or len(ek) != 44 or len(nonce) != 16 or len(ct) > MAX_CIPHERTEXT_B64:
        return None
    return {"ephemeral_public_key": ek, "nonce": nonce, "ciphertext": ct}


class NodeResultView(APIView):
    authentication_classes = []  # signed requests, not sessions: no CSRF (contract section 2.2)
    permission_classes = [AllowAny]
    throttle_classes = [IPResultThrottle, NodeResultThrottle]

    def post(self, request, task_id):
        if declared_length_too_large(request.META.get("CONTENT_LENGTH"), MAX_RESULT_BODY_BYTES):
            log_event("result.rejected", "failure", request=request, actor_type="anonymous",
                      reason_code=ErrorCode.PAYLOAD_TOO_LARGE, details={"limit_bytes": MAX_RESULT_BODY_BYTES})
            raise APIError(ErrorCode.PAYLOAD_TOO_LARGE)

        server_key = load_server_private_key()
        if server_key is None:  # a deployment mistake, not the node's fault: say so in the log, not to the node
            log_event("result.rejected", "failure", request=request, actor_type="system",
                      reason_code=ErrorCode.INTERNAL_ERROR, details={"cause": "FOGTRUST_RESULT_KEY_FILE not configured"})
            raise APIError(ErrorCode.INTERNAL_ERROR)

        raw_body = request.body  # the exact signed bytes
        window_s, _interval, policy_version = current_policy()
        task_uuid = _uuid_or_none(task_id)
        task = Task.objects.filter(pk=task_uuid).first() if task_uuid else None
        assigned = str(task.assigned_node_id) if task and task.assigned_node_id else None

        outcome = verify_result_request(
            request.headers, request.method, request.get_full_path(), raw_body, lookup_node,
            DatabaseReplayStore(), server_key, str(task_id), assigned, window_s=window_s,
        )
        now = timezone.now()
        if not outcome.accepted:
            self._reject(request, outcome.result, raw_body, task, policy_version, now)
            raise APIError(outcome.result.reason_code)

        node_id = outcome.result.node_id
        with transaction.atomic():
            # One conditional UPDATE decides who completes the task: a second valid-looking submission loses.
            won = Task.objects.filter(pk=task.pk, status=Task.Status.ASSIGNED, assigned_node_id=node_id).update(
                status=Task.Status.COMPLETED, completed_at=now
            )
            if won == 1:
                envelope = _stored_envelope(raw_body)
                TaskResult.objects.create(
                    task=task, node_id=node_id, integrity_valid=True, plaintext_sha256=outcome.plaintext_sha256,
                    received_at=now, **envelope,
                )
        if won != 1:
            task.refresh_from_db()
            result = outcome.result
            result.rules_fired.append({"rule": "task_state", "passed": False, "detail": f"task is {task.status}, not assigned"})
            decision = result.to_decision("result", subject_id=str(task.id))
            decision.update(decision="deny", reason_code=ErrorCode.TASK_INVALID_STATE, explanation="The task is not waiting for a result.")
            decision["policy_version"] = policy_version
            record_decision_dict(decision, request=request)
            log_event("result.rejected", "failure", request=request, actor_type="node", actor_id=node_id, actor_role="node",
                      target_type="task", target_id=str(task.id), reason_code=ErrorCode.TASK_INVALID_STATE, details=result.evidence)
            raise APIError(ErrorCode.TASK_INVALID_STATE)

        decision = outcome.result.to_decision("result", subject_id=str(task.id))
        decision["policy_version"] = policy_version
        record_decision_dict(decision, request=request)
        log_event("result.accepted", "success", request=request, actor_type="node", actor_id=node_id, actor_role="node",
                  target_type="task", target_id=str(task.id), details=outcome.result.evidence)
        response = Response({"accepted": True, "task_id": str(task.id), "status": "completed"}, status=201)
        response["Cache-Control"] = "no-store"
        return response

    @staticmethod
    def _reject(request, result, raw_body, task, policy_version, now):
        subject = str(task.id) if task else (result.node_id or "")
        decision = result.to_decision("result", subject_id=subject)
        decision["policy_version"] = policy_version
        record_decision_dict(decision, request=request)
        log_event(
            "result.rejected", "failure", request=request,
            actor_type="node" if result.node_id else "anonymous", actor_id=result.node_id or "", actor_role="node" if result.node_id else "",
            target_type="task" if task else "", target_id=str(task.id) if task else "",
            reason_code=result.reason_code, details=result.evidence,
        )
        # T4: a result that passed the signature but failed its integrity check is kept as evidence.
        if result.reason_code == codes.RESULT_INTEGRITY_FAILED and task and str(task.assigned_node_id) == result.node_id:
            envelope = _stored_envelope(raw_body)
            if envelope:
                TaskResult.objects.create(
                    task=task, node_id=result.node_id, integrity_valid=False, plaintext_sha256=None,
                    reason_code=codes.RESULT_INTEGRITY_FAILED, received_at=now, **envelope,
                )


class ResultDetailView(APIView):
    """The decrypted result for operators and admins. It decrypts at read time, so tampering AT REST is caught too."""

    permission_classes = [require("results.view")]

    def get(self, request, task_id):
        task_uuid = _uuid_or_none(task_id)
        row = None
        if task_uuid:
            rows = TaskResult.objects.filter(task_id=task_uuid)
            row = rows.filter(integrity_valid=True).first() or rows.first()
        if row is None:
            raise APIError(ErrorCode.NOT_FOUND)
        server_key = load_server_private_key()
        if server_key is None:
            raise APIError(ErrorCode.INTERNAL_ERROR)

        body = {
            "task": str(row.task_id), "node": str(row.node_id), "received_at": row.received_at,
            "integrity_valid": row.integrity_valid, "reason_code": row.reason_code,
            "plaintext_sha256": row.plaintext_sha256, "result": None, "result_text": None,
        }
        if row.integrity_valid:
            outcome = decrypt_envelope(
                server_key, str(row.node_id), str(row.task_id),
                {"ephemeral_public_key": row.ephemeral_public_key, "nonce": row.nonce, "ciphertext": row.ciphertext},
            )
            if outcome.accepted:
                try:
                    body["result"] = json.loads(outcome.plaintext.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    body["result_text"] = outcome.plaintext.decode("utf-8", errors="replace")
                if outcome.plaintext_sha256 != row.plaintext_sha256:  # stored hash no longer matches what decrypts
                    body.update(integrity_valid=False, reason_code=ErrorCode.RESULT_INTEGRITY_FAILED, result=None, result_text=None)
            else:
                body.update(integrity_valid=False, reason_code=outcome.result.reason_code)
            if not body["integrity_valid"]:
                log_event("result.integrity_failure_at_rest", "failure", request=request, target_type="task",
                          target_id=str(row.task_id), reason_code=body["reason_code"])
        log_event("result.view", "success", request=request, target_type="task", target_id=str(row.task_id))
        response = Response(body)
        response["Cache-Control"] = "no-store"
        return response