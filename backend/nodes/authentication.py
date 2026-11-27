"""
Authentication of requests made BY nodes (api-contract.md section 2.2).

A node has no password and no session. Every request it makes carries four headers and an
Ed25519 signature over the method, path, timestamp, nonce and body hash. This class verifies
them with Member 2's engine and, only if they all pass, hands the view the authenticated
`Node` as `request.auth`:

    class MyNodeView(APIView):
        authentication_classes = [NodeSignatureAuthentication]
        permission_classes = [IsEnrolledNode]
        throttle_classes = [NodeRequestThrottle]

Checks, in the contract's order: headers present, node exists, node active (BEFORE the
signature), signature valid, timestamp inside the policy window, nonce never used before.
Every refusal is audited (`node.auth` / failure) and stored as a Decision, and the client sees
only a generic code.

Design notes
  * A failed signature is NOT charged to the node's trust score. The node id is public, so
    anyone could send garbage signatures "as" a victim to drive its score down and get an
    honest node auto-revoked. Only requests that authenticated can affect a score.
  * An anonymous flood cannot fill the audit log: after `node_auth_failed` failures a minute from
    one client IP, further bad requests are still refused, but only one summary event a minute
    is written. The IP is never blocked, so a flood cannot lock honest nodes out.
"""

from __future__ import annotations

import time

from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from rest_framework.authentication import BaseAuthentication
from rest_framework.permissions import BasePermission
from rest_framework.throttling import SimpleRateThrottle

from audit.services import log_event
from core.decisions import record_decision_dict
from core.errors import APIError, ErrorCode
from fogtrust_crypto import codes
from fogtrust_crypto.node_auth import verify_node_request
from fogtrust_crypto.replay import DEFAULT_WINDOW_S, check_freshness, check_nonce
from fogtrust_crypto.result import Run, VerificationResult
from trust.models import PolicyConfig

from .models import Node
from .node_auth import lookup_node
from .replay_store import DatabaseReplayStore

ENGINE_NAME = "node_request_verifier"


def policy_window_s() -> int:
    """The administrator's `timestamp_window_s`, bounded so a bad value cannot disable the check."""
    value = PolicyConfig.current().values.get("timestamp_window_s", DEFAULT_WINDOW_S)
    if isinstance(value, bool) or not isinstance(value, int) or not 5 <= value <= 300:
        return DEFAULT_WINDOW_S
    return value


def verify_signed_request(headers, method, path, body, *, store=None, window_s=None, now=None) -> VerificationResult:
    """Signature, then timestamp window, then one-time nonce. Pure of HTTP: easy to test."""
    window_s = window_s or policy_window_s()
    store = store or DatabaseReplayStore()
    base = verify_node_request(headers, method, path, body, lookup_node)
    if not base.accepted:
        return base
    run = Run(ENGINE_NAME, {"timestamp_window_s": window_s}, base)
    denial = check_freshness(run, time.time() if now is None else now, window_s) or check_nonce(run, store, window_s)
    return denial or run.allow("Signed request accepted.")


class FailedNodeAuthLimiter(SimpleRateThrottle):
    """Counts FAILED node authentications per client IP, to bound how many audit rows a flood can write."""

    scope = "node_auth_failed"

    def get_cache_key(self, request, view):
        return self.cache_format % {"scope": self.scope, "ident": self.get_ident(request)}

    def record_failure(self, request) -> bool:
        """Count one failure. True while the client is still inside its budget for this minute."""
        self.key = self.get_cache_key(request, None)
        history = [t for t in self.cache.get(self.key, []) if t > self.timer() - self.duration]
        within_budget = len(history) < self.num_requests
        history.insert(0, self.timer())
        self.cache.set(self.key, history[: self.num_requests + 1], self.duration)
        return within_budget


class NodeSignatureAuthentication(BaseAuthentication):
    # IMPORTANT: inside authenticate() never let anything read `request.user`. DRF would start
    # authenticating again (it is not finished yet), which recurses and loses the audit rows.
    # Hence every log_event below is given an explicit `actor`.

    def authenticate(self, request):
        limiter = FailedNodeAuthLimiter()
        body = self._read_body(request, limiter)
        result = verify_signed_request(request.headers, request.method, request.get_full_path(), body)
        if not result.accepted:
            if limiter.record_failure(request):
                self._record_refusal(request, result)
            else:
                self._note_flood(request)
            raise APIError(result.reason_code)

        node = Node.objects.get(pk=result.node_id)
        return AnonymousUser(), node

    def authenticate_header(self, request):
        return "Ed25519-Signed-Request"

    @staticmethod
    def _read_body(request, limiter) -> bytes:
        limit = settings.NODE_REQUEST_MAX_BODY_BYTES
        declared = request.META.get("CONTENT_LENGTH", "")
        if (declared.isdigit() and int(declared) > limit) or len(request.body) > limit:
            if limiter.record_failure(request):
                log_event("node.auth", "failure", request=request, actor=AnonymousUser(), actor_type="anonymous", reason_code=codes.PAYLOAD_TOO_LARGE,
                          details={"method": request.method, "path": request.path})
            raise APIError(ErrorCode.PAYLOAD_TOO_LARGE)
        return request.body

    @staticmethod
    def _note_flood(request) -> None:
        """Past the budget: one summary event a minute per client instead of one per request."""
        if cache.add(f"audit-node-auth-flood:{request.META.get('REMOTE_ADDR', '')}", 1, timeout=60):
            log_event(
                "request.rate_limited",
                "denied",
                request=request,
                actor=AnonymousUser(),
                target_type="endpoint",
                reason_code=ErrorCode.RATE_LIMITED,
                details={"scope": "node_auth_failed", "path": request.path},
            )

    @staticmethod
    def _record_refusal(request, result: VerificationResult) -> None:
        # The node id here is only what the caller CLAIMED, so the actor stays anonymous.
        log_event(
            "node.auth",
            "failure",
            request=request,
            actor=AnonymousUser(),
            actor_type="anonymous",
            target_type="node" if result.node_id else "",
            target_id=result.node_id or "",
            reason_code=result.reason_code,
            details={"method": request.method, "path": request.path, "claimed_node_id": result.node_id or ""},
        )
        record_decision_dict(result.to_decision("node"), request=request)


class IsEnrolledNode(BasePermission):
    """Passes only when NodeSignatureAuthentication produced an active node."""

    def has_permission(self, request, view):
        node = request.auth
        return isinstance(node, Node) and node.status == Node.Status.ACTIVE


class NodeRequestThrottle(SimpleRateThrottle):
    """Per-node limit for authenticated node requests (so one chatty node cannot starve the others)."""

    scope = "node_request"

    def get_cache_key(self, request, view):
        node = request.auth
        if not isinstance(node, Node):
            return None
        return self.cache_format % {"scope": self.scope, "ident": str(node.pk)}
