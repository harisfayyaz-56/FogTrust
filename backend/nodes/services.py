"""
Business rules for enrollment tokens, node enrollment (FR-1) and node revocation (FR-6).

Views stay thin and call these functions. Each function that changes state does the change,
its audit event and its Decision row inside ONE transaction, so an action can never succeed
without a record of it (and if the record cannot be written, the action is rolled back).
Failures are recorded AFTER the rolled-back transaction, as audit/services.py requires.

Enrollment check order (docs/api-contract.md, section 5.4):
    token -> key well-formed -> proof of possession -> key unused -> name unused -> create node
Every token failure looks identical to the client (ENROLL_TOKEN_INVALID); the precise reason
goes to the audit log and the Decision, which is what the T1 tests and the evidence view read.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
import uuid
from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from audit.services import log_event
from core.decisions import record_decision
from core.errors import APIError, ErrorCode
from fogtrust_crypto.keys import CryptoKeyError, public_key_fingerprint, public_key_from_b64, verify_enrollment_proof

from trust.models import PolicyConfig

from .models import EnrollmentToken, Node
from .signals import node_revoked

logger = logging.getLogger("fogtrust.nodes")

ENROLL_ENGINE = ("enrollment_gate", "1.0.0")
REVOKE_ENGINE = ("revocation_gate", "1.0.0")

TOKEN_BYTES = 32  # secrets.token_urlsafe(32) -> 43 URL-safe characters, 256 bits


def hash_token(raw_token: str) -> str:
    """SHA-256 hex. The raw token is high-entropy, so a fast hash is the right tool (no salt needed)."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- tokens


def create_enrollment_token(*, label: str, expires_in_minutes: int, created_by=None, request=None):
    """Create a one-time token. Returns (token_row, raw_token). The raw token exists only in this return value."""
    raw_token = secrets.token_urlsafe(TOKEN_BYTES)
    now = timezone.now()
    with transaction.atomic():
        token = EnrollmentToken.objects.create(
            token_hash=hash_token(raw_token),
            label=label,
            created_by=created_by,
            created_at=now,
            expires_at=now + timedelta(minutes=expires_in_minutes),
        )
        log_event(
            "enroll.token_create",
            "success",
            request=request,
            **_actor(created_by, "management-command"),
            target_type="token",
            target_id=str(token.id),
            details={"token_id": str(token.id), "token_label": label, "expires_at": token.expires_at.isoformat()},
        )
    return token, raw_token


def cancel_enrollment_token(token: EnrollmentToken, *, by, request=None) -> EnrollmentToken:
    """Cancel an unused token with a conditional UPDATE, so cancelling and redeeming cannot both win."""
    with transaction.atomic():
        changed = EnrollmentToken.objects.filter(
            pk=token.pk, used_at__isnull=True, cancelled_at__isnull=True
        ).update(cancelled_at=timezone.now())
        if changed == 1:
            log_event(
                "enroll.token_cancel",
                "success",
                request=request,
                **_actor(by, "management-command"),
                target_type="token",
                target_id=str(token.pk),
                details={"token_id": str(token.pk), "token_label": token.label},
            )
    token.refresh_from_db()
    if changed != 1:
        log_event(
            "enroll.token_cancel",
            "failure",
            request=request,
            **_actor(by, "management-command"),
            target_type="token",
            target_id=str(token.pk),
            reason_code=ErrorCode.CONFLICT,
            details={"token_id": str(token.pk), "state": token.state()},
        )
        raise APIError(ErrorCode.CONFLICT, message="Only an unused token can be cancelled.")
    return token


def _actor(user, system_name: str) -> dict:
    """Audit actor for an action done by a signed-in user, or by the server's own command line."""
    if user is not None:
        return {"actor": user}
    return {"actor_type": "system", "actor_id": system_name, "actor_role": ""}


# ------------------------------------------------------------------------ enrollment


class _Trace:
    """Collects the rules evaluated, in the shared decision format, and times the decision."""

    def __init__(self):
        self.rules: list[dict] = []
        self.policy_version: int | None = None
        self.initial_score: int | None = None
        self._started = time.perf_counter()

    def rule(self, name: str, passed: bool, detail: str) -> None:
        self.rules.append({"rule": name, "passed": passed, "detail": detail})

    @property
    def latency_ms(self) -> float:
        return round((time.perf_counter() - self._started) * 1000, 3)


class EnrollmentRefused(Exception):
    """Internal: a check failed. `client_code` is what the caller sees; `audit_code` is the precise reason."""

    def __init__(self, client_code: str, audit_code: str, explanation: str, token_id: str = "", evidence: dict | None = None):
        super().__init__(audit_code)
        self.client_code = client_code
        self.audit_code = audit_code
        self.explanation = explanation
        self.token_id = token_id
        self.evidence = evidence or {}


def _token_problem(token: EnrollmentToken, now):
    """Return (audit_code, explanation, state) if the token cannot be redeemed, else None."""
    state = token.state(now)
    if state == EnrollmentToken.State.CANCELLED:
        return ErrorCode.ENROLL_TOKEN_INVALID, "The enrollment token was cancelled.", state
    if state == EnrollmentToken.State.USED:
        return ErrorCode.ENROLL_TOKEN_USED, "The enrollment token was already used.", state
    if state == EnrollmentToken.State.EXPIRED:
        return ErrorCode.ENROLL_TOKEN_EXPIRED, "The enrollment token has expired.", state
    return None


def find_token(raw_token: str) -> EnrollmentToken | None:
    return EnrollmentToken.objects.filter(token_hash=hash_token(raw_token)).first()


def enroll_node(*, raw_token: str, name: str, public_key: str, capacity: int, proof: str, request=None) -> Node:
    """
    FR-1. Register a node, or raise APIError with the contract's client code.

    The node, the token redemption, the audit event and the Decision are one transaction.
    """
    trace = _Trace()
    try:
        with transaction.atomic():
            node = _enroll(trace, raw_token, name, public_key, capacity, proof)
            log_event(
                "node.enroll",
                "success",
                request=request,
                actor_type="node",
                actor_id=str(node.id),
                actor_role="node",
                target_type="node",
                target_id=str(node.id),
                details={
                    "node_name": node.name,
                    "token_id": str(node.enrolled_via_id),
                    "key_fingerprint_prefix": node.key_fingerprint[:8],
                    "capacity": node.capacity,
                },
            )
            record_decision(
                subject_type="enrollment",
                subject_id=str(node.id),
                decision="allow",
                reason_code="OK",
                explanation="Enrollment accepted: valid one-time token and proof of key possession.",
                rules_fired=trace.rules,
                evidence={
                    "node_id": str(node.id),
                    "node_name": node.name,
                    "token_id": str(node.enrolled_via_id),
                    "key_fingerprint_prefix": node.key_fingerprint[:8],
                    "initial_trust_score": node.trust_score,
                },
                engine_name=ENROLL_ENGINE[0],
                engine_version=ENROLL_ENGINE[1],
                policy_version=trace.policy_version,
                thresholds={"initial_score": trace.initial_score},
                request=request,
                latency_ms=trace.latency_ms,
            )
        return node
    except EnrollmentRefused as refusal:
        _record_refusal(trace, refusal, name, request)
        raise APIError(refusal.client_code) from None


def _enroll(trace: _Trace, raw_token, name, public_key, capacity, proof) -> Node:
    now = timezone.now()

    # 1. token
    token = find_token(raw_token)
    if token is None:
        trace.rule("token_valid", False, "no token with this value exists")
        raise EnrollmentRefused(ErrorCode.ENROLL_TOKEN_INVALID, ErrorCode.ENROLL_TOKEN_INVALID, "The enrollment token is not recognised.")
    problem = _token_problem(token, now)
    if problem:
        audit_code, explanation, state = problem
        trace.rule("token_valid", False, f"token is {state}")
        raise EnrollmentRefused(
            ErrorCode.ENROLL_TOKEN_INVALID, audit_code, explanation, str(token.id), {"state": state}
        )
    trace.rule("token_valid", True, "token exists, is unused, not cancelled and not expired")

    # 2. key well formed
    try:
        public_key_from_b64(public_key)
    except CryptoKeyError:
        trace.rule("key_well_formed", False, "not a canonical base64 Ed25519 public key")
        raise EnrollmentRefused(
            ErrorCode.ENROLL_KEY_INVALID, ErrorCode.ENROLL_KEY_INVALID, "The public key is not a valid Ed25519 key.", str(token.id)
        ) from None
    fingerprint = public_key_fingerprint(public_key)
    trace.rule("key_well_formed", True, "valid Ed25519 public key")

    # 3. proof of possession
    if not verify_enrollment_proof(public_key, raw_token, name, proof):
        trace.rule("proof_of_possession", False, "proof was not signed by the private key for this public key")
        raise EnrollmentRefused(
            ErrorCode.ENROLL_PROOF_INVALID,
            ErrorCode.ENROLL_PROOF_INVALID,
            "The proof of key possession did not verify.",
            str(token.id),
            {"key_fingerprint_prefix": fingerprint[:8]},
        )
    trace.rule("proof_of_possession", True, "signature over token, name and key verifies")

    # 4. key unused, 5. name unused
    if Node.objects.filter(public_key=public_key).exists():
        trace.rule("key_unused", False, "this public key already belongs to a node")
        raise EnrollmentRefused(
            ErrorCode.ENROLL_KEY_IN_USE, ErrorCode.ENROLL_KEY_IN_USE, "This public key is already registered.", str(token.id),
            {"key_fingerprint_prefix": fingerprint[:8]},
        )
    trace.rule("key_unused", True, "no node uses this public key")
    if Node.objects.filter(name=name).exists():
        trace.rule("name_unused", False, "a node with this name exists")
        raise EnrollmentRefused(ErrorCode.NODE_NAME_TAKEN, ErrorCode.NODE_NAME_TAKEN, "A node with this name already exists.", str(token.id))
    trace.rule("name_unused", True, "no node uses this name")

    # 6. the starting trust score comes from the administrator's policy, not from this module
    policy = PolicyConfig.current()
    initial_score = policy.values.get("initial_score", settings.INITIAL_TRUST_SCORE)
    if not isinstance(initial_score, int) or isinstance(initial_score, bool) or not 0 <= initial_score <= 100:
        initial_score = settings.INITIAL_TRUST_SCORE
    trace.policy_version, trace.initial_score = policy.version, initial_score
    trace.rule("initial_trust_from_policy", True, f"policy v{policy.version} sets the starting trust score to {initial_score}")

    # 7. create the node and redeem the token together
    try:
        with transaction.atomic():  # savepoint: a unique-constraint race must not poison the outer transaction
            node = Node.objects.create(
                id=uuid.uuid4(),
                name=name,
                public_key=public_key,
                key_fingerprint=fingerprint,
                capacity=capacity,
                trust_score=initial_score,
                enrolled_at=now,
                enrolled_via=token,
            )
    except IntegrityError:
        if Node.objects.filter(public_key=public_key).exists():
            raise EnrollmentRefused(ErrorCode.ENROLL_KEY_IN_USE, ErrorCode.ENROLL_KEY_IN_USE, "This public key is already registered.", str(token.id)) from None
        raise EnrollmentRefused(ErrorCode.NODE_NAME_TAKEN, ErrorCode.NODE_NAME_TAKEN, "A node with this name already exists.", str(token.id)) from None

    # The conditional UPDATE is the real one-time guarantee: of two requests holding the same
    # token, only one changes a row. The loser's node insert is rolled back with the transaction.
    redeemed = EnrollmentToken.objects.filter(
        pk=token.pk, used_at__isnull=True, cancelled_at__isnull=True, expires_at__gt=now
    ).update(used_at=now, used_by_node=node)
    if redeemed != 1:
        fresh = EnrollmentToken.objects.get(pk=token.pk)
        audit_code, explanation, state = _token_problem(fresh, timezone.now()) or (
            ErrorCode.ENROLL_TOKEN_USED, "The enrollment token was already used.", "used",
        )
        trace.rule("token_redeemed_once", False, f"token became {state} before it could be redeemed")
        raise EnrollmentRefused(ErrorCode.ENROLL_TOKEN_INVALID, audit_code, explanation, str(token.id), {"state": state})
    trace.rule("token_redeemed_once", True, "token marked used in the same transaction as the node")
    return node


def _record_refusal(trace: _Trace, refusal: EnrollmentRefused, name: str, request) -> None:
    """Audit event and Decision for a refused enrollment. Runs after the transaction has rolled back."""
    details = {"node_name": name, "client_code": refusal.client_code, **refusal.evidence}
    if refusal.token_id:
        details["token_id"] = refusal.token_id
    with transaction.atomic():
        log_event(
            "node.enroll",
            "failure",
            request=request,
            actor_type="anonymous",
            target_type="token" if refusal.token_id else "",
            target_id=refusal.token_id,
            reason_code=refusal.audit_code,
            details=details,
        )
        record_decision(
            subject_type="enrollment",
            subject_id=refusal.token_id,
            decision="deny",
            reason_code=refusal.audit_code,
            explanation=refusal.explanation,
            rules_fired=trace.rules,
            evidence=details,
            engine_name=ENROLL_ENGINE[0],
            engine_version=ENROLL_ENGINE[1],
            request=request,
            latency_ms=trace.latency_ms,
        )


def audit_enroll_rejection(request, code: str, details: dict | None = None) -> None:
    """Record an enrollment request refused before any check ran (bad JSON, bad fields, too large)."""
    log_event(
        "node.enroll",
        "failure",
        request=request,
        actor_type="anonymous",
        reason_code=code,
        details=details or {},
    )


# ------------------------------------------------------------------------ revocation


def revoke_node(node: Node, *, reason: str, by=None, source: str = Node.RevokeSource.MANUAL, request=None) -> Node:
    """
    FR-6. Permanently revoke a node.

    `by` is the administrator for a manual revocation; None with source="automatic" is the trust
    engine (Member 3) revoking a node whose score fell below the policy limit. The status change,
    audit event and Decision are one transaction; `node_revoked` is sent after commit so the
    scheduler can requeue the node's tasks. The conditional UPDATE means two simultaneous
    revocations produce exactly one success and one NODE_ALREADY_REVOKED.
    """
    started = time.perf_counter()
    now = timezone.now()
    actor = _actor(by, "trust-engine")
    try:
        with transaction.atomic():
            changed = Node.objects.filter(pk=node.pk, status=Node.Status.ACTIVE).update(
                status=Node.Status.REVOKED,
                revoked_at=now,
                revoked_by=by,
                revoke_reason=reason,
                revoke_source=source,
            )
            if changed != 1:
                raise _AlreadyRevoked
            log_event(
                "node.revoke",
                "success",
                request=request,
                **actor,
                target_type="node",
                target_id=str(node.pk),
                details={"node_name": node.name, "reason": reason, "source": source},
            )
            record_decision(
                subject_type="node",
                subject_id=str(node.pk),
                decision="revoke",
                reason_code="OK",
                explanation=(
                    "Node revoked by an administrator."
                    if source == Node.RevokeSource.MANUAL
                    else "Node revoked automatically because its trust score fell below the policy limit."
                ),
                rules_fired=[
                    {"rule": "node_was_active", "passed": True, "detail": "status was active"},
                    {
                        "rule": "authorised_revocation",
                        "passed": True,
                        "detail": "administrator confirmed the node name" if by else "automatic policy action",
                    },
                ],
                evidence={"node_id": str(node.pk), "node_name": node.name, "source": source, "reason": reason},
                engine_name=REVOKE_ENGINE[0],
                engine_version=REVOKE_ENGINE[1],
                request=request,
                latency_ms=round((time.perf_counter() - started) * 1000, 3),
            )
            transaction.on_commit(lambda: _announce_revocation(node.pk, source, reason))
    except _AlreadyRevoked:
        log_event(
            "node.revoke",
            "failure",
            request=request,
            **actor,
            target_type="node",
            target_id=str(node.pk),
            reason_code=ErrorCode.NODE_ALREADY_REVOKED,
            details={"node_name": node.name},
        )
        raise APIError(ErrorCode.NODE_ALREADY_REVOKED) from None
    node.refresh_from_db()
    return node


class _AlreadyRevoked(Exception):
    pass


def _announce_revocation(node_id, source: str, reason: str) -> None:
    node = Node.objects.get(pk=node_id)
    for receiver, outcome in node_revoked.send_robust(sender=Node, node=node, source=source, reason=reason):
        if isinstance(outcome, Exception):
            logger.error("node_revoked receiver %s failed: %r", getattr(receiver, "__name__", receiver), outcome)


def reject_unconfirmed_revocation(node: Node, *, request) -> APIError:
    """Audit an attempt to revoke without typing the node's name, and return the error to raise."""
    log_event(
        "node.revoke",
        "failure",
        request=request,
        target_type="node",
        target_id=str(node.pk),
        reason_code=ErrorCode.CONFIRMATION_REQUIRED,
        details={"node_name": node.name},
    )
    return APIError(ErrorCode.CONFIRMATION_REQUIRED)
