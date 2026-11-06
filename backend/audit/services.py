"""
The only way to write to the audit log. Every slice calls log_event():

    from audit.services import log_event

    log_event("node.revoke", "success", request=request,
              target_type="node", target_id=str(node.id),
              details={"node_name": node.name, "reason": reason})

    # failures: give the precise error code, even if the client saw a generic one
    log_event("heartbeat.rejected", "failure", request=request,
              actor_type="node", actor_id=node_id, actor_role="node",
              reason_code=result.reason_code, details=result.evidence)

Rules for callers:
  * Write the audit event OUTSIDE any transaction.atomic() block that will be rolled
    back on failure, otherwise the record of the failure is rolled back with it.
  * Put only the fields you need in `details`. They are redacted and size-limited,
    but never pass a whole request body.
  * If the audit write fails, the exception propagates (fail closed): an action that
    cannot be recorded should not silently succeed.
"""

from __future__ import annotations

import ipaddress
import re
import time
import uuid

from django.db import IntegrityError, OperationalError, transaction
from django.utils import timezone

from .chain import CHAIN_FIELDS, GENESIS_HASH, compute_hash, verify_rows
from .models import AuditEvent
from .redaction import redact_details

ACTION_PATTERN = re.compile(r"^[a-z][a-z_]*(\.[a-z][a-z_]*)+$")
REASON_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")
MAX_ATTEMPTS = 5


def _client_ip(request) -> str:
    """REMOTE_ADDR only. X-Forwarded-For is ignored because any client can set it."""
    if request is None:
        return ""
    raw = request.META.get("REMOTE_ADDR", "")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ""


def _resolve_actor(request, actor):
    user = actor if actor is not None else getattr(request, "user", None)
    if user is not None and getattr(user, "is_authenticated", False):
        return AuditEvent.ActorType.USER, user.get_username(), getattr(user, "role", "") or ""
    return AuditEvent.ActorType.ANONYMOUS, "", ""


def log_event(
    action: str,
    outcome: str,
    *,
    request=None,
    actor=None,
    actor_type: str | None = None,
    actor_id: str | None = None,
    actor_role: str | None = None,
    target_type: str = "",
    target_id: str = "",
    reason_code: str = "",
    details: dict | None = None,
) -> AuditEvent:
    """Append one event to the chain and return it."""
    if not ACTION_PATTERN.fullmatch(action or ""):
        raise ValueError("action must look like 'area.verb', e.g. 'node.revoke'")
    if outcome not in AuditEvent.Outcome.values:
        raise ValueError(f"outcome must be one of {AuditEvent.Outcome.values}")
    if reason_code and not REASON_PATTERN.fullmatch(reason_code):
        raise ValueError("reason_code must be an error code such as 'NODE_REVOKED'")

    resolved_type, resolved_id, resolved_role = _resolve_actor(request, actor)
    if actor_type is not None:
        if actor_type not in AuditEvent.ActorType.values:
            raise ValueError(f"actor_type must be one of {AuditEvent.ActorType.values}")
        resolved_type = actor_type
        resolved_id = actor_id or ""
        resolved_role = actor_role or ""

    fields = {
        "event_id": uuid.uuid4(),
        "timestamp": timezone.now(),
        "actor_type": resolved_type,
        "actor_id": str(resolved_id)[:64],
        "actor_role": str(resolved_role)[:16],
        "action": action,
        "target_type": str(target_type)[:32],
        "target_id": str(target_id)[:64],
        "outcome": outcome,
        "reason_code": reason_code,
        "request_id": str(getattr(request, "request_id", "") or "")[:36],
        "source_ip": _client_ip(request),
        "details": redact_details(details),
    }

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            # IMMEDIATE transactions (config/settings.py) make "read the last event, then
            # insert the next one" a single serialised step. The unique prev_hash is the
            # backstop: two events can never claim the same parent, so the chain cannot fork.
            with transaction.atomic():
                last = AuditEvent.objects.order_by("-sequence").values_list("sequence", "hash").first()
                sequence, prev_hash = (last[0] + 1, last[1]) if last else (1, GENESIS_HASH)
                event = AuditEvent(sequence=sequence, prev_hash=prev_hash, **fields)
                event.hash = compute_hash(event.chain_fields())
                event.save()
                return event
        except (IntegrityError, OperationalError):
            if attempt == MAX_ATTEMPTS:
                raise
            time.sleep(0.01 * attempt)
    raise RuntimeError("unreachable")


def verify_chain():
    """Recompute every hash from the first event to the last. Returns a ChainReport."""
    rows = AuditEvent.objects.order_by("sequence").values(*CHAIN_FIELDS, "hash").iterator(chunk_size=2000)
    return verify_rows(rows)
