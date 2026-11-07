"""
Trust services layer (Member 3).

Gathers metrics from database and invokes trust.engine.compute_trust_score().
Saves TrustScoreRecord, updates Node.trust_score, and manages PolicyConfig.
"""

from __future__ import annotations

import time
from typing import Any

from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from audit.services import log_event
from core.errors import ErrorCode
from core.models import Decision
from nodes.models import Node
from trust.engine import NodeMetrics, compute_trust_score
from trust.models import PolicyConfig, TrustScoreRecord


def recompute_node_score(
    node: Node,
    increment_missed_heartbeats: int = 0,
    increment_signature_failures: int = 0,
    increment_task_failures: int = 0,
    increment_integrity_failures: int = 0,
    increment_task_successes: int = 0,
    increment_heartbeat_successes: int = 0,
    increment_load_inconsistencies: int = 0,
    request=None,
) -> TrustScoreRecord:
    """
    Computes and records an updated trust score for a node.
    Performs auto-revocation if the score falls to or below policy threshold.
    """
    policy = PolicyConfig.current()

    metrics = NodeMetrics(
        missed_heartbeats=increment_missed_heartbeats,
        signature_failures=increment_signature_failures,
        task_failures=increment_task_failures,
        integrity_failures=increment_integrity_failures,
        task_successes=increment_task_successes,
        heartbeat_successes=increment_heartbeat_successes,
        load_inconsistencies=increment_load_inconsistencies,
    )

    decision = compute_trust_score(
        current_score=node.trust_score,
        policy_values=policy.values,
        metrics=metrics,
        policy_version=policy.version,
    )

    with transaction.atomic():
        old_score = node.trust_score
        node.trust_score = decision.new_score
        record = TrustScoreRecord.objects.create(
            node=node,
            score=decision.new_score,
            previous_score=old_score,
            rules_fired=decision.rules_fired,
            policy_version=policy.version,
        )

        # Check for auto-revocation
        if decision.should_auto_revoke and node.status == Node.Status.ACTIVE:
            node.status = Node.Status.REVOKED
            node.revoked_at = timezone.now()
            node.revoke_source = Node.RevokeSource.AUTOMATIC
            node.revoke_reason = f"Trust score ({decision.new_score}) breached auto-revoke threshold ({policy.values.get('auto_revoke_below', 10)})"

            log_event(
                action="node.revoke",
                outcome="success",
                request=request,
                actor_type="system",
                actor_id="trust_engine",
                actor_role="system",
                target_type="node",
                target_id=str(node.id),
                details={
                    "node_name": node.name,
                    "reason": node.revoke_reason,
                    "source": "automatic",
                    "final_trust_score": decision.new_score,
                },
            )

        node.save(update_fields=["trust_score", "status", "revoked_at", "revoke_source", "revoke_reason"])

    # Decision audit record
    Decision.objects.create(
        subject_type="node",
        subject_id=str(node.id),
        decision=Decision.DecisionOutcome.SCORE,
        reason_code="OK",
        explanation=decision.explanation,
        rules_fired=decision.rules_fired,
        evidence={
            "node_name": node.name,
            "old_score": old_score,
            "new_score": decision.new_score,
            "auto_revoked": decision.should_auto_revoke,
        },
        engine_name="trust_score_engine",
        engine_version="1.0.0",
        policy_version=policy.version,
        thresholds=policy.values,
        decided_at=timezone.now(),
        latency_ms=decision.latency_ms,
    )

    return record


def create_policy(admin_user, values: dict[str, Any], change_reason: str, request=None) -> PolicyConfig:
    """
    Validates and creates an immutable, incremented policy version.
    """
    if not change_reason or len(change_reason.strip()) < 5:
        raise ValidationError({"change_reason": "Change reason of at least 5 characters is required."})

    required_keys = ["trust_threshold", "weights"]
    for k in required_keys:
        if k not in values:
            raise ValidationError({"values": f"Missing required policy configuration key: {k}"})

    latest = PolicyConfig.objects.order_by("-version").first()
    new_version = (latest.version + 1) if latest else 1

    merged_values = dict(latest.values if latest else {})
    merged_values.update(values)

    with transaction.atomic():
        policy = PolicyConfig.objects.create(
            version=new_version,
            values=merged_values,
            changed_by=admin_user,
            change_reason=change_reason.strip(),
        )

        log_event(
            action="policy.change",
            outcome="success",
            request=request,
            actor=admin_user,
            target_type="policy",
            target_id=str(policy.version),
            details={
                "version": policy.version,
                "change_reason": policy.change_reason,
                "updated_keys": list(values.keys()),
            },
        )

    return policy

