"""
Scheduler and task lifecycle service (Member 3).

Implements FR-3 (task queue, atomic dispatch, trust-aware load balancing vs round-robin),
and failed worker detection with automatic task reassignment (T3).
"""

from __future__ import annotations

import time
import uuid
from datetime import timedelta
from typing import Any

from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import APIException

from audit.services import log_event
from core.errors import ErrorCode
from core.models import Decision
from nodes.models import Node
from tasks.models import Task
from trust.models import PolicyConfig


class NoEligibleNodeError(APIException):
    status_code = 409
    default_code = ErrorCode.NO_ELIGIBLE_NODE
    default_detail = "No active node meeting the trust threshold has available capacity."


class TaskInvalidStateError(APIException):
    status_code = 409
    default_code = ErrorCode.TASK_INVALID_STATE
    default_detail = "Task is not in a valid state for this operation."


def assign_next_task(task: Task | None = None, mode: str = "trust_aware") -> Task | None:
    """
    Selects the next eligible queued task and assigns it atomically.
    Modes:
      - 'trust_aware': filters active nodes with trust_score >= policy threshold,
                       orders by current_load ASC (ties broken by higher trust).
      - 'round_robin': assigns to any active node with capacity in cyclic/ID order.
    Records Decision and AuditEvent on success or failure.
    """
    start_time = time.perf_counter()
    policy = PolicyConfig.current()
    trust_threshold = policy.values.get("trust_threshold", 60)

    with transaction.atomic():
        # 1. Lock candidate task
        if task is None:
            candidate_task = (
                Task.objects.select_for_update()
                .filter(status=Task.Status.QUEUED)
                .order_by("priority", "created_at")
                .first()
            )
        else:
            candidate_task = (
                Task.objects.select_for_update()
                .filter(id=task.id, status=Task.Status.QUEUED)
                .first()
            )

        if not candidate_task:
            return None

        # 2. Find eligible nodes with lock
        candidate_nodes = Node.objects.select_for_update().filter(status=Node.Status.ACTIVE)

        selected_node = None
        if mode == "trust_aware":
            # Filter strictly by trust threshold and spare capacity
            eligible_nodes = [
                n for n in candidate_nodes
                if n.trust_score >= trust_threshold and n.current_load < n.capacity
            ]
            if eligible_nodes:
                # Sort by current_load ascending, then higher trust descending
                eligible_nodes.sort(key=lambda n: (n.current_load, -n.trust_score))
                selected_node = eligible_nodes[0]
        else:
            # Round robin / naive: any node with spare capacity
            eligible_nodes = [n for n in candidate_nodes if n.current_load < n.capacity]
            if eligible_nodes:
                eligible_nodes.sort(key=lambda n: n.enrolled_at)
                selected_node = eligible_nodes[0]

        now = timezone.now()
        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 3)

        if not selected_node:
            Decision.objects.create(
                subject_type="task",
                subject_id=str(candidate_task.id),
                decision=Decision.DecisionOutcome.DENY,
                reason_code=ErrorCode.NO_ELIGIBLE_NODE,
                explanation=f"No active node met trust threshold ({trust_threshold}) with available capacity.",
                rules_fired=[
                    {"rule": "trust_threshold", "threshold": trust_threshold, "passed": False},
                    {"rule": "capacity_available", "passed": False},
                ],
                evidence={"mode": mode, "candidate_nodes_evaluated": len(candidate_nodes)},
                engine_name="scheduler_dispatcher",
                engine_version="1.0.0",
                policy_version=policy.version,
                thresholds={"trust_threshold": trust_threshold},
                decided_at=now,
                latency_ms=latency_ms,
            )
            return None

        # 3. Assign atomically
        candidate_task.status = Task.Status.ASSIGNED
        candidate_task.assigned_node = selected_node
        candidate_task.assigned_at = now
        candidate_task.attempts += 1
        candidate_task.save(update_fields=["status", "assigned_node", "assigned_at", "attempts"])

        selected_node.current_load += 1
        selected_node.save(update_fields=["current_load"])

        # 4. Decision and audit record
        Decision.objects.create(
            subject_type="task",
            subject_id=str(candidate_task.id),
            decision=Decision.DecisionOutcome.ASSIGN,
            reason_code="OK",
            explanation=f"Task assigned to node {selected_node.name} (trust={selected_node.trust_score}, load={selected_node.current_load}/{selected_node.capacity})",
            rules_fired=[
                {"rule": "trust_threshold", "threshold": trust_threshold, "node_trust": selected_node.trust_score, "passed": True},
                {"rule": "capacity_check", "load": selected_node.current_load, "capacity": selected_node.capacity, "passed": True},
            ],
            evidence={
                "node_id": str(selected_node.id),
                "node_name": selected_node.name,
                "node_trust_score": selected_node.trust_score,
                "node_load": selected_node.current_load,
                "mode": mode,
            },
            engine_name="scheduler_dispatcher",
            engine_version="1.0.0",
            policy_version=policy.version,
            thresholds={"trust_threshold": trust_threshold},
            decided_at=now,
            latency_ms=latency_ms,
        )

        log_event(
            action="task.assign",
            outcome="success",
            target_type="task",
            target_id=str(candidate_task.id),
            details={
                "node_id": str(selected_node.id),
                "node_name": selected_node.name,
                "trust_score": selected_node.trust_score,
                "mode": mode,
            },
        )

        return candidate_task


def detect_stalled_tasks(stall_seconds: int = 60) -> list[Task]:
    """
    T3: Detects worker crash or stall when an assigned node's last_seen_at
    exceeds stall_seconds. Reassigns the task or fails it after max attempts.
    Decrements node load and penalizes node trust score.
    """
    from trust.services import recompute_node_score

    now = timezone.now()
    cutoff = now - timedelta(seconds=stall_seconds)

    reassigned_or_failed: list[Task] = []

    with transaction.atomic():
        assigned_tasks = Task.objects.select_for_update().filter(
            status=Task.Status.ASSIGNED,
            assigned_node__isnull=False,
        )

        for task in assigned_tasks:
            node = task.assigned_node
            # Stalled if node hasn't been seen since before cutoff, or never seen after assigned
            is_stalled = False
            if node.last_seen_at:
                if node.last_seen_at < cutoff:
                    is_stalled = True
            elif task.assigned_at and task.assigned_at < cutoff:
                is_stalled = True

            if not is_stalled:
                continue

            # Decrement node load
            if node.current_load > 0:
                node.current_load -= 1
                node.save(update_fields=["current_load"])

            # Penalize node for worker crash
            recompute_node_score(node, increment_task_failures=1)

            if task.attempts < task.max_attempts:
                task.status = Task.Status.QUEUED
                task.assigned_node = None
                task.save(update_fields=["status", "assigned_node"])
                log_event(
                    action="task.reassign",
                    outcome="success",
                    target_type="task",
                    target_id=str(task.id),
                    details={
                        "stalled_node_id": str(node.id),
                        "stalled_node_name": node.name,
                        "attempt": task.attempts,
                        "max_attempts": task.max_attempts,
                    },
                )
            else:
                task.status = Task.Status.FAILED
                task.save(update_fields=["status"])
                log_event(
                    action="task.fail",
                    outcome="failure",
                    target_type="task",
                    target_id=str(task.id),
                    reason_code="WORKER_STALLED_MAX_ATTEMPTS",
                    details={
                        "stalled_node_id": str(node.id),
                        "stalled_node_name": node.name,
                        "attempts_reached": task.attempts,
                    },
                )

            reassigned_or_failed.append(task)

    return reassigned_or_failed

