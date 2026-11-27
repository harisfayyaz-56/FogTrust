"""
Scheduler side of FR-6: when a node is revoked, its in-flight tasks go back to the queue.

nodes.services.revoke_node() sends `node_revoked` after the revocation commits, for both a
manual revocation by an administrator and an automatic one by the trust engine. Without this
receiver, a revoked node's assigned tasks would stay "assigned" until the stall detector ran,
and the detector would also charge the node a task failure it never caused.

Rules (same limits as stall recovery in services.detect_stalled_tasks):
  * attempts left  -> back to QUEUED, no node, audited as task.reassign
  * no attempts    -> FAILED, audited as task.fail with reason NODE_REVOKED
  * the node's load returns to 0; its trust score is NOT changed (it is already revoked)
"""

from django.db import transaction
from django.dispatch import receiver

from audit.services import log_event
from core.errors import ErrorCode
from nodes.models import Node
from nodes.signals import node_revoked

from .models import Task

SCHEDULER_ACTOR = {"actor_type": "system", "actor_id": "scheduler", "actor_role": ""}


@receiver(node_revoked, dispatch_uid="tasks.requeue_tasks_of_revoked_node")
def requeue_tasks_of_revoked_node(sender, node, source, reason, **kwargs):
    with transaction.atomic():
        tasks = Task.objects.select_for_update().filter(assigned_node_id=node.pk, status=Task.Status.ASSIGNED)
        for task in tasks:
            details = {"revoked_node_id": str(node.pk), "revoked_node_name": node.name, "revoke_source": source}
            if task.attempts < task.max_attempts:
                task.status = Task.Status.QUEUED
                task.assigned_node = None
                task.assigned_at = None
                task.save(update_fields=["status", "assigned_node", "assigned_at"])
                log_event(
                    "task.reassign",
                    "success",
                    **SCHEDULER_ACTOR,
                    target_type="task",
                    target_id=str(task.id),
                    details={**details, "cause": "node_revoked", "attempt": task.attempts, "max_attempts": task.max_attempts},
                )
            else:
                task.status = Task.Status.FAILED
                task.save(update_fields=["status"])
                log_event(
                    "task.fail",
                    "failure",
                    **SCHEDULER_ACTOR,
                    target_type="task",
                    target_id=str(task.id),
                    reason_code=ErrorCode.NODE_REVOKED,
                    details={**details, "attempts_reached": task.attempts},
                )
        Node.objects.filter(pk=node.pk).update(current_load=0)
