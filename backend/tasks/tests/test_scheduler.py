from datetime import timedelta
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from audit.models import AuditEvent
from nodes.models import Node
from tasks.models import Task
from tasks.services import assign_next_task, detect_stalled_tasks
from trust.models import PolicyConfig

User = get_user_model()


class SchedulerAndT3T6Tests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="test_op", password="password123", role="operator")
        self.policy = PolicyConfig.objects.create(
            version=1,
            values={
                "trust_threshold": 60,
                "initial_score": 80,
                "auto_revoke_below": 10,
                "weights": {
                    "task_failure": -15,
                    "task_success": 5,
                },
            },
            change_reason="Test policy",
        )

    def test_T3_failed_worker_reassigns_task_and_penalizes_node(self):
        """
        T3: Worker crashes or stalls mid-task.
        Broker detects stall, reclaims load, penalizes node trust score, and reassigns task.
        """
        node_a = Node.objects.create(
            name="worker-alpha",
            public_key="k" * 44,
            key_fingerprint="fp1",
            trust_score=85,
            capacity=2,
            current_load=0,
            status=Node.Status.ACTIVE,
            last_seen_at=timezone.now() - timedelta(minutes=15),  # 15 mins inactive
        )

        task = Task.objects.create(
            task_type="checksum",
            payload={"sample": "data"},
            priority=1,
            status=Task.Status.QUEUED,
            idempotency_key="t3-key-1",
            created_by=self.user,
        )

        # 1. Assign to node A
        assigned_task = assign_next_task(task)
        self.assertIsNotNone(assigned_task)
        self.assertEqual(assigned_task.assigned_node, node_a)
        node_a.refresh_from_db()
        self.assertEqual(node_a.current_load, 1)

        # 2. Run detect_stalled_tasks
        stalled = detect_stalled_tasks(stall_seconds=60)
        self.assertEqual(len(stalled), 1)

        # 3. Assert task status reverted to queued and node penalized
        task.refresh_from_db()
        self.assertEqual(task.status, Task.Status.QUEUED)
        self.assertIsNone(task.assigned_node)
        self.assertEqual(task.attempts, 1)

        node_a.refresh_from_db()
        self.assertEqual(node_a.current_load, 0)
        # Trust dropped by task_failure weight (-15): 85 - 15 = 70
        self.assertEqual(node_a.trust_score, 70)

        # Audit event recorded
        reassign_event = AuditEvent.objects.filter(action="task.reassign", target_id=str(task.id)).first()
        self.assertIsNotNone(reassign_event)

    def test_T6_trust_aware_vs_round_robin_load_balancing(self):
        """
        T6: Comparison experiment between trust-aware load balancing and naive round-robin.
        Nodes with trust < 60 must NEVER receive tasks in trust-aware mode.
        """
        # Create 5 nodes: 2 untrusted, 3 trusted with different capacities
        n1 = Node.objects.create(name="node-untrusted-1", public_key="k1"*22, key_fingerprint="f1", trust_score=30, capacity=5)
        n2 = Node.objects.create(name="node-untrusted-2", public_key="k2"*22, key_fingerprint="f2", trust_score=55, capacity=5)
        n3 = Node.objects.create(name="node-trusted-3", public_key="k3"*22, key_fingerprint="f3", trust_score=70, capacity=5)
        n4 = Node.objects.create(name="node-trusted-4", public_key="k4"*22, key_fingerprint="f4", trust_score=85, capacity=5)
        n5 = Node.objects.create(name="node-trusted-5", public_key="k5"*22, key_fingerprint="f5", trust_score=95, capacity=5)

        # Create 9 tasks
        tasks = [
            Task.objects.create(
                task_type="checksum",
                payload={"i": i},
                priority=1,
                status=Task.Status.QUEUED,
                idempotency_key=f"t6-task-{i}",
                created_by=self.user,
            )
            for i in range(9)
        ]

        # Dispatch with trust-aware scheduling
        for t in tasks:
            assigned = assign_next_task(t, mode="trust_aware")
            self.assertIsNotNone(assigned)

        n1.refresh_from_db()
        n2.refresh_from_db()
        n3.refresh_from_db()
        n4.refresh_from_db()
        n5.refresh_from_db()

        # Untrusted nodes got zero tasks
        self.assertEqual(n1.current_load, 0)
        self.assertEqual(n2.current_load, 0)

        # The 9 tasks were distributed evenly among the 3 trusted nodes (3 each)
        self.assertEqual(n3.current_load, 3)
        self.assertEqual(n4.current_load, 3)
        self.assertEqual(n5.current_load, 3)

