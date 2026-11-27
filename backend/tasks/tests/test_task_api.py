import uuid
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient

from core.errors import ErrorCode
from fogtrust_crypto.keys import generate_private_key, public_key_to_b64
from fogtrust_crypto.node_auth import sign_request
from nodes.models import Node
from tasks.models import Task
from trust.models import PolicyConfig

User = get_user_model()


class TaskAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.operator = User.objects.create_user(
            username="op_user", password="password123", role="operator"
        )
        self.viewer = User.objects.create_user(
            username="view_user", password="password123", role="viewer"
        )
        self.policy = PolicyConfig.objects.create(
            version=1,
            values={"trust_threshold": 60, "initial_score": 80, "weights": {}},
            change_reason="Default test policy",
        )
        self.node = Node.objects.create(
            name="worker-test",
            public_key="k" * 44,
            key_fingerprint="fp_test",
            trust_score=80,
            capacity=3,
            current_load=0,
            status=Node.Status.ACTIVE,
        )

    def test_submit_task_requires_idempotency_key(self):
        self.client.force_authenticate(user=self.operator)
        resp = self.client.post(
            "/api/v1/tasks/",
            {"task_type": "checksum", "payload": {"file": "sample.bin"}, "priority": 1},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(resp.data["error"]["code"], ErrorCode.VALIDATION_ERROR)

    def test_submit_task_success_and_immediate_assignment(self):
        self.client.force_authenticate(user=self.operator)
        resp = self.client.post(
            "/api/v1/tasks/",
            {"task_type": "checksum", "payload": {"file": "sample.bin"}, "priority": 1},
            format="json",
            HTTP_IDEMPOTENCY_KEY="idem-key-100",
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.data["status"], Task.Status.ASSIGNED)
        self.assertEqual(resp.data["assigned_node"], self.node.id)

    def test_duplicate_submission_rejected_with_409(self):
        self.client.force_authenticate(user=self.operator)
        data = {"task_type": "checksum", "payload": {"file": "sample.bin"}, "priority": 1}
        
        # First submission
        r1 = self.client.post("/api/v1/tasks/", data, format="json", HTTP_IDEMPOTENCY_KEY="idem-dup-1")
        self.assertEqual(r1.status_code, status.HTTP_201_CREATED)

        # Duplicate submission with same key
        r2 = self.client.post("/api/v1/tasks/", data, format="json", HTTP_IDEMPOTENCY_KEY="idem-dup-1")
        self.assertEqual(r2.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(r2.data["error"]["code"], ErrorCode.DUPLICATE_SUBMISSION)

    def test_viewer_role_cannot_submit_task(self):
        self.client.force_authenticate(user=self.viewer)
        resp = self.client.post(
            "/api/v1/tasks/",
            {"task_type": "checksum", "payload": {"file": "sample.bin"}, "priority": 1},
            format="json",
            HTTP_IDEMPOTENCY_KEY="idem-viewer-1",
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(resp.data["error"]["code"], ErrorCode.PERMISSION_DENIED)

    def test_cancel_queued_task(self):
        self.client.force_authenticate(user=self.operator)
        # Create queued task without eligible node
        self.node.current_load = self.node.capacity
        self.node.save()

        r1 = self.client.post(
            "/api/v1/tasks/",
            {"task_type": "word_count", "payload": {"text": "hello"}, "priority": 2},
            format="json",
            HTTP_IDEMPOTENCY_KEY="idem-cancel-1",
        )
        task_id = r1.data["id"]

        r_cancel = self.client.post(f"/api/v1/tasks/{task_id}/cancel/")
        self.assertEqual(r_cancel.status_code, status.HTTP_200_OK)
        self.assertEqual(r_cancel.data["status"], Task.Status.CANCELLED)

    def test_node_fetches_next_assigned_task(self):
        # Create and assign task to self.node
        task = Task.objects.create(
            task_type="sensor_average",
            payload={"vals": [1, 2, 3]},
            priority=1,
            status=Task.Status.ASSIGNED,
            assigned_node=self.node,
            idempotency_key="node-poll-1",
            created_by=self.operator,
        )

        # Nodes are identified by their request signature, so this node needs a real key pair.
        key = generate_private_key()
        Node.objects.filter(pk=self.node.pk).update(public_key=public_key_to_b64(key.public_key()))
        path = "/api/v1/node-api/tasks/next/"
        resp = self.client.get(path, **{
            "HTTP_" + name.upper().replace("-", "_"): value
            for name, value in sign_request(key, str(self.node.id), "GET", path, b"").items()
        })
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(resp.data["task"])
        self.assertEqual(resp.data["task"]["id"], str(task.id))
