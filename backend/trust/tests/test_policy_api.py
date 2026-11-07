from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient

from audit.models import AuditEvent
from nodes.models import Node
from trust.models import PolicyConfig, TrustScoreRecord

User = get_user_model()


class PolicyAndTrustAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.admin = User.objects.create_user(
            username="admin_user", password="password123", role="admin"
        )
        self.operator = User.objects.create_user(
            username="op_user", password="password123", role="operator"
        )
        self.viewer = User.objects.create_user(
            username="view_user", password="password123", role="viewer"
        )
        self.policy = PolicyConfig.objects.create(
            version=1,
            values={
                "trust_threshold": 60,
                "initial_score": 80,
                "auto_revoke_below": 10,
                "weights": {"task_failure": -15},
            },
            change_reason="Initial test policy",
        )
        self.node = Node.objects.create(
            name="worker-policy-test",
            public_key="k" * 44,
            key_fingerprint="fp_p",
            trust_score=75,
            capacity=4,
            current_load=0,
            status=Node.Status.ACTIVE,
        )

    def test_get_current_policy(self):
        self.client.force_authenticate(user=self.viewer)
        resp = self.client.get("/api/v1/policy/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["version"], 1)
        self.assertEqual(resp.data["values"]["trust_threshold"], 60)

    def test_update_policy_admin_only(self):
        # Operator cannot update policy
        self.client.force_authenticate(user=self.operator)
        resp_denied = self.client.post(
            "/api/v1/policy/",
            {
                "values": {"trust_threshold": 75, "weights": {"task_failure": -20}},
                "change_reason": "Operator attempted policy update",
            },
            format="json",
        )
        self.assertEqual(resp_denied.status_code, status.HTTP_403_FORBIDDEN)

        # Admin can update policy
        self.client.force_authenticate(user=self.admin)
        resp_ok = self.client.post(
            "/api/v1/policy/",
            {
                "values": {"trust_threshold": 75, "weights": {"task_failure": -20}},
                "change_reason": "Raised threshold for security demo",
            },
            format="json",
        )
        self.assertEqual(resp_ok.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp_ok.data["version"], 2)
        self.assertEqual(resp_ok.data["values"]["trust_threshold"], 75)

        # Verify audit event
        audit = AuditEvent.objects.filter(action="policy.change", target_id="2").first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.actor_id, "admin_user")

    def test_get_node_trust_history(self):
        TrustScoreRecord.objects.create(
            node=self.node,
            score=70,
            previous_score=80,
            rules_fired=[{"rule": "missed_heartbeats", "contribution": -10}],
            policy_version=1,
        )
        TrustScoreRecord.objects.create(
            node=self.node,
            score=75,
            previous_score=70,
            rules_fired=[{"rule": "task_success", "contribution": 5}],
            policy_version=1,
        )

        self.client.force_authenticate(user=self.viewer)
        resp = self.client.get(f"/api/v1/nodes/{self.node.id}/trust/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        # Results are paginated
        results = resp.data.get("results", resp.data)
        self.assertEqual(len(results), 2)
        # Most recent first
        self.assertEqual(results[0]["score"], 75)
        self.assertEqual(results[1]["score"], 70)
