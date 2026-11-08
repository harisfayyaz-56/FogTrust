import unittest
from trust.engine import compute_trust_score, NodeMetrics, TrustDecision


class TrustEngineTests(unittest.TestCase):
    def setUp(self):
        self.default_policy = {
            "trust_threshold": 60,
            "initial_score": 80,
            "auto_revoke_below": 10,
            "weights": {
                "missed_heartbeat": -10,
                "signature_failure": -20,
                "task_failure": -15,
                "integrity_failure": -25,
                "load_inconsistency": -5,
                "task_success": 5,
                "heartbeat_success": 2,
            },
        }

    def test_clean_node_increases_score(self):
        metrics = NodeMetrics(task_successes=2, heartbeat_successes=5)
        decision = compute_trust_score(80, self.default_policy, metrics)
        self.assertGreater(decision.new_score, 80)
        self.assertEqual(decision.new_score, 100)  # 80 + 10 + 10 = 100
        self.assertEqual(decision.previous_score, 80)
        self.assertFalse(decision.should_auto_revoke)

    def test_signature_failures_heavily_penalized(self):
        metrics = NodeMetrics(signature_failures=3)
        decision = compute_trust_score(80, self.default_policy, metrics)
        # 80 - 60 = 20
        self.assertEqual(decision.new_score, 20)
        self.assertFalse(decision.should_auto_revoke)

    def test_integrity_failure_triggers_auto_revoke_if_low(self):
        metrics = NodeMetrics(integrity_failures=4)
        decision = compute_trust_score(80, self.default_policy, metrics)
        # 80 - 100 = clamped to 0
        self.assertEqual(decision.new_score, 0)
        self.assertTrue(decision.should_auto_revoke)
        self.assertIn("auto-revoke", decision.explanation.lower())

    def test_score_never_exceeds_100_or_drops_below_0(self):
        high_metrics = NodeMetrics(task_successes=50)
        dec_high = compute_trust_score(95, self.default_policy, high_metrics)
        self.assertEqual(dec_high.new_score, 100)

        low_metrics = NodeMetrics(integrity_failures=10)
        dec_low = compute_trust_score(20, self.default_policy, low_metrics)
        self.assertEqual(dec_low.new_score, 0)

    def test_rules_fired_structure_and_explanation(self):
        metrics = NodeMetrics(missed_heartbeats=2, task_successes=1)
        decision = compute_trust_score(70, self.default_policy, metrics, policy_version=2)
        # 70 - 20 + 5 = 55
        self.assertEqual(decision.new_score, 55)
        self.assertEqual(decision.policy_version, 2)
        self.assertEqual(len(decision.rules_fired), 2)
        rules = [r["rule"] for r in decision.rules_fired]
        self.assertIn("missed_heartbeats", rules)
        self.assertIn("task_successes", rules)
        self.assertGreater(decision.latency_ms, 0)
        self.assertLess(decision.latency_ms, 10.0)


if __name__ == "__main__":
    unittest.main()

