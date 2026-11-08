from django.conf import settings
from django.db import models


DEFAULT_POLICY_VALUES = {
    "trust_threshold": 60,
    "initial_score": 80,
    "auto_revoke_below": 10,
    "heartbeat_interval_s": 10,
    "missed_heartbeat_limit": 3,
    "timestamp_window_s": 30,
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


class PolicyConfig(models.Model):
    version = models.PositiveIntegerField(primary_key=True)
    values = models.JSONField(default=dict)
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="policy_changes",
    )
    changed_at = models.DateTimeField(auto_now_add=True)
    change_reason = models.CharField(max_length=500)

    class Meta:
        ordering = ["-version"]

    def __str__(self):
        return f"Policy v{self.version} ({self.change_reason})"

    @classmethod
    def current(cls) -> "PolicyConfig":
        latest = cls.objects.order_by("-version").first()
        if latest is None:
            latest = cls.objects.create(
                version=1,
                values=DEFAULT_POLICY_VALUES,
                change_reason="Initial default policy",
            )
        return latest


class TrustScoreRecord(models.Model):
    node = models.ForeignKey(
        "nodes.Node",
        on_delete=models.CASCADE,
        related_name="trust_records",
    )
    score = models.PositiveSmallIntegerField()
    previous_score = models.PositiveSmallIntegerField()
    rules_fired = models.JSONField(default=list)
    policy_version = models.PositiveIntegerField()
    computed_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-computed_at"]

    def __str__(self):
        return f"Node {self.node_id} score={self.score} (prev={self.previous_score}) at {self.computed_at}"
