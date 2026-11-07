import uuid
from django.db import models
from django.utils import timezone


class Decision(models.Model):
    class DecisionOutcome(models.TextChoices):
        ALLOW = "allow", "Allow"
        DENY = "deny", "Deny"
        FLAG = "flag", "Flag"
        ASSIGN = "assign", "Assign"
        REVOKE = "revoke", "Revoke"
        SCORE = "score", "Score"

    decision_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    subject_type = models.CharField(max_length=32, db_index=True)
    subject_id = models.CharField(max_length=64, db_index=True)
    decision = models.CharField(max_length=16, choices=DecisionOutcome.choices, db_index=True)
    reason_code = models.CharField(max_length=48, blank=True, db_index=True)
    explanation = models.TextField()
    rules_fired = models.JSONField(default=list)
    evidence = models.JSONField(default=dict)
    engine_name = models.CharField(max_length=64)
    engine_version = models.CharField(max_length=32)
    policy_version = models.IntegerField(default=1)
    thresholds = models.JSONField(default=dict)
    request_id = models.CharField(max_length=36, blank=True)
    decided_at = models.DateTimeField(default=timezone.now, db_index=True)
    latency_ms = models.FloatField(default=0.0)

    class Meta:
        ordering = ["-decided_at"]

    def __str__(self):
        return f"[{self.decided_at}] {self.decision} on {self.subject_type}:{self.subject_id} ({self.reason_code})"

