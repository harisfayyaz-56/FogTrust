"""
Decision: one row for every security decision any component makes
(docs/data-model.md, sections 3.9 and 4).

Enrollment accepted, heartbeat rejected, task assigned, result failed its integrity
check, node revoked: each writes one Decision. The dashboard's evidence view reads
only this table, so a reviewer can see WHY the system decided what it did and
reproduce it (rules fired, thresholds, engine version, policy version).

Never create rows directly. Call core.decisions.record_decision(), which redacts
the evidence and validates the enumerations.
"""

import uuid

from django.db import models
from django.utils import timezone


class Decision(models.Model):
    class SubjectType(models.TextChoices):
        ENROLLMENT = "enrollment", "Enrollment"
        NODE = "node", "Node"
        HEARTBEAT = "heartbeat", "Heartbeat"
        TASK = "task", "Task"
        RESULT = "result", "Result"
        POLICY = "policy", "Policy"

    class Verdict(models.TextChoices):
        ALLOW = "allow", "Allow"
        DENY = "deny", "Deny"
        FLAG = "flag", "Flag"
        ASSIGN = "assign", "Assign"
        REVOKE = "revoke", "Revoke"
        SCORE = "score", "Score"

    decision_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    subject_type = models.CharField(max_length=16, choices=SubjectType.choices, db_index=True)
    subject_id = models.CharField(max_length=64, blank=True, db_index=True)
    decision = models.CharField(max_length=16, choices=Verdict.choices, db_index=True)
    reason_code = models.CharField(max_length=48, default="OK", db_index=True)
    explanation = models.CharField(max_length=500)
    rules_fired = models.JSONField(default=list, blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    engine_name = models.CharField(max_length=48)
    engine_version = models.CharField(max_length=16)
    policy_version = models.IntegerField(null=True, blank=True)
    thresholds = models.JSONField(default=dict, blank=True)
    request_id = models.CharField(max_length=36, blank=True)
    decided_at = models.DateTimeField(default=timezone.now, db_index=True)
    latency_ms = models.FloatField(default=0.0)

    class Meta:
        db_table = "core_decision"
        ordering = ["-decided_at", "-decision_id"]

    def __str__(self) -> str:
        return f"{self.subject_type}:{self.decision} {self.reason_code}"
