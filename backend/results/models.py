"""
Encrypted task results (docs/data-model.md section 3.6, Member 2).

Only ciphertext is stored. The plaintext never reaches the database: it is decrypted in memory to check
integrity, and again when an operator views the result. What is kept in the clear is its SHA-256.

A task has at most one VALID result (database constraint). Failed attempts (a tampered ciphertext) are kept
as separate rows with integrity_valid = False so the evidence view can show them.
"""

import uuid

from django.db import models
from django.utils import timezone


class TaskResult(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    task = models.ForeignKey("tasks.Task", on_delete=models.CASCADE, related_name="results")
    node = models.ForeignKey("nodes.Node", on_delete=models.CASCADE, related_name="results")
    ephemeral_public_key = models.CharField(max_length=44)
    nonce = models.CharField(max_length=16)
    ciphertext = models.TextField()  # base64, at most 64 KB
    integrity_valid = models.BooleanField(db_index=True)
    plaintext_sha256 = models.CharField(max_length=64, null=True, blank=True)
    received_at = models.DateTimeField(default=timezone.now, db_index=True)
    reason_code = models.CharField(max_length=48, blank=True)  # empty when valid

    class Meta:
        ordering = ["-received_at"]
        constraints = [
            models.UniqueConstraint(fields=["task"], condition=models.Q(integrity_valid=True), name="one_valid_result_per_task"),
            models.CheckConstraint(
                condition=models.Q(integrity_valid=True, reason_code="") | (models.Q(integrity_valid=False) & ~models.Q(reason_code="")),
                name="result_reason_matches_integrity",
            ),
        ]

    def __str__(self) -> str:
        return f"result for {self.task_id} ({'valid' if self.integrity_valid else self.reason_code})"