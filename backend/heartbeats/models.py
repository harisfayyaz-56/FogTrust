"""
Heartbeat history and the replay-defence nonce table (docs/data-model.md section 3.4, Member 2).

Two tables, two jobs:

  UsedNonce  The replay defence. One row per nonce a node has used, kept until the nonce's window
             closes, then purged. The unique (node, nonce) constraint is what makes the check atomic:
             two copies of one request cannot both insert it, so only one is accepted.

  Heartbeat  The history people read (dashboard, evidence). One row per heartbeat from an ENROLLED
             node, accepted or rejected, with the reason. Rejections from unknown node ids are not
             stored (no node to attach them to); they live in the audit log and the Decision only.
             It is kept apart from UsedNonce because history must outlive the purge, and a rejected
             replay legitimately repeats an earlier nonce.
"""

from django.db import models
from django.utils import timezone


class Heartbeat(models.Model):
    node = models.ForeignKey("nodes.Node", on_delete=models.CASCADE, related_name="heartbeats")
    counter = models.BigIntegerField(null=True, blank=True)  # null when the body was unreadable
    nonce = models.CharField(max_length=32, blank=True)  # blank when the header was missing or malformed
    sent_at = models.DateTimeField(null=True, blank=True)  # the node's claimed time
    received_at = models.DateTimeField(default=timezone.now, db_index=True)  # server time
    reported_load = models.PositiveSmallIntegerField(null=True, blank=True)
    accepted = models.BooleanField(db_index=True)
    reason_code = models.CharField(max_length=48, blank=True)  # empty when accepted

    class Meta:
        ordering = ["-received_at", "-id"]
        indexes = [models.Index(fields=["node", "-received_at"], name="heartbeat_node_recent")]
        constraints = [
            # A nonce can be ACCEPTED once per node. Rejected rows may repeat it (that is a replay).
            models.UniqueConstraint(
                fields=["node", "nonce"], condition=models.Q(accepted=True), name="heartbeat_accepted_nonce_unique"
            ),
            models.CheckConstraint(
                condition=models.Q(accepted=True, reason_code="") | (models.Q(accepted=False) & ~models.Q(reason_code="")),
                name="heartbeat_reason_matches_outcome",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.node_id} {'ok' if self.accepted else self.reason_code}"


class UsedNonce(models.Model):
    node = models.ForeignKey("nodes.Node", on_delete=models.CASCADE, related_name="used_nonces")
    nonce = models.CharField(max_length=32)
    expires_at = models.BigIntegerField(db_index=True)  # Unix seconds: timestamp + window

    class Meta:
        constraints = [models.UniqueConstraint(fields=["node", "nonce"], name="usednonce_node_nonce_unique")]