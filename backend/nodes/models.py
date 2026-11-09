"""
Enrollment tokens and nodes (docs/data-model.md, sections 3.2 and 3.3).

Rules enforced here, not only in views:
  * identifiers are server-generated UUIDs
  * the raw enrollment token is never stored, only its SHA-256 hash
  * a node's public key and name are unique; a revoked node is permanent
  * database CHECK constraints keep capacity, trust score and revocation fields consistent
"""

import uuid

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator, RegexValidator
from django.db import models
from django.utils import timezone

NODE_NAME_PATTERN = r"^[a-z0-9][a-z0-9-]{2,63}$"


def initial_trust_score() -> int:
    return settings.INITIAL_TRUST_SCORE


class EnrollmentToken(models.Model):
    """A one-time secret an administrator gives to one new node out of band."""

    class State(models.TextChoices):
        PENDING = "pending", "Pending"
        USED = "used", "Used"
        EXPIRED = "expired", "Expired"
        CANCELLED = "cancelled", "Cancelled"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    token_hash = models.CharField(max_length=64, unique=True)
    label = models.CharField(max_length=64)
    # Null only for tokens issued from the server's command line (create_enrollment_token).
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    used_by_node = models.OneToOneField(
        "nodes.Node", null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    cancelled_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "nodes_enrollment_token"
        ordering = ["-created_at"]

    def state(self, now=None) -> str:
        now = now or timezone.now()
        if self.used_at is not None:
            return self.State.USED
        if self.cancelled_at is not None:
            return self.State.CANCELLED
        if self.expires_at <= now:
            return self.State.EXPIRED
        return self.State.PENDING

    def __str__(self) -> str:
        return f"token {self.id} ({self.label})"


class Node(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        REVOKED = "revoked", "Revoked"

    class RevokeSource(models.TextChoices):
        MANUAL = "manual", "Manual"
        AUTOMATIC = "automatic", "Automatic"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=64, unique=True, validators=[RegexValidator(NODE_NAME_PATTERN)])
    # base64 of the raw 32-byte Ed25519 key. Set once at enrollment and never changed.
    public_key = models.CharField(max_length=44, unique=True)
    key_fingerprint = models.CharField(max_length=64, unique=True)  # SHA-256 hex of the raw key
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.ACTIVE, db_index=True)
    capacity = models.PositiveSmallIntegerField(validators=[MinValueValidator(1), MaxValueValidator(100)])
    current_load = models.PositiveSmallIntegerField(default=0)  # Member 3
    trust_score = models.PositiveSmallIntegerField(
        default=initial_trust_score, validators=[MaxValueValidator(100)], db_index=True
    )  # Member 3
    last_seen_at = models.DateTimeField(null=True, blank=True)  # Member 2 (accepted heartbeat)
    last_counter = models.BigIntegerField(default=0)  # Member 2 (replay defence)
    enrolled_at = models.DateTimeField(default=timezone.now)
    # Always set by the enrollment service. Nullable so tests and seed scripts (Member 3's
    # fixtures) can create a node without going through enrollment.
    enrolled_via = models.ForeignKey(
        EnrollmentToken, null=True, blank=True, on_delete=models.PROTECT, related_name="enrolled_nodes"
    )
    revoked_at = models.DateTimeField(null=True, blank=True)
    # Null together with revoke_source="automatic": the trust engine revoked it, not a person.
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    revoke_reason = models.CharField(max_length=500, blank=True)
    revoke_source = models.CharField(max_length=16, choices=RevokeSource.choices, blank=True)

    class Meta:
        db_table = "nodes_node"
        ordering = ["name"]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(capacity__gte=1, capacity__lte=100), name="node_capacity_1_to_100"
            ),
            models.CheckConstraint(condition=models.Q(trust_score__lte=100), name="node_trust_0_to_100"),
            models.CheckConstraint(
                condition=models.Q(status__in=["active", "revoked"]), name="node_status_known"
            ),
            # A revoked node always says when and why; an active node never carries revocation data.
            models.CheckConstraint(
                condition=(
                    models.Q(status="active", revoked_at__isnull=True, revoke_reason="")
                    | models.Q(status="revoked", revoked_at__isnull=False) & ~models.Q(revoke_reason="")
                ),
                name="node_revocation_fields_consistent",
            ),
        ]

    @property
    def is_active(self) -> bool:
        return self.status == self.Status.ACTIVE

    def __str__(self) -> str:
        return f"{self.name} ({self.status})"


class NodeNonce(models.Model):
    """
    One row per signed request a node has made inside the replay window (docs/node-signing-spec.md).

    The UNIQUE (node, nonce) constraint is what makes replay detection atomic: of two copies of
    the same request, the database lets exactly one insert succeed. Rows are only needed until
    `expires_at` (request timestamp + window); after that the freshness check refuses the request
    on its own, so old rows are purged (see replay_store.DatabaseReplayStore.purge).
    """

    node = models.ForeignKey(Node, on_delete=models.CASCADE, related_name="+")
    nonce = models.CharField(max_length=32)
    expires_at = models.BigIntegerField(db_index=True)  # Unix seconds

    class Meta:
        db_table = "nodes_node_nonce"
        constraints = [models.UniqueConstraint(fields=["node", "nonce"], name="node_nonce_unique")]
