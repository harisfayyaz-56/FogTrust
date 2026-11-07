import uuid
from django.conf import settings
from django.core.validators import RegexValidator, MinValueValidator, MaxValueValidator
from django.db import models


class Node(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        REVOKED = "revoked", "Revoked"

    class RevokeSource(models.TextChoices):
        MANUAL = "manual", "Manual"
        AUTOMATIC = "automatic", "Automatic"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(
        max_length=64,
        unique=True,
        validators=[
            RegexValidator(
                regex=r"^[a-z0-9][a-z0-9-]{2,63}$",
                message="Name must be 3-64 chars: lowercase alphanumeric with internal hyphens.",
            )
        ],
    )
    public_key = models.CharField(max_length=44, unique=True)
    key_fingerprint = models.CharField(max_length=64, db_index=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.ACTIVE, db_index=True)
    capacity = models.PositiveSmallIntegerField(
        default=4,
        validators=[MinValueValidator(1), MaxValueValidator(100)],
    )
    current_load = models.PositiveSmallIntegerField(default=0)
    trust_score = models.PositiveSmallIntegerField(
        default=80,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        db_index=True,
    )
    last_seen_at = models.DateTimeField(null=True, blank=True)
    last_counter = models.BigIntegerField(default=0)
    enrolled_at = models.DateTimeField(auto_now_add=True)
    enrolled_via = models.ForeignKey(
        "nodes.EnrollmentToken",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="enrolled_nodes",
    )
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="revoked_nodes",
    )
    revoke_reason = models.CharField(max_length=500, blank=True)
    revoke_source = models.CharField(max_length=16, choices=RevokeSource.choices, null=True, blank=True)

    def __str__(self):
        return f"{self.name} ({self.status}, trust={self.trust_score}, load={self.current_load}/{self.capacity})"


class EnrollmentToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    token_hash = models.CharField(max_length=64, unique=True)
    label = models.CharField(max_length=64)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_enrollment_tokens",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    used_by_node = models.OneToOneField(
        "nodes.Node",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="used_enrollment_token",
    )
    cancelled_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Token {self.label} ({'used' if self.used_at else 'pending'})"
