"""
Append-only, hash-chained audit log.

Three layers of protection (docs/data-model.md, section 5.3):
  1. Application: save() refuses updates, delete() and queryset bulk changes raise.
  2. Database: SQLite triggers abort any UPDATE or DELETE (migration 0002).
  3. Detection: the hash chain reveals anything that gets past 1 and 2.

Never create events directly. Always call audit.services.log_event().
"""

import uuid

from django.db import models

from .chain import CHAIN_FIELDS


class AuditLogImmutableError(Exception):
    """Raised on any attempt to change or remove an audit event."""


class AuditEventQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise AuditLogImmutableError("audit log is append-only")

    def delete(self):
        raise AuditLogImmutableError("audit log is append-only")

    def bulk_update(self, objs, fields, batch_size=None):
        raise AuditLogImmutableError("audit log is append-only")

    def bulk_create(self, objs, *args, **kwargs):
        raise AuditLogImmutableError("use audit.services.log_event() so every event is chained")


class AuditEvent(models.Model):
    class ActorType(models.TextChoices):
        USER = "user", "User"
        NODE = "node", "Node"
        SYSTEM = "system", "System"
        ANONYMOUS = "anonymous", "Anonymous"

    class Outcome(models.TextChoices):
        SUCCESS = "success", "Success"
        FAILURE = "failure", "Failure"
        DENIED = "denied", "Denied"

    sequence = models.BigIntegerField(primary_key=True)
    event_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    timestamp = models.DateTimeField(db_index=True)
    actor_type = models.CharField(max_length=16, choices=ActorType.choices)
    actor_id = models.CharField(max_length=64, blank=True, db_index=True)
    actor_role = models.CharField(max_length=16, blank=True)
    action = models.CharField(max_length=64, db_index=True)
    target_type = models.CharField(max_length=32, blank=True)
    target_id = models.CharField(max_length=64, blank=True)
    outcome = models.CharField(max_length=16, choices=Outcome.choices, db_index=True)
    reason_code = models.CharField(max_length=48, blank=True)
    request_id = models.CharField(max_length=36, blank=True)
    source_ip = models.CharField(max_length=45, blank=True)
    details = models.JSONField(default=dict, blank=True)
    prev_hash = models.CharField(max_length=64, unique=True)
    hash = models.CharField(max_length=64, unique=True)

    objects = AuditEventQuerySet.as_manager()

    class Meta:
        db_table = "audit_event"  # the triggers in migration 0002 refer to this name
        ordering = ["-sequence"]

    def __str__(self) -> str:
        return f"#{self.sequence} {self.action} {self.outcome}"

    def chain_fields(self) -> dict:
        return {name: getattr(self, name) for name in CHAIN_FIELDS}

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise AuditLogImmutableError("audit log is append-only")
        if not self.hash:
            raise AuditLogImmutableError("use audit.services.log_event() so every event is chained")
        kwargs["force_insert"] = True
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise AuditLogImmutableError("audit log is append-only")
