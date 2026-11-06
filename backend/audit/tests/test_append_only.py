"""Append-only at the application and database level (threat ID-9)."""

import pytest
from django.db import DatabaseError, connection, transaction

from audit.models import AuditEvent, AuditLogImmutableError
from audit.services import log_event

pytestmark = pytest.mark.django_db


@pytest.fixture
def event():
    return log_event("test.event", "success", actor_type="system")


def test_model_save_cannot_update(event):
    event.outcome = "failure"
    with pytest.raises(AuditLogImmutableError):
        event.save()


def test_model_delete_is_refused(event):
    with pytest.raises(AuditLogImmutableError):
        event.delete()


def test_queryset_update_and_delete_are_refused(event):
    with pytest.raises(AuditLogImmutableError):
        AuditEvent.objects.filter(sequence=event.sequence).update(outcome="failure")
    with pytest.raises(AuditLogImmutableError):
        AuditEvent.objects.all().delete()


def test_unchained_creation_is_refused():
    with pytest.raises(AuditLogImmutableError):
        AuditEvent.objects.create(sequence=99, action="x.y", outcome="success", prev_hash="a" * 64)
    with pytest.raises(AuditLogImmutableError):
        AuditEvent.objects.bulk_create([AuditEvent(sequence=99)])


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE audit_event SET outcome = 'failure'",
        "DELETE FROM audit_event",
    ],
)
def test_database_triggers_block_raw_sql(event, sql):
    with pytest.raises(DatabaseError, match="append-only"):
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(sql)

    assert AuditEvent.objects.get(sequence=event.sequence).outcome == "success"
