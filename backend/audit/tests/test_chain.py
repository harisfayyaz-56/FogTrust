"""Hash chain: events link together and any later change is detected (threat ID-9)."""

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test import RequestFactory

from audit.chain import GENESIS_HASH, compute_hash
from audit.models import AuditEvent
from audit.services import log_event, verify_chain

pytestmark = pytest.mark.django_db


def write_events(count=3):
    return [log_event("test.event", "success", actor_type="system", details={"n": i}) for i in range(count)]


def without_triggers(sql, params=()):
    """Simulate an attacker editing the database file directly (bypassing app and triggers)."""
    with connection.cursor() as cursor:
        cursor.execute("DROP TRIGGER audit_event_no_update")
        cursor.execute("DROP TRIGGER audit_event_no_delete")
        cursor.execute(sql, params)


def test_events_are_linked_in_order():
    first, second, third = write_events(3)

    assert (first.sequence, second.sequence, third.sequence) == (1, 2, 3)
    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.hash
    assert third.prev_hash == second.hash
    assert len({first.hash, second.hash, third.hash}) == 3


def test_stored_hash_matches_recomputed_hash_after_reload():
    event = write_events(1)[0]
    reloaded = AuditEvent.objects.get(sequence=event.sequence)
    assert compute_hash(reloaded.chain_fields()) == reloaded.hash


def test_intact_chain_verifies():
    write_events(5)
    report = verify_chain()
    assert report.valid
    assert report.events_checked == 5
    assert report.first_broken_sequence is None


def test_empty_chain_is_valid():
    assert verify_chain().valid


def test_edited_event_is_detected():
    write_events(4)
    without_triggers("UPDATE audit_event SET outcome = 'failure' WHERE sequence = 2")

    report = verify_chain()
    assert not report.valid
    assert report.first_broken_sequence == 2
    assert report.problem == "hash_mismatch"


def test_edit_with_recomputed_hash_is_still_detected_at_next_event():
    write_events(4)
    event = AuditEvent.objects.get(sequence=2)
    fields = event.chain_fields()
    fields["outcome"] = "failure"
    without_triggers(
        "UPDATE audit_event SET outcome = 'failure', hash = %s WHERE sequence = 2", [compute_hash(fields)]
    )

    report = verify_chain()
    assert not report.valid
    assert report.first_broken_sequence == 3
    assert report.problem == "link_mismatch"


def test_deleted_event_is_detected():
    write_events(4)
    without_triggers("DELETE FROM audit_event WHERE sequence = 2")

    report = verify_chain()
    assert not report.valid
    assert report.first_broken_sequence == 3
    assert report.problem == "sequence_gap"


def test_request_context_is_recorded(make_user):
    user = make_user(username="op1", role="operator")
    request = RequestFactory().post("/x/", REMOTE_ADDR="10.0.0.7", HTTP_X_FORWARDED_FOR="6.6.6.6")
    request.user = user
    request.request_id = "0b6f4d2a-8c1e-4f3b-9a2d-5e6f7a8b9c0d"

    event = log_event("task.submit", "success", request=request, target_type="task", target_id="t-1")

    assert (event.actor_type, event.actor_id, event.actor_role) == ("user", "op1", "operator")
    assert event.request_id == request.request_id
    assert event.source_ip == "10.0.0.7"  # X-Forwarded-For is ignored: clients can forge it


def test_explicit_node_actor():
    event = log_event(
        "heartbeat.rejected",
        "failure",
        actor_type="node",
        actor_id="a7f3c2d1-0b9e-4c8d-9e1f-2a3b4c5d6e7f",
        actor_role="node",
        reason_code="HEARTBEAT_REPLAYED",
    )
    assert event.actor_type == "node"
    assert event.reason_code == "HEARTBEAT_REPLAYED"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"action": "revoke", "outcome": "success"},  # not area.verb
        {"action": "Node.Revoke", "outcome": "success"},
        {"action": "node.revoke", "outcome": "ok"},  # unknown outcome
        {"action": "node.revoke", "outcome": "success", "reason_code": "not a code"},
        {"action": "node.revoke", "outcome": "success", "actor_type": "robot"},
    ],
)
def test_invalid_events_are_refused(kwargs):
    with pytest.raises(ValueError):
        log_event(**kwargs)


def test_verify_command_succeeds_and_records_itself(capsys):
    write_events(2)
    call_command("verify_audit_chain")

    assert "Audit chain valid: 2 events checked." in capsys.readouterr().out
    latest = AuditEvent.objects.order_by("-sequence").first()
    assert (latest.action, latest.outcome, latest.actor_type) == ("audit.verify", "success", "system")


def test_verify_command_fails_on_tampering():
    write_events(3)
    without_triggers("UPDATE audit_event SET actor_id = 'someone-else' WHERE sequence = 1")

    with pytest.raises(CommandError, match="BROKEN at sequence 1"):
        call_command("verify_audit_chain", "--no-record")
